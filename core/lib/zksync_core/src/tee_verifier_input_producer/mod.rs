//! Produces input for the TEE verifier

// RUST_LOG=warn,zksync_core::tee_verifier_input_producer=debug,zksync_core::basic_witness_input_producer=debug
use std::{cell::RefCell, rc::Rc, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use multivm::{
    interface::{FinishedL1Batch, L2BlockEnv, VmInterface},
    vm_latest::HistoryEnabled,
    VmInstance,
};
use tokio::{runtime::Handle, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};
use vm_utils::{execute_tx, storage::L1BatchParamsProvider};
use zksync_crypto::hasher::blake2::Blake2Hasher;
use zksync_dal::{tee_verifier_input_producer_dal::JOB_MAX_ATTEMPT, ConnectionPool, Core, CoreDal};
use zksync_db_connection::connection::Connection;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof,
};
use zksync_object_store::{ObjectStore, ObjectStoreFactory};
use zksync_prover_interface::inputs::{PrepareBasicCircuitsJob, StorageLogMetadata};
use zksync_queued_job_processor::JobProcessor;
use zksync_state::{InMemoryStorage, PostgresStorage, ReadStorage, StorageView, WriteStorage};
use zksync_tee_verifier::TeeVerifierInput;
use zksync_types::{
    block::L2BlockExecutionData, ethabi::ethereum_types::BigEndianHash, zk_evm_types::LogQuery,
    AccountTreeId, L1BatchNumber, L2BlockNumber, L2ChainId, StorageKey, H256,
};
use zksync_utils::{bytecode::hash_bytecode, u256_to_h256};

use self::metrics::METRICS;

mod metrics;
/// Component that extracts all data (from DB) necessary to run a TEE Verifier.
/// Does this by rerunning an entire L1Batch and extracting information from both the VM run and DB.
/// This component will upload TEE Verifier Inputs to the object store.
/// This allows the TEE Verifier workflow (that needs only TEE Verifier Inputs)
/// to be run only using the object store information, having no other external dependency.
#[derive(Debug)]
pub struct TeeVerifierInputProducer {
    connection_pool: ConnectionPool<Core>,
    l2_chain_id: L2ChainId,
    object_store: Arc<dyn ObjectStore>,
}

impl TeeVerifierInputProducer {
    pub async fn new(
        connection_pool: ConnectionPool<Core>,
        store_factory: &ObjectStoreFactory,
        l2_chain_id: L2ChainId,
    ) -> anyhow::Result<Self> {
        Ok(TeeVerifierInputProducer {
            connection_pool,
            object_store: store_factory.create_store().await,
            l2_chain_id,
        })
    }

    fn process_job_impl(
        rt_handle: Handle,
        l1_batch_number: L1BatchNumber,
        started_at: Instant,
        connection_pool: ConnectionPool<Core>,
        object_store: Arc<dyn ObjectStore>,
        l2_chain_id: L2ChainId,
    ) -> anyhow::Result<TeeVerifierInput> {
        let prepare_basic_circuits_job: PrepareBasicCircuitsJob = rt_handle
            .block_on(object_store.get(l1_batch_number))
            .context("failed to get PrepareBasicCircuitsJob from object store")?;

        let mut connection = rt_handle
            .block_on(connection_pool.connection())
            .context("failed to get connection for TeeVerifierInputProducer")?;

        let new_root_hash = rt_handle
            .block_on(
                connection
                    .blocks_dal()
                    .get_l1_batch_state_root(l1_batch_number),
            )?
            .ok_or(anyhow!("Failed to get new root hash"))?;

        let miniblocks_execution_data = rt_handle.block_on(
            connection
                .transactions_dal()
                .get_l2_blocks_to_execute_for_l1_batch(l1_batch_number),
        )?;

        let fictive_miniblock_number = miniblocks_execution_data.last().unwrap().number + 1;

        let fictive_miniblock_data =
            Self::create_fictive_miniblock(&rt_handle, &mut connection, fictive_miniblock_number)?;

        let last_batch_miniblock_number = miniblocks_execution_data.first().unwrap().number - 1;

        let l1_batch_header = rt_handle
            .block_on(connection.blocks_dal().get_l1_batch_header(l1_batch_number))
            .with_context(|| format!("header is missing for L1 batch #{l1_batch_number}"))?
            .unwrap();

        let l1_batch_params_provider = rt_handle
            .block_on(L1BatchParamsProvider::new(&mut connection))
            .context("failed initializing L1 batch params provider")?;

        let first_miniblock_in_batch = rt_handle
            .block_on(
                l1_batch_params_provider
                    .load_first_l2_block_in_batch(&mut connection, l1_batch_number),
            )
            .with_context(|| {
                format!("failed loading first miniblock in L1 batch #{l1_batch_number}")
            })?
            .with_context(|| format!("no miniblocks persisted for L1 batch #{l1_batch_number}"))?;

        // In the state keeper, this value is used to reject execution.
        // All batches have already been executed by State Keeper.
        // This means we don't want to reject any execution, therefore we're using MAX as an allow all.
        let validation_computational_gas_limit = u32::MAX;

        let (system_env, l1_batch_env) = rt_handle
            .block_on(l1_batch_params_provider.load_l1_batch_params(
                &mut connection,
                &first_miniblock_in_batch,
                validation_computational_gas_limit,
                l2_chain_id,
            ))
            .context("expected miniblock to be executed and sealed")?;

        let pg_storage = PostgresStorage::new(
            rt_handle.clone(),
            connection,
            last_batch_miniblock_number,
            true,
        );
        let mut real_storage_view = StorageView::new(pg_storage);

        let used_contracts = l1_batch_header
            .used_contract_hashes
            .into_iter()
            .map(|hash| {
                ReadStorage::load_factory_dep(&mut real_storage_view, u256_to_h256(hash))
                    .map(|bytes| (u256_to_h256(hash), bytes))
            })
            .flatten()
            .collect();

        info!("Started execution of l1_batch: {l1_batch_number:?}");

        let tee_verifier_input = TeeVerifierInput {
            prepare_basic_circuits_job,
            new_root_hash,
            miniblocks_execution_data,
            fictive_miniblock_data,
            l1_batch_env,
            system_env,
            used_contracts,
        };

        Self::run_tee_verifier(tee_verifier_input.clone())?;

        info!("🚀 Looks like we verified {l1_batch_number} correctly - whoop, whoop! 🚀");

        info!("Finished execution of l1_batch: {l1_batch_number:?}");

        METRICS.process_batch_time.observe(started_at.elapsed());
        debug!(
            "TeeVerifierInputProducer took {:?} for L1BatchNumber {}",
            started_at.elapsed(),
            l1_batch_number.0
        );

        Ok(tee_verifier_input)
    }

    fn run_tee_verifier(tee_verifier_input: TeeVerifierInput) -> anyhow::Result<()> {
        let TeeVerifierInput {
            prepare_basic_circuits_job,
            new_root_hash,
            miniblocks_execution_data,
            fictive_miniblock_data,
            l1_batch_env,
            system_env,
            used_contracts,
        } = tee_verifier_input;

        let old_root_hash = l1_batch_env.previous_batch_hash.unwrap();
        let l1_batch_number = l1_batch_env.number;
        let l2_chain_id = system_env.chain_id;
        let enumeration_index = prepare_basic_circuits_job.next_enumeration_index();

        let mut raw_storage = InMemoryStorage::with_custom_system_contracts_and_chain_id(
            l2_chain_id,
            hash_bytecode,
            Vec::with_capacity(0),
        );

        for (hash, bytes) in used_contracts.into_iter() {
            trace!("raw_storage.store_factory_dep({hash}, bytes)");
            raw_storage.store_factory_dep(hash, bytes)
        }

        let block_output_with_proofs =
            Self::get_bowp_and_set_initial_values(prepare_basic_circuits_job, &mut raw_storage);

        let storage_view = Rc::new(RefCell::new(StorageView::new(&raw_storage)));

        let vm = VmInstance::new(l1_batch_env, system_env, storage_view);

        let vm_out = Self::execute_vm(miniblocks_execution_data, fictive_miniblock_data, vm)?;

        let instructions: Vec<TreeInstruction> =
            Self::generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

        // `verify_proofs` will panic!() if something does not add up.
        block_output_with_proofs
            .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
            .context("🛑 🛑 Failed to verify_proofs {l1_batch_number} correctly - oh no!")?;

        if block_output_with_proofs.root_hash() != Some(new_root_hash) {
            error!(
                "🛑 🛑 Failed to verify {l1_batch_number} correctly - oh no! {:#?} != {:#?}",
                block_output_with_proofs.root_hash(),
                new_root_hash
            );
            bail!(
                "Failed to verify {l1_batch_number} correctly - oh no! {:#?} != {:#?}",
                block_output_with_proofs.root_hash(),
                new_root_hash
            );
        }

        Ok(())
    }

    fn get_bowp_and_set_initial_values(
        prepare_basic_circuits_job: PrepareBasicCircuitsJob,
        raw_storage: &mut InMemoryStorage,
    ) -> BlockOutputWithProofs {
        let logs = prepare_basic_circuits_job
            .into_merkle_paths()
            .map(
                |StorageLogMetadata {
                     root_hash,
                     merkle_paths,
                     is_write,
                     first_write,
                     leaf_enumeration_index,
                     value_read,
                     leaf_hashed_key: leaf_storage_key,
                     ..
                 }| {
                    let root_hash = root_hash.into();
                    let merkle_path = merkle_paths.into_iter().map(|x| x.into()).collect();
                    let base: TreeLogEntry = match (is_write, first_write, leaf_enumeration_index) {
                        (false, _, 0) => TreeLogEntry::ReadMissingKey,
                        (false, _, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Read {
                                leaf_index: leaf_enumeration_index,
                                value: value_read.into(),
                            }
                        }
                        (true, true, _) => TreeLogEntry::Inserted,
                        (true, false, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Updated {
                                leaf_index: leaf_enumeration_index,
                                previous_value: value_read.into(),
                            }
                        }
                    };
                    TreeLogEntryWithProof {
                        base,
                        merkle_path,
                        root_hash,
                    }
                },
            )
            .collect();

        BlockOutputWithProofs {
            logs,
            leaf_count: 0,
        }
    }

    fn execute_vm<S: WriteStorage>(
        miniblocks_execution_data: Vec<L2BlockExecutionData>,
        fictive_miniblock_data: L2BlockExecutionData,
        mut vm: VmInstance<S, HistoryEnabled>,
    ) -> anyhow::Result<FinishedL1Batch> {
        let next_miniblocks_data = miniblocks_execution_data
            .iter()
            .skip(1)
            .chain([&fictive_miniblock_data]);

        let miniblocks_data = miniblocks_execution_data.iter().zip(next_miniblocks_data);

        for (miniblock_data, next_miniblock_data) in miniblocks_data {
            trace!(
                "Started execution of miniblock: {:?}, executing {:?} transactions",
                miniblock_data.number,
                miniblock_data.txs.len(),
            );
            for tx in &miniblock_data.txs {
                trace!("Started execution of tx: {tx:?}");
                execute_tx(tx, &mut vm)
                    .context("failed to execute transaction in TeeVerifierInputProducer")?;
                trace!("Finished execution of tx: {tx:?}");
            }
            vm.start_new_l2_block(L2BlockEnv::from_miniblock_data(next_miniblock_data));

            trace!(
                "Finished execution of miniblock: {:?}",
                miniblock_data.number
            );
        }

        Ok(vm.finish_batch())
    }

    fn create_fictive_miniblock(
        rt_handle: &Handle,
        connection: &mut Connection<Core>,
        fictive_miniblock_number: L2BlockNumber,
    ) -> anyhow::Result<L2BlockExecutionData> {
        let fictive_miniblock_data = rt_handle
            .block_on(
                connection
                    .sync_dal()
                    .sync_block(fictive_miniblock_number, false),
            )
            .context("Failed to get fictive miniblock")?
            .context("Failed to get fictive miniblock")?;
        let last_non_fictive_miniblock_data = rt_handle
            .block_on(
                connection
                    .sync_dal()
                    .sync_block(fictive_miniblock_number - 1, false),
            )
            .context("Failed to get last miniblock")?
            .context("Failed to get last miniblock")?;

        Ok(L2BlockExecutionData {
            number: fictive_miniblock_data.number,
            timestamp: fictive_miniblock_data.timestamp,
            prev_block_hash: last_non_fictive_miniblock_data.hash.unwrap_or_default(),
            virtual_blocks: fictive_miniblock_data.virtual_blocks.unwrap_or(0),
            txs: Vec::new(),
        })
    }

    fn map_log_tree(
        log_query: &LogQuery,
        tree_log_entry: &TreeLogEntry,
        idx: &mut u64,
    ) -> anyhow::Result<TreeInstruction> {
        let key = StorageKey::new(
            AccountTreeId::new(log_query.address),
            u256_to_h256(log_query.key),
        )
        .hashed_key_u256();
        Ok(match (log_query.rw_flag, *tree_log_entry) {
            (true, TreeLogEntry::Updated { leaf_index, .. }) => {
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (true, TreeLogEntry::Inserted) => {
                let leaf_index = *idx;
                *idx += 1;
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (false, TreeLogEntry::Read { value, .. }) => {
                if log_query.read_value != value.into_uint() {
                    error!(
                        "🛑 🛑 Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value, value
                    );
                    bail!(
                        "Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value,
                        value
                    );
                }
                TreeInstruction::Read(key)
            }
            (false, TreeLogEntry::ReadMissingKey { .. }) => TreeInstruction::Read(key),
            _ => {
                error!("🛑 🛑 Failed to map LogQuery to TreeInstruction");
                bail!("Failed to map LogQuery to TreeInstruction");
            }
        })
    }

    fn generate_tree_instructions(
        mut idx: u64,
        bowp: &BlockOutputWithProofs,
        vm_out: FinishedL1Batch,
    ) -> anyhow::Result<Vec<TreeInstruction>> {
        vm_out
            .final_execution_state
            .deduplicated_storage_log_queries
            .into_iter()
            .zip(bowp.logs.iter())
            .map(|(log_query, tree_log_entry)| {
                Self::map_log_tree(&log_query, &tree_log_entry.base, &mut idx)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[async_trait]
impl JobProcessor for TeeVerifierInputProducer {
    type Job = L1BatchNumber;
    type JobId = L1BatchNumber;
    type JobArtifacts = TeeVerifierInput;
    const SERVICE_NAME: &'static str = "tee_verifier_input_producer";

    async fn get_next_job(&self) -> anyhow::Result<Option<(Self::JobId, Self::Job)>> {
        let mut connection = self.connection_pool.connection().await?;
        let l1_batch_to_process = connection
            .tee_verifier_input_producer_dal()
            .get_next_tee_verifier_input_producer_job()
            .await
            .context("failed to get next basic witness input producer job")?;
        Ok(l1_batch_to_process.map(|number| (number, number)))
    }

    async fn save_failure(&self, job_id: Self::JobId, started_at: Instant, error: String) {
        let attempts = self
            .connection_pool
            .connection()
            .await
            .unwrap()
            .tee_verifier_input_producer_dal()
            .mark_job_as_failed(job_id, started_at, error)
            .await
            .expect("errored whilst marking job as failed");
        if let Some(tries) = attempts {
            warn!("Failed to process job: {job_id:?}, after {tries} tries.");
        } else {
            warn!("L1 Batch {job_id:?} was processed successfully by another worker.");
        }
    }

    async fn process_job(
        &self,
        _job_id: &Self::JobId,
        job: Self::Job,
        started_at: Instant,
    ) -> JoinHandle<anyhow::Result<Self::JobArtifacts>> {
        let l2_chain_id = self.l2_chain_id;
        let connection_pool = self.connection_pool.clone();
        let object_store = self.object_store.clone();
        tokio::task::spawn_blocking(move || {
            let rt_handle = Handle::current();
            Self::process_job_impl(
                rt_handle,
                job,
                started_at,
                connection_pool.clone(),
                object_store,
                l2_chain_id,
            )
        })
    }

    async fn save_result(
        &self,
        job_id: Self::JobId,
        started_at: Instant,
        artifacts: Self::JobArtifacts,
    ) -> anyhow::Result<()> {
        let upload_started_at = Instant::now();
        let object_path = self
            .object_store
            .put(job_id, &artifacts)
            .await
            .context("failed to upload artifacts for TeeVerifierInputProducer")?;
        METRICS
            .upload_input_time
            .observe(upload_started_at.elapsed());
        let mut connection = self
            .connection_pool
            .connection()
            .await
            .context("failed to acquire DB connection for TeeVerifierInputProducer")?;
        let mut transaction = connection
            .start_transaction()
            .await
            .context("failed to acquire DB transaction for TeeVerifierInputProducer")?;
        transaction
            .tee_verifier_input_producer_dal()
            .mark_job_as_successful(job_id, started_at, &object_path)
            .await
            .context("failed to mark job as successful for TeeVerifierInputProducer")?;
        transaction
            .commit()
            .await
            .context("failed to commit DB transaction for TeeVerifierInputProducer")?;
        METRICS.block_number_processed.set(job_id.0 as i64);
        Ok(())
    }

    fn max_attempts(&self) -> u32 {
        JOB_MAX_ATTEMPT as u32
    }

    async fn get_job_attempts(&self, job_id: &L1BatchNumber) -> anyhow::Result<u32> {
        let mut connection = self
            .connection_pool
            .connection()
            .await
            .context("failed to acquire DB connection for TeeVerifierInputProducer")?;
        connection
            .tee_verifier_input_producer_dal()
            .get_tee_verifier_input_producer_job_attempts(*job_id)
            .await
            .map(|attempts| attempts.unwrap_or(0))
            .context("failed to get job attempts for TeeVerifierInputProducer")
    }
}
