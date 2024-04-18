use std::{cell::RefCell, rc::Rc};

use anyhow::{bail, Context};
use multivm::{
    interface::{FinishedL1Batch, L2BlockEnv, VmInterface},
    vm_latest::HistoryEnabled,
    VmInstance,
};
use tracing::{error, info, level_filters::LevelFilter, trace};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use vm_utils::execute_tx;
use zksync_config::{configs::object_store::ObjectStoreMode, ObjectStoreConfig};
use zksync_crypto::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof,
};
use zksync_object_store::ObjectStoreFactory;
use zksync_prover_interface::inputs::{PrepareBasicCircuitsJob, StorageLogMetadata};
use zksync_state::{InMemoryStorage, StorageView, WriteStorage};
use zksync_tee_verifier::TeeVerifierInput;
use zksync_types::{
    block::L2BlockExecutionData, ethabi::ethereum_types::BigEndianHash, zk_evm_types::LogQuery,
    AccountTreeId, L1BatchNumber, StorageKey, H256,
};
use zksync_utils::{bytecode::hash_bytecode, u256_to_h256};

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
        get_bowp_and_set_initial_values(prepare_basic_circuits_job, &mut raw_storage);

    let storage_view = Rc::new(RefCell::new(StorageView::new(&raw_storage)));

    let vm = VmInstance::new(l1_batch_env, system_env, storage_view);

    let vm_out = execute_vm(miniblocks_execution_data, fictive_miniblock_data, vm)?;

    let instructions: Vec<TreeInstruction> =
        generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

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
        .map(|(log_query, tree_log_entry)| map_log_tree(&log_query, &tree_log_entry.base, &mut idx))
        .collect::<Result<Vec<_>, _>>()
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;

    let object_store = ObjectStoreFactory::new(ObjectStoreConfig {
        mode: ObjectStoreMode::FileBacked {
            file_backed_base_path: "artifacts".to_string(),
        },
        max_retries: 0,
    })
    .create_store()
    .await;

    let mut i = 1;
    loop {
        let v = object_store
            .get::<TeeVerifierInput>(L1BatchNumber(i))
            .await
            .context(format!("failed to get batch verifier inputs for batch {i}"))?;
        run_tee_verifier(v)?;
        info!("Successfully validated batch {i}");
        i += 1;
    }
}
