use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use async_trait::async_trait;
use multivm::{interface::L1BatchEnv, vm_1_4_2::SystemEnv, zk_evm_latest::ethereum_types::H256};
use once_cell::sync::OnceCell;
use tokio::sync::{watch, RwLock};
use vm_utils::storage::L1BatchParamsProvider;
use zksync_dal::{Connection, ConnectionPool, Core, CoreDal};
use zksync_state::{
    AsyncCatchupTask, PgOrRocksdbStorage, ReadStorageFactory, RocksdbStorageBuilder,
    StateKeeperColumnFamily, StateValue,
};
use zksync_storage::RocksDB;
use zksync_types::{block::MiniblockExecutionData, L1BatchNumber, L2ChainId, StorageKey};

/// Data needed to re-execute an L1 batch.
#[derive(Debug, Clone)]
pub struct BatchData {
    /// Parameters for L1 batch this data belongs to.
    pub l1_batch_env: L1BatchEnv,
    /// Execution process parameters.
    pub system_env: SystemEnv,
    /// List of miniblocks and corresponding transactions that were executed within batch.
    pub miniblocks: Vec<MiniblockExecutionData>,
}

#[derive(Debug, Clone)]
struct StorageData {
    batch_data: BatchData,
    storage_diffs: HashMap<StorageKey, StateValue>,
    factory_deps: HashMap<H256, Vec<u8>>,
}

/// Functionality to fetch data about processed/unprocessed batches for a particular VM runner
/// instance.
#[async_trait]
pub trait VmRunnerStorageLoader: Debug + Send + Sync + Clone + 'static {
    /// Unique name of the VM runner instance.
    fn name() -> &'static str;

    /// Returns the last L1 batch number that has been processed by this VM runner instance.
    ///
    /// # Errors
    ///
    /// Propagates DB errors.
    async fn latest_processed_batch(
        &self,
        conn: &mut Connection<'_, Core>,
    ) -> anyhow::Result<L1BatchNumber>;
}

/// Abstraction for VM runner's storage layer that provides two main features:
///
/// 1. A [`ReadStorageFactory`] implementation backed by either Postgres or RocksDB (if it's
/// caught up). Always initialized as a `Postgres` variant and is then mutated into `Rocksdb`
/// once RocksDB cache is caught up.
/// 2. Loads data needed to re-execute the next unprocessed L1 batch.
#[derive(Debug)]
pub struct VmRunnerStorage<L: VmRunnerStorageLoader> {
    pool: ConnectionPool<Core>,
    l1_batch_params_provider: L1BatchParamsProvider,
    chain_id: L2ChainId,
    max_batches_to_load: u32,
    state: Arc<RwLock<State>>,
    rocksdb_cell: Arc<OnceCell<RocksDB<StateKeeperColumnFamily>>>,
    _marker: PhantomData<L>,
}

#[derive(Debug)]
struct State {
    l1_batch_number: L1BatchNumber,
    storage: BTreeMap<L1BatchNumber, StorageData>,
}

impl<L: VmRunnerStorageLoader> VmRunnerStorage<L> {
    /// Creates a new VM runner storage using provided Postgres pool and RocksDB path.
    pub async fn new(
        pool: ConnectionPool<Core>,
        rocksdb_path: String,
        loader: L,
        enum_index_migration_chunk_size: usize, // TODO: Remove
        chain_id: L2ChainId,
        max_batches_to_load: u32,
    ) -> anyhow::Result<(Self, StorageSyncTask<L>)> {
        let mut conn = pool.connection_tagged(L::name()).await?;
        let l1_batch_params_provider = L1BatchParamsProvider::new(&mut conn)
            .await
            .context("Failed initializing L1 batch params provider")?;
        drop(conn);
        let rocksdb_cell = Arc::new(OnceCell::new());
        let state = Arc::new(RwLock::new(State {
            l1_batch_number: L1BatchNumber(0),
            storage: BTreeMap::new(),
        }));
        let task = StorageSyncTask::new(
            pool.clone(),
            max_batches_to_load,
            chain_id,
            rocksdb_path,
            enum_index_migration_chunk_size,
            loader.clone(),
            rocksdb_cell.clone(),
            state.clone(),
        )
        .await?;
        Ok((
            Self {
                pool,
                l1_batch_params_provider,
                chain_id,
                max_batches_to_load,
                state,
                rocksdb_cell,
                _marker: PhantomData,
            },
            task,
        ))
    }

    async fn access_storage_inner(
        &self,
        stop_receiver: &watch::Receiver<bool>,
        l1_batch_number: L1BatchNumber,
    ) -> anyhow::Result<Option<PgOrRocksdbStorage<'_>>> {
        if let Some(rocksdb) = self.rocksdb_cell.get() {
            loop {
                let state = self.state.read().await;
                let mut conn = self
                    .pool
                    .connection_tagged(L::name())
                    .await
                    .context("Failed getting a Postgres connection")?;
                let max_l1_batch = (state.l1_batch_number + self.max_batches_to_load).min(
                    conn.blocks_dal()
                        .get_sealed_l1_batch_number()
                        .await?
                        .unwrap_or_default(),
                );
                if l1_batch_number < state.l1_batch_number || l1_batch_number > max_l1_batch {
                    anyhow::bail!(
                        "Trying to access VM runner storage with L1 batch #{} while only [#{}; #{}] are available",
                        l1_batch_number,
                        state.l1_batch_number,
                        max_l1_batch
                    );
                }
                if l1_batch_number != state.l1_batch_number
                    && !state.storage.contains_key(&l1_batch_number)
                {
                    drop(state);
                    drop(conn);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let rocksdb_builder = RocksdbStorageBuilder::from_rocksdb(rocksdb.clone());
                let rocksdb = rocksdb_builder
                    .synchronize(&mut conn, stop_receiver, Some(state.l1_batch_number))
                    .await
                    .context("Failed to catch up RocksDB storage to Postgres")?;
                let Some(rocksdb) = rocksdb else {
                    tracing::info!("Synchronizing RocksDB interrupted");
                    return Ok(None);
                };
                let storage_diffs = state
                    .storage
                    .iter()
                    .filter_map(|(x, y)| {
                        if x <= &l1_batch_number {
                            Some(y.storage_diffs.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let factory_deps = state
                    .storage
                    .iter()
                    .filter_map(|(x, y)| {
                        if x <= &l1_batch_number {
                            Some(y.factory_deps.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                return Ok(Some(PgOrRocksdbStorage::RocksdbWithMemory(
                    rocksdb,
                    storage_diffs,
                    factory_deps,
                )));
            }
        } else {
            Ok(Some(
                PgOrRocksdbStorage::access_storage_pg(&self.pool, l1_batch_number)
                    .await
                    .context("Failed accessing Postgres storage")?,
            ))
        }
    }

    /// Loads next unprocessed L1 batch along with all transactions that VM runner needs to
    /// re-execute. These are the transactions that are included in a sealed miniblock belonging
    /// to a sealed L1 batch (with state keeper being the source of truth). The order of the
    /// transactions is the same as it was when state keeper executed them.
    ///
    /// Can return `None` if there are no batches to be processed.
    ///
    /// # Errors
    ///
    /// Propagates DB errors.
    pub async fn load_batch(
        &self,
        l1_batch_number: L1BatchNumber,
    ) -> anyhow::Result<Option<BatchData>> {
        if let Some(_) = self.rocksdb_cell.get() {
            loop {
                let state = self.state.read().await;
                let mut conn = self.pool.connection_tagged(L::name()).await?;
                let max_l1_batch = (state.l1_batch_number + self.max_batches_to_load).min(
                    conn.blocks_dal()
                        .get_sealed_l1_batch_number()
                        .await?
                        .unwrap_or_default(),
                );
                drop(conn);
                if l1_batch_number <= state.l1_batch_number || l1_batch_number > max_l1_batch {
                    tracing::debug!(
                        %l1_batch_number,
                        min_l1_batch = %(state.l1_batch_number + 1),
                        %max_l1_batch,
                        "Trying to load an L1 batch that is not available"
                    );
                    return Ok(None);
                }
                let Some(storage_data) = state.storage.get(&l1_batch_number) else {
                    drop(state);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                return Ok(Some(storage_data.batch_data.clone()));
            }
        } else {
            let mut conn = self.pool.connection_tagged(L::name()).await?;
            StorageSyncTask::<L>::load_batch_data(
                &mut conn,
                l1_batch_number,
                &self.l1_batch_params_provider,
                self.chain_id,
            )
            .await
        }
    }
}

#[async_trait]
impl<L: VmRunnerStorageLoader> ReadStorageFactory for VmRunnerStorage<L> {
    async fn access_storage(
        &self,
        stop_receiver: &watch::Receiver<bool>,
        l1_batch_number: L1BatchNumber,
    ) -> anyhow::Result<Option<PgOrRocksdbStorage<'_>>> {
        self.access_storage_inner(stop_receiver, l1_batch_number)
            .await
    }
}

/// A runnable task that catches up the provided RocksDB cache instance to the latest processed
/// batch and then continuously makes sure that this invariant is held for the foreseeable future.
/// In the meanwhile, `StorageSyncTask` also loads the next `max_batches_to_load` batches in memory
/// so that they are immediately accessible by [`VmRunnerStorage`].
#[derive(Debug)]
pub struct StorageSyncTask<L: VmRunnerStorageLoader> {
    pool: ConnectionPool<Core>,
    max_batches_to_load: u32,
    l1_batch_params_provider: L1BatchParamsProvider,
    chain_id: L2ChainId,
    rocksdb_cell: Arc<OnceCell<RocksDB<StateKeeperColumnFamily>>>,
    loader: L,
    state: Arc<RwLock<State>>,
    catchup_task: AsyncCatchupTask,
}

impl<L: VmRunnerStorageLoader> StorageSyncTask<L> {
    async fn new(
        pool: ConnectionPool<Core>,
        max_batches_to_load: u32,
        chain_id: L2ChainId,
        rocksdb_path: String,
        enum_index_migration_chunk_size: usize,
        loader: L,
        rocksdb_cell: Arc<OnceCell<RocksDB<StateKeeperColumnFamily>>>,
        state: Arc<RwLock<State>>,
    ) -> anyhow::Result<Self> {
        let mut conn = pool.connection_tagged(L::name()).await?;
        let l1_batch_params_provider = L1BatchParamsProvider::new(&mut conn)
            .await
            .context("Failed initializing L1 batch params provider")?;
        let catchup_task = AsyncCatchupTask::new(
            pool.clone(),
            rocksdb_path,
            enum_index_migration_chunk_size,
            rocksdb_cell.clone(),
            Some(loader.latest_processed_batch(&mut conn).await?),
        );
        drop(conn);
        Ok(Self {
            pool,
            max_batches_to_load,
            l1_batch_params_provider,
            chain_id,
            rocksdb_cell,
            loader,
            state,
            catchup_task,
        })
    }

    pub async fn run(self, stop_receiver: watch::Receiver<bool>) -> anyhow::Result<()> {
        self.catchup_task.run(stop_receiver.clone()).await?;
        let rocksdb = self.rocksdb_cell.get().ok_or_else(|| {
            anyhow::anyhow!("Expected RocksDB to be initialized by `AsyncCatchupTask`")
        })?;
        loop {
            if *stop_receiver.borrow() {
                tracing::info!("`StorageSyncTask` was interrupted");
                return Ok(());
            }
            // State guard lock also serves as a Mutex between `StorageSyncTask` and `VmRunnerStorage`
            let mut state = self.state.write().await;
            let mut conn = self.pool.connection_tagged(L::name()).await?;
            let latest_processed_batch = self.loader.latest_processed_batch(&mut conn).await?;
            let rocksdb_builder = RocksdbStorageBuilder::from_rocksdb(rocksdb.clone());
            let rocksdb = rocksdb_builder
                .synchronize(&mut conn, &stop_receiver, Some(latest_processed_batch))
                .await
                .context("Failed to catch up state keeper RocksDB storage to Postgres")?;
            let Some(_) = rocksdb else {
                tracing::info!("`StorageSyncTask` was interrupted during RocksDB synchronization");
                return Ok(());
            };
            state.l1_batch_number = latest_processed_batch;
            state
                .storage
                .retain(|l1_batch_number, _| l1_batch_number > &latest_processed_batch);
            let max_present = state
                .storage
                .last_entry()
                .map(|e| *e.key())
                .unwrap_or(latest_processed_batch);
            let max_desired = latest_processed_batch + self.max_batches_to_load;
            for l1_batch_number in max_present.0 + 1..=max_desired.0 {
                let l1_batch_number = L1BatchNumber(l1_batch_number);
                let Some(batch_data) = Self::load_batch_data(
                    &mut conn,
                    l1_batch_number,
                    &self.l1_batch_params_provider,
                    self.chain_id,
                )
                .await?
                else {
                    break;
                };
                let touched_slots = conn
                    .storage_logs_dal()
                    .get_touched_slots_for_l1_batch(l1_batch_number)
                    .await?;
                let keys_with_unknown_indices = touched_slots
                    .iter()
                    .map(|(key, _)| key.hashed_key())
                    .collect::<Vec<_>>();
                let enum_indices_and_batches = conn
                    .storage_logs_dal()
                    .get_l1_batches_and_indices_for_initial_writes(&keys_with_unknown_indices)
                    .await?;
                let storage_diffs = touched_slots
                    .into_iter()
                    .map(|(key, value)| {
                        (
                            key,
                            StateValue {
                                value,
                                enum_index: Some(enum_indices_and_batches[&key.hashed_key()].1),
                            },
                        )
                    })
                    .collect();

                let factory_deps = conn
                    .blocks_dal()
                    .get_l1_batch_factory_deps(l1_batch_number)
                    .await?;
                state.storage.insert(
                    batch_data.l1_batch_env.number,
                    StorageData {
                        batch_data,
                        storage_diffs,
                        factory_deps,
                    },
                );
            }
            drop(conn);
        }
    }

    async fn load_batch_data(
        conn: &mut Connection<'_, Core>,
        l1_batch_number: L1BatchNumber,
        l1_batch_params_provider: &L1BatchParamsProvider,
        chain_id: L2ChainId,
    ) -> anyhow::Result<Option<BatchData>> {
        let first_miniblock_in_batch = l1_batch_params_provider
            .load_first_miniblock_in_batch(conn, l1_batch_number)
            .await
            .with_context(|| {
                format!(
                    "Failed loading first miniblock for L1 batch #{}",
                    l1_batch_number
                )
            })?;
        let Some(first_miniblock_in_batch) = first_miniblock_in_batch else {
            return Ok(None);
        };
        let (system_env, l1_batch_env) = l1_batch_params_provider
            .load_l1_batch_params(
                conn,
                &first_miniblock_in_batch,
                // validation_computational_gas_limit is only relevant when rejecting txs, but we
                // are re-executing so none of them should be rejected
                u32::MAX,
                chain_id,
            )
            .await
            .with_context(|| format!("Failed loading params for L1 batch #{}", l1_batch_number))?;
        let miniblocks = conn
            .transactions_dal()
            .get_miniblocks_to_execute_for_l1_batch(l1_batch_number)
            .await?;
        Ok(Some(BatchData {
            l1_batch_env,
            system_env,
            miniblocks,
        }))
    }
}
