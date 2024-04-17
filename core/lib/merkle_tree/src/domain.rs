//! Tying the Merkle tree implementation to the problem domain.

use rayon::{ThreadPool, ThreadPoolBuilder};
use zksync_crypto::hasher::blake2::Blake2Hasher;
use zksync_prover_interface::inputs::{PrepareBasicCircuitsJob, StorageLogMetadata};
use zksync_types::{
    writes::{InitialStorageWrite, RepeatedStorageWrite},
    L1BatchNumber, StorageKey,
};

use crate::{
    storage::{PatchSet, Patched, RocksDBWrapper},
    types::{
        Key, Root, TreeEntry, TreeEntryWithProof, TreeInstruction, TreeLogEntry, ValueHash,
        TREE_DEPTH,
    },
    BlockOutput, HashTree, MerkleTree, MerkleTreePruner, MerkleTreePrunerHandle, NoVersionError,
};

/// Metadata for the current tree state.
#[derive(Debug, Clone)]
pub struct TreeMetadata {
    /// Current root hash of the tree.
    pub root_hash: ValueHash,
    /// 1-based index of the next leaf to be inserted in the tree.
    pub rollup_last_leaf_index: u64,
    /// Initial writes performed in the processed L1 batch in the order of provided `StorageLog`s.
    pub initial_writes: Vec<InitialStorageWrite>,
    /// Repeated writes performed in the processed L1 batch in the order of provided `StorageLog`s.
    /// No-op writes (i.e., writing the same value as previously) will be omitted.
    pub repeated_writes: Vec<RepeatedStorageWrite>,
    /// Witness information. As with `repeated_writes`, no-op updates will be omitted from Merkle paths.
    pub witness: Option<PrepareBasicCircuitsJob>,
}

#[derive(Debug, PartialEq, Eq)]
enum TreeMode {
    Lightweight,
    Full,
}

/// Domain-specific wrapper of the Merkle tree.
///
/// This wrapper will accumulate changes introduced by [`Self::process_l1_batch()`],
/// [`Self::process_l1_batches()`] and [`Self::revert_logs()`] in RAM without saving them
/// to RocksDB. The accumulated changes can be saved to RocksDB via [`Self::save()`]
/// or discarded via [`Self::reset()`].
#[derive(Debug)]
pub struct ZkSyncTree {
    tree: MerkleTree<Patched<RocksDBWrapper>>,
    thread_pool: Option<ThreadPool>,
    mode: TreeMode,
    pruning_enabled: bool,
}

impl ZkSyncTree {
    fn create_thread_pool(thread_count: usize) -> ThreadPool {
        ThreadPoolBuilder::new()
            .thread_name(|idx| format!("new-merkle-tree-{idx}"))
            .num_threads(thread_count)
            .build()
            .expect("failed initializing `rayon` thread pool")
    }

    /// Returns metadata based on `storage_logs` generated by the genesis L1 batch. This does not
    /// create a persistent tree.
    pub fn process_genesis_batch(storage_logs: &[TreeInstruction<StorageKey>]) -> BlockOutput {
        let kvs = Self::filter_write_instructions(storage_logs);
        tracing::info!(
            "Creating Merkle tree for genesis batch with {instr_count} writes",
            instr_count = kvs.len()
        );

        let kvs: Vec<_> = kvs
            .iter()
            .map(|instr| instr.map_key(StorageKey::hashed_key_u256))
            .collect();

        let mut in_memory_tree = MerkleTree::new(PatchSet::default());
        let output = in_memory_tree.extend(kvs);

        tracing::info!(
            "Processed genesis batch; root hash is {root_hash}, {leaf_count} leaves in total",
            root_hash = output.root_hash,
            leaf_count = output.leaf_count
        );
        output
    }

    /// Creates a tree with the full processing mode.
    pub fn new(db: RocksDBWrapper) -> Self {
        Self::new_with_mode(db, TreeMode::Full)
    }

    /// Creates a tree with the lightweight processing mode.
    pub fn new_lightweight(db: RocksDBWrapper) -> Self {
        Self::new_with_mode(db, TreeMode::Lightweight)
    }

    fn new_with_mode(db: RocksDBWrapper, mode: TreeMode) -> Self {
        Self {
            tree: MerkleTree::new(Patched::new(db)),
            thread_pool: None,
            mode,
            pruning_enabled: false,
        }
    }

    /// Returns tree pruner and a handle to stop it.
    ///
    /// # Panics
    ///
    /// Panics if this method was already called for the tree instance; it's logically unsound to run
    /// multiple pruners for the same tree concurrently.
    pub fn pruner(&mut self) -> (MerkleTreePruner<RocksDBWrapper>, MerkleTreePrunerHandle) {
        assert!(
            !self.pruning_enabled,
            "pruner was already obtained for the tree"
        );
        self.pruning_enabled = true;
        let db = self.tree.db.inner().clone();
        MerkleTreePruner::new(db)
    }

    /// Returns a readonly handle to the tree. The handle **does not** see uncommitted changes to the tree,
    /// only ones flushed to RocksDB.
    pub fn reader(&self) -> ZkSyncTreeReader {
        let db = self.tree.db.inner().clone();
        ZkSyncTreeReader(MerkleTree::new(db))
    }

    /// Sets the chunk size for multi-get operations. The requested keys will be split
    /// into chunks of this size and requested in parallel using `rayon`. Setting chunk size
    /// to a large value (e.g., `usize::MAX`) will effectively disable parallelism.
    ///
    /// # Panics
    ///
    /// Panics if `chunk_size` is zero.
    pub fn set_multi_get_chunk_size(&mut self, chunk_size: usize) {
        assert!(chunk_size > 0, "Multi-get chunk size must be positive");
        self.tree
            .db
            .inner_mut()
            .set_multi_get_chunk_size(chunk_size);
    }

    /// Signals that the tree should use a dedicated `rayon` thread pool for parallel operations
    /// (for now, hash computations).
    ///
    /// If `thread_count` is 0, the default number of threads will be used; see `rayon` docs
    /// for details.
    pub fn use_dedicated_thread_pool(&mut self, thread_count: usize) {
        self.thread_pool = Some(Self::create_thread_pool(thread_count));
    }

    /// Returns the current root hash of this tree.
    pub fn root_hash(&self) -> ValueHash {
        self.tree.latest_root_hash()
    }

    /// Checks whether this tree is empty.
    pub fn is_empty(&self) -> bool {
        let Some(version) = self.tree.latest_version() else {
            return true;
        };
        self.tree
            .root(version)
            .map_or(true, |root| matches!(root, Root::Empty))
    }

    /// Returns the next L1 batch number that should be processed by the tree.
    #[allow(clippy::missing_panics_doc)]
    pub fn next_l1_batch_number(&self) -> L1BatchNumber {
        let number = self.tree.latest_version().map_or(0, |version| {
            u32::try_from(version + 1).expect("integer overflow for L1 batch number")
        });
        L1BatchNumber(number)
    }

    /// Verifies tree consistency. `l1_batch_number` specifies the version of the tree
    /// to be checked, expressed as the number of latest L1 batch applied to the tree.
    ///
    /// # Panics
    ///
    /// Panics if an inconsistency is detected.
    pub fn verify_consistency(&self, l1_batch_number: L1BatchNumber) {
        let version = u64::from(l1_batch_number.0);
        self.tree
            .verify_consistency(version, true)
            .unwrap_or_else(|err| {
                panic!("Tree at version {version} is inconsistent: {err}");
            });
    }

    /// Processes an iterator of storage logs comprising a single L1 batch.
    pub fn process_l1_batch(
        &mut self,
        storage_logs: &[TreeInstruction<StorageKey>],
    ) -> TreeMetadata {
        match self.mode {
            TreeMode::Full => self.process_l1_batch_full(storage_logs),
            TreeMode::Lightweight => self.process_l1_batch_lightweight(storage_logs),
        }
    }

    fn process_l1_batch_full(
        &mut self,
        instructions: &[TreeInstruction<StorageKey>],
    ) -> TreeMetadata {
        let l1_batch_number = self.next_l1_batch_number();
        let starting_leaf_count = self.tree.latest_root().leaf_count();
        let starting_root_hash = self.tree.latest_root_hash();

        let instructions_with_hashed_keys: Vec<_> = instructions
            .iter()
            .map(|instr| instr.map_key(StorageKey::hashed_key_u256))
            .collect();

        tracing::info!(
            "Extending Merkle tree with batch #{l1_batch_number} with {instr_count} ops in full mode",
            instr_count = instructions.len()
        );

        let output = if let Some(thread_pool) = &self.thread_pool {
            thread_pool.install(|| self.tree.extend_with_proofs(instructions_with_hashed_keys))
        } else {
            self.tree.extend_with_proofs(instructions_with_hashed_keys)
        };

        let mut witness = PrepareBasicCircuitsJob::new(starting_leaf_count + 1);
        witness.reserve(output.logs.len());
        for (log, instruction) in output.logs.iter().zip(instructions) {
            let empty_levels_end = TREE_DEPTH - log.merkle_path.len();
            let empty_subtree_hashes =
                (0..empty_levels_end).map(|i| Blake2Hasher.empty_subtree_hash(i));
            let merkle_paths = log.merkle_path.iter().copied();
            let merkle_paths = empty_subtree_hashes
                .chain(merkle_paths)
                .map(|hash| hash.0)
                .collect();

            let value_written = match instruction {
                TreeInstruction::Write(entry) => entry.value.0,
                TreeInstruction::Read(_) => [0_u8; 32],
            };
            let log = StorageLogMetadata {
                root_hash: log.root_hash.0,
                is_write: !log.base.is_read(),
                first_write: matches!(log.base, TreeLogEntry::Inserted),
                merkle_paths,
                leaf_hashed_key: instruction.key().hashed_key_u256(),
                leaf_enumeration_index: match instruction {
                    TreeInstruction::Write(entry) => entry.leaf_index,
                    TreeInstruction::Read(_) => match log.base {
                        TreeLogEntry::Read { leaf_index, .. } => leaf_index,
                        TreeLogEntry::ReadMissingKey => 0,
                        _ => unreachable!("Read instructions always transform to Read / ReadMissingKey log entries"),
                    }
                },
                value_written,
                value_read: match log.base {
                    TreeLogEntry::Updated { previous_value, .. } => {
                        if previous_value.0 == value_written {
                            // A no-op update that must be omitted from the produced `witness`.
                            continue;
                        }
                        previous_value.0
                    }
                    TreeLogEntry::Read { value, .. } => value.0,
                    TreeLogEntry::Inserted | TreeLogEntry::ReadMissingKey => [0_u8; 32],
                },
            };
            witness.push_merkle_path(log);
        }

        let root_hash = output.root_hash().unwrap_or(starting_root_hash);
        let logs = output
            .logs
            .into_iter()
            .filter_map(|log| (!log.base.is_read()).then_some(log.base));
        let kvs = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                TreeInstruction::Write(entry) => Some(*entry),
                TreeInstruction::Read(_) => None,
            });
        let (initial_writes, repeated_writes) = Self::extract_writes(logs, kvs);

        tracing::info!(
            "Processed batch #{l1_batch_number}; root hash is {root_hash}, \
             {leaf_count} leaves in total, \
             {initial_writes} initial writes, {repeated_writes} repeated writes",
            leaf_count = output.leaf_count,
            initial_writes = initial_writes.len(),
            repeated_writes = repeated_writes.len()
        );

        TreeMetadata {
            root_hash,
            rollup_last_leaf_index: output.leaf_count + 1,
            initial_writes,
            repeated_writes,
            witness: Some(witness),
        }
    }

    fn extract_writes(
        logs: impl Iterator<Item = TreeLogEntry>,
        entries: impl Iterator<Item = TreeEntry<StorageKey>>,
    ) -> (Vec<InitialStorageWrite>, Vec<RepeatedStorageWrite>) {
        let mut initial_writes = vec![];
        let mut repeated_writes = vec![];
        for (log_entry, input_entry) in logs.zip(entries) {
            let key = &input_entry.key;
            match log_entry {
                TreeLogEntry::Inserted => {
                    initial_writes.push(InitialStorageWrite {
                        index: input_entry.leaf_index,
                        key: key.hashed_key_u256(),
                        value: input_entry.value,
                    });
                }
                TreeLogEntry::Updated {
                    previous_value: prev_value_hash,
                    ..
                } => {
                    if prev_value_hash != input_entry.value {
                        repeated_writes.push(RepeatedStorageWrite {
                            index: input_entry.leaf_index,
                            value: input_entry.value,
                        });
                    }
                    // Else we have a no-op update that must be omitted from `repeated_writes`.
                }
                TreeLogEntry::Read { .. } | TreeLogEntry::ReadMissingKey => {}
            }
        }
        (initial_writes, repeated_writes)
    }

    fn process_l1_batch_lightweight(
        &mut self,
        instructions: &[TreeInstruction<StorageKey>],
    ) -> TreeMetadata {
        let kvs = Self::filter_write_instructions(instructions);
        let l1_batch_number = self.next_l1_batch_number();
        tracing::info!(
            "Extending Merkle tree with batch #{l1_batch_number} with {kv_count} writes \
             in lightweight mode",
            kv_count = kvs.len()
        );

        let kvs_with_derived_key: Vec<_> = kvs
            .iter()
            .map(|entry| entry.map_key(StorageKey::hashed_key_u256))
            .collect();

        let output = if let Some(thread_pool) = &self.thread_pool {
            thread_pool.install(|| self.tree.extend(kvs_with_derived_key.clone()))
        } else {
            self.tree.extend(kvs_with_derived_key.clone())
        };
        let (initial_writes, repeated_writes) =
            Self::extract_writes(output.logs.into_iter(), kvs.into_iter());

        tracing::info!(
            "Processed batch #{l1_batch_number}; root hash is {root_hash}, \
             {leaf_count} leaves in total, \
             {initial_writes} initial writes, {repeated_writes} repeated writes",
            root_hash = output.root_hash,
            leaf_count = output.leaf_count,
            initial_writes = initial_writes.len(),
            repeated_writes = repeated_writes.len()
        );

        TreeMetadata {
            root_hash: output.root_hash,
            rollup_last_leaf_index: output.leaf_count + 1,
            initial_writes,
            repeated_writes,
            witness: None,
        }
    }

    fn filter_write_instructions(
        instructions: &[TreeInstruction<StorageKey>],
    ) -> Vec<TreeEntry<StorageKey>> {
        let kvs = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                TreeInstruction::Write(entry) => Some(*entry),
                TreeInstruction::Read(_) => None,
            });
        kvs.collect()
    }

    /// Reverts the tree to a previous state.
    ///
    /// This method will overwrite all unsaved changes in the tree.
    pub fn revert_logs(&mut self, last_l1_batch_to_keep: L1BatchNumber) {
        self.tree.db.reset();
        let retained_version_count = u64::from(last_l1_batch_to_keep.0 + 1);
        self.tree.truncate_recent_versions(retained_version_count);
    }

    /// Saves the accumulated changes in the tree to RocksDB.
    pub fn save(&mut self) {
        let mut l1_batch_numbers = self.tree.db.patched_versions();
        l1_batch_numbers.sort_unstable();
        tracing::info!("Flushing L1 batches #{l1_batch_numbers:?} to RocksDB");
        self.tree.db.flush();
    }

    /// Resets the tree to the latest database state.
    pub fn reset(&mut self) {
        self.tree.db.reset();
    }
}

/// Readonly handle to a [`ZkSyncTree`].
#[derive(Debug)]
pub struct ZkSyncTreeReader(MerkleTree<RocksDBWrapper>);

// While cloning `MerkleTree` is logically unsound, cloning a reader is reasonable since it is readonly.
impl Clone for ZkSyncTreeReader {
    fn clone(&self) -> Self {
        Self(MerkleTree::new(self.0.db.clone()))
    }
}

impl ZkSyncTreeReader {
    /// Returns the current root hash of this tree.
    pub fn root_hash(&self) -> ValueHash {
        self.0.latest_root_hash()
    }

    /// Returns the next L1 batch number that should be processed by the tree.
    #[allow(clippy::missing_panics_doc)]
    pub fn next_l1_batch_number(&self) -> L1BatchNumber {
        let number = self.0.latest_version().map_or(0, |version| {
            u32::try_from(version + 1).expect("integer overflow for L1 batch number")
        });
        L1BatchNumber(number)
    }

    /// Returns the number of leaves in the tree.
    pub fn leaf_count(&self) -> u64 {
        self.0.latest_root().leaf_count()
    }

    /// Reads entries together with Merkle proofs with the specified keys from the tree. The entries are returned
    /// in the same order as requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree `version` is missing.
    pub fn entries_with_proofs(
        &self,
        l1_batch_number: L1BatchNumber,
        keys: &[Key],
    ) -> Result<Vec<TreeEntryWithProof>, NoVersionError> {
        let version = u64::from(l1_batch_number.0);
        self.0.entries_with_proofs(version, keys)
    }
}
