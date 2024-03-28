//! Types for the tee_verifier

// Can't be put in `zksync_types`, because it would add a circular dependency.

use multivm::interface::{L1BatchEnv, SystemEnv};
use serde::{Deserialize, Serialize};
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_object_store::{Bucket, StoredObject, _reexports::BoxedError};
use zksync_prover_interface::inputs::PrepareBasicCircuitsJob;
use zksync_types::block::L2BlockExecutionData;

/// Storage data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeVerifierInput {
    pub prepare_basic_circuits_job: PrepareBasicCircuitsJob,
    pub new_root_hash: H256,
    pub miniblocks_execution_data: Vec<L2BlockExecutionData>,
    pub fictive_miniblock_data: L2BlockExecutionData,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnv,
    pub used_contracts: Vec<(H256, Vec<u8>)>,
}

impl StoredObject for TeeVerifierInput {
    const BUCKET: Bucket = Bucket::TeeVerifierInput;
    type Key<'a> = L1BatchNumber;

    fn encode_key(key: Self::Key<'_>) -> String {
        format!("tee_verifier_input_for_l1_batch_{key}.bin")
    }

    fn serialize(&self) -> Result<Vec<u8>, BoxedError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self, &mut buf)?;
        Ok(buf)
    }

    fn deserialize(bytes: Vec<u8>) -> Result<Self, BoxedError> {
        let val: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        val.deserialized().map_err(From::from)
    }
}

#[cfg(test)]
mod tests {
    use multivm::zk_evm_latest::ethereum_types::U256;
    use zksync_basic_types::L2ChainId;
    use zksync_prover_interface::inputs::StorageLogMetadata;

    use super::*;

    #[test]
    fn test_prepare_basic_circuits_job_serialization() {
        let zero_hash = [0_u8; 32];
        let logs = (0..10).map(|i| {
            let mut merkle_paths = vec![zero_hash; 255];
            merkle_paths.push([i as u8; 32]);
            StorageLogMetadata {
                root_hash: zero_hash,
                is_write: i % 2 == 0,
                first_write: i % 3 == 0,
                merkle_paths,
                leaf_hashed_key: U256::from(i),
                leaf_enumeration_index: i + 1,
                value_written: [i as u8; 32],
                value_read: [0; 32],
            }
        });
        let logs: Vec<_> = logs.collect();

        let mut original = PrepareBasicCircuitsJob::new(4);
        original.reserve(logs.len());
        for log in &logs {
            original.push_merkle_path(log.clone());
        }

        let mut serialized = Vec::new();
        ciborium::into_writer(&original, &mut serialized).unwrap();
        let deserialized: PrepareBasicCircuitsJob =
            ciborium::from_reader(serialized.as_slice()).unwrap();
    }

    #[test]
    fn test_u256_serialization() {
        let zero_hash = [1_u64; 4];
        let original = U256(zero_hash);
        let mut serialized = Vec::new();
        ciborium::into_writer(&original, &mut serialized).unwrap();
        let deserialized: U256 = ciborium::from_reader(serialized.as_slice()).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_l2chain_id_serialization() {
        use std::str::FromStr;
        let original = L2ChainId::from_str("100").unwrap();
        let mut serialized = Vec::new();
        ciborium::into_writer(&original, &mut serialized).unwrap();
        let deserialized: L2ChainId = ciborium::from_reader(serialized.as_slice()).unwrap();

        assert_eq!(original, deserialized);
    }
}
