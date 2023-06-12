//! extra witness for taiko circuits

use crate::{evm_circuit::util::rlc, table::PiFieldTag};
use eth_types::{Address, Field, Hash, ToLittleEndian, ToWord, H256};
use halo2_proofs::circuit::Value;

// TODO: calculate the method_signature
const ANCHOR_TX_METHOD_SIGNATURE: u32 = 0;

/// Taiko witness
#[derive(Debug, Default, Clone)]
pub struct Taiko {
    /// l1 signal service address
    pub l1_signal_service: Address,
    /// l2 signal service address
    pub l2_signal_service: Address,
    /// l2 contract address
    pub l2_contract: Address,
    /// meta hash
    pub meta_hash: MetaHash,
    /// block hash value
    pub block_hash: Hash,
    /// the parent block hash
    pub parent_hash: Hash,
    /// signal root
    pub signal_root: Hash,
    /// extra message
    pub graffiti: H256,
    /// Prover address
    pub prover: Address,
    /// gas used
    pub gas_used: u32,
    /// parent gas used
    pub parent_gas_used: u32,
    /// blockMaxGasLimit
    pub block_max_gas_limit: u64,
    /// maxTransactionsPerBlock
    pub max_transactions_per_block: u64,
    /// maxBytesPerTxList
    pub max_bytes_per_tx_list: u64,

    /// anchor gas cost
    pub anchor_gas_cost: u64,
}

#[derive(Debug, Default, Clone)]
pub struct MetaHash {
    /// meta id
    pub id: u64,
    /// meta timestamp
    pub timestamp: u64,
    /// l1 block height
    pub l1_height: u64,
    /// l1 block hash
    pub l1_hash: Hash,
    /// l1 block mix hash
    pub l1_mix_hash: Hash,
    /// deposits processed
    pub deposits_processed: Hash,
    /// tx list hash
    pub tx_list_hash: Hash,
    /// tx list byte start
    pub tx_list_byte_start: u32, // u24
    /// tx list byte end
    pub tx_list_byte_end: u32, // u24
    /// gas limit
    pub gas_limit: u32,
    /// beneficiary
    pub beneficiary: Address,
    /// treasury
    pub treasury: Address,
}

impl MetaHash {
    pub fn hash(&self) -> Hash {
        todo!()
    }
}

impl Taiko {
    /// Assignments for pi table
    pub fn table_assignments<F: Field>(&self, randomness: Value<F>) -> [[Value<F>; 2]; 6] {
        [
            [
                Value::known(F::from(PiFieldTag::Null as u64)),
                Value::known(F::ZERO),
            ],
            [
                Value::known(F::from(PiFieldTag::MethodSign as u64)),
                Value::known(F::from(ANCHOR_TX_METHOD_SIGNATURE as u64)),
            ],
            [
                Value::known(F::from(PiFieldTag::L1Hash as u64)),
                randomness.map(|randomness| {
                    rlc::value(&self.meta_hash.l1_hash.to_word().to_le_bytes(), randomness)
                }),
            ],
            [
                Value::known(F::from(PiFieldTag::L1SignalRoot as u64)),
                randomness.map(|randomness| {
                    rlc::value(&self.signal_root.to_word().to_le_bytes(), randomness)
                }),
            ],
            [
                Value::known(F::from(PiFieldTag::L1Height as u64)),
                Value::known(F::from(self.meta_hash.l1_height)),
            ],
            [
                Value::known(F::from(PiFieldTag::ParentGasUsed as u64)),
                Value::known(F::from(self.parent_gas_used as u64)),
            ],
        ]
    }
}
