//! extra witness for taiko circuits

use eth_types::{Address, Hash, H256};

/// Taiko witness
#[derive(Debug, Default)]
pub struct Taiko {
    /// l1 signal service address
    pub l1_signal_service: Address,
    /// l2 signal service address
    pub l2_signal_service: Address,
    /// l2 contract address
    pub l2_contract: Address,
    /// meta hash
    pub meta_hash: Hash,
    /// signal root
    pub signal_root: Hash,
    /// extra message
    pub graffiti: H256,
    /// Prover address
    pub prover: Address,
    /// parent gas used
    pub parent_gas_used: u32,
}
