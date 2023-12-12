#![allow(missing_docs)]

use alloy_primitives::{B256, U256};

use alloy_sol_types::{sol, SolValue};
use eth_types::Address;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

/// L1 signal service
pub static L1_SIGNAL_SERVICE: Lazy<Address> = Lazy::new(|| {
    Address::from_str("0xcD5e2bebd3DfE46e4BF96aE2ac7B89B22cc6a982")
        .expect("invalid l1 signal service")
});

/// L2 signal service
pub static L2_SIGNAL_SERVICE: Lazy<Address> = Lazy::new(|| {
    Address::from_str("0x1000777700000000000000000000000000000007")
        .expect("invalid l2 signal service")
});

/// Taiko's treasury, which is used in EndTx
/// trasury_balance = treasury_balance_prev + base_fee * gas_used;
pub static TREASURY: Lazy<Address> = Lazy::new(|| {
    Address::from_str("0xdf09A0afD09a63fb04ab3573922437e1e637dE8b")
        .expect("invalid treasury account")
});

pub const ANCHOR_METHOD_SIGNATURE: u32 = 0xda69d3db;

sol! {
    #[derive(Debug, Default, Deserialize, Serialize)]
    struct BlockMetadata {
        bytes32 l1Hash; // slot 1
        bytes32 difficulty; // slot 2
        bytes32 blobHash; //or txListHash (if Blob not yet supported), // slot 3
        bytes32 extraData; // slot 4
        bytes32 depositsHash; // slot 5
        address coinbase; // L2 coinbase, // slot 6
        uint64 id;
        uint32 gasLimit;
        uint64 timestamp; // slot 7
        uint64 l1Height;
        uint24 txListByteOffset;
        uint24 txListByteSize;
        uint16 minTier;
        bool blobUsed;
        bytes32 parentMetaHash; // slot 8
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    struct Transition {
        bytes32 parentHash;
        bytes32 blockHash;
        bytes32 signalRoot;
        bytes32 graffiti;
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    struct PseZkVerifierCalcInstance {
        bytes32 parentHash;
        bytes32 blockHash;
        bytes32 signalRoot;
        bytes32 graffiti;
        bytes32 metaHash;
        address prover;
        bytes32 txListHash;
        uint256 pointValue;
    }

}

#[derive(Debug)]
pub enum EvidenceType {
    Sgx {
        new_pubkey: Address, // the evidence signature public key
    },
    PseZk,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProtocolInstance {
    pub transition: Transition,
    pub block_metadata: BlockMetadata,
    pub prover: Address,
}

impl ProtocolInstance {
    /// PseZkVerifier.sol
    // function calcInstance(
    //     TaikoData.Transition memory tran,
    //     address prover,
    //     bytes32 metaHash,
    //     bytes32 txListHash,
    //     uint256 pointValue
    // )
    // return keccak256(abi.encode(tran, prover, metaHash, txListHash, pointValue));
    pub fn hash(&self, evidence_type: EvidenceType) -> B256 {
        match evidence_type {
            EvidenceType::Sgx { new_pubkey: _ } => todo!(),
            EvidenceType::PseZk => {
                // keccak256(abi.encode(tran, prover, metaHash, txListHash, pointValue));
                keccak(self.abi_encode()).into()
            }
        }
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        let meta_hash = keccak(self.block_metadata.abi_encode());
        PseZkVerifierCalcInstance {
            parentHash: self.transition.parentHash,
            blockHash: self.transition.blockHash,
            signalRoot: self.transition.signalRoot,
            graffiti: self.transition.graffiti,
            metaHash: meta_hash.into(),
            prover: self.prover.as_fixed_bytes().into(),
            txListHash: self.block_metadata.blobHash,
            pointValue: U256::from(0),
        }
        .abi_encode()
    }

    pub fn parentHash(&self) -> Vec<u8> {
        self.transition.parentHash.abi_encode()
    }

    pub fn blockHash(&self) -> Vec<u8> {
        self.transition.blockHash.abi_encode()
    }

    pub fn signalRoot(&self) -> Vec<u8> {
        self.transition.signalRoot.abi_encode()
    }

    pub fn graffiti(&self) -> Vec<u8> {
        self.transition.graffiti.abi_encode()
    }

    pub fn prover(&self) -> Vec<u8> {
        let sol_addr = alloy_sol_types::private::Address::from(self.prover.as_fixed_bytes());
        sol_addr.abi_encode()
    }

    pub fn meta_hash(&self) -> Vec<u8> {
        keccak(self.block_metadata.abi_encode()).into()
    }

    pub fn tx_list_hash(&self) -> Vec<u8> {
        self.block_metadata.blobHash.abi_encode()
    }

    pub fn point_value(&self) -> Vec<u8> {
        U256::from(0).abi_encode()
    }
}

#[inline]
pub fn keccak(data: impl AsRef<[u8]>) -> [u8; 32] {
    // TODO: Remove this benchmarking code once performance testing is complete.
    // std::hint::black_box(sha2::Sha256::digest(&data));
    Keccak256::digest(data).into()
}
