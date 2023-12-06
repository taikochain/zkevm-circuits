#![allow(missing_docs)]

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{B256, U160, U256, Address};
use alloy_sol_types::{sol, SolValue};
use eth_types::{Address, Bytes, ToBigEndian, ToWord, H160};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{iter, str::FromStr};

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

    #[derive(Debug)]
    struct Transition {
        bytes32 parentHash;
        bytes32 blockHash;
        bytes32 signalRoot;
        bytes32 graffiti;
    }
}

#[derive(Debug)]
pub enum EvidenceType {
    Sgx {
        new_pubkey: Address, // the evidence signature public key
    },
    PseZk {
        prover: Address,
    },
}

pub struct ProtocolInstance {
    pub transition: Transition,
    pub block_metadata: BlockMetadata,
    pub prover: Address,
}

impl ProtocolInstance {
    // keccak256(abi.encode(tran, newInstance, prover, metaHash))
    pub fn hash(&self, evidence_type: EvidenceType) -> B256 {
        match evidence_type {
            EvidenceType::Sgx { new_pubkey } => todo!(),
            EvidenceType::PseZk{ prover } => {
                // keccak256(abi.encode(tran, prover, metaHash, txListHash, pointValue));
                self.transition;
                let meta_hash = keccak(self.block_metadata.abi_encode());
                self.block_metadata.blobHash;
                keccak(
                    (
                        self.transition,
                        prover,
                        meta_hash,
                        self.block_metadata.blobHash,
                        0,
                    ).abi_encode()
                ).into()
                
            },
        }
    }
}

#[inline]
pub fn keccak(data: impl AsRef<[u8]>) -> [u8; 32] {
    // TODO: Remove this benchmarking code once performance testing is complete.
    // std::hint::black_box(sha2::Sha256::digest(&data));
    Keccak256::digest(data).into()
}