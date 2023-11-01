#![allow(missing_docs)]

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{B256, U160, U256};
use alloy_sol_types::{sol, SolValue};
use eth_types::{Address, Bytes, ToBigEndian, ToWord};
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
    struct EthDeposit {
        address recipient;
        uint96 amount;
        uint64 id;
    }
}

sol! {
    #[derive(Debug, Default, Deserialize, Serialize)]
    struct BlockMetadata {
        bytes32 l1Hash; // constrain: anchor call
        bytes32 difficulty; // constrain: l2 block's difficulty
        bytes32 txListHash; // constrain: l2 txlist
        bytes32 extraData; // constrain: l2 block's extra data
        uint64 id; // constrain: l2 block's number
        uint64 timestamp; // constrain: l2 block's timestamp
        uint64 l1Height; // constrain: anchor
        uint32 gasLimit; // constrain: l2 block's gas limit - anchor gas limit
        address coinbase; // constrain: L2 coinbase
        EthDeposit[] depositsProcessed; // constrain: l2 withdraw root
    }
}

#[inline]
pub fn keccak(data: impl AsRef<[u8]>) -> [u8; 32] {
    // TODO: Remove this benchmarking code once performance testing is complete.
    // std::hint::black_box(sha2::Sha256::digest(&data));
    Keccak256::digest(data).into()
}

impl BlockMetadata {
    pub fn withdraws_root(&self) -> B256 {
        // FIXME: mpt root
        keccak(self.depositsProcessed.abi_encode()).into()
    }

    // function hashMetadata(TaikoData.BlockMetadata memory meta)
    //         internal
    //         pure
    //         returns (bytes32 hash)
    //     {
    //         uint256[7] memory inputs;
    //         inputs[0] = uint256(meta.l1Hash);
    //         inputs[1] = uint256(meta.difficulty);
    //         inputs[2] = uint256(meta.txListHash);
    //         inputs[3] = uint256(meta.extraData);
    //         inputs[4] = (uint256(meta.id)) | (uint256(meta.timestamp) << 64)
    //             | (uint256(meta.l1Height) << 128) | (uint256(meta.gasLimit) << 192);
    //         inputs[5] = uint256(uint160(meta.coinbase));
    //         inputs[6] = uint256(keccak256(abi.encode(meta.depositsProcessed)));

    //         assembly {
    //             hash := keccak256(inputs, 224 /*mul(7, 32)*/ )
    //         }
    //     }

    pub fn hash(&self) -> B256 {
        let field0 = self.l1Hash;
        let field1 = self.difficulty;
        let field2 = self.txListHash;
        let field3 = self.extraData;
        let field4: U256 = U256::from(self.id)
            | U256::from(self.timestamp) << 64
            | U256::from(self.l1Height) << 128
            | U256::from(self.gasLimit) << 192;
        let coinbase: U160 = self.coinbase.into();
        let field5 = U256::from(coinbase);
        let field6 = keccak(self.depositsProcessed.abi_encode());
        let input: Vec<u8> = iter::empty()
            .chain(field0)
            .chain(field1)
            .chain(field2)
            .chain(field3)
            .chain(field4.to_be_bytes_vec())
            .chain(field5.to_be_bytes_vec())
            .chain(field6)
            .collect();
        keccak(input).into()
    }
}

sol! {
    #[derive(Debug, Default, Deserialize, Serialize)]
    struct BlockEvidence {
        BlockMetadata blockMetadata;
        bytes32 parentHash; // constrain: l2 parent hash
        bytes32 blockHash; // constrain: l2 block hash
        bytes32 signalRoot; // constrain: ??l2 service account storage root??
        bytes32 graffiti; // constrain: l2 block's graffiti
    }
}

pub enum EvidenceType {
    Sgx {
        prover: Address,
        new_pubkey: Address, // the evidence signature public key
    },
    PseZk {
        prover: Address,
    },
}

impl BlockEvidence {
    // keccak256(
    //     abi.encode(
    //         evidence.metaHash,
    //         evidence.parentHash,
    //         evidence.blockHash,
    //         evidence.signalRoot,
    //         evidence.graffiti,
    //         assignedProver,
    //         newPubKey
    //     )
    // );
    pub fn abi_encode(&self, evidence_type: EvidenceType) -> Vec<u8> {
        use DynSolValue::*;
        let mut abi_encode_tuple = vec![
            FixedBytes(self.blockMetadata.hash(), 32),
            FixedBytes(self.parentHash, 32),
            FixedBytes(self.blockHash, 32),
            FixedBytes(self.signalRoot, 32),
            FixedBytes(self.graffiti, 32),
        ];
        match evidence_type {
            EvidenceType::Sgx { prover, new_pubkey } => {
                abi_encode_tuple.extend(vec![
                    Address(prover.to_fixed_bytes().into()),
                    Address(new_pubkey.to_fixed_bytes().into()),
                ]);
            }
            EvidenceType::PseZk { prover } => {
                abi_encode_tuple.push(Address(prover.to_fixed_bytes().into()));
            }
        };
        // println!("BlockEvidence abi_encode_tuple: {:?}", abi_encode_tuple);
        Tuple(abi_encode_tuple).abi_encode()
    }

    pub fn hash(&self, evidence_type: EvidenceType) -> B256 {
        keccak(self.abi_encode(evidence_type)).into()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInstance {
    pub block_evidence: BlockEvidence,
    pub prover: Address,
}

pub const ANCHOR_METHOD_SIGNATURE: u32 = 0xda69d3db;

impl ProtocolInstance {
    /// gen anchor call
    // anchor(l1_hash,signal_root,l1_height,parent_gas_used)
    pub fn anchor_call(&self, parent_gas_used: u32) -> Bytes {
        let mut result = Vec::new();
        result.extend_from_slice(&ANCHOR_METHOD_SIGNATURE.to_be_bytes());
        result.extend_from_slice(self.block_evidence.blockMetadata.l1Hash.as_slice());
        result.extend_from_slice(self.block_evidence.signalRoot.as_slice());
        result.extend_from_slice(self.block_evidence.blockMetadata.l1Hash.as_slice());
        result.extend_from_slice(&(parent_gas_used as u64).to_word().to_be_bytes());
        result.into()
    }
}
