/// Public data circuits verifies the things related to public data, s///uch as rlp decoding
/// txlist and
// public data itself. for examplp: rlp decoding, we need to parse pub fn calldata from every
// proposalBlock call and give txlist bytes to the circuit.
use std::str::FromStr;

use bus_mapping::{
    circuit_input_builder::{
        protocol_instance::{self, BlockEvidence},
        BlockMetadata, BuilderClient, ProtocolInstance,
    },
    rpc::BlockNumber,
};
use eth_types::{Address, Block as EthBlock, Hash, ToBigEndian, Transaction, H256};
use ethers::{
    abi::{Function, Param, ParamType, StateMutability},
    utils::{hex, keccak256},
};
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey},
};

use crate::{
    circuits_utils::{get_general_params, IntegrationTest, CIRCUITS_PARAMS},
    get_client, GETH_L1_URL, GETH_L2_URL,
};
use alloy_primitives::FixedBytes;
use testool::{parse_address, parse_hash};
use zkevm_circuits::{
    util::SubCircuit,
    witness::{block_convert, Block},
};

// Stateless
const PROTOCOL_ADDRESS: &str = "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";
const GOLDEN_TOUCH_ADDRESS: &str = "0000777735367b36bC9B61C50022d9D0700dB4Ec";
const L1_SIGNAL_SERVICE: &str = "1000777700000000000000000000000000000001";
const L2_SIGNAL_SERVICE: &str = "1000777700000000000000000000000000000001";
const L2_CONTRACT: &str = "1000777700000000000000000000000000000001";
const PROPOSAL_TX_METHOD_SIGNATURE: &str = "ef16e845";
const GAS_LIMIT: u32 = 820000000;

// Stateful
const SIGNAL_ROOT: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const PROVER: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const EXTRA_DATA: &str = "fuck off";
const GRAFFITI: &str = "fuck off";
const DIFICULTY: &str = "000000";

fn gen_protocol_instance(
    l1_block: EthBlock<Transaction>,
    l2_block: EthBlock<Transaction>,
    l2_parent_hash: H256,
) -> ProtocolInstance {
    let proposal_tx = filter_proposal_txs(&l1_block)
        .last()
        .expect("proposal_tx not found")
        .clone();
    let txlist = get_txlist_bytes(&proposal_tx);
    let block_evidence = BlockEvidence {
        blockMetadata: BlockMetadata {
            l1Hash: l1_block.hash.unwrap().as_fixed_bytes().into(),
            difficulty: to_fixed_bytes(DIFICULTY),
            txListHash: keccak256(txlist).into(),
            extraData: to_fixed_bytes(EXTRA_DATA),
            id: l2_block.number.unwrap().as_u64(),
            timestamp: l1_block.timestamp.as_u64(),
            l1Height: l1_block.number.unwrap().as_u64() - 1,
            gasLimit: GAS_LIMIT,
            coinbase: proposal_tx.from.as_fixed_bytes().into(),
            depositsProcessed: vec![],
        },
        parentHash: l2_parent_hash.as_fixed_bytes().into(),
        blockHash: l2_block.hash.unwrap().as_fixed_bytes().into(),
        signalRoot: to_fixed_bytes(SIGNAL_ROOT),
        graffiti: to_fixed_bytes(GRAFFITI),
    };

    ProtocolInstance {
        block_evidence,
        prover: PROVER.parse().unwrap(),
    }
}

/// Specify the target l2 block, then filter the Anchor for l1_height,
/// retrieve the l1 block where the l2 block is proposed,
/// then generate the protocol instance with both avaliable blocks info.
pub async fn gen_block_with_instance(block_num: u64) -> Block<Fr> {
    // Get L2 block
    let cli = get_client(&GETH_L2_URL);
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS, None)
        .await
        .unwrap();
    let (builder, l2_block) = cli.gen_inputs(block_num).await.unwrap();
    let mut witness_block =
        block_convert(&builder.block, &builder.code_db).expect("block convert failed");

    // Get L1 block
    let (_, _, l1_height, _) = get_anchor_tx_info(&filter_anchor_tx(&l2_block));
    let l1_block = get_client(&GETH_L1_URL)
        .get_block_by_number(BlockNumber::from(l1_height))
        .await
        .unwrap();

    let protocol_instance = gen_protocol_instance(
        l1_block,
        l2_block,
        H256::from(
            witness_block.context.history_hashes[witness_block.context.history_hashes.len() - 1]
                .to_be_bytes(),
        ),
    );
    witness_block.protocol_instance = Some(protocol_instance);
    witness_block
}

/// Get the proposed txlist from L1 by filtering the txs to PROTOCOL_ADDRESS
/// and blockPropose method signature.
pub fn filter_proposal_txs(block: &EthBlock<Transaction>) -> Vec<Transaction> {
    let protocol_address = Address::from_str(PROTOCOL_ADDRESS).unwrap();
    block
        .transactions
        .iter()
        .filter(|tx| {
            tx.to
                .map(|to| {
                    to == protocol_address
                        && tx.input.len() > 4
                        && tx.input[0..4] == hex::decode(PROPOSAL_TX_METHOD_SIGNATURE).unwrap()
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>()
}
///
pub fn filter_anchor_tx(block: &EthBlock<Transaction>) -> Transaction {
    let protocol_address = Address::from_str(GOLDEN_TOUCH_ADDRESS).unwrap();
    assert!(!block.transactions.is_empty());
    assert!(block.transactions[0].from == protocol_address);
    block.transactions[0].clone()
}

/// abi: anchor(bytes32 l1Hash, bytes32 l1SignalRoot, uint64 l1Height, uint32 parentGasUsed)
pub fn get_anchor_tx_info(tx: &Transaction) -> (Hash, Hash, u64, u32) {
    #[allow(deprecated)]
    let function = Function {
        name: "anchor".to_owned(),
        inputs: vec![
            Param {
                name: "l1Hash".to_owned(),
                kind: ParamType::FixedBytes(32),
                internal_type: None,
            },
            Param {
                name: "l1SignalRoot".to_owned(),
                kind: ParamType::FixedBytes(32),
                internal_type: None,
            },
            Param {
                name: "l1Height".to_owned(),
                kind: ParamType::Uint(64),
                internal_type: None,
            },
            Param {
                name: "parentGasUsed".to_owned(),
                kind: ParamType::Uint(32),
                internal_type: None,
            },
        ],
        outputs: vec![],
        state_mutability: StateMutability::NonPayable,
        #[warn(deprecated)]
        constant: None,
    };

    let input_data = &tx.input[4..]; // Extract the remaining input data
    let decoded_calldata = function.decode_input(input_data).unwrap();

    let l1hash_bytes: [u8; 32] = decoded_calldata[0]
        .clone()
        .into_fixed_bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let l1_sig_root_bytes: [u8; 32] = decoded_calldata[1]
        .clone()
        .into_fixed_bytes()
        .unwrap()
        .try_into()
        .unwrap();
    (
        l1hash_bytes.into(),
        l1_sig_root_bytes.into(),
        decoded_calldata[2].clone().into_uint().unwrap().as_u64(),
        decoded_calldata[3].clone().into_uint().unwrap().as_u32(),
    )
}

///
pub fn get_txlist_bytes(tx: &Transaction) -> Vec<u8> {
    #[allow(deprecated)]
    let function = Function {
        name: "proposeBlock".to_owned(), // Replace with the function name
        inputs: vec![
            Param {
                name: "input".to_owned(),
                kind: ParamType::Bytes,
                internal_type: None,
            },
            Param {
                name: "txList".to_owned(),
                kind: ParamType::Bytes,
                internal_type: None,
            },
        ],
        outputs: vec![],
        state_mutability: StateMutability::NonPayable,
        #[warn(deprecated)]
        constant: None,
    };

    let input_data = &tx.input[4..]; // Extract the remaining input data
    let decoded_calldata = function.decode_input(input_data).unwrap();
    let txlist: Vec<u8> = decoded_calldata[1].clone().into_bytes().unwrap();
    txlist
}

#[inline]
fn to_fixed_bytes(s: &str) -> FixedBytes<32> {
    H256::from_str(s).unwrap().as_fixed_bytes().into()
}
