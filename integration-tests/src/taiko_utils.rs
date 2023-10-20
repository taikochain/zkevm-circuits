/// Public data circuits verifies the things related to public data, s///uch as rlp decoding txlist and
// public data itself. for examplp: rlp decoding, we need to parse pub fn calldata from every
// proposalBlock call and give txlist bytes to the circuit.

use std::str::FromStr;

use bus_mapping::circuit_input_builder::{BuilderClient, MetaData, ProtocolInstance};
use eth_types::{Address, Block as EthBlock, Hash, Transaction};
use ethers::{
    abi::{Function, Param, ParamType, StateMutability},
    utils::hex,
};
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey},
};

use crate::{
    get_client,
    integration_test_circuits::{get_general_params, IntegrationTest, CIRCUITS_PARAMS},
    GETH_L2_URL,
};
use testool::{parse_address, parse_hash};
use zkevm_circuits::{
    util::SubCircuit,
    witness::{block_convert, Block},
};


/// Block explorer URL is https://explorer.internal.taiko.xyz
/// The block that has only one anchor
pub const TAIKO_BLOCK_ANCHOR_ONLY: u64 = 5368;
/// The block that has ERC20 transfer
pub const TAIKO_BLOCK_TRANSFER_SUCCEED: u64 = 1270;

/// sepolia protocal address
const ID: u64 = 10;
const TIMESTAMP: u64 = 1694510352;
const L1_HEIGHT: u64 = 4272887;
const PROTOCOL_ADDRESS: &str = "6375394335f34848b850114b66a49d6f47f2cda8";
const PROPOSAL_TX_METHOD_SIGNATURE: &str = "ef16e845";
/// testnet golden touch address
const GOLDEN_TOUCH_ADDRESS: &str = "0000777735367b36bC9B61C50022d9D0700dB4Ec";
const L1_HASH: &str = "6e3b781b2d9a04e21ecba49e67dc3fb0a8242408cc07fa6fed5d8bd0eca2c985";
const L1_MIX_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DEPOSITS_PROCESSED: &str = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const TX_LIST_HASH: &str = "569e75fc77c1a856f6daaf9e69d8a9566ca34aa47f9133711ce065a571af0cfd";
const TX_LIST_BYTE_START: u32 = 0;
const TX_LIST_BYTE_END: u32 = 0;
const GAS_LIMIT: u32 = 820000000;
const BENEFICIARY: &str = "0000777700000000000000000000000000000001";
const TREASURY: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const BLOCK_HASH: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const PARENT_HASH: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const SIGNAL_ROOT: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const GRAFFITI: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const PROVER: &str = "df09A0afD09a63fb04ab3573922437e1e637dE8b";
const GAS_USED: u32 = 141003;
const PARENT_GAS_USED: u32 = 123960;
const BLOCK_MAX_GAS_LIMIT: u64 = 6000000;
const MAX_TRANSACTIONS_PER_BLOCK: u64 = 79;
const MAX_BYTES_PER_TX_LIST: u64 = 120000;
const L1_SIGNAL_SERVICE: &str = "1000777700000000000000000000000000000001";
const L2_SIGNAL_SERVICE: &str = "1000777700000000000000000000000000000001";
const L2_CONTRACT: &str = "1000777700000000000000000000000000000001";
const ANCHOR_GAS_LIMIT: u64 = 180000;
///
trait ProtocolInstanceTest {
    type ProtocolInstance;
    async fn block_with_instance(&self, block_num: u64) -> Block<Fr>;
    fn get_key_from_block(&mut self, block: Block<Fr>) -> ProvingKey<G1Affine>;
}

impl<C: SubCircuit<Fr> + Circuit<Fr>> ProtocolInstanceTest for IntegrationTest<C> {
    type ProtocolInstance = ProtocolInstance;

    async fn block_with_instance(&self, block_num: u64) -> Block<Fr> {
        let instance = ProtocolInstance {
            meta_data: MetaData {
                id: ID,
                timestamp: TIMESTAMP,
                l1_height: L1_HEIGHT,
                l1_hash: parse_hash(L1_HASH).unwrap(),
                l1_mix_hash: parse_hash(L1_MIX_HASH).unwrap(),
                deposits_processed: parse_hash(DEPOSITS_PROCESSED).unwrap(),
                tx_list_hash: parse_hash(TX_LIST_HASH).unwrap(),
                tx_list_byte_start: TX_LIST_BYTE_START,
                tx_list_byte_end: TX_LIST_BYTE_END,
                gas_limit: GAS_LIMIT,
                beneficiary: parse_address(BENEFICIARY).unwrap(),
                treasury: parse_address(TREASURY).unwrap(),
            },
            block_hash: parse_hash(BLOCK_HASH).unwrap(),
            parent_hash: parse_hash(PARENT_HASH).unwrap(),
            signal_root: parse_hash(SIGNAL_ROOT).unwrap(),
            graffiti: parse_hash(GRAFFITI).unwrap(),
            prover: parse_address(PROVER).unwrap(),
            gas_used: GAS_USED,
            parent_gas_used: PARENT_GAS_USED,
            block_max_gas_limit: BLOCK_MAX_GAS_LIMIT,
            max_transactions_per_block: MAX_TRANSACTIONS_PER_BLOCK,
            max_bytes_per_tx_list: MAX_BYTES_PER_TX_LIST,
            l1_signal_service: parse_address(L1_SIGNAL_SERVICE).unwrap(),
            l2_signal_service: parse_address(L2_SIGNAL_SERVICE).unwrap(),
            l2_contract: parse_address(L2_CONTRACT).unwrap(),
            anchor_gas_limit: ANCHOR_GAS_LIMIT,
        };
        let cli = get_client(&GETH_L2_URL);
        let cli = BuilderClient::new(cli, CIRCUITS_PARAMS, Some(instance.clone()))
            .await
            .unwrap();

        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
        block_convert(&builder.block, &builder.code_db).expect("block convert failed")
    }

    fn get_key_from_block(&mut self, block: Block<Fr>) -> ProvingKey<G1Affine> {
        let circuit = C::new_from_block(&block);
        let general_params = get_general_params(self.degree);
        let verifying_key =
            keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let key =
            keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail");
        self.key = Some(key.clone());
        key
    }
}
///
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

///abi: anchor(bytes32 l1Hash, bytes32 l1SignalRoot, uint64 l1Height, uint32 parentGasUsed)
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
