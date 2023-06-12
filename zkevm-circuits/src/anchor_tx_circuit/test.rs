#![allow(unused_imports)]
use super::{
    sign_verify::{GOLDEN_TOUCH_ADDRESS, GOLDEN_TOUCH_PRIVATEKEY, GOLDEN_TOUCH_WALLET},
    *,
};
use crate::{
    util::{log2_ceil, unusable_rows},
    witness::{block_convert, Block},
};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::{address, geth_types::GethData, ToWord, Word};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use itertools::Itertools;
use mock::{AddrOrWallet, TestContext};

#[test]
fn tx_circuit_unusable_rows() {
    assert_eq!(
        AnchorTxCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, TestAnchorTxCircuit::<Fr>>(()),
    )
}

fn run<F: Field>(block: &Block<F>) -> Result<(), Vec<VerifyFailure>> {
    let k =
        log2_ceil(AnchorTxCircuit::<Fr>::unusable_rows() + AnchorTxCircuit::<Fr>::min_num_rows());
    let circuit = TestAnchorTxCircuit::<F>::new_from_block(block);

    let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.verify()
}

const GAS_LIMIT: u64 = 1500000;

fn gen_block<const NUM_TXS: usize>(max_txs: usize, max_calldata: usize, taiko: Taiko) -> Block<Fr> {
    let block: GethData = TestContext::<1, NUM_TXS>::new(
        None,
        |_accs| {},
        |mut txs, _accs| {
            txs[0]
                .gas(GAS_LIMIT.to_word())
                .gas_price(ANCHOR_TX_GAS_PRICE.to_word())
                .from(GOLDEN_TOUCH_WALLET.clone())
                .to(taiko.l2_contract)
                .value(ANCHOR_TX_VALUE.to_word());
        },
        |block, _tx| block,
    )
    .unwrap()
    .into();
    let circuits_params = CircuitsParams {
        max_txs,
        max_calldata,
        ..Default::default()
    };
    let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), circuits_params)
        .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let mut block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    block.taiko = taiko;
    block
}

#[test]
fn test() {
    let block = gen_block::<2>(2, 100, Taiko::default());
    assert_eq!(run::<Fr>(&block), Ok(()));
}
