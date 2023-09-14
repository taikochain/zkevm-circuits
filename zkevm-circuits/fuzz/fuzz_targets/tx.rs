#![no_main]

use libfuzzer_sys::fuzz_target;
use halo2_proofs::{
    // dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use zkevm_circuits::tx_circuit::test::run;
use eth_types::geth_types::Transaction;
use mock::MockTransaction;
// use zkevm_circuits::tx_circuit::TxCircuit;
// use halo2_proofs::dev::MockProver;

fuzz_target!(|_data: &[u8]| {
    // fuzzed code goes here
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    // let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();
    let tx: Transaction = MockTransaction::default()
        .value(word!("0x3e8")
        .build()
        .into();

    assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(())));
});
