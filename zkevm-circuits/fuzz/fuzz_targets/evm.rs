#![no_main]

use libfuzzer_sys::fuzz_target;
use halo2_proofs::{
    // dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use zkevm_circuits::tx_circuit::test::run;
use eth_types::{
    geth_types::Transaction, word, Bytes, Word,
};
use mock::MockTransaction;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use bus_mapping::circuit_input_builder::CircuitsParams;
use zkevm_circuits::test_util::CircuitTestBuilder;
use zkevm_circuits::evm_circuit::test::EvmCircuit::get_test_cicuit_from_block;
// use zkevm_circuits::tx_circuit::TxCircuit;
// use halo2_proofs::dev::MockProver;

fuzz_target!(|_data: &[u8]| {
    // fuzzed code goes here
     let to = mock::MOCK_ACCOUNTS[0];
        let from = mock::MOCK_ACCOUNTS[1];

        let balance = mock::eth(1);
        let ctx = mock::TestContext::<2, 2>::new(
            None,
            |accs| {
                accs[0].address(to).balance(balance);
                accs[1].address(from).balance(balance).nonce(1);
            },
            |mut txs, _| {
                // Work around no payment to the coinbase address
                txs[0].to(to).from(from).nonce(1);
                txs[1]
                    .to(to)
                    .from(from)
                    .nonce(2)
                    .gas_price(mock::gwei(1))
                    .gas(Word::from(1))
                    .enable_skipping_invalid_tx(false);
            },
            |block, _| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_txs: 2,
                ..Default::default()
            })
            .run();
});
