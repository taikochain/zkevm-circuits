#![no_main]
#![feature(generic_arg_infer)]

use std::cell::RefCell;
// use zkevm_circuits::tx_circuit::TxCircuit;
// use halo2_proofs::dev::MockProver;
use std::panic;
use std::rc::Rc;

use libfuzzer_sys::fuzz_target;

use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types::Word;
use zkevm_circuits::test_util::CircuitTestBuilder;

fuzz_target!(|_data: &[u8]| {
    // fuzzed code goes here

    let to = mock::MOCK_ACCOUNTS[0];
    let from = mock::MOCK_ACCOUNTS[1];
    let balance = mock::eth(1);
    panic::set_hook(Box::new(|info| {
        let to = mock::MOCK_ACCOUNTS[0];
        let from = mock::MOCK_ACCOUNTS[1];
        let balance = mock::eth(1);
        println!("My Hook: {:?}", info);
        println!("My Hook :Before Creating TestContext");
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
                    .gas(Word::from(2100))
                    .enable_skipping_invalid_tx(true);
            },
            |block, _| block,
        )
        .unwrap();
        println!("My Hook :After Creating TestContext");

        let mut ctb = CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
            max_txs: 2,
            ..Default::default()
        });

        ctb = ctb.run();

        println!("My Hook: After running Circuit Builder");
        eprintln!("My ctb: {:?}", ctb.block.unwrap().txs.len());

    }));

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
                    .gas(Word::from(2100))
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

