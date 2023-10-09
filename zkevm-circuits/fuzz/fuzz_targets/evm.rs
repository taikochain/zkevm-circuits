#![no_main]
#![feature(generic_arg_infer)]
extern crate num_bigint;
extern crate num_traits;

use std::panic;
use libfuzzer_sys::fuzz_target;
use rand::Rng;
use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types::Address;
use eth_types::Bytes;
use eth_types::H256;
use eth_types::Word;
use mock::MockAccount;
use mock::MockTransaction;
use num_traits::FromPrimitive;
use zkevm_circuits::test_util::CircuitTestBuilder;

mod lib;
use crate::lib::AccountMember;
use crate::lib::TransactionMember;


#[derive(Clone, Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct EVMRandomInput<const NACC: usize, const NTX: usize> {
    pub accounts_random_input: [[[u8; 128]; 5]; NACC],
    pub transactions_random_input: [[u8; 128]; NTX],
}

const CURRENT_NACC: usize = 200;
const CURRENT_NTX: usize = 100;

fuzz_target!(|evm_random_input: EVMRandomInput<CURRENT_NACC,CURRENT_NTX>| {

    eprintln!("EVM Random Input: {:?}", evm_random_input.clone());

    // Hook activates when a Panic has occured (invalid transactions found). Some transactions are invalid. Skipping invalid transactions is on.
    panic::set_hook(Box::new(move |info| {
        println!("Panic reason: {:?}", info);
        let ctx = mock::TestContext::<CURRENT_NACC, CURRENT_NTX>::new(
            None,
            |accs| {
                AccountMember::<CURRENT_NACC>::randomize_all_accounts(accs, &evm_random_input.accounts_random_input.clone());
            },
            |mut txs, accs| {
                TransactionMember::<CURRENT_NTX>::randomize_transactions_one_random_member(txs.try_into().expect("NTX mismatch"), &evm_random_input.transactions_random_input.clone(), true);
            },
            |block, _| block,
        )
        .unwrap();

        let mut ctb = CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
            max_txs: CURRENT_NTX,
            ..Default::default()
        });

        ctb = ctb.run();
    }));

    // Assume all transactions are valid. Panic if not. Skipping invalid transactions is off.
    let ctx = mock::TestContext::<CURRENT_NACC, CURRENT_NTX>::new(
            None,
            |accs| {
                AccountMember::<CURRENT_NACC>::randomize_all_accounts(accs, &evm_random_input.accounts_random_input.clone());
            },
            |mut txs, _| {
                TransactionMember::<CURRENT_NTX>::randomize_transactions_one_random_member(txs.try_into().expect("NTX mismatch"), &evm_random_input.transactions_random_input.clone(), false);
            },
            |block, _| block,
        )
        .unwrap();
    CircuitTestBuilder::new_from_test_ctx(ctx)
        .params(CircuitsParams {
            max_txs: CURRENT_NTX,
            ..Default::default()
        })
    .run();
});

