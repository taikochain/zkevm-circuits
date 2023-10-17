#![no_main]
#![feature(generic_arg_infer)]
extern crate num_bigint;
extern crate num_traits;

use std::collections::HashSet;
use std::panic;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rand::Rng;

use bus_mapping::circuit_input_builder::CircuitsParams;
use num_traits::FromPrimitive;
use zkevm_circuits::test_util::CircuitTestBuilder;

use crate::lib::AccountMember;
use crate::lib::EVMRandomInputs;
use crate::lib::TransactionMember;

mod lib;

const CURRENT_NACC: usize = 2;
const CURRENT_NTX: usize = 1;

fuzz_target!(|evm_random_inputs: EVMRandomInputs| {

    println!("EVM Random Input: \n accounts length: {:?} \n transactions length: {:?}", evm_random_inputs.accounts_random_input.len(), evm_random_inputs.transactions_random_input.len());
    if evm_random_inputs.accounts_random_input.len()!= CURRENT_NACC {
        return;
    }
    if evm_random_inputs.transactions_random_input.len()!= CURRENT_NTX {
        return;
    }

    let mut seen_addresses = HashSet::new();
    let mut has_duplicates = false;

    for input in &evm_random_inputs.accounts_random_input {
        if seen_addresses.contains(&input.accounts_random_address) {
            // Address is a duplicate
            has_duplicates = true;
            break;
        } else {
            seen_addresses.insert(input.accounts_random_address);
        }
    }

    if has_duplicates {
        return;
    }

    let cloned_evm_random_inputs_1 = Arc::new(evm_random_inputs.clone());
    let cloned_evm_random_inputs_2 = Arc::clone(&cloned_evm_random_inputs_1);
    let cloned_evm_random_inputs_3 = Arc::clone(&cloned_evm_random_inputs_1);
    let cloned_evm_random_inputs_4 = Arc::clone(&cloned_evm_random_inputs_1);

    // Hook activates when a Panic has occured (invalid transactions found). Some transactions are invalid. Skipping invalid transactions is on.
    panic::set_hook(Box::new(move |info| {
        println!("Panic reason: {:?}", info);
        let ctx = mock::TestContext::<CURRENT_NACC, CURRENT_NTX>::new(
            None,
            |accs| {
                AccountMember::<CURRENT_NACC>::randomize_all_accounts(accs, cloned_evm_random_inputs_1.as_ref().clone());
            },
            |txs, accs| {
<<<<<<< HEAD
                let (transactions, accounts) =TransactionMember::<CURRENT_NTX>::randomize_transactions_vec_one_random_member_for_accounts(accs.clone().to_vec(), txs, cloned_evm_random_inputs_2.as_ref().clone(), true, true);
                println!("Skip: true; Input txs: {:?}", transactions);
                println!("Skip: true; Input accs: {:?}", accounts);
=======
                let (transactions, accounts) =TransactionMember::<CURRENT_NTX>::randomize_transactions_vec_one_random_member_for_accounts(accs.clone().to_vec(), txs, cloned_evm_random_inputs_2.as_ref().clone(), true);
                println!("Input txs: {:?}", transactions);
                println!("Input accs: {:?}", accounts);
>>>>>>> 2bc45d86fcb33a20f33f6f1323b44624b25ea08b
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
                AccountMember::<CURRENT_NACC>::randomize_all_accounts(accs, cloned_evm_random_inputs_3.as_ref().clone());
            },
            |txs, accs| {
<<<<<<< HEAD
                let (transactions, accounts) = TransactionMember::<CURRENT_NTX>::randomize_transactions_vec_one_random_member_for_accounts(accs.clone().to_vec(), txs, cloned_evm_random_inputs_4.as_ref().clone(), false, false);
                println!("Skip: false; Input txs: {:?}", transactions);
                println!("Skip: false; Input accs: {:?}", accounts);
=======
                TransactionMember::<CURRENT_NTX>::randomize_transactions_vec_one_random_member_for_accounts(accs.clone().to_vec(), txs, cloned_evm_random_inputs_4.as_ref().clone(), false);
>>>>>>> 2bc45d86fcb33a20f33f6f1323b44624b25ea08b
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

