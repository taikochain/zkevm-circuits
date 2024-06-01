#![no_main]

use halo2_proofs::halo2curves::bn256::Fr;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;

use eth_types::geth_types::Transaction;
use mock::MockTransaction;
use zkevm_circuits::tx_circuit::test::run;

use crate::lib::TransactionMember;
use crate::lib::TxRandomInput;
mod lib;

// use mock::AddrOrWallet;



use rand_chacha::ChaCha20Rng;




const CURRENT_NTX: usize = 1;
const CURRENT_NACC: usize = 0;

fuzz_target!(|tx_random_input: TxRandomInput| {

    println!("tx random input count: {:?}", tx_random_input.transactions_random_input.len());

    if tx_random_input.transactions_random_input.len() != CURRENT_NTX {
        return;
    }
    if tx_random_input.transactions_random_to == [0; 20] {
        return;
    }

    const MAX_CALLDATA: usize = 32;
    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    let mut transactions = vec![MockTransaction::default(); CURRENT_NTX];
    transactions = TransactionMember::<CURRENT_NTX>::randomize_transactions_vec_one_random_member(
        transactions,
        tx_random_input
    );
    let  transactions: Vec<Transaction>=
            transactions.iter_mut().map(|tx| {
                let tx_build = tx.build();
                // println!("Tx after build: {:?}", tx_build);
                tx_build
            }).map(|tx| {
                let tx_transformed: Transaction = tx.clone().into();
                // println!("Tx after tranformation: {:?}", tx_transformed);
                tx_transformed
            }).filter(|tx| {
                tx.v != 0
            }).collect();

    if transactions.len() == 0 {
        return;
    }

    println!("Input: {:?}", transactions);
    assert_eq!(run::<Fr>(transactions, chain_id, CURRENT_NTX, MAX_CALLDATA), Ok(()));
});