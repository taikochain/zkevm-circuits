#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;
use eth_types::{U256, Word};
use libfuzzer_sys::arbitrary::Arbitrary;
use zkevm_circuits::exp_circuit::test::test_ok;
use zkevm_circuits::exp_circuit::test::test_ok_multiple;
use zkevm_circuits::exp_circuit::test::gen_code_multiple;
use zkevm_circuits::exp_circuit::test::gen_data;
use zkevm_circuits::exp_circuit::test::test_exp_circuit;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness::block_convert;
use bus_mapping::circuit_input_builder::ExpStep;
use rand::Rng;
// src/lib.rs

#[derive(Debug,libfuzzer_sys::arbitrary::Arbitrary)]
pub struct ExpInput {
    pub base: u64,
    pub exponent: u64,
}

#[derive(Debug,libfuzzer_sys::arbitrary::Arbitrary)]
pub struct ExpInputCollection {
    pub inputs: Vec<ExpInput>,
}

impl ExpInputCollection {
    pub fn to_word_pairs(&self) -> Vec<(Word, Word)> {
        self.inputs.iter().map(|input| (Word::from(input.base), Word::from(input.exponent))).collect()
    }
}

// Assuming the Word type and ExpInput struct look like this:
// type Word = u64

fuzz_target!(|expInputCollection: ExpInputCollection| {
    if expInputCollection.inputs.len() == 0 {
        return;
    }

    let code = gen_code_multiple(expInputCollection.to_word_pairs());
    let mut builder = gen_data(code);

    let mut rng = rand::thread_rng();
    let introduce_error: bool = rng.gen();
    if introduce_error {
        println!("Introducing error");
        builder.block.exp_events[0].exponentiation = U256::from(10);
        builder.block.exp_events[0].steps.push(ExpStep::from((Word::from(1), Word::from(2), Word::from(3))));
    }

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    test_exp_circuit(19, block);
});
