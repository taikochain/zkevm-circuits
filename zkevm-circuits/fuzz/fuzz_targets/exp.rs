#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use bus_mapping::circuit_input_builder::ExpStep;
use eth_types::{Word, U256};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use log::error;
use rand::Rng;
use std::panic;
use zkevm_circuits::{
    exp_circuit::{
        test::{gen_code_multiple, gen_data, test_exp_circuit, test_ok, test_ok_multiple},
        ExpCircuit,
    },
    witness::block_convert,
};

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct ExpInput {
    pub base: u64,
    pub exponent: u64,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct ExpInputCollection {
    pub inputs: Vec<ExpInput>,
}

impl ExpInputCollection {
    pub fn to_word_pairs(&self) -> Vec<(Word, Word)> {
        let mut rng = rand::thread_rng(); // Initialize the random number generator
        self.inputs
            .iter()
            .map(|input| {
                let random_base_factor = rng.gen_range(1..=4);
                let random_exp_factor = rng.gen_range(1..=4);
                println!(
                    "random_base_factor: {}, random_exp_factor: {}",
                    random_base_factor, random_exp_factor
                );
                println!("random_base: {}, random_exp {}", input.base, input.exponent);

                let final_base = Word::from(input.base) * Word::from(random_base_factor);
                let final_exp = Word::from(input.exponent) * Word::from(random_exp_factor);
                println!("final_base: {}, final_exp: {}", final_base, final_exp);

                (Word::from(final_base), Word::from(final_exp))
            })
            .collect()
    }
}

fuzz_target!(|exp_input_collection: ExpInputCollection| {
    if exp_input_collection.inputs.len() == 0 {
        return;
    }

    let result = panic::catch_unwind(|| {
        let code = gen_code_multiple(exp_input_collection.to_word_pairs());
        let mut builder = gen_data(code);

        let mut rng = rand::thread_rng();
        let introduce_error: bool = rng.gen();
        let mut success = true;
        if introduce_error {
            println!("Introducing error");
            success = false;
            builder.block.exp_events[0].exponentiation = U256::from(10);
            builder.block.exp_events[0].steps.push(ExpStep::from((
                Word::from(1),
                Word::from(2),
                Word::from(3),
            )));
        } else {
            println!("Not introducing error");
        }

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        let circuit = ExpCircuit::<Fr>::new(
            block.exp_events.clone(),
            block.circuits_params.max_exp_steps,
        );
        let prover = MockProver::<Fr>::run(19, &circuit, vec![]).unwrap();
        let ver_result = prover.verify_par();
        if let Err(failures) = &ver_result {
            for failure in failures.iter() {
                error!("{}", failure);
            }
        }
        let error_msg = if success { "valid" } else { "invalid" };
        assert_eq!(ver_result.is_ok(), success, "proof must be {}", error_msg);
    });

    match result {
        Ok(_) => {
            // No panic occurred, handle the result if needed
        }
        Err(e) => {
            // Handle the panic
            if let Some(err) = e.downcast_ref::<&str>() {
                println!("Panic occurred: {}", err);
            } else {
                println!("Unknown panic occurred");
            }
        }
    }
});
