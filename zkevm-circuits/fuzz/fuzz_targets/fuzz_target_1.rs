#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
// extern crate std;

use zkevm_circuits::bytecode_circuit::bytecode_unroller::unroll;
use zkevm_circuits::bytecode_circuit::test::test_bytecode_circuit_unrolled;
use halo2_proofs::halo2curves::bn256::Fr;

use evm_disassembler::{disassemble_str, disassemble_bytes, format_operations};

fuzz_target!(|data: &[u8]| {
    if data.len() == 0 {
        return;
    }
    if data.len() > 24576 {
        return;
    }
    // if (vec![232,33]).contains(&binary_to_decimal(data)) {
    //     return;
    // }

    let instructions_from_bytes = disassemble_bytes(data.to_vec());

    let k = 9;
    let bytecode = data.to_vec();
    let unrolled = unroll(bytecode);
    match instructions_from_bytes {
        Ok(_) => {
            println!("Found valid bytecode");
            test_bytecode_circuit_unrolled::<Fr>(k, vec![(&unrolled).clone()], true);
            }
        Err(_e) => {
            println!("Found invalid bytecode");
            test_bytecode_circuit_unrolled::<Fr>(k, vec![(&unrolled).clone()], false);
        }
    }
});

fn binary_to_decimal(binary: &[u8]) -> u64 {
    let mut decimal = 0;
    for &bit in binary {
        decimal = (decimal << 1) + u64::from(bit);
    }
    decimal
}