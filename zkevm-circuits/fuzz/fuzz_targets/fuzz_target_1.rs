#![no_main]
#[macro_use]
// extern crate libfuzzer_sys;
// extern crate std;

use zkevm_circuits::bytecode_circuit::bytecode_unroller::unroll;
use zkevm_circuits::bytecode_circuit::test::test_bytecode_circuit_unrolled;

fuzz_target!(|data: &[u8]| {
    if data.len() > 24576 {
        return;
    }

    let k = 9;
    let bytecode = data.to_vec();
    let unrolled = unroll(bytecode);
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
});