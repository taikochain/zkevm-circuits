#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;
use bus_mapping::operation::{
    MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
};
use eth_types::{
    address,
    evm_types::{MemoryAddress, StackAddress},
    Address, Field, ToAddress, Word, U256,
};
use zkevm_circuits::state_circuit::test::test_state_circuit_ok;
use bus_mapping::operation::Op;
#[derive(Debug,libfuzzer_sys::arbitrary::Arbitrary)]
pub struct MemoryOperation {
    pub rwCounter: usize,
    pub rw: bool,
    pub callId: usize,
    pub memoryAddress: u8,
    pub value: u8,
}

#[derive(Debug,libfuzzer_sys::arbitrary::Arbitrary)]
pub struct MemoryOperationCollection {
    pub memoryOperations: Vec<MemoryOperation>,
}

impl MemoryOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<MemoryOp>> {
        self.memoryOperations
            .iter()
            .map(|mo| {
                let memory_op = Operation::new(
                    RWCounter::from(mo.rwCounter),
                    convertBoolToRW(mo.rw),
                    MemoryOp::new(
                        mo.callId,
                        MemoryAddress::from(mo.memoryAddress),
                        mo.value,
                    ),
                );
                memory_op
            })
            .collect()
    }
}

fuzz_target!(|mo: MemoryOperationCollection| {
    // fuzzed code goes here
    // let memory_op_0 = Operation::new(
    //     RWCounter::from(mo.rwCounter),
    //     convertBoolToRW(mo.rw),
    //     MemoryOp::new(mo.callId, MemoryAddress::from(mo.memoryAddress), mo.value),
    // );
    if mo.memoryOperations.is_empty() {
        return;
    }
    test_state_circuit_ok(mo.to_operations(), vec![], vec![]);
});

fn convertBoolToRW(value: bool) -> RW {
    if value {
        RW::WRITE
    } else {
        RW::READ
    }
}