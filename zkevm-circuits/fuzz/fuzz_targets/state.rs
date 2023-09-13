#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;
use bus_mapping::operation::{
    MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
    TxAccessListAccountOp, TxAccessListAccountStorageOp,
};
use eth_types::{
    address,
    evm_types::{MemoryAddress, StackAddress},
    Address, Field, ToAddress, Word, U256,
};
use zkevm_circuits::state_circuit::test::test_state_circuit_ok;
use bus_mapping::operation::Op;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::dev::MockProver;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::witness::RwMap;
use zkevm_circuits::util::SubCircuit;
use log::error;
use std::collections::HashSet;
use std::collections::HashMap;
use rand::Rng;

const N_ROWS: usize = 1 << 16;

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct MemoryOperation {
    pub rw_counter: usize,
    pub rw: bool,
    pub call_id: usize,
    pub memory_address: u32,
    pub value: u8,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct MemoryOperationCollection {
    pub memory_operations: Vec<MemoryOperation>,
}

impl MemoryOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<MemoryOp>> {
        let mut rw_counter = 0;
        let mut memory_values: HashMap<u32, u8> = HashMap::new();
        self.memory_operations
            .iter()
            .map(|mo| {
                rw_counter += 1;
                if mo.rw {
                    // Write operation
                    memory_values.insert(mo.memory_address, mo.value);
                } else {
                    // Read operation
                    if !memory_values.contains_key(&mo.memory_address) {
                        // First read, set value to 0
                        memory_values.insert(mo.memory_address, 0);
                    }
                }

                let memory_op = Operation::new(
                    RWCounter::from(rw_counter),
                    convertBoolToRW(mo.rw),
                    MemoryOp::new(
                        // mo.call_id,
                        1,
                        MemoryAddress::from(mo.memory_address),
                        *memory_values.get(&mo.memory_address).unwrap(),
                    ),
                );
                rw_counter += 1;
                memory_op
            })
            .collect()
    }
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct StackOperation {
    pub rw_counter: usize,
    pub rw: bool,
    pub call_id: usize,
    pub stack_address: usize,
    pub value: u32,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct StackOperationCollection {
    pub stack_operations: Vec<StackOperation>,
}

impl StackOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<StackOp>> {
        let mut rng = rand::thread_rng();
        let mut rw_counter = 0;
        let mut stack_pointer: usize = 1;


        let mut written_values: HashMap<usize, u32> = HashMap::new();
        let mut known_stack_pointers: HashSet<usize> = HashSet::new();

        self.stack_operations
            .iter()
            .enumerate()
            .map(|(index, so)| {
                let mut random_value: i8 = rng.gen_range(0..=2);
                random_value -= 1;
                // let random_value: i8 = rng.gen_range(0..=1);
                // let mut new_stack_pointer = match stack_pointer {
                //     0 if random_value > 0 => stack_pointer + 1,
                //     1 if random_value < 0 => 0,
                //     2 if random_value < 0 => 1,
                //     _ => stack_pointer.wrapping_add(random_value as usize),
                // };
                let mut new_stack_pointer = stack_pointer.wrapping_add(random_value as usize);
                if new_stack_pointer >= 1024 {
                    new_stack_pointer = 1023;
                }

                if new_stack_pointer < stack_pointer && so.rw {
                    written_values.remove(&stack_pointer);
                    known_stack_pointers.remove(&stack_pointer);
                }

                rw_counter += 1;
                if index == 0 || !known_stack_pointers.contains(&new_stack_pointer) || so.rw {
                    written_values.insert(new_stack_pointer, so.value);
                    known_stack_pointers.insert(new_stack_pointer);

                    let Stack_op = Operation::new(
                        RWCounter::from(rw_counter),
                        convertBoolToRW(true),
                        StackOp::new(
                            // so.call_id,
                            1,
                            StackAddress::from(new_stack_pointer),
                            Word::from(so.value),
                        ),
                    );
                    Stack_op
                } else {
                    let read_value = *written_values.get(&new_stack_pointer).unwrap_or(&0);

                    let Stack_op = Operation::new(
                        RWCounter::from(rw_counter),
                        convertBoolToRW(so.rw),
                        StackOp::new(
                            // so.call_id,
                            1,
                            StackAddress::from(new_stack_pointer),
                            Word::from(read_value),
                        ),
                    );
                    Stack_op
                }
            })
            .collect()
    }
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct StorageOperation {
    pub rw_counter: usize,
    pub rw: bool,
    pub storage_address: [u8; 20],
    pub key: u32,
    pub value: u32,
    pub value_prev: u32,
    pub tx_id: usize,
    pub committed_value: u32,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct StorageOperationCollection {
    pub storage_operations: Vec<StorageOperation>,
}

impl StorageOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<StorageOp>> {
        let mut rw_counter = 0;
        let mut storage_values: HashMap<([u8; 20], u32), u32> = HashMap::new();


        self.storage_operations
            .iter()
            .map(|so| {
                rw_counter += 1;
                let address_key = (so.storage_address, so.key);
                let storage_op = if so.rw {
                    // Write operation: Update the storage value
                    let initial_value_prev = *storage_values.get(&address_key).unwrap_or(&so.committed_value);
                    storage_values.insert(address_key, so.value);
                    Operation::new(
                        RWCounter::from(rw_counter),
                        convertBoolToRW(so.rw),
                        StorageOp::new(
                            Address::from(so.storage_address),
                            Word::from(so.key),
                            Word::from(so.value), // Use the new value for writes
                            Word::from(initial_value_prev), // Set value_prev initially to committed_value
                            // so.tx_id,
                            1,
                            Word::from(so.committed_value),
                        ),
                    )
                } else {
                    // Read operation: Determine if it's the first read at this address and key
                    let is_first_read = !storage_values.contains_key(&address_key);
                    let read_value = if is_first_read {
                        // First read: Return committed_value
                        so.committed_value
                    } else {
                        // Not the first read: Retrieve the previously written value
                        *storage_values.get(&address_key).unwrap_or(&so.committed_value)
                    };
                    Operation::new(
                        RWCounter::from(rw_counter),
                        convertBoolToRW(so.rw),
                        StorageOp::new(
                            Address::from(so.storage_address),
                            Word::from(so.key),
                            Word::from(read_value),
                            Word::from(so.committed_value), // Use committed_value for value_prev
                            // so.tx_id,
                            1,
                            Word::from(so.committed_value),
                        ),
                    )
                };
                storage_op
            })
            .collect()
    }
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct TxAccessListAccountOperation {
    pub rw_counter: usize,
    pub rw: bool,
    pub tx_id: usize,
    pub account_address: [u8; 20],
    pub is_warm: bool,
    pub is_warm_prev: bool,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct TxAccessListAccountOperationCollection {
    pub tx_access_list_account_operations: Vec<TxAccessListAccountOperation>,
}

impl TxAccessListAccountOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<TxAccessListAccountOp>> {
        let mut rw_counter = 0;
        let mut access_list_state: HashMap<[u8; 20], (bool, bool)> = HashMap::new();

        self.tx_access_list_account_operations.iter()
            .map(|operation| {
                rw_counter += 1;
                let address_key = operation.account_address;
                let (is_warm, is_warm_prev) = *access_list_state.get(&address_key).unwrap_or(&(false, false));
                // Write operation: Update the access list state
                match (is_warm, is_warm_prev) {
                    (false, false) => {
                        access_list_state.insert(address_key, (true, false));
                    }
                    (true, false) => {
                        access_list_state.insert(address_key, (true, true));
                    }
                    _ => {}
                }
                Operation::new(
                    RWCounter::from(rw_counter),
                    convertBoolToRW(operation.rw),
                    TxAccessListAccountOp {
                        tx_id: 0,
                        address: Address::from(operation.account_address),
                        is_warm: is_warm,
                        is_warm_prev: is_warm_prev,
                    },
                )
            })
            .collect()
    }
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct TxAccessListAccountStorageOperation {
    pub rw_counter: usize,
    pub rw: bool,
    pub tx_id: usize,
    pub account_address: [u8; 20],
    pub key: u32,
    pub is_warm: bool,
    pub is_warm_prev: bool,
}

#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct TxAccessListAccountStorageOperationCollection {
    pub tx_access_list_account_storage_operations: Vec<TxAccessListAccountStorageOperation>,
}

impl TxAccessListAccountStorageOperationCollection {
    pub fn to_operations(&self) -> Vec<Operation<TxAccessListAccountStorageOp>> {
        let mut rw_counter = 0;
        let mut access_list_state: HashMap<([u8; 20], u32), (bool, bool)> = HashMap::new();

        self.tx_access_list_account_storage_operations.iter()
            .map(|operation| {
                rw_counter += 1;
                let address_key = (operation.account_address, operation.key);
                let (is_warm, is_warm_prev) = *access_list_state.get(&address_key).unwrap_or(&(false, false));
                // Write operation: Update the access list state
                match (is_warm, is_warm_prev) {
                    (false, false) => {
                        access_list_state.insert(address_key, (true, false));
                    }
                    (true, false) => {
                        access_list_state.insert(address_key, (true, true));
                    }
                    _ => {}
                }
                Operation::new(
                    RWCounter::from(rw_counter),
                    convertBoolToRW(operation.rw),
                    TxAccessListAccountStorageOp {
                        tx_id: 0,
                        address: Address::from(operation.account_address),
                        key: Word::from(operation.key),
                        is_warm: is_warm,
                        is_warm_prev: is_warm_prev,
                    },
                )
            })
            .collect()
    }
}


#[derive(Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct StateInputCollections {
    pub memory_operations: MemoryOperationCollection,
    pub stack_operations: StackOperationCollection,
    pub storage_operations: StorageOperationCollection,
    pub tx_access_list_account_operations: TxAccessListAccountOperationCollection,
    pub tx_access_list_account_storage_operations: TxAccessListAccountStorageOperationCollection,

}

fuzz_target!(|sic: StateInputCollections| {
    // if sic.memory_operations.memory_operations.len() < 20 {
    //     return;
    // }
    // if sic.stack_operations.stack_operations.len() < 20 {
    //     return;
    // }
    // if sic.storage_operations.storage_operations.len() < 20 {
    //     return
    // }
    // if sic.tx_access_list_account_operations.tx_access_list_account_operations.len() < 20 {
    //     return;
    // }
    if sic.tx_access_list_account_storage_operations.tx_access_list_account_storage_operations.len() < 3 {
        return;
    }
    let success = true;
    // println!("{:?}", sic);
    let rw_map = RwMap::from(&OperationContainer {
        // memory: sic.memory_operations.to_operations(),
        // stack: sic.stack_operations.to_operations(),
        // storage: sic.storage_operations.to_operations(),
        // tx_access_list_account: sic.tx_access_list_account_operations.to_operations(),
        tx_access_list_account_storage: sic.tx_access_list_account_storage_operations.to_operations(),
        ..Default::default()
    });
    println!("{:?}", rw_map);

    let circuit = StateCircuit::<Fr>::new(rw_map, N_ROWS);
    let instance = circuit.instance();

    let prover = MockProver::<Fr>::run(19, &circuit, instance).unwrap();
    let ver_result = prover.verify_par();
    if let Err(failures) = &ver_result {
        for failure in failures.iter() {
            error!("{}", failure);
        }
    }
    let error_msg = if success { "valid" } else { "invalid" };
    assert_eq!(ver_result.is_ok(), success, "proof must be {}", error_msg);
});

fn convertBoolToRW(value: bool) -> RW {
    if value {
        RW::WRITE
    } else {
        RW::READ
    }
}