use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::LtGadget,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            CachedRegion, Cell, MemoryAddress, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::not;
use halo2_proofs::{circuit::Value, plonk::Error};
use integer::rns::Common;

#[derive(Clone, Debug)]
pub(crate) struct ReturnDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    /// Holds the memory address for return data from where we read.
    return_data_offset: Cell<F>, //MemoryAddress<F>,
    /// Holds the size of the return data.
    return_data_size: Cell<F>, //RandomLinearCombination<F, N_BYTES_MEMORY_ADDRESS>,
    /// The data is copied to memory. To verify this
    /// copy operation we need the MemoryAddressGadget.
    dst_memory_addr: MemoryAddressGadget<F>,
    /// Holds the memory address for the offset in return data from where we
    /// read.
    data_offset: MemoryAddress<F>,
    /// Opcode RETURNDATACOPY has a dynamic gas cost:
    /// gas_code = static_gas * minimum_word_size + memory_expansion_cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    /// Opcode RETURNDATAECOPY needs to copy data into memory. We account for
    /// the copying costs using the memory copier gas gadget.
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    /// RW inverse counter from the copy table at the start of related copy
    /// steps.
    copy_rwc_inc: Cell<F>,
    /// Out of bound check circuit.
    in_bound_check: LtGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for ReturnDataCopyGadget<F> {
    const NAME: &'static str = "RETURNDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURNDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // let dest_offset = cb.query_rlc();
        let dest_offset = cb.query_cell();
        let data_offset = cb.query_rlc();
        let size = cb.query_rlc();

        // 1. Pop dest_offset, offset, length from stack
        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(size.expr());

        // 2. Add lookup constraint in the call context for the returndatacopy field.
        let return_data_offset = cb.query_cell();
        let return_data_size = cb.query_cell();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataOffset,
            return_data_offset.expr(),
        );
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataLength,
            return_data_size.expr(),
        );

        // 3. contraints for copy: copy overflow check
        // i.e., offset + size <= return_data_size
        let in_bound_check = LtGadget::construct(
            cb,
            from_bytes::expr(&data_offset.cells) + size.expr(),
            return_data_size.expr() + 1.expr(),
        );
        cb.require_equal(
            "offset + size < return_data_size + 1",
            in_bound_check.expr(),
            1.expr(),
        );

        // 4 memory copy
        // Construct memory address in the destionation (memory) to which we copy code.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dest_offset, size);

        // Calculate the next memory size and the gas cost for this memory
        // access. This also accounts for the dynamic gas required to copy bytes to
        // memory.
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [dst_memory_addr.address()],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        let copy_rwc_inc = cb.query_cell();
        cb.condition(dst_memory_addr.has_length(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                return_data_offset.expr() + from_bytes::expr(&data_offset.cells),
                return_data_offset.expr() + return_data_size.expr(),
                dst_memory_addr.offset(),
                dst_memory_addr.length(),
                0.expr(), // for RETURNDATACOPY rlc_acc is 0
                cb.curr.state.rw_counter.expr() + cb.rw_counter_offset().expr(),
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(dst_memory_addr.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset() + copy_rwc_inc.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            gas_left: Delta(
                -(OpcodeId::CALLDATACOPY.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            return_data_offset,
            return_data_size,
            dst_memory_addr,
            data_offset,
            memory_expansion,
            memory_copier_gas,
            copy_rwc_inc,
            in_bound_check,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [dest_offset, data_offset, size] =
            [0, 1, 2].map(|i| block.rws[step.rw_indices[i as usize]].stack_value());

        self.data_offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let [return_data_offset, return_data_size] =
            [3, 4].map(|i| block.rws[step.rw_indices[i as usize]].call_context_value());
        self.return_data_offset.assign(
            region,
            offset,
            Value::known(
                return_data_offset
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.return_data_size.assign(
            region,
            offset,
            Value::known(
                return_data_size
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        // assign the destination memory offset.
        let memory_address =
            self.dst_memory_addr
                .assign(region, offset, dest_offset, size, block.randomness)?;

        // assign to gadgets handling memory expansion cost and copying cost.
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_cost)?;

        // rw_counter increase from copy lookup is `length` memory read & writes
        let copy_rwc_inc = size + size;
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                copy_rwc_inc // 1 read & 1 write
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let copy_end_offset = data_offset + size;
        self.in_bound_check.assign(
            region,
            offset,
            copy_end_offset
                .to_scalar()
                .expect("unexpected U256 -> Scalar conversion failure"),
            (return_data_size + 1)
                .to_scalar()
                .expect("unexpected U256 -> Scalar conversion failure"),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_ok_internal(
        return_data_offset: usize,
        return_data_size: usize,
        dest_offset: usize,
        offset: usize,
        size: usize,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        let pushdata = rand_bytes(32);
        let code_b = bytecode! {
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH1(0)
            MSTORE

            PUSH32(return_data_size)
            PUSH1(return_data_offset)
            RETURN
            STOP
        };

        // code A calls code B.
        let code_a = bytecode! {
            // call ADDR_B.
            PUSH32(return_data_size) // retLength
            PUSH1(return_data_offset) // retOffset
            PUSH1(0x00) // argsLength
            PUSH1(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            RETURNDATASIZE
            PUSH1(size) // size
            PUSH1(offset) // offset
            PUSH1(dest_offset) // dest_offset
            RETURNDATACOPY
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_a).code(code_a);
                accs[1].address(addr_b).code(code_b);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    #[test]
    fn returndatacopy_gadget_do_nothing() {
        test_ok_internal(0x00, 0x02, 0x10, 0x00, 0x00);
    }

    #[test]
    fn returndatacopy_gadget_simple() {
        test_ok_internal(0x00, 0x02, 0x10, 0x00, 0x02);
    }

    #[test]
    fn returndatacopy_gadget_large() {
        test_ok_internal(0x00, 0x20, 0x20, 0x00, 0x20);
    }

    #[test]
    fn returndatacopy_gadget_large_partial() {
        test_ok_internal(0x00, 0x20, 0x20, 0x10, 0x10);
    }

    #[test]
    fn returndatacopy_gadget_zero_length() {
        test_ok_internal(0x00, 0x00, 0x20, 0x00, 0x00);
    }

    // TODO: revert is normal, no need to panic. maybe we need a padding trace log
    // to test this.
    // #[test]
    // #[should_panic]
    // fn returndatacopy_gadget_out_of_bound() {
    //     test_ok_internal(0x00, 0x10, 0x20, 0x10, 0x10);
    // }

    #[test]
    #[should_panic]
    fn returndatacopy_gadget_out_of_gas() {
        test_ok_internal(0x00, 0x10, 0x20000, 0x10, 0x10);
    }
}
