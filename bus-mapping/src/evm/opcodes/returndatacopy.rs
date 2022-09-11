use crate::circuit_input_builder::{
    CircuitInputStateRef, CopyDataType, CopyEvent, CopyStep, ExecStep, NumberOrHash,
};
use crate::evm::Opcode;
use crate::operation::{CallContextField, MemoryOp, RW};
use crate::Error;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatacopy;

impl Opcode for Returndatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // TODO: complete `ExecStep` and circuit implementation
        let mut exec_step = state.new_step(&geth_steps[0])?;

        // reconstruction
        let geth_step = &geth_steps[0];
        let dest_offset = geth_step.stack.nth_last(0)?;
        let offset = geth_step.stack.nth_last(1)?;
        let size = geth_step.stack.nth_last(2)?;

        state.stack_read(
            &mut exec_step,
            geth_step.stack.nth_last_filled(0),
            dest_offset,
        )?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), size)?;

        let call_id = state.call()?.call_id;
        let call_ctx = state.call_ctx()?;
        let return_data = call_ctx.return_data.clone();
        let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
        let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
        assert_eq!(
            last_callee_return_data_length as usize,
            return_data.len(),
            "callee return data size should be correct"
        );

        // read last callee info
        for (field, value) in [
            (
                CallContextField::LastCalleeReturnDataOffset,
                last_callee_return_data_offset.into(),
            ),
            (
                CallContextField::LastCalleeReturnDataLength,
                return_data.len().into(),
            ),
        ] {
            state.call_context_read(&mut exec_step, call_id, field, value);
        }

        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;
        let length = size.as_usize();
        if length != 0 {
            let mem_starts = dest_offset.as_usize();
            let mem_ends = mem_starts + length;
            let data_starts = offset.as_usize();
            let data_ends = data_starts + length;
            let minimal_length = dest_offset.as_usize() + length;
            if data_ends <= return_data.len() {
                memory.extend_at_least(minimal_length);
                memory[mem_starts..mem_ends].copy_from_slice(&return_data[data_starts..data_ends]);
            } else {
                assert_eq!(geth_steps.len(), 1);
                // if overflows this opcode would fails current context, so
                // there is no more steps.
            }
        }

        let copy_event = gen_copy_event(state, geth_step)?;
        state.push_copy(copy_event);
        Ok(vec![exec_step])
    }
}

fn gen_copy_steps(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    src_addr_end: u64,
    bytes_left: u64,
    _is_root: bool,
) -> Result<Vec<CopyStep>, Error> {
    let mut copy_steps = Vec::with_capacity(2 * bytes_left as usize);
    for idx in 0..bytes_left {
        let addr = src_addr + idx;
        let rwc = state.block_ctx.rwc;
        let (value, is_pad) = if addr < src_addr_end {
            let byte = state.call_ctx()?.return_data
                [(addr - state.call()?.last_callee_return_data_offset) as usize];
            state.push_op(
                exec_step,
                RW::READ,
                MemoryOp::new(state.call()?.last_callee_id, addr.into(), byte),
            );
            (byte, false)
        } else {
            //TODO: return out of bound
            assert!(addr < src_addr_end, "return data copy out of bound");
            (1, false)
        };
        let tag = CopyDataType::Memory;
        // Read
        copy_steps.push(CopyStep {
            addr,
            tag,
            rw: RW::READ,
            value,
            is_code: None,
            is_pad,
            rwc,
            rwc_inc_left: 0,
        });
        // Write
        copy_steps.push(CopyStep {
            addr: dst_addr + idx,
            tag: CopyDataType::Memory,
            rw: RW::WRITE,
            value,
            is_code: None,
            is_pad: false,
            rwc: state.block_ctx.rwc,
            rwc_inc_left: 0,
        });
        state.memory_write(exec_step, (dst_addr + idx).into(), value)?;
    }

    for cs in copy_steps.iter_mut() {
        cs.rwc_inc_left = state.block_ctx.rwc.0 as u64 - cs.rwc.0 as u64;
    }

    Ok(copy_steps)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<CopyEvent, Error> {
    let dst_memory_offset = geth_step.stack.nth_last(0)?.as_u64();
    let data_offset = geth_step.stack.nth_last(1)?.as_u64();
    let length = geth_step.stack.nth_last(2)?.as_u64();

    let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
    let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
    let (src_addr, src_addr_end) = (
        last_callee_return_data_offset + data_offset,
        last_callee_return_data_offset + last_callee_return_data_length,
    );

    let mut exec_step = state.new_step(geth_step)?;
    let copy_steps = gen_copy_steps(
        state,
        &mut exec_step,
        src_addr,
        dst_memory_offset,
        src_addr_end,
        length,
        state.call()?.is_root,
    )?;

    let (src_type, src_id) = (CopyDataType::Memory, state.call()?.call_id);

    Ok(CopyEvent {
        src_type,
        src_id: NumberOrHash::Number(src_id),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(src_id),
        dst_addr: dst_memory_offset,
        log_id: None,
        length,
        steps: copy_steps,
    })
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_ok() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL

            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

            STOP
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_revert() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL

            PUSH1 (0x40)
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

            STOP
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
