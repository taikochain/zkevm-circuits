use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::EVMConstraintBuilder, CachedRegion,
        Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};


/// Gadget for invalid Tx
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidTxGadget<F> {
    dummy: F,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidTxGadget<F> {
    const NAME: &'static str = "ErrorInvalidTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidTx;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {

        Self {
            dummy: F::ZERO,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
    
        Ok(())
    }
}


#[cfg(test)]
mod test {
}