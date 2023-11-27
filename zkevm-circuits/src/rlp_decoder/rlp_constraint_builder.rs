use eth_types::Field;

use halo2_proofs::plonk::Expression;

use crate::{
    circuit_tools::{
        cell_manager::{CellType},
    },
    evm_circuit::table::Table,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RLPCellType {
    StoragePhase1,
    StoragePhase2,
    StoragePermutation,
    LookupByte,
    Lookup(Table),
}

impl Default for RLPCellType {
    fn default() -> Self {
        Self::StoragePhase1
    }
}

impl CellType for RLPCellType {
    // The phase that given `Expression` becomes evaluateable.
    fn expr_phase<F: Field>(expr: &Expression<F>) -> u8 {
        use Expression::*;
        match expr {
            Challenge(challenge) => challenge.phase() + 1,
            Advice(query) => query.phase(),
            Constant(_) | Selector(_) | Fixed(_) | Instance(_) => 0,
            Negated(a) | Expression::Scaled(a, _) => Self::expr_phase(a),
            Sum(a, b) | Product(a, b) => std::cmp::max(Self::expr_phase(a), Self::expr_phase(b)),
        }
    }

    /// Return the storage phase of phase
    fn storage_for_phase(phase: u8) -> Self {
        match phase {
            0 => RLPCellType::StoragePhase1,
            1 => RLPCellType::StoragePhase2,
            _ => unreachable!(),
        }
    }

    /// Return the storage cell of the expression
    fn storage_for_expr<F: Field>(expr: &Expression<F>) -> Self {
        Self::storage_for_phase(Self::expr_phase::<F>(expr))
    }

    fn byte_type() -> Option<Self> {
        RLPCellType::LookupByte.into()
    }
}
