use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;

use crate::{
    circuit_tools::{
        cell_manager::{Cell, CellManager, CellType},
        constraint_builder::ConstraintBuilder,
    },
    util::Challenges,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) enum RLPCellType {
    #[default]
    StoragePhase1 = 0,
    StoragePhase2,
    StoragePermutation,
    LookupByte,
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
        todo!()
    }
}

/// RLPConstraintBuilder
#[derive(Clone)]
pub struct RLPConstraintBuilder<F> {
    pub(crate) base: ConstraintBuilder<F, RLPCellType>,
    pub(crate) challenges: Option<Challenges<Expression<F>>>,
    pub(crate) key_r: Expression<F>,
    pub(crate) keccak_r: Expression<F>,
}

impl<F: Field> RLPConstraintBuilder<F> {
    pub(crate) fn new(
        max_degree: usize,
        challenges: Option<Challenges<Expression<F>>>,
        cell_manager: Option<CellManager<F, RLPCellType>>,
    ) -> Self {
        RLPConstraintBuilder {
            base: ConstraintBuilder::new(
                max_degree,
                cell_manager,
                Some(challenges.clone().unwrap().lookup_input().expr()),
            ),
            key_r: challenges.clone().unwrap().keccak_input().expr(),
            keccak_r: challenges.clone().unwrap().keccak_input().expr(),
            challenges,
        }
    }

    pub(crate) fn push_condition(&mut self, condition: Expression<F>) {
        self.base.push_condition(condition)
    }

    pub(crate) fn pop_condition(&mut self) {
        self.base.pop_condition()
    }

    pub(crate) fn query_bool(&mut self) -> Cell<F> {
        self.base.query_bool()
    }

    pub(crate) fn query_byte(&mut self) -> Cell<F> {
        self.base.query_one(RLPCellType::LookupByte)
    }

    pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.base
            .query_cells_dyn(RLPCellType::LookupByte, N)
            .try_into()
            .unwrap()
    }

    pub(crate) fn query_bytes_dyn(&mut self, count: usize) -> Vec<Cell<F>> {
        self.base.query_cells_dyn(RLPCellType::StoragePhase1, count)
    }

    pub(crate) fn query_cell(&mut self) -> Cell<F> {
        self.base.query_default()
    }

    pub(crate) fn query_cells<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.base
            .query_cells_dyn(RLPCellType::default(), N)
            .try_into()
            .unwrap()
    }

    pub(crate) fn query_cell_with_type(&mut self, cell_type: RLPCellType) -> Cell<F> {
        self.base.query_cell_with_type(cell_type)
    }

    pub(crate) fn require_equal(
        &mut self,
        name: &'static str,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.base.require_equal(name, lhs, rhs)
    }

    pub(crate) fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.base.require_in_set(name, value, set)
    }

    pub(crate) fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.base.require_boolean(name, value)
    }
}
