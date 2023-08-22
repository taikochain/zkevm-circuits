use crate::{
    circuit,
    circuit_tools::{
        cached_region::CachedRegion, cell_manager::CellManager,
        constraint_builder::ConstraintBuilder, gadgets::LtGadget,
    },
    evm_circuit::table::Table,
    util::Challenges,
};
use eth_types::Field;

use halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};

use super::{
    rlp_constraint_builder::RLPCellType, RlpDecoderCircuitConfigWitness, RlpDecoderTable1A6FColumns,
};

/// this is for nested txlist rlp length check.
/// A full txlist rlp is:
/// [ # level 0 length check column: list of TX header
///     [ # level 1 length check column: list of TX header
///         [ # level 2 length check column: tx structure header
///             nonce: 3,
///             ...,
///             access_list:
///             [ # level 3 length check column: list of AccessList header
///                 [ # level 4 length check column: AccessList structure header
///                     address: 1,
///                     storage_keys:
///                     [ #level 5 length check column: list of key header
///                         1,
///                     ] #end L5
///                 ], # end L4
///                 [ # level 3 length check column
///                     address: 2,
///                     storage_keys:
///                     [ # level 4 length check column
///                         2,
///                     ] # end L5
///                 ], # end L4
///             ], # end L3
///             ...,
///         ], # end L2
///     ], # end L1
///     ...,
///     [tx N]
/// ] # end L0
/// So, the max nested list num is 6
pub(crate) const MAX_NESTED_LEVEL_NUM: usize = 6;

#[derive(Debug, Clone)]
pub(crate) struct RemainLengthStackGadget<F: Field> {
    /// list length checking column
    pub nested_rlp_remains: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// current enabled level
    /// [0,0,1,0,0,0] for level 3
    /// [0,1,0,0,0,0] for level 2
    pub q_stack_level: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// condition check for all curr_remain_length > 0
    pub z_cmp_prev_remain: Vec<LtGadget<F, 4>>,
    /// bytes_in_row <= prev_lv_remain (if exists)
    pub row_bytes_cmp_prev_remain: Vec<LtGadget<F, 4>>,
    /// nested[0] >= nested[1] >= ... >= nested[n]
    pub remain_upper_leq_lower: Vec<LtGadget<F, 4>>,
}

impl<F: Field> RemainLengthStackGadget<F> {
    pub(crate) fn new(
        cs: &mut ConstraintSystem<F>,
        q_enable: &Selector,
        bytes_in_row: Column<Advice>,
        lookup_tables: &RlpDecoderTable1A6FColumns,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        // TODO: using shared cells.
        let cm = CellManager::new(
            cs,
            // Type, #cols, phase, permutable
            vec![
                (
                    RLPCellType::StoragePhase1,
                    3 * MAX_NESTED_LEVEL_NUM - 1, // 1 bool for each lt gadget
                    1,
                    false,
                ),
                (
                    RLPCellType::LookupByte,
                    4 * (3 * MAX_NESTED_LEVEL_NUM - 1), // 4 foreach lt gadget
                    1,
                    false,
                ),
            ],
            0,
            1,
        );
        let mut cb: ConstraintBuilder<F, RLPCellType> =
            ConstraintBuilder::new(4, Some(cm), Some(challenges.evm_word()));

        cb.preload_tables(
            cs,
            &[(RLPCellType::LookupByte, &lookup_tables.fixed_columns)],
        );

        let nested_rlp_remains: [_; MAX_NESTED_LEVEL_NUM] = (0..MAX_NESTED_LEVEL_NUM)
            .map(|_| cs.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let q_nested_level: [_; MAX_NESTED_LEVEL_NUM] = (0..MAX_NESTED_LEVEL_NUM)
            .map(|_| cs.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // bytes_in_row <= prev_lv_remain (if exists)
        let mut row_bytes_cmp_prev_remain: Vec<LtGadget<F, 4>> = vec![];
        // 0 <= prev_remain
        let mut z_cmp_prev_remain: Vec<LtGadget<F, 4>> = vec![];
        // nested[0] >= nested[1] >= ... >= nested[n]
        let mut remain_upper_leq_lower: Vec<LtGadget<F, 4>> = vec![];

        cs.create_gate("Nested level length check", |meta| {
            circuit!([meta, cb], {
                //"sum level flag == 0/1",
                require!(sum::expr(q_nested_level.iter().map(|l| a!(l))) => bool);

                // use matchx! and region
                (row_bytes_cmp_prev_remain, z_cmp_prev_remain) = nested_rlp_remains
                    .iter()
                    .map(|&lv_remain| {
                        (
                            LtGadget::construct(&mut cb, a!(bytes_in_row), a!(lv_remain, -1)),
                            LtGadget::construct(&mut cb, 0.expr(), a!(lv_remain, -1)),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip();

                // nested[0] >= nested[1] >= ... >= nested[n]
                for pair in nested_rlp_remains.windows(2) {
                    remain_upper_leq_lower.push(LtGadget::construct(
                        &mut cb,
                        a!(pair[1]),
                        a!(pair[0]) + 1.expr(),
                    ));
                }

                // if curr level length == 0, then, lower level flag == 1, cur level flag == 0
                q_nested_level.iter().enumerate().for_each(|(i, &level)| {
                    ifx! {not::expr(z_cmp_prev_remain[i].expr()) => {
                        // cb.require_zero("level flag == 0 if left == 0", level_enabled_prev)
                        require!(a!(level, -1) => 0.expr());
                    }}

                    ifx! {a!(level) => {
                        // if curr level is i, all levels below i should minus bytes_in_row
                        // TODO: better way to do this?
                        for j in 0..i {
                            require!(a!(nested_rlp_remains[j]) =>
                            a!(nested_rlp_remains[j], -1) - a!(bytes_in_row));
                        }

                        // if length is inited above.
                        ifx!{a!(level, -1) => {
                            require!(a!(nested_rlp_remains[i]) =>
                            a!(nested_rlp_remains[i], -1) - a!(bytes_in_row));

                            // curr prev length should be less equal than bytes_in_row
                            // "curr bytes in row <= prev remain length",
                            require!(row_bytes_cmp_prev_remain[i].expr() => 1.expr());
                        }};
                    }};
                });
            });

            let enable = meta.query_selector(*q_enable);
            cb.build_constraints(Some(enable))
        });

        cb.build_lookups(
            cs,
            &[cb.cell_manager.clone().unwrap()],
            &[(RLPCellType::LookupByte, RLPCellType::Lookup(Table::Fixed))],
            Some(*q_enable),
        );

        Self {
            nested_rlp_remains,
            q_stack_level: q_nested_level,
            z_cmp_prev_remain,
            row_bytes_cmp_prev_remain,
            remain_upper_leq_lower,
        }
    }

    pub(crate) fn assign_rows(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        wits: &[RlpDecoderCircuitConfigWitness<F>],
    ) -> Result<(), Error> {
        let mut prev_wit = wits.last().unwrap();

        for (row_idx, wit) in wits.iter().enumerate() {
            let mut q_levels = [0u64; MAX_NESTED_LEVEL_NUM];
            if let Some(idx) = wit.nested_rlp_remains.iter().rposition(|&l| l > 0) {
                q_levels[idx] = 1;
            }

            for (i, remains) in self.nested_rlp_remains.iter().enumerate() {
                region
                    .assign_advice(
                        || format!("config.nested_remains[{}]", i),
                        *remains,
                        offset + row_idx,
                        || Value::known(F::from(wit.nested_rlp_remains[i] as u64)),
                    )
                    .map(|_| ())?;
            }

            self.q_stack_level
                .iter()
                .enumerate()
                .try_for_each(|(i, &q_level)| {
                    region
                        .assign_advice(
                            || "nested rlp length",
                            q_level,
                            offset + row_idx,
                            || Value::known(F::from(q_levels[i])),
                        )
                        .map(|_| ())
                })?;

            self.z_cmp_prev_remain
                .iter()
                .enumerate()
                .try_for_each(|(i, gadget)| {
                    gadget
                        .assign(
                            region,
                            offset + row_idx,
                            F::ZERO,
                            F::from(prev_wit.nested_rlp_remains[i] as u64),
                        )
                        .map(|_| ())
                })?;
            self.row_bytes_cmp_prev_remain
                .iter()
                .enumerate()
                .try_for_each(|(i, gadget)| {
                    gadget
                        .assign(
                            region,
                            offset + row_idx,
                            F::from(wit.rlp_bytes_in_row as u64),
                            F::from(prev_wit.nested_rlp_remains[i] as u64),
                        )
                        .map(|_| ())
                })?;
            self.remain_upper_leq_lower
                .iter()
                .enumerate()
                .try_for_each(|(i, gadget)| {
                    gadget
                        .assign(
                            region,
                            offset + row_idx,
                            F::from(wit.nested_rlp_remains[i + 1] as u64),
                            F::from(wit.nested_rlp_remains[i] as u64 + 1),
                        )
                        .map(|_| ())
                })?;

            prev_wit = wit;
        }
        Ok(())
    }
}
