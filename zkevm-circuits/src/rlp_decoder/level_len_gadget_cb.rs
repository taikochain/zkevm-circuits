use crate::{
    circuit_tools::{
        cached_region::CachedRegion,
        cell_manager::{Cell, CellManager},
        gadgets::LtGadget,
    },
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    util::Challenges,
};
use eth_types::Field;

use gadgets::{
    less_than::{LtChip, LtConfig},
    util::not,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};

use crate::util::Expr;
pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};

use super::{
    rlp_constraint_builder::{RLPCellType, RLPConstraintBuilder},
    RlpDecoderCircuitConfigWitness,
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
pub(crate) struct CbNestedRemainLengthGadget<F: Field> {
    /// list length checking column
    pub nested_rlp_remains: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// current enabled level
    /// [1,1,1,0,0,0] for level 3
    /// [1,1,0,0,0,0] for level 2
    pub q_nested_level: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// condition check for all curr_remain_length > 0
    pub zero_cmp_prev_nested_remains: Vec<LtGadget<F, 4>>,
    /// bytes_in_row <= prev_lv_remain (if exists)
    pub row_bytes_cmp_prev_nested_remains: Vec<LtGadget<F, 4>>,
    /// nested[0] >= nested[1] >= ... >= nested[n]
    pub remain_upper_leq_lower: Vec<LtGadget<F, 4>>,
}

impl<F: Field> CbNestedRemainLengthGadget<F> {
    pub(crate) fn new(
        cs: &mut ConstraintSystem<F>,
        q_enable: &Selector,
        bytes_in_row: Expression<F>,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        let cm = CellManager::new(
            cs,
            // Type, #cols, phase, permutable
            vec![
                (
                    RLPCellType::StoragePhase1,
                    MAX_NESTED_LEVEL_NUM + MAX_NESTED_LEVEL_NUM,
                    1,
                    false,
                ),
                (RLPCellType::LookupByte, 4 * 3, 1, false),
            ],
            0,
            1,
        );
        let mut cb = RLPConstraintBuilder::new(5, Some(challenges), Some(cm));

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
        let mut row_bytes_cmp_prev_nested_remains: Vec<LtGadget<F, 4>> = vec![];
        // 0 <= prev_remain
        let mut zero_cmp_prev_nested_remains: Vec<LtGadget<F, 4>> = vec![];
        // nested[0] >= nested[1] >= ... >= nested[n]
        let mut remain_upper_leq_lower: Vec<LtGadget<F, 4>> = vec![];

        cs.create_gate("Nested level length check", |meta| {
            // let mut cb = BaseConstraintBuilder::new(8);
            cb.base.require_boolean(
                "sum level flag == 0/1",
                q_nested_level.iter().fold(0.expr(), |acc, &level| {
                    acc.expr() + meta.query_advice(level, Rotation::cur())
                }),
            );

            row_bytes_cmp_prev_nested_remains = nested_rlp_remains
                .iter()
                .zip(q_nested_level.iter())
                .map(|(&curr_lv_remain_len, &q_level)| {
                    let prev_remain = meta.query_advice(curr_lv_remain_len, Rotation::prev());
                    LtGadget::construct(&mut cb.base, bytes_in_row.clone(), prev_remain)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // prev_nested_remain > 0
            zero_cmp_prev_nested_remains = nested_rlp_remains
                .iter()
                .zip(q_nested_level.iter())
                .map(|(&remain_len, &q_level)| {
                    let prev_remain = meta.query_advice(remain_len, Rotation::prev());
                    LtGadget::construct(&mut cb.base, 0.expr(), prev_remain)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            remain_upper_leq_lower = {
                let mut iter = nested_rlp_remains.iter().peekable();
                let mut le_gadgets = vec![];
                let mut idx = 0;
                while let Some(low_lv_remain) = iter.next() {
                    if let Some(high_lv_remain) = iter.peek() {
                        let q_level = q_nested_level[idx + 1];
                        let h_remain = meta.query_advice(**high_lv_remain, Rotation::cur());
                        let l_remain =
                            meta.query_advice(*low_lv_remain, Rotation::cur()) + 1.expr();

                        le_gadgets.push(LtGadget::construct(
                            &mut cb.base,
                            h_remain.expr(),
                            l_remain.expr(),
                        ));
                        idx += 1;
                    }
                }
                le_gadgets.try_into().unwrap()
            };

            // if curr level length == 0, then, lower level flag == 1, cur level flag == 0
            q_nested_level
                .iter()
                .enumerate()
                .for_each(|(idx, &level_enabled)| {
                    let level_enabled_prev = meta.query_advice(level_enabled, Rotation::prev());
                    let zero_left_prev = not::expr(zero_cmp_prev_nested_remains[idx].expr());
                    cb.base.condition(zero_left_prev, |cb| {
                        cb.require_zero("level flag == 0 if left == 0", level_enabled_prev)
                    })
                });

            // if prev nested rlp remain > 0, current nested rlp remain = prev nested rlp remain -
            // bytes_in_row
            q_nested_level.iter().enumerate().for_each(|(i, &level)| {
                let enabled_level = meta.query_advice(level, Rotation::cur());
                cb.base.condition(enabled_level, |cb| {
                    // if curr level is i, all levels below i should be minused by bytes_in_row
                    for j in 0..i {
                        let nested_rlp_remain_prev =
                            meta.query_advice(nested_rlp_remains[j], Rotation::prev());

                        cb.require_equal(
                            "nested rlp remain",
                            meta.query_advice(nested_rlp_remains[j], Rotation::cur()),
                            nested_rlp_remain_prev - bytes_in_row.expr(),
                        );
                    }

                    // curr prev length should be less equal than bytes_in_row
                    cb.require_equal(
                        "curr bytes in row <= prev remain length",
                        row_bytes_cmp_prev_nested_remains[i].expr(),
                        1.expr(),
                    )
                });
            });

            cb.base.build_constraints()
        });

        Self {
            nested_rlp_remains,
            q_nested_level,
            zero_cmp_prev_nested_remains,
            row_bytes_cmp_prev_nested_remains,
            remain_upper_leq_lower,
        }
    }

    pub(crate) fn construct(
        &self,
        meta: &mut VirtualCells<F>,
        cb: &mut BaseConstraintBuilder<F>,
    ) -> Result<(), Error> {
        Ok(())
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
            if let Some(idx) = wit.nested_rlp_lengths.iter().rposition(|&l| l > 0) {
                q_levels[idx] = 1;
            }

            for (i, remains) in self.nested_rlp_remains.iter().enumerate() {
                region
                    .assign_advice(
                        || format!("config.nested_remains[{}]", i),
                        *remains,
                        offset + row_idx,
                        || Value::known(F::from(wit.nested_rlp_lengths[i] as u64)),
                    )
                    .map(|_| ())?;
            }

            self.q_nested_level
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

            self.zero_cmp_prev_nested_remains
                .iter()
                .enumerate()
                .try_for_each(|(i, gadget)| {
                    gadget
                        .assign(
                            region,
                            offset + row_idx,
                            F::ZERO,
                            F::from(prev_wit.nested_rlp_lengths[i] as u64),
                        )
                        .map(|_| ())
                })?;
            self.row_bytes_cmp_prev_nested_remains
                .iter()
                .enumerate()
                .try_for_each(|(i, gadget)| {
                    gadget
                        .assign(
                            region,
                            offset + row_idx,
                            F::from(wit.rlp_bytes_in_row as u64),
                            F::from(prev_wit.nested_rlp_lengths[i] as u64),
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
                            F::from(wit.nested_rlp_lengths[i + 1] as u64),
                            F::from(wit.nested_rlp_lengths[i] as u64),
                        )
                        .map(|_| ())
                })?;

            prev_wit = wit;
        }
        Ok(())
    }
}
