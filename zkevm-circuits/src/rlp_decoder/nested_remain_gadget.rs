

use crate::{
    evm_circuit::util::{
        constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    },
    util::{SubCircuitConfig},
};
use eth_types::{Field};

use gadgets::{
    less_than::{LtChip, LtConfig},
    util::{not},
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Fixed, Selector,
        VirtualCells,
    },
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

use super::RlpDecoderCircuitConfigWitness;

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
pub(crate) struct NestedRemainLengthGadget<F: Field> {
    /// list length checking column
    pub nested_rlp_remains: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// current enabled level
    /// [1,1,1,0,0,0] for level 3
    /// [1,1,0,0,0,0] for level 2
    pub q_nested_level: [Column<Advice>; MAX_NESTED_LEVEL_NUM],
    /// condition check for all curr_remain_length > 0
    pub zero_cmp_prev_nested_remains: Vec<LtConfig<F, 4>>,
    /// bytes_in_row <= prev_lv_remain (if exists)
    pub row_bytes_cmp_prev_nested_remains: Vec<LtConfig<F, 4>>,
    /// nested[0] >= nested[1] >= ... >= nested[n]
    pub remain_upper_leq_lower: Vec<LtConfig<F, 4>>,
    /// top level length
    top_level_len: Column<Advice>,
    /// allocated for lt
    shared_advices: Vec<Column<Advice>>,
    /// allocated for lt
    shared_fixes: Vec<Column<Fixed>>,
}

impl<F: Field> NestedRemainLengthGadget<F> {
    pub(crate) fn new(
        cs: &mut ConstraintSystem<F>,
        q_enable: &Selector,
        top_level_len: Column<Advice>,
    ) -> Self {
        let nested_rlp_remains: [_; MAX_NESTED_LEVEL_NUM] = (0..MAX_NESTED_LEVEL_NUM)
            .map(|_| cs.advice_column())
            .collect::<Vec<Column<Advice>>>()
            .try_into()
            .unwrap();
        let q_nested_level: [_; MAX_NESTED_LEVEL_NUM] = (0..MAX_NESTED_LEVEL_NUM)
            .map(|_| cs.advice_column())
            .collect::<Vec<Column<Advice>>>()
            .try_into()
            .unwrap();

        // 5a + 1f
        let shared_advices = (0..5 * 3).map(|_| cs.advice_column()).collect::<Vec<_>>();
        let shared_fixes = vec![cs.fixed_column()];

        // make sure all shared col are bytes
        shared_advices.iter().for_each(|column| {
            cs.lookup_any("range check for u8", |meta| {
                let u8_cell = meta.query_advice(*column, Rotation::cur());
                let u8_range = meta.query_fixed(shared_fixes[0], Rotation::cur());
                vec![(u8_cell, u8_range)]
            });
        });

        // prev_nested_remain > 0
        let zero_cmp_prev_nested_remains: Vec<LtConfig<F, 4>> = nested_rlp_remains
            .iter()
            .zip(q_nested_level.iter())
            .map(|(&remain_len, &q_level)| {
                LtChip::configure_by_columns(
                    "zero_cmp_prev_nested_remains",
                    cs,
                    |meta| {
                        meta.query_advice(q_level, Rotation::prev())
                            * meta.query_selector(*q_enable)
                    },
                    |_| 0.expr(),
                    |meta: &mut VirtualCells<F>| meta.query_advice(remain_len, Rotation::prev()),
                    shared_advices[0],
                    shared_advices[1..5].try_into().unwrap(),
                    shared_fixes[0],
                    true,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // bytes_in_row <= prev_lv_remain (if prev_lv_remain > 0)
        let row_bytes_cmp_prev_nested_remains: Vec<LtConfig<F, 4>> = nested_rlp_remains
            .iter()
            .zip(q_nested_level.iter())
            .map(|(&curr_lv_remain_len, &q_level)| {
                LtChip::configure_by_columns(
                    "row_bytes_cmp_prev_nested_remains",
                    cs,
                    |meta| {
                        meta.query_advice(q_level, Rotation::prev())
                            * meta.query_selector(*q_enable)
                    },
                    |meta| meta.query_advice(top_level_len, Rotation::cur()),
                    |meta| meta.query_advice(curr_lv_remain_len, Rotation::prev()) + 1.expr(),
                    shared_advices[5],
                    shared_advices[6..10].try_into().unwrap(),
                    shared_fixes[0],
                    true,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // nested[0] >= nested[1] >= ... >= nested[n]
        let remain_upper_leq_lower: Vec<LtConfig<F, 4>> = {
            let mut iter = nested_rlp_remains.iter().peekable();
            let mut le_gadgets = vec![];
            let mut idx = 0;
            while let Some(low_lv_remain) = iter.next() {
                if let Some(high_lv_remain) = iter.peek() {
                    let q_level = q_nested_level[idx + 1];
                    le_gadgets.push(LtChip::configure_by_columns(
                        "remain_upper_leq_lower",
                        cs,
                        |meta| {
                            meta.query_advice(q_level, Rotation::cur())
                                * meta.query_selector(*q_enable)
                        },
                        |meta| meta.query_advice(**high_lv_remain, Rotation::cur()),
                        |meta| meta.query_advice(*low_lv_remain, Rotation::cur()) + 1.expr(),
                        shared_advices[10],
                        shared_advices[11..15].try_into().unwrap(),
                        shared_fixes[0],
                        true,
                    ));
                    idx += 1;
                }
            }
            le_gadgets.try_into().unwrap()
        };

        cs.create_gate("Nested level length check", |meta| {
            let mut cb = BaseConstraintBuilder::new(8);

            q_nested_level.iter().for_each(|&level| {
                cb.require_boolean(
                    "level flag check",
                    meta.query_advice(level, Rotation::cur()),
                )
            });

            cb.require_boolean(
                "sum level flag == 0/1",
                q_nested_level.iter().fold(0.expr(), |acc, &level| {
                    acc + meta.query_advice(level, Rotation::cur())
                }),
            );

            // if curr level length == 0, then, lower level flag == 1, cur level flag == 0
            q_nested_level
                .iter()
                .enumerate()
                .for_each(|(idx, &level_enabled)| {
                    let level_enabled_prev = meta.query_advice(level_enabled, Rotation::prev());
                    let zero_left_prev =
                        not::expr(zero_cmp_prev_nested_remains[idx].is_lt(meta, None));
                    cb.condition(zero_left_prev, |cb| {
                        cb.require_zero("level flag == 0 if left == 0", level_enabled_prev)
                    })
                });

            cb.gate(q_enable.expr())
        });

        Self {
            nested_rlp_remains,
            q_nested_level,
            zero_cmp_prev_nested_remains,
            row_bytes_cmp_prev_nested_remains,
            remain_upper_leq_lower,
            top_level_len,
            shared_advices,
            shared_fixes,
        }
    }

    pub(crate) fn construct(
        &self,
        meta: &mut VirtualCells<F>,
        cb: &mut BaseConstraintBuilder<F>,
    ) -> Result<(), Error> {
        // if prev nested rlp remain > 0, current nested rlp remain = prev nested rlp remain -
        // bytes_in_row
        self.q_nested_level
            .iter()
            .enumerate()
            .for_each(|(i, &level)| {
                let bytes_in_row = meta.query_advice(self.top_level_len, Rotation::cur());
                let enabled_level = meta.query_advice(level, Rotation::cur());
                cb.condition(enabled_level, |cb| {
                    // if curr level is i, all levels below i should be minused by bytes_in_row
                    for j in 0..i {
                        let nested_rlp_remain_prev =
                            meta.query_advice(self.nested_rlp_remains[j], Rotation::prev());

                        cb.require_equal(
                            "nested rlp remain",
                            meta.query_advice(self.nested_rlp_remains[j], Rotation::cur()),
                            nested_rlp_remain_prev - bytes_in_row.expr(),
                        );
                    }

                    // curr prev length should be less equal than bytes_in_row
                    cb.require_equal(
                        "curr bytes in row <= prev remain length",
                        self.row_bytes_cmp_prev_nested_remains[i].is_lt(meta, None),
                        1.expr(),
                    )
                });
            });

        Ok(())
    }

    pub(crate) fn assign_rows(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wit: &RlpDecoderCircuitConfigWitness<F>,
    ) -> Result<(), Error> {
        let mut q_levels = [0u64; MAX_NESTED_LEVEL_NUM];
        if let Some(idx) = wit.nested_rlp_lengths.iter().rposition(|&l| l > 0) {
            q_levels[idx] = 1;
        }

        self.q_nested_level
            .iter()
            .enumerate()
            .try_for_each(|(i, &q_level)| {
                region
                    .assign_advice(
                        || "nested rlp length",
                        q_level,
                        offset,
                        || Value::known(F::from(q_levels[i])),
                    )
                    .map(|_| ())
            })?;

        Ok(())
    }
}
