use crate::{
    circuit_tools::{
        cached_region::CachedRegion,
        cell_manager::{Cell, CellManager},
        gadgets::LtGadget,
    },
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    rlp_decoder_tables::RlpDecoderFixedTableTag,
    util::Challenges,
};
use eth_types::Field;

use gadgets::{
    impl_expr,
    less_than::{LtChip, LtConfig},
    util::{and, not, or, sum},
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;

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
    RlpDecoderCircuitConfig, RlpDecoderCircuitConfigArgs, RlpDecoderCircuitConfigWitness,
};

/// RlpDecodeTypeTag is used to index the flag of rlp decoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RlpDecodeTypeTag {
    #[default]
    /// Nothing for no rlp decoding
    DoNothing = 0,
    /// SingleByte: 0x00 - 0x7f
    SingleByte,
    /// NullValue: 0x80
    NullValue,
    /// ShortString: 0x81~0xb7, value means bytes without leading 0
    ShortStringValue,
    /// ShortString: 0x81~0xb7, bytes contains leading 0
    ShortStringBytes,
    /// LongString: 0xb8
    LongString1,
    /// LongString: 0xb9
    LongString2,
    /// LongString: 0xba
    LongString3,
    /// EmptyList: 0xc0
    EmptyList,
    /// ShortList: 0xc1 ~ 0xf7
    ShortList,
    /// LongList1: 0xf8
    LongList1,
    /// LongList2: 0xf9, 0xFFFF upto (64K)
    LongList2,
    /// LongList3: 0xfa, 0xFFFFFF upto (16M)
    LongList3,
    /// PartialRlp: for those rlp that is not complete
    PartialRlp,
}
impl_expr!(RlpDecodeTypeTag);

pub(crate) const RLP_DECODE_TYPE_NUM: usize = RlpDecodeTypeTag::PartialRlp as usize + 1;

impl<T, const N: usize> std::ops::Index<RlpDecodeTypeTag> for [T; N] {
    type Output = T;

    fn index(&self, index: RlpDecodeTypeTag) -> &Self::Output {
        &self[index as usize]
    }
}

impl<T> std::ops::Index<RlpDecodeTypeTag> for Vec<T> {
    type Output = T;

    fn index(&self, index: RlpDecodeTypeTag) -> &Self::Output {
        &self[index as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// index type of decode error
pub enum RlpDecodeErrorType {
    /// the first byte is invalid, for example 0x00 for byte or 0xBF for list
    HeaderDecError,
    /// the length of rlp is invalid, for example 0xB854 or 0xB900FF for string
    LenOfLenError,
    /// the value of rlp is invalid, for example 0x8100 or 0x8179 for string
    ValueError,
    /// the rlp is not complete, for example 0xF8<EOF> for list
    RunOutOfDataError(usize),
}
pub(crate) const RLP_DECODE_ERROR_TYPE_NUM: usize = 4;

impl From<RlpDecodeErrorType> for usize {
    fn from(rlp_decode_error: RlpDecodeErrorType) -> usize {
        match rlp_decode_error {
            RlpDecodeErrorType::HeaderDecError => 0,
            RlpDecodeErrorType::LenOfLenError => 1,
            RlpDecodeErrorType::ValueError => 2,
            RlpDecodeErrorType::RunOutOfDataError(_) => 3,
        }
    }
}

impl<T, const N: usize> std::ops::Index<RlpDecodeErrorType> for [T; N] {
    type Output = T;

    fn index(&self, index: RlpDecodeErrorType) -> &Self::Output {
        &self[usize::from(index)]
    }
}

impl<T> std::ops::Index<RlpDecodeErrorType> for Vec<T> {
    type Output = T;

    fn index(&self, index: RlpDecodeErrorType) -> &Self::Output {
        &self[usize::from(index)]
    }
}

// TODO: combine with TxFieldTag in table.rs
// Marker that defines whether an Operation performs a `READ` or a `WRITE`.
/// RlpTxFieldTag is used to tell the field of tx, used as state in the circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RlpTxFieldTag {
    #[default]
    /// for tx list rlp header
    TxListRlpHeader = 0,
    /// for rlp header
    TxRlpHeader,
    /// for tx nonce
    Nonce,
    /// gas price
    GasPrice,
    /// Gas
    Gas,
    /// To
    To,
    /// Value
    Value,
    /// Data
    Data,
    /// SignV
    SignV,
    /// SignR
    SignR,
    /// SignS
    SignS,
    /// DecodeError
    DecodeError,
    /// Padding
    Padding,
    // 1559 extra field
    /// 1559 tx container, which is a long string starts with 0xb8/b9/ba
    TypedTxHeader,
    /// for 1559 typed tx
    TxType,
    /// ChainID
    ChainID,
    /// GasTipCap
    GasTipCap,
    /// GasFeeCap
    GasFeeCap,
    /// AccessList
    AccessList,
}
impl_expr!(RlpTxFieldTag);

impl<T, const N: usize> std::ops::Index<RlpTxFieldTag> for [T; N] {
    type Output = T;

    fn index(&self, index: RlpTxFieldTag) -> &Self::Output {
        &self[index as usize]
    }
}

impl<T> std::ops::Index<RlpTxFieldTag> for Vec<T> {
    type Output = T;

    fn index(&self, index: RlpTxFieldTag) -> &Self::Output {
        &self[index as usize]
    }
}

pub(crate) const LEGACY_TX_FIELD_NUM: usize = RlpTxFieldTag::Padding as usize + 1;
pub(crate) const TX1559_TX_FIELD_NUM: usize = RlpTxFieldTag::AccessList as usize + 1;

/// max byte column num which is used to store the rlp raw bytes
pub const MAX_BYTE_COLUMN_NUM: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct TxListRlpBytesGadget<F: Field> {
    // column need offset access
    pub(crate) tx_member: Column<Advice>,
    pub(crate) tx_member_complete: Column<Advice>,
    pub(crate) tx_id: Column<Advice>,
    pub(crate) valid: Column<Advice>,

    // fix
    pub(crate) q_first: Column<Fixed>,
    pub(crate) q_last: Column<Fixed>,

    // cell in row
    pub(crate) tx_type: Cell<F>,
    pub(crate) rlp_type: Cell<F>,
    pub(crate) value: Cell<F>,
    pub(crate) q_rlp_types: [Cell<F>; RLP_DECODE_TYPE_NUM],
    pub(crate) bytes: [Cell<F>; MAX_BYTE_COLUMN_NUM],
    pub(crate) q_decode_errors: [Cell<F>; RLP_DECODE_ERROR_TYPE_NUM],
    pub(crate) q_tx_members: [Cell<F>; TX1559_TX_FIELD_NUM as usize],
}

impl<F: Field> TxListRlpBytesGadget<F> {
    pub(crate) fn new(
        cs: &mut ConstraintSystem<F>,
        q_enable: &Selector,
        aux_tables: RlpDecoderCircuitConfigArgs<F>,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        let cm = CellManager::new(
            cs,
            // Type, #cols, phase, permutable
            vec![
                (
                    RLPCellType::StoragePhase1,
                    3 + RLP_DECODE_TYPE_NUM
                        + MAX_BYTE_COLUMN_NUM
                        + RLP_DECODE_ERROR_TYPE_NUM
                        + TX1559_TX_FIELD_NUM,
                    1,
                    false,
                ),
                (RLPCellType::LookupByte, 4 * 3, 1, false),
            ],
            0,
            1,
        );
        let mut cb = RLPConstraintBuilder::new(5, Some(challenges), Some(cm));

        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();

        let tx_id = cs.advice_column();
        let tx_type = cb.query_byte();
        let tx_member = cs.advice_column();
        let tx_member_complete = cs.advice_column();
        let valid = cs.advice_column();

        let rlp_type = cb.query_byte();
        let value = cb.query_byte();
        let q_rlp_types: [Cell<F>; RLP_DECODE_TYPE_NUM] = (0..RLP_DECODE_TYPE_NUM)
            .map(|_| cb.query_bool())
            .collect_vec()
            .try_into()
            .unwrap();
        let bytes: [Cell<F>; MAX_BYTE_COLUMN_NUM] = cb.query_bytes();
        let q_decode_errors: [Cell<F>; RLP_DECODE_ERROR_TYPE_NUM] = (0..RLP_DECODE_ERROR_TYPE_NUM)
            .map(|_| cb.query_bool())
            .collect_vec()
            .try_into()
            .unwrap();
        let q_tx_members: [Cell<F>; TX1559_TX_FIELD_NUM as usize] = (0..TX1559_TX_FIELD_NUM)
            .map(|_| cb.query_bool())
            .collect_vec()
            .try_into()
            .unwrap();

        // // lookup tx_field_switch table
        cs.lookup_any("rlp tx field transition", |meta| {
            let current_member = meta.query_advice(tx_member, Rotation::cur());
            let next_member = meta.query_advice(tx_member, Rotation::next());

            let table = &aux_tables.rlp_fixed_table.tx_member_switch_table;
            let table_tag = meta.query_fixed(table.table_tag, Rotation::cur());
            let curr_member_in_table = meta.query_fixed(table.current_tx_field, Rotation::cur());
            let next_member_in_table = meta.query_fixed(table.next_tx_field, Rotation::cur());
            let q_enable = meta.query_selector(*q_enable);
            // let is_last = meta.query_fixed(q_last, Rotation::cur());

            // state change happens only if current member is complete.
            let curr_member_is_complete = meta.query_advice(tx_member_complete, Rotation::cur());
            let query_able = and::expr([
                // not::expr(is_last.expr()),
                q_enable.expr(),
                curr_member_is_complete.expr(),
            ]);
            vec![
                (
                    query_able.expr() * RlpDecoderFixedTableTag::TxFieldSwitchTable.expr(),
                    table_tag,
                ),
                (query_able.expr() * current_member, curr_member_in_table),
                (query_able.expr() * next_member, next_member_in_table),
            ]
        });

        // lookup rlp_types table
        // TODO: bytes[1] as prefix of len also need to be constrainted
        cs.lookup_any("rlp decodable check", |meta| {
            let tx_type = tx_type.expr();
            let tx_member_cur = meta.query_advice(tx_member, Rotation::cur());
            let byte0 = bytes[0].expr();
            let decodable = not::expr(q_decode_errors[RlpDecodeErrorType::HeaderDecError].expr());
            let prev_is_valid = meta.query_advice(valid, Rotation::prev());
            let q_enable = meta.query_selector(*q_enable);

            let is_not_partial = not::expr(q_tx_members[RlpDecodeTypeTag::PartialRlp].expr());

            let table = &aux_tables.rlp_fixed_table.tx_decode_table;
            let table_tag = meta.query_fixed(table.table_tag, Rotation::cur());
            let tx_type_in_table = meta.query_fixed(table.tx_type, Rotation::cur());
            let tx_member_in_table = meta.query_fixed(table.tx_field_tag, Rotation::cur());
            let byte0_in_table = meta.query_fixed(table.byte_0, Rotation::cur());
            let decodable_in_table = meta.query_fixed(table.decodable, Rotation::cur());

            let query_able = q_enable.expr() * is_not_partial.expr() * prev_is_valid.expr();
            vec![
                (
                    query_able.expr() * RlpDecoderFixedTableTag::RlpDecoderTable.expr(),
                    table_tag,
                ),
                (query_able.expr() * tx_type, tx_type_in_table),
                (query_able.expr() * tx_member_cur, tx_member_in_table),
                (query_able.expr() * byte0, byte0_in_table),
                (query_able.expr() * decodable, decodable_in_table),
            ]
        });

        // constaints
        cs.create_gate("common logic for rlp decode", |meta| {
            // bind the rlp_type and rlp_type selector
            q_rlp_types
                .clone()
                .iter()
                .enumerate()
                .for_each(|(i, q_rlp_type)| {
                    cb.base.condition(q_rlp_type.expr(), |cb| {
                        cb.require_equal("rlp type check", q_rlp_type.expr(), i.expr())
                    });
                });
            cb.require_equal("1 rlp type only", sum::expr(q_rlp_types.clone()), 1.expr());

            // bind the q_field with the field tag
            q_tx_members
                .clone()
                .iter()
                .enumerate()
                .for_each(|(i, q_member)| {
                    cb.base.condition(q_member.expr(), |cb| {
                        cb.require_equal("tag check", q_member.expr(), i.expr())
                    });
                });
            cb.require_equal("1 tx field only", sum::expr(q_tx_members.clone()), 1.expr());

            cb.require_equal(
                "1 decode error only",
                sum::expr(q_decode_errors.clone()),
                1.expr(),
            );

            cb.require_boolean(
                "field complete boolean",
                meta.query_advice(tx_member_complete, Rotation::cur()),
            );

            let valid_cur = meta.query_advice(valid, Rotation::cur());
            let valid_next = meta.query_advice(valid, Rotation::next());
            cb.require_equal(
                "valid should be consistent after invalid",
                and::expr([valid_cur.expr(), valid_next.expr()]),
                valid_next.expr(),
            );

            // if not in error state and not in padding state, the valid comes from the error states
            let not_error_state: Expression<F> =
                not::expr(q_tx_members[RlpTxFieldTag::DecodeError].clone());
            let not_padding_state = not::expr(q_tx_members[RlpTxFieldTag::Padding].clone());
            cb.base
                .condition(and::expr([not_error_state, not_padding_state]), |cb| {
                    cb.require_equal(
                        "if any(errors) then valid must false",
                        or::expr(q_decode_errors.iter().map(|e| e.expr()).collect::<Vec<_>>()),
                        not::expr(valid_cur.expr()),
                    )
                });

            cb.base.build_constraints()
        });

        Self {
            // cols
            tx_id,
            tx_member,
            tx_member_complete,
            valid,
            // fix
            q_first,
            q_last,
            // cells
            tx_type,
            rlp_type,
            value,
            q_rlp_types,
            bytes,
            q_decode_errors,
            q_tx_members,
        }
    }

    pub(crate) fn is_tx_member(&self, member: RlpTxFieldTag) -> Expression<F> {
        self.q_tx_members[member].expr()
    }

    pub(crate) fn is_error(&self, error: RlpDecodeErrorType) -> Expression<F> {
        self.q_decode_errors[usize::from(error)].expr()
    }

    pub(crate) fn is_rlp_type(&self, rlp_type: RlpDecodeTypeTag) -> Expression<F> {
        self.q_rlp_types[rlp_type].expr()
    }

    pub(crate) fn tx_member_length(&self) -> Expression<F> {
        // NOTE: partial len is calculated outside.

        // TODO: use matchx!
        // RlpDecodeTypeTag::DoNothing =>
        self.is_rlp_type(RlpDecodeTypeTag::DoNothing) * 0.expr()
            //RlpDecodeTypeTag::SingleByte => 
            + {
                self.is_rlp_type(RlpDecodeTypeTag::SingleByte) * 1.expr()
            }
            //RlpDecodeTypeTag::NullValue => 
            + self.is_rlp_type(RlpDecodeTypeTag::NullValue) * 1.expr()
            //RlpDecodeTypeTag::ShortStringValue => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::ShortStringValue)
                    * (self.bytes[0].expr() - 0x80.expr() + 1.expr())
            }
            //RlpDecodeTypeTag::ShortStringBytes => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::ShortStringBytes)
                    * (self.bytes[0].expr() - 0x80.expr() + 1.expr())
            }
            //RlpDecodeTypeTag::LongString1 => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::LongString1) * (self.bytes[1].expr() + 2.expr())
            }
            //RlpDecodeTypeTag::LongString2 => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::LongString2)
                    * (self.bytes[1].expr() * 256.expr() + self.bytes[2].expr() + 3.expr())
            }
            //RlpDecodeTypeTag::LongString3 => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::LongString3)
                    * (self.bytes[1].expr() * 65536.expr()
                        + self.bytes[2].expr() * 256.expr()
                        + self.bytes[3].expr()
                        + 4.expr())
            }
            //RlpDecodeTypeTag::EmptyList => 
            +self.is_rlp_type(RlpDecodeTypeTag::EmptyList) * 1.expr()
            //RlpDecodeTypeTag::ShortList => 
            +{
                self.is_rlp_type(RlpDecodeTypeTag::ShortList)
                    * (self.bytes[0].expr() - 0xc0.expr() + 1.expr())
            }
    }

    // 0xb8/b9/ba => b1 / b1<<8+b2 / b1<<16+b2<<8+b3
    pub(crate) fn list_member_length(&self) -> Expression<F> {
        // RlpDecodeTypeTag::LongList1 =>
        self.is_rlp_type(RlpDecodeTypeTag::LongList1) * (self.bytes[1].expr())
            + {
                // RlpDecodeTypeTag::LongList2 =>
                self.is_rlp_type(RlpDecodeTypeTag::LongList2)
                    * (self.bytes[1].expr() * 256.expr() + self.bytes[2].expr())
            }
            + {
                // RlpDecodeTypeTag::LongList3 =>
                self.is_rlp_type(RlpDecodeTypeTag::LongList3)
                    * (self.bytes[1].expr() * 65536.expr()
                        + self.bytes[2].expr() * 256.expr()
                        + self.bytes[3].expr())
            }
    }

    // 0xb8/b9/ba => 1+(1/2/3)
    pub(crate) fn list_header_row_length(&self) -> Expression<F> {
        // RlpDecodeTypeTag::LongList1 =>
        self.is_rlp_type(RlpDecodeTypeTag::LongList1) * (2.expr())
            + {
                // RlpDecodeTypeTag::LongList2 =>
                self.is_rlp_type(RlpDecodeTypeTag::LongList2)
                    * (self.bytes[1].expr() * 256.expr() + 3.expr())
            }
            + {
                // RlpDecodeTypeTag::LongList3 =>
                self.is_rlp_type(RlpDecodeTypeTag::LongList3) * (4.expr())
            }
    }

    pub(crate) fn decode_valid(self) -> Expression<F> {
        or::expr(
            self.q_decode_errors
                .iter()
                .map(|e| e.expr())
                .collect::<Vec<_>>(),
        )
    }

    pub(crate) fn assign_rows(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        wits: &[RlpDecoderCircuitConfigWitness<F>],
    ) -> Result<(), Error> {
        let mut prev_wit = wits.last().unwrap();

        for (row_id, wit) in wits.iter().enumerate() {
            region.assign_advice(
                || "assign tx_member",
                self.tx_member,
                offset + row_id,
                || Value::known(F::from(wit.tx_member as u64)),
            )?;

            region.assign_advice(
                || "assign tx_member_complete",
                self.tx_member_complete,
                offset + row_id,
                || Value::known(F::from(wit.complete as u64)),
            )?;

            region.assign_advice(
                || "assign tx_id",
                self.tx_id,
                offset + row_id,
                || Value::known(F::from(wit.tx_id as u64)),
            )?;

            region.assign_fixed(
                || "assign q_first",
                self.q_first,
                offset + row_id,
                || Value::known(F::from(wit.q_first as u64)),
            )?;

            region.assign_fixed(
                || "assign q_last",
                self.q_last,
                offset + row_id,
                || Value::known(F::from(wit.q_last as u64)),
            )?;

            self.tx_type
                .assign(region, offset + row_id, F::from(wit.tx_type as u64))?;
            self.rlp_type
                .assign(region, offset + row_id, F::from(wit.rlp_type as u64))?;
            self.value.assign(region, offset + row_id, wit.value)?;

            self.q_rlp_types.iter().enumerate().try_for_each(|(i, q)| {
                q.assign(
                    region,
                    offset + row_id,
                    F::from((wit.rlp_type as u64 == i as u64) as u64),
                )
                .map(|_| ())
            })?;

            // bytes: [Cell<F>; MAX_BYTE_COLUMN_NUM],
            self.bytes.iter().enumerate().try_for_each(|(i, b)| {
                let v = {
                    if i < wit.bytes.len() {
                        F::from(wit.bytes[i] as u64)
                    } else {
                        F::ZERO
                    }
                };
                b.assign(region, offset, v).map(|_| ())
            })?;

            self.q_decode_errors
                .iter()
                .enumerate()
                .try_for_each(|(i, q)| {
                    q.assign(region, offset + row_id, F::from(wit.errors[i] as u64))
                        .map(|_| ())
                })?;

            self.q_tx_members
                .iter()
                .enumerate()
                .try_for_each(|(i, m)| {
                    m.assign(
                        region,
                        offset,
                        F::from((i == wit.tx_member as usize) as u64),
                    )
                    .map(|_| ())
                })?;

            prev_wit = wit;
        }

        Ok(())
    }
}
