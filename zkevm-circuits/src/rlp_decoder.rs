//! The rlp decoding transaction list circuit implementation.

use std::marker::PhantomData;

use crate::{
    circuit,
    circuit_tools::{cached_region::CachedRegion, constraint_builder::ConstraintBuilder},
    evm_circuit::util::rlc,
    impl_expr,
    rlp_decoder::level_len_gadget_cb::RemainLengthStackGadget,
    rlp_decoder_tables::{
        RlpDecodeRule, RlpDecoderFixedTable, RlpDecoderFixedTableTag, RLP_TX_FIELD_DECODE_RULES,
    },
    table::KeccakTable,
    util::{log2_ceil, Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::{AccessList, Field, Transaction, Word};
use ethers_core::utils::rlp;
use gadgets::{
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, or},
};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector,
    },
    poly::Rotation,
};
use keccak256::plain::Keccak;

use crate::util::Expr;
pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};
use mock::MockTransaction;

mod level_len_gadget_cb;
mod rlp_constraint_builder;
mod txlist_rlp_bytes;
pub(crate) use level_len_gadget_cb::MAX_NESTED_LEVEL_NUM;
pub(crate) use txlist_rlp_bytes::{
    RlpDecodeErrorType, RlpDecodeTypeTag, TxListRlpBytesGadget, MAX_BYTE_COLUMN_NUM,
    RLP_DECODE_ERROR_TYPE_NUM,
};

const NUM_BLINDING_ROWS: usize = 64;

/// fix table with union-ed 6 columns
pub type RlpDecoderTable1A6FColumns = RlpDecoderFixedTable<1, 6>;

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

const TX1559_TX_FIELD_NUM: usize = RlpTxFieldTag::AccessList as usize + 1;

// TODO: combine with TxFieldTag in table.rs
// Marker that defines whether an Operation performs a `READ` or a `WRITE`.
/// RlpTxTypeTag is used to tell the type of tx
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RlpTxTypeTag {
    #[default]
    /// legacy tx
    TxLegacyType = 0,
    /// 1559 tx
    Tx1559Type,
}
impl_expr!(RlpTxTypeTag);

/// Witness for RlpDecoderCircuit
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RlpDecoderCircuitConfigWitness<F: Field> {
    /// tx_id column
    pub tx_id: u64,
    /// tx_type column
    pub tx_type: RlpTxTypeTag,
    /// tag column
    pub tx_member: RlpTxFieldTag,
    /// complete column
    pub complete: bool,
    /// rlp types: [single, short, long, very_long, fixed(33)]
    pub rlp_type: RlpDecodeTypeTag,
    /// rlp_tag_length, the length of this rlp field
    pub rlp_tx_member_length: u64,
    /// rlp length of nested levels
    pub nested_rlp_remains: [usize; MAX_NESTED_LEVEL_NUM],
    /// remained rows, for n < 33 fields, it is n, for m > 33 fields, it is 33 and next row is
    /// partial, next_length = m - 33
    pub rlp_bytes_in_row: u8,
    /// r_mult column, (length, r_mult) => @fixed
    pub r_mult: F,
    /// value
    pub value: F,
    /// acc_rlc_value
    pub acc_rlc_value: F,
    /// bytes
    pub bytes: Vec<u8>, //[u8; MAX_BYTE_COLUMN],
    /// decode error types: [header, len_of_len, value, run_out_of_data]
    pub errors: [bool; RLP_DECODE_ERROR_TYPE_NUM],
    /// valid, 0 for invalid, 1 for valid, should be == decodable at the end of the circuit
    pub valid: bool,
    /// full chip enable
    pub q_enable: bool,
    /// the begining
    pub q_first: bool,
    /// the end
    pub q_last: bool,
    /// r_mult_comp
    pub r_mult_comp: F,
    /// rlc_quotient
    pub rlc_quotient: F,
}

/// Config for RlpDecoderCircuit
#[derive(Clone, Debug)]
pub struct RlpDecoderCircuitConfig<F: Field> {
    /// tx_id column
    pub tx_id: Column<Advice>,
    /// tx_type column
    pub tx_type: Column<Advice>,
    /// tag column
    pub tx_member: Column<Advice>,
    /// complete column
    pub complete: Column<Advice>,
    /// rlp_tag_length, the length of this rlp field
    pub rlp_tx_member_length: Column<Advice>,
    /// remained rows, for n < 33 fields, it is n, for m > 33 fields, it is 33 and next row is
    /// partial, next_length = m - 33
    pub rlp_bytes_in_row: Column<Advice>,
    /// r_mult column, (length, r_mult) => @fixed, r_mult == r ^ length
    pub r_mult: Column<Advice>,
    /// acc_rlc_value
    pub acc_rlc_value: Column<Advice>,
    /// valid, 0 for invalid, 1 for valid, should be == decodable at the end of the circuit
    pub valid: Column<Advice>,
    /// dynamic selector for fields
    pub q_tx_members: [Column<Advice>; TX1559_TX_FIELD_NUM as usize],
    /// full chip enable
    pub q_enable: Selector,
    /// the begining
    pub q_first: Column<Fixed>,
    /// the end
    pub q_last: Column<Fixed>,
    /// aux tables
    pub aux_tables: RlpDecoderCircuitConfigArgs<F>,
    /// condition check for <=55
    pub v_gt_55: LtConfig<F, 1>,
    /// condition check for > 0
    pub v_gt_0: LtConfig<F, 1>,
    /// condition check for prev_remain_length > 33
    pub remain_length_gt_33: LtConfig<F, 4>,
    /// condition check for prev_remain_length >= cur_length
    pub remain_length_ge_length: LtConfig<F, 4>,
    /// divide factor for big endian rlc, r_mult_comp * r_mult = r ^ MAX_BYTE_COLUMN_NUM(33)
    pub r_mult_comp: Column<Advice>,
    /// quotient value for big endian rlc, rlc_quotient = rlc[0..MAX_BYTE_COLUMN_NUM] / r_mult_comp
    pub rlc_quotient: Column<Advice>,
    /// gadget for rlp bytes
    pub(crate) txlist_rlp_bytes_gadget: TxListRlpBytesGadget<F>,
    /// gadget for rlp length stack
    pub(crate) remain_len_stack_gadget: RemainLengthStackGadget<F>,
}

#[derive(Clone, Debug)]
/// Circuit configuration arguments
pub struct RlpDecoderCircuitConfigArgs<F: Field> {
    /// shared fixed tables
    pub rlp_decoder_table: RlpDecoderTable1A6FColumns,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for RlpDecoderCircuitConfig<F> {
    type ConfigArgs = RlpDecoderCircuitConfigArgs<F>;

    /// Return a new RlpDecoderCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, aux_tables: Self::ConfigArgs) -> Self {
        let tx_id = meta.advice_column();
        let tx_type = meta.advice_column();
        let tx_member = meta.advice_column();
        let complete = meta.advice_column();
        let rlp_tx_member_length = meta.advice_column();
        let bytes_in_row = meta.advice_column();
        let r_mult = meta.advice_column_in(SecondPhase);
        let acc_rlc_value = meta.advice_column_in(SecondPhase);
        let valid = meta.advice_column();
        let q_tx_members: [Column<Advice>; TX1559_TX_FIELD_NUM as usize] = (0..TX1559_TX_FIELD_NUM)
            .map(|_| meta.advice_column())
            .collect::<Vec<Column<Advice>>>()
            .try_into()
            .unwrap();
        let q_enable = meta.complex_selector();
        let q_first = meta.fixed_column();
        let q_last = meta.fixed_column();
        let r_mult_comp = meta.advice_column_in(SecondPhase);
        let rlc_quotient = meta.advice_column_in(SecondPhase);

        let challenges = aux_tables.challenges.clone();
        let txlist_rlp_bytes =
            TxListRlpBytesGadget::new(meta, q_enable.clone(), challenges.clone());
        let byte_cells = txlist_rlp_bytes.bytes.clone();
        let decode_errors = txlist_rlp_bytes.q_decode_errors.clone();

        let remain_len_stack_gadget = RemainLengthStackGadget::new(
            meta,
            &q_enable,
            bytes_in_row.clone(),
            &aux_tables.rlp_decoder_table,
            challenges.clone(),
        );
        let nested_rlp_remains: [Column<Advice>; MAX_NESTED_LEVEL_NUM as usize] =
            remain_len_stack_gadget.nested_rlp_remains;
        let rlp_total_remain = nested_rlp_remains[0];
        let rlp_typed_tx_remain = nested_rlp_remains[1];
        let rlp_inner_tx_remain = nested_rlp_remains[2];

        // lt gadgets
        let cmp_55_lt_byte1 = LtChip::configure(
            meta,
            |meta| {
                txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList1)
                    * meta.query_selector(q_enable)
            },
            |_| 55.expr(),
            |_| byte_cells[1].expr(),
        );

        let cmp_0_lt_byte1 = LtChip::configure(
            meta,
            |meta| {
                or::expr([
                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::ShortStringValue),
                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList2),
                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList3),
                ]) * meta.query_selector(q_enable)
            },
            |_| 0.expr(),
            |_| byte_cells[1].expr(),
        );

        let cmp_max_row_bytes_lt_remains: LtConfig<F, 4> = LtChip::configure(
            meta,
            |meta| {
                not::expr(meta.query_advice(valid, Rotation::cur())) * meta.query_selector(q_enable)
            },
            |_| MAX_BYTE_COLUMN_NUM.expr(),
            |meta| meta.query_advice(rlp_total_remain, Rotation::prev()),
        );

        // less equal n == less than n+1
        let cmp_length_le_prev_remain: LtConfig<F, 4> = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| meta.query_advice(rlp_tx_member_length, Rotation::cur()),
            |meta| meta.query_advice(rlp_total_remain, Rotation::prev()) + 1.expr(),
        );

        let mut cb: ConstraintBuilder<F, RLPCellType> =
            ConstraintBuilder::new(4, None, Some(challenges.evm_word()));

        /////////////////////////////////
        //// lookups
        //// /////////////////////////////
        // output txlist hash check
        // meta.lookup_any("comsumed all bytes correctly", |meta| {
        //     let is_enabled = meta.query_fixed(q_first, Rotation::next());
        //     let input_rlc = meta.query_advice(acc_rlc_value, Rotation::cur());
        //     let input_len = meta.query_advice(rlp_remain_length, Rotation::cur());
        //     let hash_rlc = meta.query_advice(value, Rotation::cur());

        //     let table = &aux_tables.keccak_table;
        //     let table_is_enabled = meta.query_advice(table.is_enabled, Rotation::cur());
        //     let table_input_rlc = meta.query_advice(table.input_rlc, Rotation::cur());
        //     let table_input_len = meta.query_advice(table.input_len, Rotation::cur());
        //     let table_hash_rlc = meta.query_advice(table.output_rlc, Rotation::cur());

        //     vec![
        //         (is_enabled.expr(), table_is_enabled.expr()),
        //         (is_enabled.expr() * input_rlc.expr(), table_input_rlc.expr()),
        //         (is_enabled.expr() * input_len.expr(), table_input_len.expr()),
        //         (is_enabled.expr() * hash_rlc.expr(), table_hash_rlc.expr()),
        //     ]
        // });

        // lookup rlp_types table
        // TODO: bytes[1] as prefix of len also need to be constrainted
        meta.lookup_any("rlp decodable check", |meta| {
            let tx_type = meta.query_advice(tx_type, Rotation::cur());
            let tx_member_cur = meta.query_advice(tx_member, Rotation::cur());
            let byte0 = byte_cells[0].expr();
            let decodable = not::expr(decode_errors[RlpDecodeErrorType::HeaderDecError].expr());
            let prev_is_valid = meta.query_advice(valid, Rotation::prev());
            let q_enable = meta.query_selector(q_enable);

            let is_not_partial =
                not::expr(txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::PartialRlp));

            let table = &aux_tables.rlp_decoder_table.tx_decode_table;
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

        // // lookup tx_field_switch table
        meta.lookup_any("rlp tx field transition", |meta| {
            let current_member = meta.query_advice(tx_member, Rotation::cur());
            let next_member = meta.query_advice(tx_member, Rotation::next());

            let table = &aux_tables.rlp_decoder_table.tx_member_switch_table;
            let table_tag = meta.query_fixed(table.table_tag, Rotation::cur());
            let curr_member_in_table = meta.query_fixed(table.current_tx_field, Rotation::cur());
            let next_member_in_table = meta.query_fixed(table.next_tx_field, Rotation::cur());
            let q_enable = meta.query_selector(q_enable);
            let is_last = meta.query_fixed(q_last, Rotation::cur());

            // state change happens only if current member is complete.
            let curr_member_is_complete = meta.query_advice(complete, Rotation::cur());
            let query_able = and::expr([
                not::expr(is_last.expr()),
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

        // lookup r_mult/r_mult_comp table with length,
        // TODO: r_mult is adv, add constraint for pow
        meta.lookup_any("rlp r_mult check", |meta| {
            let r_mult = meta.query_advice(r_mult, Rotation::cur());
            let pow = meta.query_advice(bytes_in_row, Rotation::cur());

            let table = &aux_tables.rlp_decoder_table.r_mult_pow_table;
            let table_tag = meta.query_fixed(table.table_tag, Rotation::cur());
            let r_mult_in_table = meta.query_advice(table.r_mult, Rotation::cur());
            let r_pow_in_table = meta.query_fixed(table.length, Rotation::cur());

            let q_enable = meta.query_selector(q_enable);
            vec![
                (
                    q_enable.expr() * RlpDecoderFixedTableTag::RMult.expr(),
                    table_tag,
                ),
                (q_enable.expr() * r_mult, r_mult_in_table),
                (q_enable.expr() * pow, r_pow_in_table),
            ]
        });
        meta.lookup_any("rlp r_mult_comp check", |meta| {
            let r_mult_comp = meta.query_advice(r_mult_comp, Rotation::cur());
            let pow = MAX_BYTE_COLUMN_NUM.expr() - meta.query_advice(bytes_in_row, Rotation::cur());

            let table = &aux_tables.rlp_decoder_table.r_mult_pow_table;
            let table_tag = meta.query_fixed(table.table_tag, Rotation::cur());
            let r_mult_in_table = meta.query_advice(table.r_mult, Rotation::cur());
            let r_pow_in_table = meta.query_fixed(table.length, Rotation::cur());

            let q_enable = meta.query_selector(q_enable);
            vec![
                (
                    q_enable.expr() * RlpDecoderFixedTableTag::RMult.expr(),
                    table_tag,
                ),
                (q_enable.expr() * r_mult_comp, r_mult_in_table),
                (q_enable.expr() * pow, r_pow_in_table),
            ]
        });

        //// ////////////////////////////
        //// constraints
        //// ////////////////////////////
        let keccak_r = challenges.keccak_input().clone();
        meta.create_gate("txlist rlp decoding", |meta| {
            let rev_byte_cells = byte_cells
                .iter()
                .rev()
                .map(|c| c.expr())
                .collect::<Vec<_>>();

            cb.restart();
            circuit!([meta, cb], {
                ifx!{q!(q_enable) => {
                    require!(a!(valid) => bool);
                    require!(a!(complete) => bool);

                    // bind the q_field with the field tag
                    q_tx_members.iter().enumerate().for_each(|(i, q_m)| {
                        require!(a!(q_m) => bool);
                        ifx! {a!(q_m) => {
                            require!(a!(tx_member) => i.expr());
                        }}
                    });
                    // only 1 tx_member is true
                    require!(sum::expr(q_tx_members.iter().map(|m| a!(m))) => 1.expr());

                    // "rlc_quotient = rlc[0..32]/r_mult_comp",
                    require!(a!(rlc_quotient) * a!(r_mult_comp) => rlc::expr(&rev_byte_cells, keccak_r));
                    // "rlc = prev_rlc * r_mult + rlc[0..32]/r_mult_comp",
                    require!(a!(acc_rlc_value) => a!(r_mult) * a!(acc_rlc_value, -1) + a!(rlc_quotient));

                    // "valid should be consistent after invalid",
                    require!(and::expr([a!(valid), a!(valid, 1)]) => a!(valid, 1));

                    // if not in error state and not in padding state, the valid comes from the error states
                    ifx!{and::expr([not!(a!(q_tx_members[RlpTxFieldTag::DecodeError])),not!(a!(q_tx_members[RlpTxFieldTag::DecodeError]))]) => {
                            require!(not::expr(a!(valid)) => txlist_rlp_bytes.any_error());
                    }}

                    ifx!{a!(valid) => {
                        require!(cmp_length_le_prev_remain.is_lt(meta, None) => 1.expr());
                    }}

                    // tx member constraints
                    ifx!{and::expr([
                        a!(valid),
                        not!(f!(q_first)),
                        not!(a!(q_tx_members[RlpTxFieldTag::TxRlpHeader])),
                        not!(a!(q_tx_members[RlpTxFieldTag::TypedTxHeader])),
                    ]) => {
                        ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::PartialRlp) => {
                            // "length = prev_length - prev_bytes_in_row",
                            require!(a!(rlp_tx_member_length) => a!(rlp_tx_member_length, -1) - a!(bytes_in_row, -1));
                            // above line is not complete.
                            require!(a!(complete, -1) => 0.expr());
                        } elsex {
                            // complete member length == decoded member length
                            require!(a!(rlp_tx_member_length) => txlist_rlp_bytes.tx_member_length());
                        }}

                        ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::ShortStringValue) => {
                            require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                        }}
                        ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString1) => {
                            require!(cmp_55_lt_byte1.is_lt(meta, None) => 1.expr());
                        }}
                        ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString2) => {
                            require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                        }}
                        ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString3) => {
                            require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                        }}

                        ifx!{a!(complete) => {
                            // "complete = 1 => rlp_tag_length = bytes_in_row",
                            require!(a!(rlp_tx_member_length) => a!(bytes_in_row));
                        } elsex {
                            //"!complete => MAX_BYTES_COL == bytes_in_row"
                            require!(a!(bytes_in_row) => MAX_BYTE_COLUMN_NUM.expr());
                        }}
                    }}

                    // first row is txlist rlp header
                    ifx!{f!(q_first) => {
                        require!(a!(tx_id) => 0);
                        require!(a!(tx_type) => 1.expr());
                        require!(a!(tx_member) => 0);
                        require!(a!(complete) => 1.expr());
                        require!(a!(acc_rlc_value, -1) => 0);

                        ifx!{a!(valid) => {
                            require!(a!(rlp_total_remain) => txlist_rlp_bytes.list_member_length());
                            require!(a!(rlp_tx_member_length) => txlist_rlp_bytes.list_header_bytes_in_row());

                            //TODO: use matchx!
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList1) => {
                                // "v should be >55",
                                require!(cmp_55_lt_byte1.is_lt(meta, None) => 1.expr());
                                // TODO: byte_cells_cur[1] > 55, and check with len_decode flag
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList2) => {
                                // "v should be > 0",
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList3) => {
                                // "v should be > 0",
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                        }}
                    }}

                    // for typed tx header, string enc of tx
                    ifx!{a!(q_tx_members[RlpTxFieldTag::TypedTxHeader]) => {
                        //"tx_id == tx_id_prev + 1",
                        require!(a!(tx_id) => a!(tx_id, -1) + 1.expr());
                        // 1559
                        require!(a!(tx_type) => RlpTxTypeTag::Tx1559Type.expr());
                        require!(a!(complete) => 1.expr());
                        // last typed tx ends above
                        require!(a!(rlp_typed_tx_remain, -1) => 0.expr());

                        ifx!{a!(valid) => {
                            require!(a!(rlp_tx_member_length) => txlist_rlp_bytes.string_header_bytes_in_row());
                            require!(a!(rlp_typed_tx_remain) => txlist_rlp_bytes.string_member_length());

                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString1) => {
                                require!(cmp_55_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString2) => {
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString3) => {
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                        }}
                    }}

                    // for tx header, list enc of tx members
                    ifx!{a!(q_tx_members[RlpTxFieldTag::TxRlpHeader]) => {
                        require!(a!(tx_type) => RlpTxTypeTag::Tx1559Type.expr());
                        require!(a!(complete) => 1.expr());

                        // prev tx inner remain is 0
                        require!(a!(rlp_inner_tx_remain, -1) => 0.expr());

                        ifx!{a!(valid) => {
                            // "rlp_tag_length = rlp_header length",
                            require!(a!(rlp_tx_member_length) => byte_cells[0].expr() - 247.expr() + 1.expr());
                            require!(a!(rlp_inner_tx_remain) => txlist_rlp_bytes.list_member_length());

                            //TODO: use matchx!
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList1) => {
                                // "v should be >55",
                                require!(cmp_55_lt_byte1.is_lt(meta, None) => 1.expr());
                                // TODO: byte_cells_cur[1] > 55, and check with len_decode flag
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList2) => {
                                // "v should be > 0",
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                            ifx!{txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList3) => {
                                // "v should be > 0",
                                require!(cmp_0_lt_byte1.is_lt(meta, None) => 1.expr());
                            }}
                        }}
                    }}

                    // for padding
                    ifx!{a!(q_tx_members[RlpTxFieldTag::Padding]) => {
                        require!(a!(tx_member) => RlpTxFieldTag::Padding.expr());
                        require!(a!(complete) => 1.expr());
                        require!(a!(r_mult) => 1.expr());
                        require!(a!(rlp_tx_member_length) => 0.expr());
                        require!(a!(rlp_total_remain) => 0.expr());
                        require!(a!(rlp_total_remain, -1) => 0.expr());
                        require!(a!(acc_rlc_value, -1) => a!(acc_rlc_value));
                        byte_cells.iter().for_each(|c| {
                            require!(c.expr() => 0.expr());
                        });
                    }}

                    ifx!{f!(q_last) => {
                        require!(a!(q_tx_members[RlpTxFieldTag::Padding]) => 1.expr());
                    }}
                }}
            });

            cb.build_constraints(None)
        });

        meta.create_gate("invalid state gate", |meta| {
            cb.restart();
            circuit!([meta, cb], {
                ifx! {and::expr([q!(q_enable), not!(a!(valid))]) => {
                    // error gates and error state handling
                    // 1. each error has its own check to avoid fake error witness
                    // 2. error state needs extra logic to process all the rest bytes

                    // header error is looked up, no extra check
                    // ifx!{decode_errors[RlpDecodeErrorType::HeaderDecError] => {}}
                    ifx!{decode_errors[RlpDecodeErrorType::LenOfLenError] => {
                        // len error happens only if (short1 && b[1] < 55) || (short2/3 && b[1] == 0)
                        require!(or::expr([
                            and::expr([
                                or::expr([
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString1),
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList1),
                                ]),
                                not!(cmp_55_lt_byte1.is_lt(meta, None))
                            ]),
                            and::expr([
                                or::expr([
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString2),
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongString3),
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList2),
                                    txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::LongList3),
                                ]),
                                not!(cmp_0_lt_byte1.is_lt(meta, None))
                            ]),
                        ]) => 1.expr())
                    }}
                    ifx!{decode_errors[RlpDecodeErrorType::ValueError] => {
                        require!(
                            // value error on if short string value with leading 0
                            and::expr([
                                txlist_rlp_bytes.is_rlp_type(RlpDecodeTypeTag::ShortStringValue),
                                not!(cmp_0_lt_byte1.is_lt(meta, None))
                            ]) => 1.expr()
                        )
                    }}
                    // TODO: check eof
                    // ifx!{decode_errors[RlpDecodeErrorType::RunOutOfDataError(0)] => {}}

                    ifx!{a!(q_tx_members[RlpTxFieldTag::DecodeError]) => {
                        require!(a!(tx_member) => RlpTxFieldTag::DecodeError.expr());
                        require!(a!(complete) => 1.expr());

                        // remain_length = prev_remain_length - length;
                        require!(a!(rlp_total_remain) => a!(rlp_total_remain, -1) - a!(rlp_tx_member_length));
                        // above row is invalid
                        require!(a!(valid, -1) => 0.expr());

                        ifx!{cmp_max_row_bytes_lt_remains.is_lt(meta, None) => {
                            require!(a!(rlp_tx_member_length) => MAX_BYTE_COLUMN_NUM.expr());
                        } elsex {
                            require!(a!(rlp_tx_member_length) => a!(rlp_total_remain, -1));
                        }}
                    }}

                }}
            });
            cb.build_constraints(None)
        });

        log::info!(
            "rlp decoder config: meta info (a:{}, f:{}, i:{}, l:{}, d:{}).",
            meta.num_advice_columns(),
            meta.num_fixed_columns(),
            meta.num_instance_columns(),
            meta.lookups().len(),
            meta.degree()
        );

        let circuit_config = RlpDecoderCircuitConfig {
            tx_id,
            tx_type,
            tx_member,
            complete,
            rlp_tx_member_length,
            rlp_bytes_in_row: bytes_in_row,
            r_mult,
            acc_rlc_value,
            valid,
            q_tx_members,
            q_enable,
            q_first,
            q_last,
            aux_tables,
            v_gt_55: cmp_55_lt_byte1,
            v_gt_0: cmp_0_lt_byte1,
            remain_length_gt_33: cmp_max_row_bytes_lt_remains,
            remain_length_ge_length: cmp_length_le_prev_remain,
            r_mult_comp,
            rlc_quotient,
            txlist_rlp_bytes_gadget: txlist_rlp_bytes,
            remain_len_stack_gadget,
        };
        circuit_config
    }
}

impl<F: Field> RlpDecoderCircuitConfig<F> {
    fn assign_rows(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wits: &[RlpDecoderCircuitConfigWitness<F>],
    ) -> Result<(), Error> {
        let mut offset = offset;
        self.name_row_members(region);

        let mut cached_region = CachedRegion::new(region);
        // TODO
        self.remain_len_stack_gadget
            .assign_rows(&mut cached_region, offset, wits)?;
        self.txlist_rlp_bytes_gadget
            .assign_rows(&mut cached_region, offset, wits)?;

        let mut prev_wit = wits.last().unwrap();
        for wit in wits {
            let gt_55_chip = LtChip::construct(self.v_gt_55);
            let gt_0_chip = LtChip::construct(self.v_gt_0);

            let gt_33_chip = LtChip::construct(self.remain_length_gt_33);
            let enough_remain_chip = LtChip::construct(self.remain_length_ge_length);

            let leading_val = if wit.bytes.len() > 1 { wit.bytes[1] } else { 0 };
            gt_55_chip.assign(region, offset, F::from(55u64), F::from(leading_val as u64))?;
            gt_0_chip.assign(region, offset, F::ZERO, F::from(leading_val as u64))?;

            let remain_bytes = prev_wit.nested_rlp_remains[0] as u64;
            let current_member_bytes = wit.rlp_tx_member_length;
            gt_33_chip.assign(
                region,
                offset,
                F::from(MAX_BYTE_COLUMN_NUM as u64),
                F::from(remain_bytes),
            )?;
            enough_remain_chip.assign(
                region,
                offset,
                F::from(current_member_bytes),
                F::from(remain_bytes) + F::ONE,
            )?;

            self.assign_row(region, offset, wit)?;
            prev_wit = wit;
            offset += 1;
        }
        Ok(())
    }

    fn name_row_members(&self, region: &mut Region<'_, F>) {
        region.name_column(|| "config.tx_id", self.tx_id);
        region.name_column(|| "config.tx_type", self.tx_type);
        region.name_column(|| "config.tag", self.tx_member);
        region.name_column(|| "config.complete", self.complete);
        region.name_column(|| "config.rlp_tag_length", self.rlp_tx_member_length);
        for (i, rlp_item_remain) in self
            .remain_len_stack_gadget
            .nested_rlp_remains
            .iter()
            .enumerate()
        {
            region.name_column(
                || format!("config.rlp_item_remain-[{}]", i),
                *rlp_item_remain,
            );
        }
        region.name_column(|| "config.r_mult", self.r_mult);
        region.name_column(|| "config.acc_rlc_value", self.acc_rlc_value);
        region.name_column(|| "config.valid", self.valid);
    }

    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        w: &RlpDecoderCircuitConfigWitness<F>,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "config.tx_id",
            self.tx_id,
            offset,
            || Value::known(F::from(w.tx_id)),
        )?;
        region.assign_advice(
            || "config.tx_type",
            self.tx_type,
            offset,
            || Value::known(F::from(w.tx_type as u64)),
        )?;
        region.assign_advice(
            || "config.tag",
            self.tx_member,
            offset,
            || Value::known(F::from(w.tx_member as u64)),
        )?;
        region.assign_advice(
            || "config.complete",
            self.complete,
            offset,
            || Value::known(F::from(w.complete as u64)),
        )?;
        region.assign_advice(
            || "config.rlp_tag_length",
            self.rlp_tx_member_length,
            offset,
            || Value::known(F::from(w.rlp_tx_member_length)),
        )?;
        region.assign_advice(
            || "config.tag_bytes_in_row",
            self.rlp_bytes_in_row,
            offset,
            || Value::known(F::from(w.rlp_bytes_in_row as u64)),
        )?;
        region.assign_advice(
            || "config.r_mult",
            self.r_mult,
            offset,
            || Value::known(w.r_mult),
        )?;
        region.assign_advice(
            || "config.acc_rlc_value",
            self.acc_rlc_value,
            offset,
            || Value::known(w.acc_rlc_value),
        )?;
        region.assign_advice(
            || "config.valid",
            self.valid,
            offset,
            || Value::known(F::from(w.valid as u64)),
        )?;
        self.q_tx_members
            .iter()
            .enumerate()
            .try_for_each(|(i, q_field)| {
                region
                    .assign_advice(
                        || format!("config.q_fields[{}]", i),
                        *q_field,
                        offset,
                        || {
                            if i == w.tx_member as usize {
                                Value::known(F::ONE)
                            } else {
                                Value::known(F::ZERO)
                            }
                        },
                    )
                    .map(|_| ())
            })?;
        region.assign_fixed(
            || "config.q_first",
            self.q_first,
            offset,
            || Value::known(F::from(w.q_first as u64)),
        )?;
        region.assign_fixed(
            || "config.q_last",
            self.q_last,
            offset,
            || Value::known(F::from(w.q_last as u64)),
        )?;
        region.assign_advice(
            || "config.r_mult_comp",
            self.r_mult_comp,
            offset,
            || Value::known(w.r_mult_comp),
        )?;
        region.assign_advice(
            || "config.rlc_quotient",
            self.rlc_quotient,
            offset,
            || Value::known(w.rlc_quotient),
        )?;
        if w.q_enable {
            self.q_enable.enable(region, offset)?;
        }

        Ok(())
    }
}

/// rlp decode Circuit for verifying transaction signatures
/// also using GOOD flag to indicate whether the circuit is for good or bad witness
#[derive(Clone, Default, Debug)]
pub struct RlpDecoderCircuit<F: Field> {
    /// input bytes
    pub bytes: Vec<u8>,
    /// Size of the circuit
    pub size: usize,
    /// check witness validness, None means no check.
    pub is_valid: Option<bool>,
    /// phantom
    pub _marker: PhantomData<F>,
}

impl<F: Field> RlpDecoderCircuit<F> {
    /// Return a new RlpDecoderCircuit
    pub fn new(bytes: Vec<u8>, degree: usize) -> Self {
        Self::dbg_new(bytes, degree, None)
    }

    /// Return a new RlpDecoderCircuit with witness validness check option
    pub fn dbg_new(bytes: Vec<u8>, degree: usize, witness_is_valid: Option<bool>) -> Self {
        RlpDecoderCircuit::<F> {
            bytes,
            size: 1 << degree,
            is_valid: witness_is_valid,
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows(block: &witness::Block<F>) -> (usize, usize) {
        let txs_len = block.txs.len();
        let call_data_rows = block.txs.iter().fold(0, |acc, tx| {
            acc + tx.call_data.len() / MAX_BYTE_COLUMN_NUM + 1
        });

        let min_num_rows = Self::calc_min_num_rows(txs_len, call_data_rows);
        (min_num_rows, min_num_rows)
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows_from_tx(txs: &Vec<Transaction>) -> (usize, usize) {
        let txs_len = txs.len();
        let call_data_rows = txs
            .iter()
            .fold(0, |acc, tx| acc + tx.input.len() / MAX_BYTE_COLUMN_NUM + 1);

        let min_num_rows = Self::calc_min_num_rows(txs_len, call_data_rows);
        (min_num_rows, min_num_rows)
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    /// Note: valid 1559 rlp encoded bytes only
    pub fn min_num_rows_from_valid_bytes(txlist_bytes: &Vec<u8>) -> (usize, usize) {
        let typed_tx_bytes_vec: Vec<Vec<u8>> = rlp::decode_list(txlist_bytes);
        let txs = typed_tx_bytes_vec
            .iter()
            .map(|typed_tx_bytes| {
                // skip the type byte
                assert_eq!(*typed_tx_bytes.first().unwrap(), 0x02);
                rlp::decode(typed_tx_bytes).unwrap()
            })
            .collect::<Vec<Transaction>>();

        Self::min_num_rows_from_tx(&txs)
    }

    fn calc_min_num_rows(txs_len: usize, call_data_rows: usize) -> usize {
        // add 2 for prev and next rotations.
        let constraint_size = txs_len * TX1559_TX_FIELD_NUM + call_data_rows + 2;
        let tables_size = RlpDecoderTable1A6FColumns::table_size();
        log::info!(
            "constraint_size: {}, tables_size: {}",
            constraint_size,
            tables_size
        );
        constraint_size + tables_size + NUM_BLINDING_ROWS
    }
}

impl<F: Field> SubCircuit<F> for RlpDecoderCircuit<F> {
    type Config = RlpDecoderCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let bytes = prepare_eip1559_txlist_rlp_bytes(&block.eth_block.transactions);
        let degree = log2_ceil(Self::min_num_rows(block).0) as usize;
        RlpDecoderCircuit::new(bytes, degree)
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        RlpDecoderCircuit::<F>::min_num_rows(block)
    }

    /// Make the assignments to the RlpDecodeCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut randomness = F::ONE;
        challenges.keccak_input().map(|r| randomness = r);
        log::trace!(
            "randomness: {:?}, rlc_bytes = {:?}",
            randomness,
            rlc::value(self.bytes.iter().rev(), randomness)
        );

        let witness: Vec<RlpDecoderCircuitConfigWitness<F>> =
            gen_rlp_decode_state_witness(&self.bytes, randomness, self.size);

        for (i, w) in witness.iter().enumerate() {
            log::trace!("witness[{}]: {:?}", i, w);
        }

        if self.is_valid.is_some() {
            assert_eq!(witness[witness.len() - 2].q_last, true);
            assert_eq!(witness[witness.len() - 2].valid, self.is_valid.unwrap());
        }

        config
            .aux_tables
            .rlp_decoder_table
            .load(layouter, challenges)?;

        config
            .aux_tables
            .keccak_table
            .dev_load(layouter, &[self.bytes.clone()], challenges)?;

        // load LtChip table, can it be merged into 1 column?
        LtChip::construct(config.v_gt_55).load(layouter)?;
        LtChip::construct(config.v_gt_0).load(layouter)?;
        LtChip::construct(config.remain_length_gt_33).load(layouter)?;
        LtChip::construct(config.remain_length_ge_length).load(layouter)?;

        layouter.assign_region(
            || "rlp witness region",
            |mut region| {
                let offset = 0;
                config.assign_rows(&mut region, offset, &witness)?;
                Ok(())
            },
        )
    }

    fn instance(&self) -> Vec<Vec<F>> {
        // empty instance now
        vec![vec![]]
    }

    fn unusable_rows() -> usize {
        todo!()
    }
}

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field> Circuit<F> for RlpDecoderCircuit<F> {
    type Config = (RlpDecoderCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let rlp_fixed_table = RlpDecoderTable1A6FColumns::construct(meta);

        let config = {
            // let challenges_expr = challenges.exprs(meta);
            let r = 11u64;
            let challenges_expr = Challenges::mock(r.expr(), r.expr(), r.expr());
            RlpDecoderCircuitConfig::new(
                meta,
                RlpDecoderCircuitConfigArgs {
                    rlp_decoder_table: rlp_fixed_table,
                    keccak_table,
                    challenges: challenges_expr,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, _challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // let challenges = challenges.values(&mut layouter);
        let r = F::from(11u64);
        let challenges = Challenges::mock(Value::known(r), Value::known(r), Value::known(r));

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }

    type Params = Option<F>;

    fn params(&self) -> Self::Params {
        Self::Params::default()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        Self::configure(meta)
    }
}

trait RlpTxFieldStateWittnessGenerator<F: Field> {
    fn next(
        &self,
        k: usize,
        tx_id: u64,
        bytes: &[u8],
        r: F,
        witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
    ) -> (Self, Option<usize>)
    where
        Self: Sized;

    fn rlp_decode_field_check(
        &self,
        bytes: &[u8],
        tx_id: u64,
        r: F,
        decode_rule: &RlpDecodeRule,
        witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
        next_state: RlpTxFieldTag,
    ) -> (Self, Option<usize>)
    where
        Self: Sized;
}

// using error to tell n
// consider the case which both error happens like 0xFA 0x00 0x01 EOF, both EOF error & len_of_len
// error happens
fn read_nbytes(bytes: &[u8], n: usize) -> Result<&[u8], &[u8]> {
    if n <= bytes.len() {
        Ok(&bytes[..n])
    } else {
        Err(bytes)
    }
}

fn rlp_bytes_len(bytes: &[u8]) -> usize {
    bytes.iter().fold(0, |acc, byte| acc * 256 + *byte as usize)
}

impl<F: Field> RlpTxFieldStateWittnessGenerator<F> for RlpTxFieldTag {
    fn next(
        &self,
        k: usize,
        tx_id: u64,
        bytes: &[u8],
        r: F,
        witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
    ) -> (Self, Option<usize>) {
        let decode_rules = RLP_TX_FIELD_DECODE_RULES
            .iter()
            .filter(|rule| rule.0 == RlpTxTypeTag::Tx1559Type && rule.1 == *self)
            .collect::<Vec<&(RlpTxTypeTag, RlpTxFieldTag, RlpDecodeRule)>>();
        assert!(decode_rules.len() >= 1);
        let (_, _, mut decode_rule) = decode_rules[0];

        macro_rules! state_switch {
            ($next_state: expr) => {
                self.rlp_decode_field_check(bytes, tx_id, r, &decode_rule, witness, $next_state)
            };
        }

        match self {
            RlpTxFieldTag::TxListRlpHeader => {
                // this is the begining row
                let res = state_switch!(RlpTxFieldTag::TypedTxHeader);

                // check the length of the whole list here as txlist header should have the same
                // length as the whole byte stream
                let mut wit = witness.last_mut().unwrap();
                if wit.valid {
                    let level_len = rlp_bytes_len(&wit.bytes[1..wit.rlp_bytes_in_row as usize]);
                    let valid = level_len == wit.nested_rlp_remains[0];
                    if valid {
                        res
                    } else {
                        // TODO: use a specific error type
                        wit.errors[usize::from(RlpDecodeErrorType::ValueError)] = true;
                        wit.valid = false;
                        (RlpTxFieldTag::DecodeError, res.1)
                    }
                } else {
                    res
                }
            }
            RlpTxFieldTag::TypedTxHeader => {
                let res = state_switch!(RlpTxFieldTag::TxType);
                let mut wit = witness.last_mut().unwrap();
                let level_len = rlp_bytes_len(&wit.bytes[1..wit.rlp_bytes_in_row as usize]);
                let nested_level = self.get_nested_level();
                wit.nested_rlp_remains[nested_level] = level_len;
                res
            }
            RlpTxFieldTag::TxType => state_switch!(RlpTxFieldTag::TxRlpHeader),
            RlpTxFieldTag::TxRlpHeader => {
                let res = state_switch!(RlpTxFieldTag::ChainID);
                let mut wit = witness.last_mut().unwrap();
                let level_len = rlp_bytes_len(&wit.bytes[1..wit.rlp_bytes_in_row as usize]);
                let nested_level = self.get_nested_level();
                wit.nested_rlp_remains[nested_level] = level_len;
                res
            }
            RlpTxFieldTag::ChainID => state_switch!(RlpTxFieldTag::Nonce),
            RlpTxFieldTag::Nonce => state_switch!(RlpTxFieldTag::GasTipCap),
            RlpTxFieldTag::GasTipCap => state_switch!(RlpTxFieldTag::GasFeeCap),
            RlpTxFieldTag::GasFeeCap => state_switch!(RlpTxFieldTag::Gas),
            RlpTxFieldTag::GasPrice => todo!(), // state_switch!(RlpTxFieldTag::Gas),
            RlpTxFieldTag::Gas => state_switch!(RlpTxFieldTag::To),
            RlpTxFieldTag::To => {
                assert!(decode_rules.len() == 2);
                if bytes.len() >= 1 && bytes[0] == 0x80 {
                    // empty to address
                    assert!(decode_rules[1].2 == RlpDecodeRule::Empty);
                    decode_rule = decode_rules[1].2;
                }
                state_switch!(RlpTxFieldTag::Value)
            }
            RlpTxFieldTag::Value => state_switch!(RlpTxFieldTag::Data),
            RlpTxFieldTag::Data => state_switch!(RlpTxFieldTag::AccessList),
            RlpTxFieldTag::AccessList => state_switch!(RlpTxFieldTag::SignV),
            RlpTxFieldTag::SignV => state_switch!(RlpTxFieldTag::SignR),
            RlpTxFieldTag::SignR => state_switch!(RlpTxFieldTag::SignS),
            RlpTxFieldTag::SignS => {
                // Tricky: we need to check if the bytes hold SignS only.
                let next_state = if bytes.len() <= 33 {
                    RlpTxFieldTag::Padding
                } else {
                    RlpTxFieldTag::TypedTxHeader
                };
                self.rlp_decode_field_check(bytes, tx_id, r, &decode_rule, witness, next_state)
            }
            RlpTxFieldTag::Padding => {
                let witness_len = witness.len();
                assert!(k > (witness_len + 1 + NUM_BLINDING_ROWS));
                fixup_acc_rlc_new(witness, r);
                complete_paddings_new(witness, r, k as usize - witness_len - 1 - NUM_BLINDING_ROWS);
                (RlpTxFieldTag::Padding, None)
            }
            RlpTxFieldTag::DecodeError => {
                let rest_bytes = bytes.len().min(MAX_BYTE_COLUMN_NUM);
                let rlp_remain_length = witness.last().unwrap().nested_rlp_remains[0];
                let mut nested_remain_lengths = [rlp_remain_length, 0, 0, 0, 0, 0];
                witness.append(&mut self.generate_rlp_row_witness_new(
                    tx_id,
                    &bytes[..rest_bytes],
                    r,
                    &mut nested_remain_lengths,
                    0,
                    None,
                ));

                if rest_bytes == bytes.len() {
                    (RlpTxFieldTag::Padding, Some(rest_bytes))
                } else {
                    (RlpTxFieldTag::DecodeError, Some(rest_bytes))
                }
            }
        }
    }

    fn rlp_decode_field_check(
        &self,
        bytes: &[u8],
        tx_id: u64,
        r: F,
        decode_rule: &RlpDecodeRule,
        witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
        next_state: RlpTxFieldTag,
    ) -> (RlpTxFieldTag, Option<usize>) {
        let mut nested_remain_lengths = witness.last().unwrap().nested_rlp_remains.clone();
        let current_nested_level = self.get_nested_level();
        macro_rules! append_new_witness {
            ($bytes: expr, $error: expr) => {
                witness.append(&mut self.generate_rlp_row_witness_new(
                    tx_id,
                    $bytes,
                    r,
                    &mut nested_remain_lengths,
                    current_nested_level,
                    $error,
                ))
            };
        }

        let res = read_nbytes(bytes, 1);
        match res {
            Ok(bytes_read_header) => {
                let head_byte0 = bytes_read_header[0];
                // if decode rule check failed
                let (_, decodable) = decode_rule.rule_check(head_byte0);
                if !decodable {
                    append_new_witness!(&bytes[..1], Some(RlpDecodeErrorType::HeaderDecError));
                    (RlpTxFieldTag::DecodeError, Some(1))
                } else {
                    match decode_rule {
                        RlpDecodeRule::Padding => unreachable!(),
                        RlpDecodeRule::Empty => match head_byte0 {
                            0x80 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            _ => unreachable!(),
                        },
                        RlpDecodeRule::TxType1559 => match head_byte0 {
                            0x02 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            _ => {
                                append_new_witness!(
                                    &bytes[..1],
                                    Some(RlpDecodeErrorType::HeaderDecError)
                                );
                                (RlpTxFieldTag::DecodeError, Some(1))
                            }
                        },
                        RlpDecodeRule::Uint64 => unreachable!(),
                        RlpDecodeRule::Uint96 => match head_byte0 {
                            1..=0x80 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            0x81..=0x8c => {
                                let mut offset = 1;
                                let len_of_val = (head_byte0 - 0x80) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_val);
                                match res {
                                    Ok(val_bytes_read) => {
                                        let val_byte0 = val_bytes_read[0];
                                        if len_of_val == 1 && val_byte0 < 0x80 {
                                            append_new_witness!(
                                                &bytes[..offset + 1],
                                                Some(RlpDecodeErrorType::LenOfLenError) /* maybe val error is better */
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset + 1))
                                        } else if len_of_val > 1 && val_byte0 == 0 {
                                            append_new_witness!(
                                                &bytes[..offset + 1],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset + 1))
                                        } else {
                                            offset += val_bytes_read.len();
                                            append_new_witness!(&bytes[..offset], None);
                                            (next_state, Some(offset))
                                        }
                                    }
                                    Err(val_bytes_read) => {
                                        let readed_len = val_bytes_read.len();
                                        append_new_witness!(
                                            &bytes[..offset + readed_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_val,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(offset + readed_len))
                                    }
                                }
                            }
                            _ => panic!("meet unsupported header byte {:?}", bytes),
                        },
                        RlpDecodeRule::Uint256 => match head_byte0 {
                            1..=0x80 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            0x81..=0xa0 => {
                                let mut offset = 1;
                                let len_of_val = (head_byte0 - 0x80) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_val);
                                match res {
                                    Ok(val_bytes_read) => {
                                        let val_byte0 = val_bytes_read[0];
                                        if len_of_val == 1 && val_byte0 <= 0x80 {
                                            append_new_witness!(
                                                &bytes[..offset + 1],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset + 1))
                                        } else if len_of_val > 1 && val_byte0 == 0 {
                                            append_new_witness!(
                                                &bytes[..offset + 1],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset + 1))
                                        } else {
                                            offset += val_bytes_read.len();
                                            append_new_witness!(&bytes[..offset], None);
                                            (next_state, Some(offset))
                                        }
                                    }
                                    Err(val_bytes_read) => {
                                        let read_len = val_bytes_read.len();
                                        append_new_witness!(
                                            &bytes[..offset + read_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_val,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(offset + read_len))
                                    }
                                }
                            }
                            _ => panic!("meet unsupported header byte {:?}", bytes),
                        },
                        RlpDecodeRule::Address => match head_byte0 {
                            0x94 => {
                                let mut offset = 1;
                                let len_of_val = 0x14 as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_val);
                                match res {
                                    Ok(val_bytes_read) => {
                                        offset += val_bytes_read.len();
                                        append_new_witness!(&bytes[..offset], None);
                                        (next_state, Some(offset))
                                    }
                                    Err(val_bytes_read) => {
                                        let read_len = val_bytes_read.len();
                                        append_new_witness!(
                                            &bytes[..offset + read_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_val,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(offset + read_len))
                                    }
                                }
                            }
                            _ => unreachable!(),
                        },
                        RlpDecodeRule::Bytes48K => match head_byte0 {
                            0..=0x80 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            0x81..=0xb7 => {
                                let mut offset = 1;
                                let len_of_val = (head_byte0 - 0x80) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_val);
                                match res {
                                    Ok(val_bytes_read) => {
                                        let val_byte0 = val_bytes_read[0];
                                        if len_of_val == 1 && val_byte0 < 0x80 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else {
                                            offset += len_of_val as usize;
                                            append_new_witness!(&bytes[..offset], None);
                                            (next_state, Some(offset))
                                        }
                                    }
                                    Err(val_bytes_read) => {
                                        let read_len = val_bytes_read.len();
                                        let bytes_len = offset + read_len;
                                        append_new_witness!(
                                            &bytes[..bytes_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_val,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(bytes_len))
                                    }
                                }
                            }
                            0xb8..=0xba => {
                                let mut offset = 1;
                                let len_of_len = (head_byte0 - 0xb7) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_len);
                                match res {
                                    Ok(len_bytes_read) => {
                                        let len_byte0 = len_bytes_read[0];
                                        if len_of_len == 1 && len_byte0 <= 55 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else if len_of_len > 1 && len_byte0 == 0 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else {
                                            offset += len_bytes_read.len();
                                            let val_bytes_len = rlp_bytes_len(len_bytes_read);
                                            let res = read_nbytes(&bytes[offset..], val_bytes_len);
                                            match res {
                                                Ok(val_bytes_read) => {
                                                    offset += val_bytes_read.len();
                                                    append_new_witness!(&bytes[..offset], None);
                                                    (next_state, Some(offset))
                                                }
                                                Err(val_bytes_read) => {
                                                    let read_len = val_bytes_read.len();
                                                    let bytes_len = offset + read_len;
                                                    append_new_witness!(
                                                        &bytes[..bytes_len],
                                                        Some(
                                                            RlpDecodeErrorType::RunOutOfDataError(
                                                                offset + val_bytes_len,
                                                            )
                                                        )
                                                    );
                                                    (RlpTxFieldTag::DecodeError, Some(bytes_len))
                                                }
                                            }
                                        }
                                    }
                                    Err(len_bytes_read) => {
                                        let read_len = len_bytes_read.len();
                                        let bytes_len = offset + read_len;
                                        append_new_witness!(
                                            &bytes[..bytes_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_len,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(bytes_len))
                                    }
                                }
                            }
                            _ => {
                                append_new_witness!(
                                    &bytes[..1],
                                    Some(RlpDecodeErrorType::HeaderDecError)
                                );
                                (RlpTxFieldTag::DecodeError, Some(1))
                            }
                        },
                        RlpDecodeRule::EmptyList => match head_byte0 {
                            0xc0 => {
                                append_new_witness!(&bytes[..1], None);
                                (next_state, Some(1))
                            }
                            _ => {
                                append_new_witness!(
                                    &bytes[..1],
                                    Some(RlpDecodeErrorType::ValueError)
                                );
                                (RlpTxFieldTag::DecodeError, Some(1))
                            }
                        },
                        RlpDecodeRule::LongBytes => match head_byte0 {
                            0xb8..=0xba => {
                                let mut offset = 1;
                                let len_of_len = (head_byte0 - 0xb7) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_len);
                                match res {
                                    Ok(len_bytes_read) => {
                                        let len_byte0 = len_bytes_read[0];
                                        if len_of_len == 1 && len_byte0 <= 55 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else if len_of_len > 1 && len_byte0 == 0 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else {
                                            offset += len_bytes_read.len();
                                            let val_bytes_len = rlp_bytes_len(len_bytes_read);
                                            let res = read_nbytes(&bytes[offset..], val_bytes_len);
                                            match res {
                                                Ok(_) => {
                                                    append_new_witness!(&bytes[..offset], None);
                                                    (next_state, Some(offset))
                                                }
                                                Err(val_bytes_read) => {
                                                    let read_len = val_bytes_read.len();
                                                    let bytes_len = offset + read_len;
                                                    append_new_witness!(
                                                        &bytes[..bytes_len],
                                                        Some(
                                                            RlpDecodeErrorType::RunOutOfDataError(
                                                                offset + val_bytes_len,
                                                            )
                                                        )
                                                    );
                                                    (RlpTxFieldTag::DecodeError, Some(bytes_len))
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        append_new_witness!(
                                            &bytes[..offset],
                                            Some(RlpDecodeErrorType::ValueError)
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(offset))
                                    }
                                }
                            }
                            _ => unreachable!(),
                        },
                        RlpDecodeRule::LongList => {
                            let header_byte0 = bytes_read_header[0];
                            // if decode rule check failed
                            let (_, decodable) = decode_rule.rule_check(header_byte0);
                            if !decodable {
                                append_new_witness!(
                                    &bytes[..1],
                                    Some(RlpDecodeErrorType::HeaderDecError)
                                );
                                (RlpTxFieldTag::DecodeError, Some(1))
                            } else {
                                let mut offset = 1;
                                let len_of_len = (header_byte0 - 0xF7) as usize;
                                let res = read_nbytes(&bytes[offset..], len_of_len);
                                match res {
                                    Ok(len_bytes_read) => {
                                        let len_byte0 = len_bytes_read[0];
                                        if len_of_len == 1 && len_byte0 <= 55 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else if len_of_len > 1 && len_byte0 == 0 {
                                            offset += 1;
                                            append_new_witness!(
                                                &bytes[..offset],
                                                Some(RlpDecodeErrorType::LenOfLenError)
                                            );
                                            (RlpTxFieldTag::DecodeError, Some(offset))
                                        } else {
                                            // TODO: consume rlp_bytes_len(consumed_bytes) and get
                                            // EOF error earlier?
                                            offset += len_bytes_read.len();
                                            let val_bytes_len = rlp_bytes_len(len_bytes_read);
                                            let res = read_nbytes(&bytes[offset..], val_bytes_len);
                                            match res {
                                                Ok(_) => {
                                                    append_new_witness!(&bytes[..offset], None);
                                                    (next_state, Some(offset))
                                                }
                                                Err(_) => {
                                                    append_new_witness!(
                                                        &bytes[..offset],
                                                        Some(RlpDecodeErrorType::ValueError)
                                                    );
                                                    (RlpTxFieldTag::DecodeError, Some(offset))
                                                }
                                            }
                                        }
                                    }
                                    Err(consumed_bytes) => {
                                        let read_len = consumed_bytes.len();
                                        let bytes_len = offset + read_len;
                                        append_new_witness!(
                                            &bytes[..bytes_len],
                                            Some(RlpDecodeErrorType::RunOutOfDataError(
                                                offset + len_of_len,
                                            ))
                                        );
                                        (RlpTxFieldTag::DecodeError, Some(bytes_len))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // error flag row
                append_new_witness!(&bytes, Some(RlpDecodeErrorType::RunOutOfDataError(1)));
                (RlpTxFieldTag::DecodeError, Some(0))
            }
        }
    }
}

// more private helper functions
impl RlpTxFieldTag {
    fn get_nested_level(&self) -> usize {
        match self {
            RlpTxFieldTag::TxListRlpHeader => 0,
            RlpTxFieldTag::TypedTxHeader => 1,
            RlpTxFieldTag::TxType => 1,
            RlpTxFieldTag::TxRlpHeader => 2,
            RlpTxFieldTag::ChainID => 2,
            RlpTxFieldTag::Nonce => 2,
            RlpTxFieldTag::GasTipCap => 2,
            RlpTxFieldTag::GasFeeCap => 2,
            RlpTxFieldTag::GasPrice => 2,
            RlpTxFieldTag::Gas => 2,
            RlpTxFieldTag::To => 2,
            RlpTxFieldTag::Value => 2,
            RlpTxFieldTag::Data => 2,
            RlpTxFieldTag::AccessList => 3,
            // TODO: AccessList.Address => 4
            // TODO: AccessList.Storage => 5
            RlpTxFieldTag::SignV => 2,
            RlpTxFieldTag::SignR => 2,
            RlpTxFieldTag::SignS => 2,
            RlpTxFieldTag::Padding => 0,
            RlpTxFieldTag::DecodeError => 0,
        }
    }

    fn generate_rlp_row_witness_new<F: Field>(
        &self,
        tx_id: u64,
        raw_bytes: &[u8],
        r: F,
        nested_remain_lengths: &mut [usize; MAX_NESTED_LEVEL_NUM],
        current_nested_level: usize,
        error_type: Option<RlpDecodeErrorType>,
    ) -> Vec<RlpDecoderCircuitConfigWitness<F>> {
        // print!(
        //     "generate witness for (tx_id: {}, tx_member: {:?}, raw_bytes: {:?}, r: {:?},
        // rlp_remain_length: {:?}, error_id: {:?})",
        //     tx_id, tx_member, raw_bytes, r, rlp_remain_length, error_type
        // );
        let mut witness = vec![];
        let (mut rlp_type, _, _, _) = self.generate_rlp_type_witness(raw_bytes);
        let partial_rlp_type = RlpDecodeTypeTag::PartialRlp;
        let mut rlp_tx_member_len = raw_bytes.len();
        let mut tx_member_remain = raw_bytes.len();

        let mut errors = [false; 4];
        if let Some(error_idx) = error_type {
            match error_idx {
                RlpDecodeErrorType::HeaderDecError
                | RlpDecodeErrorType::LenOfLenError
                | RlpDecodeErrorType::ValueError => {
                    // these error cases never cross raw
                    assert!(error_type.is_none() || (raw_bytes.len() <= MAX_BYTE_COLUMN_NUM));
                    errors[usize::from(error_idx)] = true;
                }
                RlpDecodeErrorType::RunOutOfDataError(decode_len) => {
                    errors[usize::from(error_idx)] = true;
                    assert!(rlp_tx_member_len < decode_len);
                    rlp_tx_member_len = decode_len;
                }
            }
        }

        macro_rules! update_nested_rlp_lengths {
            ($current_rlp_length:expr) => {{
                for i in 0..MAX_NESTED_LEVEL_NUM {
                    if i <= current_nested_level && nested_remain_lengths[i] > 0 {
                        assert!(nested_remain_lengths[i] >= $current_rlp_length);
                        nested_remain_lengths[i] -= $current_rlp_length;
                    } else if i > current_nested_level {
                        assert_eq!(nested_remain_lengths[i], 0);
                    }
                }
                nested_remain_lengths.clone()
            }};
        }

        macro_rules! generate_witness {
            () => {{
                let mut temp_witness_vec = Vec::new();
                let mut tag_remain_length = rlp_tx_member_len;
                let mut raw_bytes_offset = 0;
                while tx_member_remain > MAX_BYTE_COLUMN_NUM {
                    temp_witness_vec.push(RlpDecoderCircuitConfigWitness::<F> {
                        tx_id: tx_id,
                        tx_type: RlpTxTypeTag::Tx1559Type,
                        tx_member: self.clone(),
                        complete: false,
                        rlp_type: rlp_type,
                        rlp_tx_member_length: tag_remain_length as u64,
                        nested_rlp_remains: update_nested_rlp_lengths!(MAX_BYTE_COLUMN_NUM),
                        rlp_bytes_in_row: MAX_BYTE_COLUMN_NUM as u8,
                        r_mult: r.pow(&[MAX_BYTE_COLUMN_NUM as u64, 0, 0, 0]),
                        value: F::ZERO,
                        acc_rlc_value: F::ZERO,
                        bytes: raw_bytes[raw_bytes_offset..raw_bytes_offset + MAX_BYTE_COLUMN_NUM]
                            .to_vec(),
                        errors: [false; 4],
                        valid: true,
                        q_enable: true,
                        q_first: false,
                        q_last: false,
                        r_mult_comp: F::ONE,
                        rlc_quotient: F::ZERO,
                    });
                    raw_bytes_offset += MAX_BYTE_COLUMN_NUM;
                    tag_remain_length -= MAX_BYTE_COLUMN_NUM;
                    tx_member_remain -= MAX_BYTE_COLUMN_NUM;
                    rlp_type = partial_rlp_type;
                }
                temp_witness_vec.push(RlpDecoderCircuitConfigWitness::<F> {
                    tx_id: tx_id,
                    tx_type: RlpTxTypeTag::Tx1559Type,
                    tx_member: self.clone(),
                    complete: true,
                    rlp_type: rlp_type,
                    rlp_tx_member_length: tx_member_remain as u64,
                    nested_rlp_remains: update_nested_rlp_lengths!(tx_member_remain),
                    rlp_bytes_in_row: tx_member_remain as u8,
                    r_mult: r.pow(&[tx_member_remain as u64, 0, 0, 0]),
                    value: F::ZERO,
                    acc_rlc_value: F::ZERO,
                    bytes: raw_bytes[raw_bytes_offset..].to_vec(),
                    errors: errors,
                    valid: (self != &RlpTxFieldTag::DecodeError) && errors.iter().all(|&err| !err),
                    q_enable: true,
                    q_first: self == &RlpTxFieldTag::TxListRlpHeader,
                    q_last: false,
                    r_mult_comp: r.pow(&[(MAX_BYTE_COLUMN_NUM - tx_member_remain) as u64, 0, 0, 0]),
                    rlc_quotient: F::ZERO,
                });
                temp_witness_vec
            }};
        }

        // TODO: reorganize the match
        match self {
            RlpTxFieldTag::TxListRlpHeader => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::TxRlpHeader => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::Nonce => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::GasPrice => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::Gas => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::To => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::Value => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::Data => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::SignV => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::SignR => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::SignS => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::DecodeError => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::TypedTxHeader => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::TxType => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::ChainID => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::GasTipCap => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::GasFeeCap => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::AccessList => witness.append(&mut generate_witness!()),
            RlpTxFieldTag::Padding => {
                unreachable!("Padding should not be here")
            }
        }
        witness
    }

    fn generate_rlp_type_witness(&self, bytes: &[u8]) -> (RlpDecodeTypeTag, bool, bool, bool) {
        let mut header_decodable = true;
        let mut len_decodable = true;
        let mut value_decodable = true;
        let header_byte = bytes.first().unwrap_or(&0).to_owned();
        let rlp_type = match header_byte {
            0x00 => {
                header_decodable = false;
                RlpDecodeTypeTag::SingleByte
            }
            0x01..=0x7f => RlpDecodeTypeTag::SingleByte,
            0x80 => RlpDecodeTypeTag::NullValue,
            0x81..=0xb7 => {
                if header_byte == 0x81 {
                    value_decodable = bytes.len() > 1 && bytes[1] >= 0x80;
                } else {
                    value_decodable = bytes.len() > 1 && bytes[1] > 0;
                }
                match self {
                    RlpTxFieldTag::To => {
                        value_decodable = true;
                        RlpDecodeTypeTag::ShortStringBytes
                    }
                    RlpTxFieldTag::Data => {
                        value_decodable = true;
                        RlpDecodeTypeTag::ShortStringBytes
                    }
                    _ => RlpDecodeTypeTag::ShortStringValue,
                }
            }
            0xb8 => {
                len_decodable = bytes.len() > 1 && bytes[1] >= 0x80;
                RlpDecodeTypeTag::LongString1
            }
            0xb9 => {
                len_decodable = bytes.len() > 1 && bytes[1] > 0;
                RlpDecodeTypeTag::LongString2
            }
            0xba => {
                len_decodable = bytes.len() > 1 && bytes[1] > 0;
                RlpDecodeTypeTag::LongString3
            }
            0xc0 => RlpDecodeTypeTag::EmptyList,
            0xc1..=0xf7 => RlpDecodeTypeTag::ShortList,
            0xf8 => RlpDecodeTypeTag::LongList1,
            0xf9 => RlpDecodeTypeTag::LongList2,
            0xfa => RlpDecodeTypeTag::LongList3,
            _ => {
                header_decodable = false;
                RlpDecodeTypeTag::DoNothing
            }
        };
        (rlp_type, header_decodable, len_decodable, value_decodable)
    }
}

fn gen_rlp_decode_state_witness<F: Field>(
    bytes: &[u8],
    r: F,
    k: usize,
) -> Vec<RlpDecoderCircuitConfigWitness<F>> {
    // update the rlp bytes hash
    let mut hasher = Keccak::default();
    hasher.update(bytes);
    let hash = hasher.digest();

    let mut witness = vec![RlpDecoderCircuitConfigWitness::<F> {
        nested_rlp_remains: [bytes.len(), 0, 0, 0, 0, 0],
        value: rlc::value(hash.iter().rev(), r),
        ..Default::default()
    }];

    let mut tx_id: u64 = 0;
    let mut offset = 0;
    let mut init_state = RlpTxFieldTag::TxListRlpHeader;

    loop {
        let (next_state, next_offset) =
            init_state.next(k, tx_id, &bytes[offset..], r, &mut witness);
        if next_state == RlpTxFieldTag::TypedTxHeader {
            tx_id += 1;
        }
        match next_offset {
            Some(n) => {
                offset += n;
                init_state = next_state;
            }
            None => {
                break;
            }
        }
    }
    witness
}

fn fixup_acc_rlc_new<F: Field>(
    witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
    randomness: F,
) {
    let mut prev_acc_rlc = F::ZERO;
    // skip the first line
    for i in 1..witness.len() {
        let cur_wit = &mut witness[i];
        let mut bytes = cur_wit.bytes.clone();
        bytes.resize(MAX_BYTE_COLUMN_NUM, 0);
        bytes.reverse();
        cur_wit.rlc_quotient =
            rlc::value(&bytes, randomness) * cur_wit.r_mult_comp.invert().unwrap();
        cur_wit.acc_rlc_value = prev_acc_rlc * cur_wit.r_mult + cur_wit.rlc_quotient;
        prev_acc_rlc = cur_wit.acc_rlc_value;
    }
}

fn complete_paddings_new<F: Field>(
    witness: &mut Vec<RlpDecoderCircuitConfigWitness<F>>,
    randomness: F,
    num_padding_to_last_row: usize,
) {
    let before_padding = witness.last().unwrap().clone();
    let r_mult_comp_padding = randomness.pow(&[(MAX_BYTE_COLUMN_NUM) as u64, 0, 0, 0]);
    for i in 0..num_padding_to_last_row {
        witness.push(RlpDecoderCircuitConfigWitness::<F> {
            tx_id: 0,
            tx_type: RlpTxTypeTag::Tx1559Type,
            tx_member: RlpTxFieldTag::Padding,
            complete: true,
            rlp_type: RlpDecodeTypeTag::DoNothing,
            rlp_tx_member_length: 0,
            nested_rlp_remains: [0; MAX_NESTED_LEVEL_NUM],
            rlp_bytes_in_row: 0,
            r_mult: F::ONE,
            value: F::ZERO,
            acc_rlc_value: before_padding.acc_rlc_value,
            bytes: [0; MAX_BYTE_COLUMN_NUM].to_vec(),
            errors: before_padding.errors,
            valid: before_padding.valid,
            q_enable: true,
            q_first: false,
            q_last: i == num_padding_to_last_row - 1,
            r_mult_comp: r_mult_comp_padding,
            rlc_quotient: F::ZERO,
        });
    }
    witness.push(RlpDecoderCircuitConfigWitness::<F>::default());
}

/// Signed transaction in a witness block
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Transaction data.
    pub tx: Transaction,
    /// ECDSA signature on the transaction.
    pub signature: ethers_core::types::Signature,
}

use rlp::{Encodable, RlpStream};

use self::{
    rlp_constraint_builder::RLPCellType,
    rlp_decode_circuit_test_helper::prepare_eip1559_txlist_rlp_bytes,
};

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&Word::from(self.tx.nonce));
        s.append(&self.tx.gas_price.unwrap());
        s.append(&Word::from(self.tx.gas));
        if let Some(addr) = self.tx.to {
            s.append(&addr);
        } else {
            s.append(&"");
        }
        s.append(&self.tx.value);
        s.append(&self.tx.input.to_vec());
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl From<&Transaction> for SignedTransaction {
    fn from(tx: &Transaction) -> Self {
        Self {
            tx: tx.clone(),
            signature: ethers_core::types::Signature {
                v: tx.v.as_u64(),
                r: tx.r,
                s: tx.s,
            },
        }
    }
}

impl From<MockTransaction> for SignedTransaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let tx = Transaction {
            hash: mock_tx.hash.unwrap(),
            nonce: mock_tx.nonce.into(),
            gas_price: Some(mock_tx.gas_price),
            gas: mock_tx.gas,
            to: mock_tx.to.map(|to| to.address()),
            value: mock_tx.value,
            input: mock_tx.input,
            v: mock_tx.v.unwrap(),
            r: mock_tx.r.unwrap(),
            s: mock_tx.s.unwrap(),
            ..Default::default()
        };
        SignedTransaction::from(&tx)
    }
}

/// Signed dynamic fee transaction in a witness block
#[derive(Debug, Clone)]
pub struct SignedDynamicFeeTransaction {
    /// Transaction data.
    pub tx: Transaction,
    /// ECDSA signature on the transaction.
    pub signature: ethers_core::types::Signature,
}

impl Encodable for SignedDynamicFeeTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&2u8);
        s.begin_list(12);
        s.append(&self.tx.chain_id.unwrap());
        s.append(&Word::from(self.tx.nonce));
        s.append(&self.tx.max_priority_fee_per_gas.unwrap());
        s.append(&self.tx.max_fee_per_gas.unwrap());
        s.append(&Word::from(self.tx.gas));
        if let Some(addr) = self.tx.to {
            s.append(&addr);
        } else {
            s.append(&"");
        }
        s.append(&self.tx.value);
        s.append(&self.tx.input.to_vec());
        s.append(&self.tx.access_list.clone().unwrap()); // todo access list
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl From<&Transaction> for SignedDynamicFeeTransaction {
    fn from(tx: &Transaction) -> Self {
        Self {
            tx: tx.clone(),
            signature: ethers_core::types::Signature {
                v: tx.v.as_u64(),
                r: tx.r,
                s: tx.s,
            },
        }
    }
}

impl From<MockTransaction> for SignedDynamicFeeTransaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let tx = Transaction {
            hash: mock_tx.hash.unwrap(),
            nonce: mock_tx.nonce.into(),
            chain_id: Some(mock_tx.chain_id),
            max_fee_per_gas: Some(mock_tx.max_fee_per_gas),
            max_priority_fee_per_gas: Some(mock_tx.max_priority_fee_per_gas),
            gas: mock_tx.gas,
            to: mock_tx.to.map(|to| to.address()),
            value: mock_tx.value,
            input: mock_tx.input,
            access_list: Some(AccessList(vec![])), // TODO: add access list
            v: mock_tx.v.unwrap(),
            r: mock_tx.r.unwrap(),
            s: mock_tx.s.unwrap(),
            ..Default::default()
        };
        SignedDynamicFeeTransaction::from(&tx)
    }
}

/// test module for rlp decoder circuit
pub mod rlp_decode_circuit_test_helper {
    use super::*;
    use crate::util::log2_ceil;
    use ethers_core::utils::hex;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };

    /// test rlp decoder circuit
    pub fn run_rlp_circuit<F: Field>(
        rlp_bytes: Vec<u8>,
        k: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = RlpDecoderCircuit::<F>::new(rlp_bytes, k);
        let prover = match MockProver::run(k as u32, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    /// test valid rlp bytes
    pub fn run_rlp_circuit_for_valid_bytes(rlp_bytes: &Vec<u8>) -> Result<(), Vec<VerifyFailure>> {
        let k = log2_ceil(RlpDecoderCircuit::<Fr>::min_num_rows_from_valid_bytes(&rlp_bytes).0);
        log::info!("degree {} ... ", k);
        let circuit = RlpDecoderCircuit::<Fr>::dbg_new(rlp_bytes.clone(), k as usize, Some(true));
        let prover = match MockProver::run(k as u32, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    /// run rlp decode circuit for a list of transactions
    pub fn run<F: Field>(txs: Vec<Transaction>) -> Result<(), Vec<VerifyFailure>> {
        let k = log2_ceil(RlpDecoderCircuit::<Fr>::min_num_rows_from_tx(&txs).0);

        let rlp_bytes = prepare_eip1559_txlist_rlp_bytes(&txs);
        log::trace!("rlp_bytes = {:?}", hex::encode(&rlp_bytes));

        let circuit = RlpDecoderCircuit::<F>::new(rlp_bytes, k as usize);
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    // fn prepare_legacy_txlist_rlp_bytes(txs: Vec<Transaction>) -> Vec<u8> {
    //     let encodable_txs: Vec<SignedTransaction> =
    //         txs.iter().map(|tx| tx.into()).collect::<Vec<_>>();
    //     let rlp_bytes = rlp::encode_list(&encodable_txs);
    //     log::trace!("rlp_bytes = {:?}", hex::encode(&rlp_bytes));
    //     rlp_bytes.to_vec()
    // }

    /// prepare rlp bytes for a list of eip1559 transactions
    pub fn prepare_eip1559_txlist_rlp_bytes(txs: &Vec<Transaction>) -> Vec<u8> {
        // note: rlp(txs) = rlp([rlp(rlp(tx1) as bytes), rlp(rlp(tx2) as bytes)]
        let encodable_txs: Vec<SignedDynamicFeeTransaction> =
            txs.iter().map(|tx| tx.into()).collect::<Vec<_>>();

        let tx_byte_array: Vec<Vec<u8>> = encodable_txs
            .iter()
            .map(|tx| {
                let rlp_tx = rlp::encode(tx);
                let rlp_tx_bytes = rlp_tx.to_vec();
                rlp_tx_bytes
            })
            .collect::<Vec<Vec<u8>>>();
        let rlp_txs = rlp::encode_list::<Vec<u8>, Vec<u8>>(&tx_byte_array);
        println!("rlp_txs = {:?}", hex::encode(rlp_txs.clone()));

        rlp_txs.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{rlp_decode_circuit_test_helper::run, *};
    use halo2_proofs::halo2curves::bn256::Fr;
    use mock::AddrOrWallet;
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    #[ignore]
    fn tx_circuit_0tx() {
        // 0xc0 is for invalid case.
        assert_eq!(run::<Fr>(vec![]), Ok(()));
    }

    #[test]
    fn tx_circuit_1tx() {
        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));
    }

    #[test]
    fn tx_circuit_2tx() {
        let tx1: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();
        let tx2: Transaction = mock::CORRECT_MOCK_TXS[1].clone().into();
        assert_eq!(run::<Fr>(vec![tx1, tx2]), Ok(()));
    }

    #[test]
    fn tx_circuit_1tx_non_to() {
        let mut rng = ChaCha20Rng::seed_from_u64(2u64);
        let tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));
    }

    #[test]
    fn tx_circuit_tx_with_various_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(2u64);
        let mut tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .input(eth_types::Bytes::from(b"0"))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));

        tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .input(eth_types::Bytes::from(b"1"))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));

        tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .input(eth_types::Bytes::from(
                (0..55).map(|v| v % 255).collect::<Vec<u8>>(),
            ))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));

        tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .input(eth_types::Bytes::from(
                (0..65536).map(|v| v as u8).collect::<Vec<u8>>(),
            ))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx]), Ok(()));

        tx = mock::MockTransaction::default()
            .from(AddrOrWallet::random(&mut rng))
            .input(eth_types::Bytes::from(
                (0..65536 * 2).map(|v| v as u8).collect::<Vec<u8>>(),
            ))
            .build()
            .into();
        assert_eq!(run::<Fr>(vec![tx.clone(), tx.clone()]), Ok(()));
    }

    /// invalid rlp_test
    mod invalid_rlp_test {
        use super::*;
        use halo2_proofs::dev::{MockProver, VerifyFailure};
        use pretty_assertions::assert_eq;

        /// predefined tx bytes:</br>
        /// "f8 50"         : witness[1]: list header </br>
        /// "f8 4e"         : witness[2]: tx header </br>
        /// "80"            : witness[3]: nonce </br>
        /// "01"            : witness[4]: gas_price </br>
        /// "83 0f4240"     : witness[5]: gas </br>
        /// "80"            : witness[6]: to </br>
        /// "80"            : witness[7]: value </br>
        /// "82 3031"       : witness[8]: input </br>
        /// "82 0a98"       : witness[9]: v </br>
        /// "a0 b058..adca" : witness[10]: r </br>
        /// "a0 53fb..0541" : witness[11]: s </br>
        fn const_tx_hex() -> String {
            String::from("f852")
                + "f850"
                + "80"
                + "01"
                + "830f4240"
                + "80"
                + "80"
                + "823031"
                + "820a98"
                + "a0b05805737618f6ac1ef211c02575f2fa82026fa1742caf192e2cffcd4161adca"
                + "a053fbe3d9957dffafca84c419fdd1cead150834c5de9f3215c66327123c0a0541"
        }

        fn generate_rlp_bytes(txs: Vec<Transaction>) -> Vec<u8> {
            let encodable_txs: Vec<SignedTransaction> =
                txs.iter().map(|tx| tx.into()).collect::<Vec<_>>();
            let rlp_bytes = rlp::encode_list(&encodable_txs);
            // println!("input rlp_bytes = {:?}", hex::encode(&rlp_bytes));
            rlp_bytes.to_vec()
        }

        pub fn run_bad_rlp_circuit<F: Field>(
            rlp_bytes: Vec<u8>,
            k: usize,
        ) -> Result<(), Vec<VerifyFailure>> {
            let circuit = RlpDecoderCircuit::<F>::dbg_new(rlp_bytes, k, Some(false));
            let prover = match MockProver::run(k as u32, &circuit, vec![]) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify()
        }

        #[test]
        fn const_tx_decode_is_ok() {
            let k = 12;
            let rlp_bytes = hex::decode(const_tx_hex()).unwrap();
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            // println!("witness = {:?}", &witness);
            assert_eq!(witness[witness.len() - 2].valid, true);
            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_list_header_header() {
            let mut rlp_bytes = hex::decode(const_tx_hex()).unwrap();
            rlp_bytes[0] = 0xc0;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_list_header_0_len() {
            let mut rlp_bytes = hex::decode(const_tx_hex()).unwrap();
            rlp_bytes[1] = 0x00;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        // rlp.exceptions.DecodingError: RLP string ends with 1 superfluous bytes
        #[test]
        fn invalid_rlp_wrong_list_header_short_len() {
            let mut rlp_bytes = hex::decode(const_tx_hex()).unwrap();
            rlp_bytes[1] = 0x49;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_header_header() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[2] = 0xf5;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, true);
            assert_eq!(witness[2].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_header_0_len() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[3] = 0x00;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_header_small_len() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[3] = 0x3c;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_header_big_len() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[3] = 0xff;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_field_nonce() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[4] = 0x00;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[2].valid, true);
            assert_eq!(witness[3].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_field_gas() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[5] = 0x00;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[3].valid, true);
            assert_eq!(witness[4].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_field_to() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[10] = 0x00;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[5].valid, true);
            assert_eq!(witness[6].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_wrong_tx_field_data() {
            let mut rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            rlp_bytes[12] = 0x81;
            rlp_bytes[13] = 0x02;

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[7].valid, true);
            assert_eq!(witness[8].valid, false);
            assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
        }

        #[test]
        fn invalid_rlp_not_enough_length() {
            let rlp_bytes = hex::decode(&const_tx_hex()).unwrap();
            let trimmed_rlp_bytes = &rlp_bytes[..1];

            let k = 12;
            let witness = gen_rlp_decode_state_witness(trimmed_rlp_bytes, Fr::one(), 1 << k);
            // assert_eq!(witness[1].valid, false);
            // assert_eq!(witness[witness.len() - 2].valid, false);

            assert_eq!(
                run_bad_rlp_circuit::<Fr>(trimmed_rlp_bytes.to_vec(), k),
                Ok(())
            );
        }

        #[test]
        fn invalid_rlp_eof_in_data() {
            let mut rng = ChaCha20Rng::seed_from_u64(2u64);
            let txs: Vec<Transaction> = vec![mock::MockTransaction::default()
                .from(AddrOrWallet::random(&mut rng))
                .input(eth_types::Bytes::from(
                    (0..65536).map(|v| v as u8).collect::<Vec<u8>>(),
                ))
                .build()
                .into()];
            let rlp_bytes = generate_rlp_bytes(txs.clone());
            assert_eq!(rlp_bytes.len(), 16 + 4 + 65536 + 3 + 33 + 33);

            let trimmed_size = rlp_bytes.len() - 33 - 33 - 3 - 1500;
            let trimmed_rlp_bytes = &rlp_bytes[..trimmed_size];

            let size = RlpDecoderCircuit::<Fr>::min_num_rows_from_tx(&txs.clone()).0;
            let witness = gen_rlp_decode_state_witness(trimmed_rlp_bytes, Fr::one(), size);
            assert_eq!(witness[1].valid, false);

            let k = log2_ceil(size) as usize;
            assert_eq!(
                run_bad_rlp_circuit::<Fr>(trimmed_rlp_bytes.to_vec(), k),
                Ok(())
            );
        }

        #[test]
        fn fuzz_regression_1() {
            let rlp_bytes = vec![0xba];

            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes.to_vec(), k), Ok(()));
        }

        #[test]
        fn fuzz_regression_2() {
            let rlp_bytes = vec![0, 178];
            let k = 12;
            let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
            assert_eq!(witness[1].valid, false);

            assert_eq!(run_bad_rlp_circuit::<Fr>(rlp_bytes.to_vec(), k), Ok(()));
        }
    }
}

#[cfg(test)]
mod test_1559_rlp_circuit {
    use std::{fs, path::PathBuf};

    use super::{rlp_decode_circuit_test_helper::prepare_eip1559_txlist_rlp_bytes, *};
    use crate::util::log2_ceil;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;

    pub fn dbg_run_rlp_circuit<F: Field>(
        rlp_bytes: Vec<u8>,
        k: usize,
        is_valid: Option<bool>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = RlpDecoderCircuit::<F>::dbg_new(rlp_bytes, k, is_valid);
        let prover = match MockProver::run(k as u32, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    /// test rlp decoder circuit
    fn run_good_rlp_circuit<F: Field>(
        rlp_bytes: Vec<u8>,
        k: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        dbg_run_rlp_circuit::<F>(rlp_bytes, k, Some(true))
    }

    fn run_bad_rlp_circuit<F: Field>(
        rlp_bytes: Vec<u8>,
        k: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        dbg_run_rlp_circuit::<F>(rlp_bytes, k, Some(false))
    }

    /// predefined tx bytes:</br>
    /// f865b86302f86001800201649400000000000000000000000000000000000000006480c080a091e9a510919059098df3 </br>
    /// c43b00657fbc596d075773b19b173a747e274503fdc5a0561e1db778068ade22d5fbeafe88a6beb9257b3ddaecf1c0f1 </br>
    /// 63e04c9cca6aa0 </br>
    /// fields: </br>
    /// "f8 65"   : tx list rlp header </br>
    /// "b8 63"   : witness[1]: typed tx header </br>
    /// "02"      : witness[2]: tx type </br>
    /// "f8 60"   : witness[.]: tx rlp header </br>
    /// "01"      : witness[.]: chain id </br>
    /// "80"      : witness[.]: nonce </br>
    /// "02"      : witness[.]: tip cap </br>
    /// "01"      : witness[.]: fee cap </br>
    /// "64"      : witness[.]: gas </br>
    /// "94 ...." : witness[.]: to </br>
    /// "64"      : witness[.]: value </br>
    /// "80"      : witness[.]: input </br>
    /// "c0"      : witness[.]: access list </br>
    /// "80"      : witness[.]: v </br>
    /// "a0 ...." : witness[.]: r </br>
    /// "a0 ...." : witness[.]: s </br>
    fn const_1559_hex() -> String {
        String::from("f865")
            + "b863"
            + "02"
            + "f860"
            + "01"
            + "80"
            + "02"
            + "01"
            + "64"
            + "940000000000000000000000000000000000000000"
            + "64"
            + "80"
            + "c0"
            + "80"
            + "a01c758784e91d3e616d6d4b70a6dac27a00512a76c96dc258a9ad48cdada0267d"
            + "a01343bbb9dc377773f13519dbdb71051ee90d52080c2bc77f5f808118dff5341a"
    }

    #[test]
    fn gen_1559_witness() {
        let rlp_bytes = hex::decode(const_1559_hex()).unwrap();

        let k = 12;
        let witness = gen_rlp_decode_state_witness(&rlp_bytes, Fr::one(), 1 << k);
        // for wit in &witness[..=16] {
        //     println!("{:?}", wit);
        // }

        assert_eq!(witness[1].tx_member, RlpTxFieldTag::TxListRlpHeader);
        assert_eq!(witness[2].tx_member, RlpTxFieldTag::TypedTxHeader);
        assert_eq!(witness[3].tx_member, RlpTxFieldTag::TxType);
        assert_eq!(witness[4].tx_member, RlpTxFieldTag::TxRlpHeader);
        assert_eq!(witness[5].tx_member, RlpTxFieldTag::ChainID);
        assert_eq!(witness[6].tx_member, RlpTxFieldTag::Nonce);
        assert_eq!(witness[7].tx_member, RlpTxFieldTag::GasTipCap);
        assert_eq!(witness[8].tx_member, RlpTxFieldTag::GasFeeCap);
        assert_eq!(witness[9].tx_member, RlpTxFieldTag::Gas);
        assert_eq!(witness[10].tx_member, RlpTxFieldTag::To);
        assert_eq!(witness[13].tx_member, RlpTxFieldTag::Value);
        assert_eq!(witness[14].tx_member, RlpTxFieldTag::Data);
        assert_eq!(witness[15].tx_member, RlpTxFieldTag::AccessList);
        assert_eq!(witness[16].tx_member, RlpTxFieldTag::SignV);
        assert_eq!(witness[17].tx_member, RlpTxFieldTag::SignR);
        assert_eq!(witness[22].tx_member, RlpTxFieldTag::SignS);
    }

    #[test]
    fn test_min_rows() {
        let rlp_bytes = hex::decode(const_1559_hex()).unwrap();
        let k = log2_ceil(RlpDecoderCircuit::<Fr>::min_num_rows_from_valid_bytes(&rlp_bytes).0);
        assert_eq!(k, 13);
    }

    #[test]
    fn test_const_tx() {
        let rlp_bytes = hex::decode(const_1559_hex()).unwrap();

        let k = 13;
        assert_eq!(run_good_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
    }

    #[test]
    fn test_mock_txlist() {
        let rlp_bytes = prepare_eip1559_txlist_rlp_bytes(&vec![
            mock::CORRECT_MOCK_TXS[0].clone().into(),
            mock::CORRECT_MOCK_TXS[1].clone().into(),
            mock::CORRECT_MOCK_TXS[2].clone().into(),
        ]);

        let k = 13;
        assert_eq!(run_good_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
    }

    #[test]
    fn test_devnet_txlist() {
        let rlp_bytes = hex::decode("f925feb9037802f9037483028c5d0f84b2d05e0084b2d05e00830a8be494cda789373261b53558e4369a8bd949e7b9da699880b9030411b804ab000000000000\
00000000000052b9f47c7668fbea2231c7ebdd44bda9bd4aee180000000000000000000000000000000000000000000000000000000000000060383635313439\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000264e15916340000\
0000000000000000000018e34fc44a321180e55766b0234897ed3c573e3400000000000000000000000000000000000000000000000000000000000001400000\
00000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c00000\
00000000000000000000000000000000000000000000000000000000022000000000000000000000000018e34fc44a321180e55766b0234897ed3c573e340000\
0000000000000000000018e34fc44a321180e55766b0234897ed3c573e3400000000000000000000000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000018e34fc44a321180e55766b0234897ed3c573e340000\
00000000000000000000000000000000000000000000000000000000000a416c696461647579656e000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000348424700000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000037697066733a2f2f516d51506f48515847625875743546576261427464534a724a4c39\
33626b76424d516f584e7274706e734b34614d2f3000000000000000000000000000000000000000000000000000000000000000000000000000000000010000\
000000000000000000007f24eb18ca58a3d487707bf246ce41035d3a818f00000000000000000000000000000000000000000000000000000000c080a0a92d0b\
d3494d562a6a11d63b1f30ce9412b2755ceb50871fad68cdca90cfd377a01a0241caecf973355f4cc706fbdcdf1aabcc98b6d41ff5b75e0ac40690a62402b901\
7802f9017483028c5d0c847735940084773594018301be9a94501f63210ae6d7eeb50dae74da5ae407515ee24680b9010438ed17390000000000000000000000\
000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000011badaf4b4c3c0f50000000000000000000000\
0000000000000000000000000000000000000000a0000000000000000000000000bbed33164d8eabb0a7705857b22b41034026c36b0000000000000000000000\
000000000000000000000000000000000064c39c4b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000\
006302744962a0578e814c675b40909e64d9966b0d000000000000000000000000a4505bb7aa37c2b68cfbc92105d10100220748ebc080a02889dd398be9d49a\
859965bee70415fc144c9325add55201f4dde2b001327844a07dbfddcc936c42e51153654dccad0c050c70201d0746b16873f0a9d6f4651c50b8b502f8b28302\
8c5d018459682f008459682f0182b4e894a4505bb7aa37c2b68cfbc92105d10100220748eb80b844095ea7b3000000000000000000000000501f63210ae6d7ee\
b50dae74da5ae407515ee2460000000000000000000000000000000000000000000000022b1c8c1227a00000c080a0376aec53b6adee9adff0eb309391edb044\
8af6d921869c9eb9970a9ca8342616a04bd75c0703ce2dde341262ba837a7e7e887cebd03d4db73082748a4e66556fc6b9015e02f9015a83028c5d3f8459682f\
008459682f0183021eec94501f63210ae6d7eeb50dae74da5ae407515ee246872386f26fc10000b8e47ff36ab500000000000000000000000000000000000000\
0000000002aa5e163518112ee70000000000000000000000000000000000000000000000000000000000000080000000000000000000000000902e7256a6121b\
3b4b7c5affee93672e0a726cff0000000000000000000000000000000000000000000000000000000064c39c3d00000000000000000000000000000000000000\
000000000000000000000000020000000000000000000000001017f42d1d3e7d490ea3cc4c95591c339ba71ac50000000000000000000000006302744962a057\
8e814c675b40909e64d9966b0dc080a0c0d2ac6a6080e4078d751b975e8977caac275fa0e8d4c691058c8e53a2f91f94a06773542748da53097dc0297e05ad98\
109daa04943b081ed477ca76c14b281faeb8b502f8b283028c5d1b8459682f008459682f01827ecf947b1a3117b2b9be3a3c31e5a097c7f890199666ac80b844\
095ea7b3000000000000000000000000501f63210ae6d7eeb50dae74da5ae407515ee24600000000000000000000000000000000000000000000000000000000\
00155cc0c080a0d75df8b2cd2054fcc38459373928e189f9588466f531d360a27d275e3a55f18da060e4d1b185c7a854cb54e1794b7234048cf84ec99e29a1a6\
b4a4db951da2e177b8b502f8b283028c5d808459682f008459682f0182b41c946302744962a0578e814c675b40909e64d9966b0d80b844095ea7b30000000000\
000000000000001000777700000000000000000000000000000002000000000000000000000000000000000000000000000000d02ab486cedc0000c001a02beb\
a5f757c6e02469400b62051ff4aec4db6684889107d2cb085b8e2015280ea020e7503629c2ef65a030a262b0dc3e0a2fb9ebeb22a045800d0cf6c497e832aeb9\
019f02f9019b83028c5d078459682f008459682f0183040ab79410007777000000000000000000000000000000028703e8715ad6b160b90124ee1490b2000000\
0000000000000000000000000000000000000000000000000000aa36a7000000000000000000000000a593b6f881ad3d366db4dbfeccafd97b8d0db841000000\
000000000000000000a4505bb7aa37c2b68cfbc92105d10100220748eb0000000000000000000000000000000000000000000000008ac7230489e80000000000\
00000000000000000000000000000000000000000000000000002fe9a00000000000000000000000000000000000000000000000000003e8715ad6b160000000\
000000000000000000a593b6f881ad3d366db4dbfeccafd97b8d0db8410000000000000000000000000000000000000000000000000000000000000100000000\
0000000000000000000000000000000000000000000000000000000000c001a03192f2691ea58e0fc7956ff04153a7f4158c344862735002df221cd0594ad52d\
a01c258f81b52448d3158621a694f0db55d22b5409438b9e5fc2ea4ff39e171387b9019f02f9019b83028c5d038459682f008459682f0183040ac39410007777\
000000000000000000000000000000028703e8715a938de0b90124ee1490b20000000000000000000000000000000000000000000000000000000000aa36a700\
0000000000000000000000235e1ecaf69428a0d721e88a287a97a4f2033c2e000000000000000000000000a4505bb7aa37c2b68cfbc92105d10100220748eb00\
0000000000000000000000000000000000000000000001a055690d9db8000000000000000000000000000000000000000000000000000000000000002fe9a000\
00000000000000000000000000000000000000000000000003e8715a938de0000000000000000000000000235e1ecaf69428a0d721e88a287a97a4f2033c2e00\
000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000c0\
80a012a00d2f9e5cd827949d007e606761a4a10892a227ff82f4835a416255544155a0167c886f230ddfc3fc52fec1d0e481ee67966bf4a405091364f55a524e\
1a2382b9015f02f9015b83028c5d138459682f008459682f018301f15a94501f63210ae6d7eeb50dae74da5ae407515ee2468801bfed178d480000b8e47ff36a\
b500000000000000000000000000000000000000000000001a577b4ae1ecf8f40000000000000000000000000000000000000000000000000000000000000000\
800000000000000000000000002441e072fb1b0b32b18713ed7f3513ac0cbc5b7d0000000000000000000000000000000000000000000000000000000064c39c\
4e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000001017f42d1d3e7d490ea3cc4c95591c339ba71a\
c5000000000000000000000000a4505bb7aa37c2b68cfbc92105d10100220748ebc001a0504977ec6af4e0a1299b7df284c4aa13bd3d9c454ed1321ca7ebd1c8\
a0fe3a8aa03bb7d41093d07a6a04a161f3f7a755e330ac96bec5f9d17a4ba538808d69d20cb9029a02f9029683028c5d82f23f8459682f008459682f028302ec\
c2944e7c942d51d977459108ba497fdc71ae0fc54a0080b90224f3840f600000000000000000000000000000000000000000000000000000000000012a990000\
00000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c00000\
000000000000000000000000000000000000000000000000000000000020df8f2b88820c2757e8b715fa4877cde03c92d03895ea2f339886e3ebcd30a5320e29\
77b23de014afa3175d5c25604ce9e3bf9ed113531dbc98e3c79c10514dc39ae62eb4857aa775fac01a973012bf0a85b1bf05117878076f06e081bfa6549880b9\
fc56d8c89c6a173310c01f25dd9548fb3a1a4633bca566073b642a6831d000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000003f7220000\
0000000000000000000000000000000000000000000000000000001e5e7b000000000000000000000000000000000000000000000000000000000000001c0000\
0000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000040c6ad\
a7907c6c0ce4c3e15d85a42f9549432cefb7021ea39db09d4e3595c5d8282980bfeb6d6e5bf9a4f821aa62771809fe0f269ca0489bade86fa8b853dd675ac080\
a05679384a6c8de7837d73394872c4701b5feb2decc508dd1ddede51aee151f79da050b81eb0b6bb489eb7a9290df0d9e3b17bf759f86b89f461539946885277\
f135b9027f02f9027b83028c5d808459682f008459682f01830214e294100077770000000000000000000000000000000487b4d54778b76fc0b9020496e17852\
00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001\
0000000000000000000000005bc9ad36deccbd0f079375d998227f95a8086bbd0000000000000000000000000000000000000000000000000000000000028c5d\
0000000000000000000000000000000000000000000000000000000000aa36a70000000000000000000000005bc9ad36deccbd0f079375d998227f95a8086bbd\
0000000000000000000000005bc9ad36deccbd0f079375d998227f95a8086bbd0000000000000000000000005bc9ad36deccbd0f079375d998227f95a8086bbd\
00000000000000000000000000000000000000000000000000b1a2bc2ec500000000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000003328b49f26fc000000000000000000000000000000000000000000000000000000000000222e0\
00000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001c0\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
c001a01ca5999c62ad9922ed976c76daec95158b69a2fdc288f91e8375bf0be2d5d234a03487748ab3d94428c1b52711c2aecc0d71311319a3564bffdb54e174\
30b45098b901b802f901b483028c5d0a8459682f008459682f0183040d5e94501f63210ae6d7eeb50dae74da5ae407515ee24680b90144ded9382a0000000000\
00000000000000a4505bb7aa37c2b68cfbc92105d10100220748eb000000000000000000000000000000000000000000000000007a091b538174520000000000\
000000000000000000000000000000000000002277cd5834d2d3ba000000000000000000000000000000000000000000000000000245585fdf8eb30000000000\
00000000000000b640437d5d94f97a373e065289170f092c098a130000000000000000000000000000000000000000000000000000000064c39c3f0000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b7f539499be\
2202ae10161e74780dc5deab62216fe3355fe4cd27c46f4b8839e618aae0b5cfe7dac2c8886d55f3cddfb44eb282061e256ad61e804d83a4067876c080a0ae4e\
04512f1f840d323f5ce8f749762e81e388e9b85747ba97387b0d27c4320da0704f7556b815dd42c0cd646ca234a5cb5d00d48d6ddcc5810f04864c4ffea541b9\
0f7b02f90f7783028c5d830120f58459682f008459682f028310c8e0944e7c942d51d977459108ba497fdc71ae0fc54a0080b90f04ef16e84500000000000000\
00000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000000000000000\
000000000000000000000000000000000000000000000000c04e801c6b70ea36389de5fc9a74db2324a391a2be55c33e413edcd8753f767d7600000000000000\
0000000000100077770000000000000000000000000000000100000000000000000000000000000000000000000000000000000000004c4b4000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000da100000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000da1f90d9eb90d9b02\
f90d9783028c5e830187828459682f008459682f02830868cc94100077770000000000000000000000000000000480b90d24fee99b2200000000000000000000\
0000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000003e000000000000000000000\
00000000000000000000000000000000000000021129000000000000000000000000d90d8e85d0472ebc61267ecbba544252b719745200000000000000000000\
00000000000000000000000000000000000000028c5d0000000000000000000000000000000000000000000000000000000000028c5e00000000000000000000\
0000655324aede1cab4c65d2240e9d5302847262f0e0000000000000000000000000100077770000000000000000000000000000000200000000000000000000\
0000655324aede1cab4c65d2240e9d5302847262f0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001085267e63ed6000000000000000000000\
000000000000000000000000000000000000000222e000000000000000000000000000000000000000000000000000000000000001a000000000000000000000\
0000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000001a40c6fab82000000000000\
0000000000000000000000000000000000000000000000000080000000000000000000000000655324aede1cab4c65d2240e9d5302847262f0e0000000000000\
000000000000655324aede1cab4c65d2240e9d5302847262f0e0000000000000000000000000000000000000000000000000a688906bd8b00000000000000000\
0000000000000000000000000000000000000000000000028c5d000000000000000000000000a4505bb7aa37c2b68cfbc92105d10100220748eb000000000000\
000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000a0000000000000\
00000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000005484f52534500\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020486f72736520\
546f6b656e2862726964676564f09f8c883131313535313131290000000000000000000000000000000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000092000000000000000000000\
0000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000d339800000000000000000000\
000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000896f90893b90214f90211a0\
fe2ddfdbb89768dc65a17beca4a8bf243616465d4cedacf17dbf494f2f8b1795a0f341b4bc87ad6e515c6cdaf581941a6b2987ca9f2b1784e65362c287445491\
87a0ca9131bcc32f56c6f566a90153b98d093e390f51cd403a6729097d604ca76169a02521ce439c1075fcadeb96e3289fd8d91dfdba4523f4c5638d1472438e\
c1ff65a0116ecc0ff7e51bbe5116bf33f825f1594ece44a4c17fcf41165fc6f7fb24e75ca0e2b638fc10d4127d38e95ea0adec66f4e0db8cbe47879cf6410eaa\
e5e5176fb2a07e749de6a6a9ac00c9a0142315a2950d673baacedcee58abd02058969923aaaba0687b834ea8cd110c8cc1aa425eeb6a1840781f8cd21824ad55\
92fca3e310fcefa0a26d7b944a851b3f0649b3276dfd32ad5f13f6d8424fde104accc6e98e092427a0230ceb2a903223aa20ec7aa1574b7c82100cbc8d5473be\
08c7298b0a437d8663a0d8ea8e2788463e76e937d5c28a88d223653525d082fa30a4c3613fc441b9ddeca0ef15ce91449669256f66aba758a5705653c1530b70\
1e65b6b4c2682f0d917736a0d684ab94e6396e83919cc0740a1fce74f87b76c6ced6a601300123cb746f566aa04717d330b2761d964ab812e4be3c9662fbef38\
29e01af802e50f59272aadb016a0cd2b5af93b1da28fab2221bf14cef160b68c729dacb73c96a6fae09942880c9ca0b1bf8212ec0073ee68973ea9a3a2ef8292\
635dd185bd85751fa735047c2f12ac80b90214f90211a02e04f6ccffe812778d73e5edd71ec6e88d66799e21e4e1cf289c00e0593d9e75a0a4c6b5403d08831a\
48777904e0bd582b5eb2fd435e86b404a340648f1c07c8eda03a5a83f8390ce834355c9b909ebf3a168059c7c718e04e3db06164bd87d3c805a05880a05ed90a\
4e915b6dfffe045ef86640956633a1ea772ea654329800b93d6da0ac11d1143c0849a36326131d58f6e9e4905ed9d6bb71eab538a420602dd74db0a09a7d706c\
a89e455ea0e84b5f6d364734b8211532ef019d3f6f0c3ad3f8b22145a06f803b054de3776ad08b56aa77acc0b12fd22ae10d05707c3e21c1b27ef56ee6a08cfa\
3a3cd41e437d07e5f5929cd37136ffb5b6fb619037eee6f51ba2db9dd55fa03b0cfd396f0f63ea6fbe14cb96ea78d6a5fb32dd113fd00b55f3946cd91efd44a0\
a6183b5acaa9b645821c3d4659bcbc0650ee8c858877ba7dda3975e33a71381ca00a83a5309e5608d40d5b1decf52c64f40b4d78d2239ef73bc80de3986edc4b\
85a02c635079b09c53837e650a2301f1cb790b9c18eff452e1da51e1392b7a29a459a00fd704736227de56d67f89fd976f456952b0597a178338b7b63147b402\
af28a8a06dfa61f6e1617220334f9bcbd8074fc29b06d4a87695bc0c56472695284c70aea034859735c1845a89c127132524a6c87e76fb4330914fbea3725caf\
b362679590a0a64f419ae11448888a260b8e784dd50be2ad0312c12b852ef25d4a33aa990a5780b90214f90211a0a377ec5382bab2fac4d111df2bf1c6c9eb08\
b5b85dfb4c127da19256a7121888a01fe0ce5dd1994cff2bdba8d2c72cb0d6ae62a6f1c0a0e214abb8ecc622aa96dca0a46cdc4aa0d8563f8a731f2960b4b8f3\
d15ce509b3c69a183f3ca83f1f2eaf16a017733ec82abc6e6725689ba978197e844f4beb5f5111c58dc7fc261a19d37226a018e23422c7369c8257307bc1c5cd\
4cc4750e66ad4f3394e505609b5ee934cb1aa0d70cd0626a071fc0a8dd7432f960d26d2bbfe0e7375c7165f64dc69ab108bdcea00e392492b63488377f37d5ce\
5fbcf466ded6f027b98d0eea1cd531b94b215c54a036cf806a9d1039c4fbb25dac891c44df00f7f1042fe7c015b0d67aae961d07c1a0980554a1bc124152c9f8\
1eef48c484857350171217b1be604c5bfd85e0538785a0fe2ba95684cf0dec25d8b4d2994c48376fd9626da16f8ef45d512bb00542b288a0c81cf9cd3f3af4b2\
49cb1771755201f47a2bf7b89ba40ae242e43ffd3d76c548a070291612e276a97b27ff6d24e2ff5bd69137af8e06909571dfed236265162586a046d88b3eaaf7\
ff63619c9c8cd8823366909e45edf1694c6821afcc58bdc80282a05ff7516db9003c9aeeb1d00d86578219e0397f3a8c9234971ce2c4b1dc1beb26a099cd4772\
34d68d481d77860882424ac0cce6527f217b2e76cf53859bbbbb2e4fa0f1319b7a1c633fef2d0d26c4248bdbd4af5e0c995229e658fc746e5cc55db21c80b901\
d4f901d1a0ca80012db94e7b452a3bb15c35c4491854b4c2074d33ebd5d080ec71182769aaa07a430a12837a081c5d52434c1f0cf91978e98101411d8e19c737\
09292b45e042a0b748cd978e2f53b0f2e750c0eae8825fbc4860112859cc42d9d9f659d1083639a02744191d9f7dc309cf36f4e3cd6c3be953f9b13c92ad6ec7\
5d6a26416a9a1abaa02c4f5e7a29ca1938c916758b9e909184a0f945a04225ecf3a83a3a2e586475e180a00f7658c01fef807877f24d9337c1a203856f107781\
b430b63556a63eab71726d80a01ea759492bc734da8c70fa99298dc5908b3446c3efa1df221bc1abede6430edca068c79aba7675f232086d29c84342328d2b15\
ac2e30e7390e0fe180e4da0299f6a05c39eaf868599fcd5ff6873670011b269c8689b17bdab850648a74f38792b9a7a0b0ce0e662264a44c3f19b2bed5ecbf91\
196a5b3095edd528925d486747c0c9e5a08cb4791d7de705890b9497c444580d35e681ab48962dd4519f0b383ddf5fc0a4a060fc07089c78acec1515410e184c\
ea9153e2560f40afbba68788f62495d112c9a0c4541857e446e2dbebc1837490c7dad570bba5eef1a6f5093e49a124142e737fa009f59f7eb9505a47ba4dabdb\
341d94919b001301761ebb0800e46fab470a53ca80b853f85180a06d6a06ecbb914f2888061bed0d0992d4575af95792e1554f6eb37bd6aee90f2980a09128bf\
ac2b326505597a28ec267f4d9444c8cc191c5c45be660cb7c5843eaea180808080808080808080808080a1e09e3357dac59283c9442a8577f0e657317fc5c56b\
12af720342a260e43a3caa0100000000000000000000c080a07c761a0e7fe2f299c3f940c6e41e180c323363a85981ca4b8ead42cacc81e13ca03df8a82ff1d3\
0272822e2437169bf80b8e2a0396958fdf1fb973078876f1df8900000000000000000000000000000000000000000000000000000000000000c001a016786a0d\
f08c5e3e77b6a30a890c018e5b9e96f02cee01b70ab954490a80ebefa04e76da9a823e00ef9590b231353ef4abbc33f84c2e99d47db58f2fa3da3da636b90281\
02f9027d83028c5d268459682f008459682f01830214ee9410007777000000000000000000000000000000048904e1036db4237a9120b9020496e17852000000\
00000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000\
00000000000000000088888a9a780355dcb8b534768d1c25da19b8b8880000000000000000000000000000000000000000000000000000000000028c5d000000\
0000000000000000000000000000000000000000000000000000aa36a700000000000000000000000088888a9a780355dcb8b534768d1c25da19b8b888000000\
00000000000000000088888a9a780355dcb8b534768d1c25da19b8b88800000000000000000000000088888a9a780355dcb8b534768d1c25da19b8b888000000\
000000000000000000000000000000000000000004e1003b28d92800000000000000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000003328b4a52912000000000000000000000000000000000000000000000000000000000000222e0000000\
00000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001c0000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c001a0\
676ec5a0f9bc6efdec4f448b97e0ce27d8e0d3a25a7d16c0934be0bd8f61f394a0678399eda7932e7541899d8dd4a493ae62190d24a59759e7baf2b3b88091f6\
63")
        .unwrap();

        let k = 15;
        assert_eq!(run_good_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
    }

    #[test]
    fn test_devnet_txlist_from_file() {
        let d: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "resources",
            "test",
            "txlist_rlp_bytes.hex",
        ]
        .iter()
        .collect::<PathBuf>();
        println!("read file from {}", d.display());
        let rlp_bytes = hex::decode(
            fs::read_to_string(d)
                .unwrap()
                .to_ascii_lowercase()
                .trim_start_matches("0x"),
        )
        .unwrap();

        // println!("rlp_bytes = {:?}", rlp_bytes);
        let k = 15;
        assert_eq!(run_good_rlp_circuit::<Fr>(rlp_bytes, k), Ok(()));
    }
}
