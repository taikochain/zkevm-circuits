//! The rlp decoding tables implementation.

use crate::{
    impl_expr,
    rlp_decoder::{RlpDecodeTypeTag, RlpTxFieldTag, RlpTxTypeTag, MAX_BYTE_COLUMN_NUM},
    util::Challenges,
};
use eth_types::Field;
pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase},
};

/// Rlp encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RlpDecodeRule {
    /// The Padding RLP encoding type is a single byte 0x00
    Padding = 0,
    /// The RLP encoding type is a empty string, i.e., 0x80
    Empty,
    /// The RLP encoding type is a single byte value 2, i.e., 0x02
    TxType1559,
    /// The RLP encoding type is a uint64
    Uint64,
    /// The RLP encoding type is a uint96, for gas/nonce/price/ect
    Uint96,
    /// The RLP encoding type is a uint256, normally for signature
    Uint256,
    /// The RLP encoding type is a address 20bytes i.e., 0x94xxxx
    Address,
    /// The RLP encoding type is a string which is upto 48k bytes, a exception is it accepts
    /// leading 00
    Bytes48K,
    /// The RLP encoding type is a string which is upto 16M bytes, i.e., 0xb800 ~ 0xbaFFFFFF
    LongBytes,
    /// The RLP encoding empty list type
    EmptyList,
    /// The RLP encoding empty long list type, upto 16M, i.e., 0xF9FFFFFF
    LongList,
}

impl RlpDecodeRule {
    /// load the decode rule table, like.:
    /// | tx_type(legacy/1559) | field | rlp type | byte[0] | decodable |
    /// | legacy               | nonce | uint96   | 0x00    | false     |
    /// | legacy               | nonce | uint96   | 0x01    | true      |
    ///  ...
    /// | legacy               | signS | uint256  | 0xa0    | true      |
    /// | legacy               | signS | byte256  | 0xa1    | false     |
    ///  ...
    pub fn rule_check(&self, byte0: u8) -> (RlpDecodeTypeTag, bool) {
        let (rlp_type, decodable) = match self {
            RlpDecodeRule::Padding => (RlpDecodeTypeTag::DoNothing, true),
            RlpDecodeRule::Empty => match byte0 {
                0x80 => (RlpDecodeTypeTag::SingleByte, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::TxType1559 => match byte0 {
                0x2 => (RlpDecodeTypeTag::SingleByte, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::Uint64 => match byte0 {
                // 0 is error: non-canonical integer (leading zero bytes) for uint64
                1..=0x80 => (RlpDecodeTypeTag::SingleByte, true),
                0x81..=0x88 => (RlpDecodeTypeTag::ShortStringValue, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::Uint96 => match byte0 {
                // 0 is error: non-canonical integer (leading zero bytes) for uint96
                1..=0x80 => (RlpDecodeTypeTag::SingleByte, true),
                0x81..=0x8c => (RlpDecodeTypeTag::ShortStringValue, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::Uint256 => match byte0 {
                // 0 is error: non-canonical integer (leading zero bytes) for uint256
                1..=0x80 => (RlpDecodeTypeTag::SingleByte, true),
                0x81..=0xa0 => (RlpDecodeTypeTag::ShortStringValue, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::Address => match byte0 {
                0x94 => (RlpDecodeTypeTag::ShortStringBytes, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::Bytes48K => match byte0 {
                0 => (RlpDecodeTypeTag::SingleByte, true),        // 0x00
                1..=0x80 => (RlpDecodeTypeTag::SingleByte, true), // 0x01..=0x80
                0x81..=0xb7 => (RlpDecodeTypeTag::ShortStringBytes, true),
                0xb8 => (RlpDecodeTypeTag::LongString1, true),
                0xb9 => (RlpDecodeTypeTag::LongString2, true),
                0xba => (RlpDecodeTypeTag::LongString3, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::LongBytes => match byte0 {
                0xb8 => (RlpDecodeTypeTag::LongString1, true),
                0xb9 => (RlpDecodeTypeTag::LongString2, true),
                0xba => (RlpDecodeTypeTag::LongString3, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::EmptyList => match byte0 {
                0xc0 => (RlpDecodeTypeTag::EmptyList, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
            RlpDecodeRule::LongList => match byte0 {
                0xf8 => (RlpDecodeTypeTag::LongList1, true),
                0xf9 => (RlpDecodeTypeTag::LongList2, true),
                0xfa => (RlpDecodeTypeTag::LongList3, true),
                _ => (RlpDecodeTypeTag::DoNothing, false),
            },
        };
        (rlp_type, decodable)
    }
}

/// rules of tx members
pub const RLP_TX_FIELD_DECODE_RULES: [(RlpTxTypeTag, RlpTxFieldTag, RlpDecodeRule); 20] = [
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::TxListRlpHeader,
        RlpDecodeRule::LongList,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::TypedTxHeader,
        RlpDecodeRule::LongBytes,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::TxType,
        RlpDecodeRule::TxType1559,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::TxRlpHeader,
        RlpDecodeRule::LongList,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::ChainID,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::Nonce,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::GasPrice,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::GasTipCap,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::GasFeeCap,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::Gas,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::To,
        RlpDecodeRule::Address,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::To,
        RlpDecodeRule::Empty,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::Value,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::Data,
        RlpDecodeRule::Bytes48K,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::AccessList,
        RlpDecodeRule::EmptyList,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::SignV,
        RlpDecodeRule::Uint96,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::SignR,
        RlpDecodeRule::Uint256,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::SignS,
        RlpDecodeRule::Uint256,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::Padding,
        RlpDecodeRule::Padding,
    ),
    (
        RlpTxTypeTag::Tx1559Type,
        RlpTxFieldTag::DecodeError,
        RlpDecodeRule::Padding,
    ),
];

/// Table that contains the fields of all possible RLP decodable fields
#[derive(Clone, Debug)]
pub struct RlpDecoderTable {
    /// The table tag
    pub table_tag: Column<Fixed>,
    /// The tx type tag
    pub tx_type: Column<Fixed>,
    /// The tx field tag
    pub tx_field_tag: Column<Fixed>,
    /// The RLP type
    pub rlp_type: Column<Fixed>,
    /// The first byte of the RLP encoded field
    pub byte_0: Column<Fixed>,
    /// Whether the field is decodable
    pub decodable: Column<Fixed>,
}

impl RlpDecoderTable {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            table_tag: meta.fixed_column(),
            tx_type: meta.fixed_column(),
            tx_field_tag: meta.fixed_column(),
            rlp_type: meta.fixed_column(),
            byte_0: meta.fixed_column(),
            decodable: meta.fixed_column(),
        }
    }

    /// build from existing columns
    pub fn build_from_columns(columns: &[Column<Fixed>]) -> Self {
        assert!(columns.len() > 5);
        Self {
            table_tag: columns[0],
            tx_type: columns[1],
            tx_field_tag: columns[2],
            byte_0: columns[3],
            rlp_type: columns[4],
            decodable: columns[5],
        }
    }

    /// Get the row num of the RLP decoding table
    pub fn table_size() -> usize {
        // item count * 256
        RLP_TX_FIELD_DECODE_RULES.len() * 256
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // make a list with all member of rlpTxFieldTag literally
        layouter.assign_region(
            || "load rlp decoder table",
            |mut region| {
                let mut offset = 0;
                let table_tag = RlpDecoderFixedTableTag::RlpDecoderTable as u64;

                for (tx_type, tx_field_tag, decode_rule) in RLP_TX_FIELD_DECODE_RULES.iter() {
                    for byte_val in 0..=255u8 {
                        let (rlp_type, decodable) = decode_rule.rule_check(byte_val);
                        let rule_table_row = [
                            table_tag,
                            *tx_type as u64,
                            *tx_field_tag as u64,
                            rlp_type as u64,
                            byte_val as u64,
                            decodable as u64,
                        ];

                        log::trace!("rule_table_row: {:?} @ offset {}.", &rule_table_row, offset);
                        rule_table_row
                            .iter()
                            .zip([
                                self.table_tag,
                                self.tx_type,
                                self.tx_field_tag,
                                self.rlp_type,
                                self.byte_0,
                                self.decodable,
                            ])
                            .try_for_each(|(value, col)| {
                                region
                                    .assign_fixed(
                                        || "load rlp rule decoder table",
                                        col,
                                        offset,
                                        || Value::known(F::from(*value)),
                                    )
                                    .map(|_| ())
                            })?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

/// Table that contains the fields of possible state transitions
#[derive(Clone, Debug)]
pub struct TxFieldSwitchTable {
    /// table tag of the table
    pub table_tag: Column<Fixed>,
    /// The current tx field
    pub current_tx_field: Column<Fixed>,
    /// The next tx field
    pub next_tx_field: Column<Fixed>,
}

static TX_FIELD_TRANSITION_TABLE: [(RlpTxFieldTag, &[RlpTxFieldTag]); 19] = [
    (
        RlpTxFieldTag::TxListRlpHeader,
        &[RlpTxFieldTag::TypedTxHeader, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::TypedTxHeader,
        &[RlpTxFieldTag::TxType, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::TxType,
        &[RlpTxFieldTag::TxRlpHeader, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::TxRlpHeader,
        &[RlpTxFieldTag::ChainID, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::ChainID,
        &[RlpTxFieldTag::Nonce, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::Nonce,
        &[RlpTxFieldTag::GasTipCap, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::GasTipCap,
        &[RlpTxFieldTag::GasFeeCap, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::GasFeeCap,
        &[RlpTxFieldTag::Gas, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::Gas,
        &[RlpTxFieldTag::To, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::To,
        &[RlpTxFieldTag::Value, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::Value,
        &[RlpTxFieldTag::Data, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::Data,
        &[RlpTxFieldTag::AccessList, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::AccessList,
        &[RlpTxFieldTag::SignV, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::SignV,
        &[RlpTxFieldTag::SignR, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::SignR,
        &[RlpTxFieldTag::SignS, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::SignS,
        &[RlpTxFieldTag::TypedTxHeader, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::SignS,
        &[RlpTxFieldTag::Padding, RlpTxFieldTag::DecodeError],
    ),
    (
        RlpTxFieldTag::DecodeError,
        &[RlpTxFieldTag::Padding, RlpTxFieldTag::DecodeError],
    ),
    (RlpTxFieldTag::Padding, &[RlpTxFieldTag::Padding]),
];

impl TxFieldSwitchTable {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            table_tag: meta.fixed_column(),
            current_tx_field: meta.fixed_column(),
            next_tx_field: meta.fixed_column(),
        }
    }

    /// build from existed columns
    pub fn build_from_columns(columns: &[Column<Fixed>]) -> Self {
        assert!(columns.len() > 2);
        Self {
            table_tag: columns[0],
            current_tx_field: columns[1],
            next_tx_field: columns[2],
        }
    }

    /// Get the row num of the table
    pub fn table_size() -> usize {
        TX_FIELD_TRANSITION_TABLE.len()
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // make a list with all member of rlpTxFieldTag literally
        let tx_field_trans_table = &TX_FIELD_TRANSITION_TABLE;

        layouter.assign_region(
            || "load tx struct field switch table",
            |mut region| {
                let mut offset = 0;
                tx_field_trans_table
                    .iter()
                    .try_for_each(|(current_tx_field, next_tx_fields)| {
                        for next_tx_field in next_tx_fields.iter() {
                            region.assign_fixed(
                                || "table tag",
                                self.table_tag,
                                offset,
                                || {
                                    Value::known(F::from(
                                        RlpDecoderFixedTableTag::TxFieldSwitchTable as u64,
                                    ))
                                },
                            )?;
                            region.assign_fixed(
                                || "current tx field",
                                self.current_tx_field,
                                offset,
                                || Value::known(F::from(*current_tx_field as u64)),
                            )?;
                            region.assign_fixed(
                                || "next tx field",
                                self.next_tx_field,
                                offset,
                                || Value::known(F::from(*next_tx_field as u64)),
                            )?;
                            offset += 1;
                        }
                        Ok(())
                    })
            },
        )
    }
}

/// Table that contains the pow of randomness
#[derive(Clone, Debug)]
pub struct RMultPowTable {
    /// table tag
    pub table_tag: Column<Fixed>,
    /// pow number
    pub length: Column<Fixed>,
    /// pow of randomness
    pub r_mult: Column<Advice>,
}

impl RMultPowTable {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            table_tag: meta.fixed_column(),
            length: meta.fixed_column(),
            r_mult: meta.advice_column(),
        }
    }

    /// build from existed columns
    pub fn build_from_columns(
        advice_columns: &[Column<Advice>],
        fixed_columns: &[Column<Fixed>],
    ) -> Self {
        assert!(advice_columns.len() > 0 && fixed_columns.len() > 1);
        Self {
            table_tag: fixed_columns[0],
            length: fixed_columns[1],
            r_mult: advice_columns[0],
        }
    }

    /// Get the row num of the table
    pub fn table_size() -> usize {
        MAX_BYTE_COLUMN_NUM
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut randomness = F::ZERO;
        challenges.keccak_input().map(|r| randomness = r);

        layouter.assign_region(
            || "load rlp r_mult table",
            |mut region| {
                (0..=MAX_BYTE_COLUMN_NUM).try_for_each(|i| {
                    region.assign_fixed(
                        || "table tag",
                        self.table_tag,
                        i,
                        || Value::known(F::from(RlpDecoderFixedTableTag::RMult as u64)),
                    )?;
                    region.assign_fixed(
                        || "pow",
                        self.length,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                    region.assign_advice(
                        || "r_mult",
                        self.r_mult,
                        i,
                        || Value::known(randomness.pow(&[i as u64, 0, 0, 0])),
                    )?;
                    Ok(())
                })
            },
        )?;
        Ok(())
    }
}

/// for value range lookup
#[derive(Clone, Debug)]
pub struct RangeTable<const N: usize> {
    /// table tag
    pub table_tag: Column<Fixed>,
    /// value in range
    pub value: Column<Fixed>,
}

impl<const N: usize> RangeTable<N> {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            table_tag: meta.fixed_column(),
            value: meta.fixed_column(),
        }
    }

    /// build from existed columns
    pub fn build_from_columns(columns: &[Column<Fixed>]) -> Self {
        assert!(columns.len() > 2);
        Self {
            table_tag: columns[0],
            value: columns[1],
        }
    }

    /// Get the row num of the table
    pub fn table_size() -> usize {
        match N {
            0..=256 => 256,
            _ => unimplemented!(),
        }
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut randomness = F::ZERO;
        challenges.keccak_input().map(|r| randomness = r);

        let tag = match N {
            0..=256 => RlpDecoderFixedTableTag::Range256 as u64,
            _ => unimplemented!(),
        };
        layouter.assign_region(
            || format!("load rlp range {} table", N),
            |mut region| {
                (0..N).try_for_each(|i| {
                    region.assign_fixed(
                        || "table tag",
                        self.table_tag,
                        i,
                        || Value::known(F::from(tag)),
                    )?;
                    region.assign_fixed(
                        || "range value",
                        self.value,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                    Ok(())
                })
            },
        )?;
        Ok(())
    }
}

type ByteRangeTable = RangeTable<256>;

/// For decodable flag check, for example:
/// 1. 0xF836 is invalid because the len_of_len is 0x36 which is < 55, so the len_decodable is
///    false.
/// 2. 0x8100 is invalid because the value is 00 which <0x80 should be not after 0x81, normally
///    value needs to be non-zero as rlp does not have leading 0.
#[derive(Clone, Debug)]
pub struct InvalidRlpBytesTable {
    /// table tag
    pub table_tag: Column<Fixed>,
    /// byte value
    pub value: Column<Fixed>,
    /// decodable in len_of_len heading
    pub len_decodable: Column<Fixed>,
    /// decodable in value heading
    pub val_decodable: Column<Fixed>,
}

impl InvalidRlpBytesTable {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            table_tag: meta.fixed_column(),
            value: meta.fixed_column(),
            len_decodable: meta.fixed_column(),
            val_decodable: meta.fixed_column(),
        }
    }

    /// build from existed columns
    pub fn build_from_columns(columns: &[Column<Fixed>]) -> Self {
        assert!(columns.len() > 2);
        Self {
            table_tag: columns[0],
            value: columns[1],
            len_decodable: columns[2],
            val_decodable: columns[3],
        }
    }

    /// Get the row num of the table
    pub fn table_size() -> usize {
        256
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut randomness = F::ZERO;
        challenges.keccak_input().map(|r| randomness = r);

        layouter.assign_region(
            || format!("load rlp heading bytes"),
            |mut region| {
                (0..256).try_for_each(|i| {
                    region.assign_fixed(
                        || "table tag",
                        self.table_tag,
                        i,
                        || {
                            Value::known(F::from(
                                RlpDecoderFixedTableTag::HeadingByteValidTable as u64,
                            ))
                        },
                    )?;
                    region.assign_fixed(
                        || "value",
                        self.value,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                    region.assign_fixed(
                        || "len_of_len valid",
                        self.len_decodable,
                        i,
                        || {
                            if i <= 55 {
                                Value::known(F::ZERO)
                            } else {
                                Value::known(F::ONE)
                            }
                        },
                    )?;
                    region.assign_fixed(
                        || "value valid",
                        self.val_decodable,
                        i,
                        || {
                            if i > 0x0 {
                                Value::known(F::ONE)
                            } else {
                                Value::known(F::ZERO)
                            }
                        },
                    )?;
                    Ok(())
                })
            },
        )?;
        Ok(())
    }
}

/// tag for shared fixed table
#[derive(Clone, Copy, Debug)]
pub enum RlpDecoderFixedTableTag {
    /// All zero lookup data
    Disabled = 0,
    /// Power of randomness: [1, r], [2, r^2],...
    RMult,
    /// 0 - 255
    Range256,
    /// Decode rule table for rlp tx
    RlpDecoderTable,
    /// Tx field switch table
    TxFieldSwitchTable,
    /// valid len/value heading byte
    HeadingByteValidTable,
}
impl_expr!(RlpDecoderFixedTableTag);

#[derive(Clone, Debug)]
/// shared fix tables
pub struct RlpDecoderFixedTable<const NA: usize, const NF: usize> {
    /// rlp decoder table
    pub tx_decode_table: RlpDecoderTable,
    /// tx field switch table
    pub tx_member_switch_table: TxFieldSwitchTable,
    /// r_mult pow table
    pub r_mult_pow_table: RMultPowTable,
    /// range table
    pub byte_range_table: ByteRangeTable,
    // TODO: range table, invalid byte table
    /// shared columns for all fix tables
    pub fixed_columns: [Column<Fixed>; NF],
    /// shared columns for all fix tables
    pub advice_columns: [Column<Advice>; NA],
}

impl<const NA: usize, const NF: usize> RlpDecoderFixedTable<NA, NF> {
    /// Construct a new RlpDecoderTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let fixed_columns = array_init::array_init(|_| meta.fixed_column());
        let advice_columns = array_init::array_init(|_| meta.advice_column_in(SecondPhase));
        Self {
            tx_decode_table: RlpDecoderTable::build_from_columns(&fixed_columns),
            tx_member_switch_table: TxFieldSwitchTable::build_from_columns(&fixed_columns),
            r_mult_pow_table: RMultPowTable::build_from_columns(&advice_columns, &fixed_columns),
            byte_range_table: ByteRangeTable::build_from_columns(&fixed_columns),
            fixed_columns,
            advice_columns,
        }
    }

    /// Get the row num of the table
    pub fn table_size() -> usize {
        RlpDecoderTable::table_size()
            + TxFieldSwitchTable::table_size()
            + RMultPowTable::table_size()
            + ByteRangeTable::table_size()
            + 1
    }

    /// Assign the values of the table to the circuit
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // TODO: load all in one region explicitly
        layouter.assign_region(
            || "load disabled row",
            |mut region| {
                self.fixed_columns.iter().try_for_each(|column| {
                    region
                        .assign_fixed(|| "table tag", *column, 0, || Value::known(F::ZERO))
                        .map(|_| ())
                })?;
                Ok(())
            },
        )?;
        self.tx_decode_table.load(layouter, challenges)?;
        self.tx_member_switch_table.load(layouter, challenges)?;
        self.r_mult_pow_table.load(layouter, challenges)?;
        self.byte_range_table.load(layouter, challenges)?;
        Ok(())
    }
}
