//! # How to check the signature
//!
//! 1. IF r == GX1 OR r == GX2
//! 2. IF r == GX2 THEN MUST WHEN r == GX1 AND s == 0
//! 3. IF s == 0 THEN GX1_MUL_PRIVATEKEY + msg_hash == N
//!
//! So, IF r == GX2 THEN GX1_MUL_PRIVATEKEY + msg_hash == N
//!
//! ## Why we only need to prove the equation: GX1_MUL_PRIVATEKEY + msg_hash == N
//!
//! based on the algorithm of [taiko-mono](https://github.com/taikoxyz/taiko-mono/blob/ad26803e5bcbcc76b812084b7bd08f45992e59dd/packages/protocol/contracts/libs/LibAnchorSignature.sol#L68)
//!
//! ### The formula of signature with K = 1
//!
//! ```
//! s = (GX1 * GOLDEN_TOUCH_PRIVATEKEY + msg_hash) (mod N) (K = 1)
//! ```
//!
//! #### Formula deformation
//!
//! ```
//! s = (GX1 * GOLDEN_TOUCH_PRIVATEKEY (mod N) + msg_hash (mod N)) (mod N)
//! ```
//!
//! - Our `GX1_MUL_PRIVATEKEY` is equal to `GX1 * GOLDEN_TOUCH_PRIVATEKEY (mod N)`
//! - Our `msg_hash` has already been (mod N) in [zkevm-circuit](https://github.com/taikoxyz/zkevm-circuits/blob/839152c04ab3ddd1b8ce32632a407e5e7ef823a8/eth-types/src/geth_types.rs#L236)
//!
//! ```rust
//! let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
//! ```
//!
//! ### Summary
//!
//! ```
//! because: 0 < GX1_MUL_PRIVATEKEY + msg_hash < 2N
//! need prove: (GX1_MUL_PRIVATEKEY + msg_hash) (mod N) == 0
//! so: GX1_MUL_PRIVATEKEY + msg_hash == N
//! ```

use crate::{
    evm_circuit::util::{
        constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
        split_u256_limb64,
    },
    table::{LookupTable, TxFieldTag, TxTable},
    util::Challenges,
    witness::Transaction,
};
use eth_types::{address, word, Address, Field, ToBigEndian, ToLittleEndian, Word, U256};
use ethers_signers::LocalWallet;
use gadgets::{
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    mul_add::{MulAddChip, MulAddConfig},
    util::{split_u256, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};
use once_cell::sync::Lazy;
use std::str::FromStr;

const MAX_DEGREE: usize = 9;
const BYTE_POW_BASE: u64 = 1 << 8;

pub(crate) static GOLDEN_TOUCH_ADDRESS: Lazy<Address> =
    Lazy::new(|| address!("0x0000777735367b36bC9B61C50022d9D0700dB4Ec"));

// 0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38
pub(crate) static GOLDEN_TOUCH_PRIVATEKEY: Lazy<Word> =
    Lazy::new(|| word!("0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38"));

pub(crate) static GOLDEN_TOUCH_WALLET: Lazy<LocalWallet> = Lazy::new(|| {
    LocalWallet::from_str("0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38")
        .unwrap()
});

// 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
pub(crate) static GX1: Lazy<Word> =
    Lazy::new(|| word!("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
static GX1_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX1));

// 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
pub(crate) static GX2: Lazy<Word> =
    Lazy::new(|| word!("0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"));
static GX2_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX2));

// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
pub(crate) static N: Lazy<Word> =
    Lazy::new(|| word!("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));
static N_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&N));

// private key 0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38
// GX1 * PRIVATEKEY(mod N) = 0x4341adf5a780b4a87939938fd7a032f6e6664c7da553c121d3b4947429639122
pub(crate) static GX1_MUL_PRIVATEKEY: Lazy<Word> =
    Lazy::new(|| word!("0x4341adf5a780b4a87939938fd7a032f6e6664c7da553c121d3b4947429639122"));
static GX1_MUL_PRIVATEKEY_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX1_MUL_PRIVATEKEY));
static GX1_MUL_PRIVATEKEY_LIMB64: Lazy<[U256; 4]> =
    Lazy::new(|| split_u256_limb64(&GX1_MUL_PRIVATEKEY));

// GX2 * PRIVATEKEY(mod N) = 0x4a43b192ca74cab200d6c086df90fb729abca9e52d38b8fa0beb4eafe70956de
static GX2_MUL_PRIVATEKEY: Lazy<Word> =
    Lazy::new(|| word!("0x4a43b192ca74cab200d6c086df90fb729abca9e52d38b8fa0beb4eafe70956de"));
static GX2_MUL_PRIVATEKEY_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX2_MUL_PRIVATEKEY));

// In mul_add chip, we have a * b + c == d
// => a == GX1_MUL_PRIVATEKEY
// => b == 1
// => c == msg_hash
// => d == N
//
// # The circuit layout
// - msg_hash (c)
// - SigR

#[derive(Debug, Clone)]
pub(crate) struct SignVerifyConfig<F: Field> {
    tx_table: TxTable,

    q_sign_start: Selector,
    q_sign_step: Selector,
    q_sign_end: Selector,
    tag: Column<Fixed>,
    sign: Column<Advice>,
    sign_rlc_acc: Column<Advice>,
    // split u256 to low and high
    q_u64_start: Selector,
    q_u64_step: Selector,
    q_u64_end: Selector,
    sign_u64_acc: Column<Advice>,

    q_check: Selector,
    mul_add: MulAddConfig<F>,
    is_equal_gx2: IsEqualConfig<F>,
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        tx_table: TxTable,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let q_sign_start = meta.complex_selector();
        let q_sign_step = meta.complex_selector();
        let q_sign_end = meta.complex_selector();
        let tag = meta.fixed_column();
        let sign = meta.advice_column();
        let sign_rlc_acc = meta.advice_column_in(SecondPhase);

        let q_u64_start = meta.complex_selector();
        let q_u64_step = meta.complex_selector();
        let q_u64_end = meta.complex_selector();
        let sign_u64_acc = meta.advice_column();

        let gx1_rlc = crate::evm_circuit::util::rlc::expr(
            GX1.to_le_bytes()
                .map(|v| Expression::Constant(F::from(v as u64)))
                .as_ref(),
            challenges.evm_word(),
        );

        let gx2_rlc = crate::evm_circuit::util::rlc::expr(
            GX2.to_le_bytes()
                .map(|v| Expression::Constant(F::from(v as u64)))
                .as_ref(),
            challenges.evm_word(),
        );
        let q_check = meta.complex_selector();
        let is_equal_gx2 = IsEqualChip::configure(
            meta,
            |meta| meta.query_selector(q_check),
            |meta| meta.query_advice(sign_rlc_acc, Rotation(63)), // SigR == GX2
            |_| gx2_rlc.expr(),
        );

        let mul_add = MulAddChip::configure(meta, |meta| {
            is_equal_gx2.is_equal_expression.expr() * meta.query_selector(q_check)
        });

        // signature rlc
        meta.create_gate(
            "sign_rlc_acc[i+1] = sign_rlc_acc[i] * randomness + sign[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_sign_step = meta.query_selector(q_sign_step);
                let sign_rlc_acc_next = meta.query_advice(sign_rlc_acc, Rotation::next());
                let sign_rlc_acc = meta.query_advice(sign_rlc_acc, Rotation::cur());
                let sign = meta.query_advice(sign, Rotation::next());
                let randomness = challenges.evm_word();
                cb.require_equal(
                    "sign_rlc_acc[i+1] = sign_rlc_acc[i] * randomness + sign[i+1]",
                    sign_rlc_acc_next,
                    sign_rlc_acc * randomness + sign,
                );
                cb.gate(q_sign_step)
            },
        );

        meta.create_gate("sign_rlc_acc[0] = sign[0]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_sign_start = meta.query_selector(q_sign_start);
            let sign_rlc_acc = meta.query_advice(sign_rlc_acc, Rotation::cur());
            let sign = meta.query_advice(sign, Rotation::cur());

            cb.require_equal("sign_rlc_acc[0] = sign[0]", sign_rlc_acc, sign);
            cb.gate(q_sign_start)
        });

        meta.lookup_any("sign_r or msg_hash in tx_table", |meta| {
            let q_sign_end = meta.query_selector(q_sign_end);

            let tx_id = super::ANCHOR_TX_ID.expr();
            let tag = meta.query_fixed(tag, Rotation::cur());
            let index = 0.expr();
            let value = meta.query_advice(sign_rlc_acc, Rotation::cur());

            [tx_id, tag, index, value]
                .into_iter()
                .zip(tx_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (q_sign_end.expr() * arg, table))
                .collect::<Vec<_>>()
        });

        // signature u64
        meta.create_gate(
            "sign_u64_acc[i+1] = sign_u64_acc[i] * BYTE_POW_BASE + sign[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_u64_step = meta.query_selector(q_u64_step);
                let sign_u64_acc_next = meta.query_advice(sign_u64_acc, Rotation::next());
                let sign_u64_acc = meta.query_advice(sign_u64_acc, Rotation::cur());
                let sign_next = meta.query_advice(sign, Rotation::next());
                cb.require_equal(
                    "sign_u64_acc[i+1] = sign_u64_acc[i] * BYTE_POW_BASE + sign[i+1]",
                    sign_u64_acc_next,
                    sign_u64_acc * BYTE_POW_BASE.expr() + sign_next,
                );
                cb.gate(q_u64_step)
            },
        );

        meta.create_gate("sign_u64_acc[start] = sign[start]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_u64_start = meta.query_selector(q_u64_start);
            let sign_u64_acc = meta.query_advice(sign_u64_acc, Rotation::cur());
            let sign = meta.query_advice(sign, Rotation::cur());

            cb.require_equal("sign_u64_acc[start] = sign[start]", sign_u64_acc, sign);
            cb.gate(q_u64_start)
        });

        // check SigR
        meta.create_gate(
            "IF r == GX2 THEN a(msg_hash) * b(1) + c(GX1_MUL_PRIVATEKEY) == d(N)",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_check = meta.query_selector(q_check);

                let sign_rlc_acc = meta.query_advice(sign_rlc_acc, Rotation(63));

                cb.require_in_set("r in (GX1, GX2)", sign_rlc_acc, vec![gx1_rlc, gx2_rlc]);

                // a == msg_hash
                let (a_limbs_cur0, a_limbs_cur1, a_limbs_cur2, a_limbs_cur3) =
                    mul_add.a_limbs_cur(meta);

                // c == msg_hash
                let a_limb0 = meta.query_advice(sign_u64_acc, Rotation(31));
                let a_limb1 = meta.query_advice(sign_u64_acc, Rotation(23));
                let a_limb2 = meta.query_advice(sign_u64_acc, Rotation(15));
                let a_limb3 = meta.query_advice(sign_u64_acc, Rotation(7));
                cb.require_equal("a_limb0", a_limbs_cur0, a_limb0);
                cb.require_equal("a_limb1", a_limbs_cur1, a_limb1);
                cb.require_equal("a_limb2", a_limbs_cur2, a_limb2);
                cb.require_equal("a_limb3", a_limbs_cur3, a_limb3);

                // b == 1
                let (b_limb0, b_limb1, b_limb2, b_limb3) = mul_add.b_limbs_cur(meta);
                let b_limb = split_u256_limb64(&U256::one())
                    .map(|v| Expression::Constant(F::from(v.as_u64())));
                cb.require_equal("b_limb0", b_limb0, b_limb[0].expr());
                cb.require_equal("b_limb1", b_limb1, b_limb[1].expr());
                cb.require_equal("b_limb2", b_limb2, b_limb[2].expr());
                cb.require_equal("b_limb3", b_limb3, b_limb[3].expr());

                // c == GX1_MUL_PRIVATEKEY
                let c_lo_hi0 =
                    Expression::Constant(F::from_u128(GX1_MUL_PRIVATEKEY_LO_HI.0.as_u128()));
                let c_lo_hi1 =
                    Expression::Constant(F::from_u128(GX1_MUL_PRIVATEKEY_LO_HI.1.as_u128()));
                let (c_lo_cur, c_hi_cur) = mul_add.c_lo_hi_cur(meta);
                cb.require_equal("c_lo_cur", c_lo_hi0, c_lo_cur);
                cb.require_equal("c_hi_cur", c_lo_hi1, c_hi_cur);

                // d == N
                let (d_lo_cur, d_hi_cur) = mul_add.d_lo_hi_cur(meta);
                let d_lo_cur_expr = Expression::Constant(F::from_u128(N_LO_HI.0.as_u128()));
                let d_hi_cur_expr = Expression::Constant(F::from_u128(N_LO_HI.1.as_u128()));

                cb.require_equal("d_lo_cur", d_lo_cur_expr, d_lo_cur);
                cb.require_equal("d_hi_cur", d_hi_cur_expr, d_hi_cur);
                cb.gate(q_check)
            },
        );

        Self {
            tx_table,

            q_sign_start,
            q_sign_step,
            q_sign_end,
            tag,
            sign,
            sign_rlc_acc,

            q_u64_start,
            q_u64_step,
            q_u64_end,
            sign_u64_acc,

            q_check,
            mul_add,
            is_equal_gx2,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_field(
        &self,
        region: &mut Region<'_, F>,
        _annotation: &'static str,
        offset: &mut usize,
        tag: TxFieldTag,
        value: [u8; 32],
        challenges: &Challenges<Value<F>>,
    ) -> Result<Value<F>, Error> {
        let mut rlc_acc = Value::known(F::ZERO);
        let randomness = challenges.evm_word();

        let mut assign_u64 = |offset: &mut usize, value: &[u8]| -> Result<(), Error> {
            let mut u64_acc = Value::known(F::ZERO);
            for (idx, byte) in value.iter().enumerate() {
                let row_offset = *offset + idx;
                u64_acc = u64_acc * Value::known(F::from(BYTE_POW_BASE))
                    + Value::known(F::from(*byte as u64));
                region.assign_advice(
                    || "sign_u64_acc",
                    self.sign_u64_acc,
                    row_offset,
                    || u64_acc,
                )?;
                // setup selector
                if idx == 0 {
                    self.q_u64_start.enable(region, row_offset)?;
                }
                // the last offset of field
                if idx == 7 {
                    self.q_u64_end.enable(region, row_offset)?;
                } else {
                    self.q_u64_step.enable(region, row_offset)?;
                }
            }
            *offset += 8;
            Ok(())
        };

        let mut assign_u64_offset = *offset;
        assign_u64(&mut assign_u64_offset, &value[..8])?;
        assign_u64(&mut assign_u64_offset, &value[8..16])?;
        assign_u64(&mut assign_u64_offset, &value[16..24])?;
        assign_u64(&mut assign_u64_offset, &value[24..])?;

        for (idx, byte) in value.iter().enumerate() {
            let row_offset = *offset + idx;
            region.assign_advice(
                || "sign",
                self.sign,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;
            region.assign_fixed(
                || "tag",
                self.tag,
                row_offset,
                || Value::known(F::from(tag as u64)),
            )?;

            rlc_acc = rlc_acc * randomness + Value::known(F::from(*byte as u64));
            region.assign_advice(|| "sign_rlc_acc", self.sign_rlc_acc, row_offset, || rlc_acc)?;
            // setup selector
            if idx == 0 {
                self.q_sign_start.enable(region, row_offset)?;
            }
            // the last offset of field
            if idx == 31 {
                self.q_sign_end.enable(region, row_offset)?;
            } else {
                self.q_sign_step.enable(region, row_offset)?;
            }
        }
        *offset += 32;
        Ok(rlc_acc)
    }

    fn load_mul_add(&self, region: &mut Region<'_, F>, msg_hash: Word) -> Result<(), Error> {
        let chip = MulAddChip::construct(self.mul_add.clone());
        chip.assign(region, 0, [msg_hash, U256::one(), *GX1_MUL_PRIVATEKEY, *N])
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub(crate) fn min_num_rows() -> usize {
        64 // msg_hash(32B) + sign_r(32B)
    }

    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        anchor_tx: &Transaction,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "anchor sign verify",
            |ref mut region| {
                self.q_check.enable(region, 0)?;

                let msg_hash = U256::from_little_endian(&anchor_tx.tx_sign_hash.to_fixed_bytes());
                self.load_mul_add(region, msg_hash)?;
                let mut offset = 0;
                for (annotation, tag, need_check, value) in [
                    (
                        "msg_hash",
                        TxFieldTag::TxSignHash,
                        false,
                        msg_hash.to_be_bytes(),
                    ),
                    ("sign_r", TxFieldTag::SigR, true, anchor_tx.r.to_be_bytes()),
                ] {
                    let rlc_acc =
                        self.assign_field(region, annotation, &mut offset, tag, value, challenges)?;
                    if need_check {
                        let gx2_rlc = challenges.evm_word().map(|randomness| {
                            crate::evm_circuit::util::rlc::value(&GX2.to_le_bytes(), randomness)
                        });
                        let chip = IsEqualChip::construct(self.is_equal_gx2.clone());
                        chip.assign(region, 0, rlc_acc, gx2_rlc)?;
                    }
                }
                Ok(())
            },
        )
    }
}
