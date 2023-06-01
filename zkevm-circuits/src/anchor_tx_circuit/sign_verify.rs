use crate::{
    evm_circuit::util::{
        constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
        split_u256_limb64,
    },
    table::{TxFieldTag, TxTable},
    util::Challenges,
};
use eth_types::{geth_types::Transaction, Field, ToBigEndian, Word, U256};
use gadgets::{
    is_equal::IsEqualChip,
    mul_add::{MulAddChip, MulAddConfig},
    util::{split_u256, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};
use log::error;
use once_cell::sync::Lazy;

const ANCHOR_TX_ID: usize = 0;
const MAX_DEGREE: usize = 10;
const BYTE_POW_BASE: u64 = 1 << 8;

// 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
const GX1: Word = U256([
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
]);
static GX1_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX1));

// 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
const GX2: Word = U256([
    0xabac09b95c709ee5,
    0x5c778e4b8cef3ca7,
    0x3045406e95c07cd8,
    0xc6047f9441ed7d6d,
]);
static GX2_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX2));

// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
const N: Word = U256([
    0xbfd25e8cd0364141,
    0xbaaedce6af48a03b,
    0xfffffffffffffffe,
    0xffffffffffffffff,
]);
static N_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&N));

// private key 0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38
// GX1 * PRIVATEKEY(mod N) = 0x4341adf5a780b4a87939938fd7a032f6e6664c7da553c121d3b4947429639122
const GX1_MUL_PRIVATEKEY: Word = U256([
    0xd3b4947429639122,
    0xe6664c7da553c121,
    0x7939938fd7a032f6,
    0x4341adf5a780b4a8,
]);
static GX1_MUL_PRIVATEKEY_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX1_MUL_PRIVATEKEY));
static GX1_MUL_PRIVATEKEY_LIMB64: Lazy<[U256; 4]> =
    Lazy::new(|| split_u256_limb64(&GX1_MUL_PRIVATEKEY));

// GX2 * PRIVATEKEY(mod N) = 0x4a43b192ca74cab200d6c086df90fb729abca9e52d38b8fa0beb4eafe70956de
const GX2_MUL_PRIVATEKEY: Word = U256([
    0x0beb4eafe70956de,
    0x9abca9e52d38b8fa,
    0x00d6c086df90fb72,
    0x4a43b192ca74cab2,
]);
static GX2_MUL_PRIVATEKEY_LO_HI: Lazy<(U256, U256)> = Lazy::new(|| split_u256(&GX2_MUL_PRIVATEKEY));

// # How to check the signature
// 1. IF r == GX1 OR r == GX2
// 2. IF r == GX2 THEN MUST WHEN r == GX1 AND s == 0
// 3. IF s == 0 THEN (GX1_MUL_PRIVATEKEY + msg_hash) == N
// => IF r == GX2 THEN GX1_MUL_PRIVATEKEY + msg_hash == N
// In mul_add chip, we have a * b + c == d
// => a == GX1_MUL_PRIVATEKEY
// => b == 1
// => c == msg_hash
// => d == N
//
// # The layout
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
    q_u128_start: Selector,
    q_u128_step: Selector,
    q_u128_end: Selector,
    sign_u128_acc: Column<Advice>,

    q_check: Selector,
    mul_add: MulAddConfig<F>,
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

        let q_u128_start = meta.complex_selector();
        let q_u128_step = meta.complex_selector();
        let q_u128_end = meta.complex_selector();
        let sign_u128_acc = meta.advice_column();

        let q_check = meta.complex_selector();
        let mul_add = MulAddChip::configure(meta, |meta| meta.query_selector(q_check));

        let gx1_rlc = crate::evm_circuit::util::rlc::expr(
            GX1.to_be_bytes()
                .map(|v| Expression::Constant(F::from(v as u64)))
                .as_ref(),
            challenges.evm_word(),
        );

        let gx2_rlc = crate::evm_circuit::util::rlc::expr(
            GX2.to_be_bytes()
                .map(|v| Expression::Constant(F::from(v as u64)))
                .as_ref(),
            challenges.evm_word(),
        );
        let is_equal_gx2 = IsEqualChip::configure(
            meta,
            |meta| meta.query_selector(q_check),
            |meta| meta.query_advice(sign_rlc_acc, Rotation(64)), // SigR == GX2
            |_| gx2_rlc.expr(),
        );

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

            let tx_id = ANCHOR_TX_ID.expr();
            let tag = meta.query_fixed(tag, Rotation::cur());
            let index = 0.expr();
            let value = meta.query_advice(sign_rlc_acc, Rotation::cur());
            vec![
                (
                    q_sign_end.expr() * tx_id,
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                ),
                (
                    q_sign_end.expr() * tag,
                    meta.query_fixed(tx_table.tag, Rotation::cur()),
                ),
                (
                    q_sign_end.expr() * index,
                    meta.query_advice(tx_table.index, Rotation::cur()),
                ),
                (
                    q_sign_end * value,
                    meta.query_advice(tx_table.value, Rotation::cur()),
                ),
            ]
        });
        // signature u128
        meta.create_gate(
            "sign_u128_acc[i+1] = sign_u128_acc[i] * BYTE_POW_BASE + sign[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_u128_step = meta.query_selector(q_u128_step);
                let sign_u128_acc_next = meta.query_advice(sign_u128_acc, Rotation::next());
                let sign_u128_acc = meta.query_advice(sign_u128_acc, Rotation::cur());
                let sign_next = meta.query_advice(sign, Rotation::next());
                cb.require_equal(
                    "sign_u128_acc[i+1] = sign_u128_acc[i] * BYTE_POW_BASE + sign[i+1]",
                    sign_u128_acc_next,
                    sign_u128_acc * BYTE_POW_BASE.expr() + sign_next,
                );
                cb.gate(q_u128_step)
            },
        );
        meta.create_gate("sign_u128_acc[start] = sign[start]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_u128_start = meta.query_selector(q_u128_start);
            let sign_u128_acc = meta.query_advice(sign_u128_acc, Rotation::cur());
            let sign = meta.query_advice(sign, Rotation::cur());

            cb.require_equal("sign_u128_acc[start] = sign[start]", sign_u128_acc, sign);
            cb.gate(q_u128_start)
        });

        // check SigR
        meta.create_gate(
            "IF r == GX2 THEN a(GX1_MUL_PRIVATEKEY) * b(1) + c(msg_hash) == d(N)",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_check = meta.query_selector(q_check);

                let sign_rlc_acc = meta.query_advice(sign_rlc_acc, Rotation(64));

                cb.require_in_set("r in (GX1, GX2)", sign_rlc_acc, vec![gx1_rlc, gx2_rlc]);

                cb.condition(is_equal_gx2.is_equal_expression, |cb| {
                    // a == GX1_MUL_PRIVATEKEY
                    let (a_limb0, a_limb1, a_limb2, a_limb3) = mul_add.a_limbs_cur(meta);
                    let a_limb = GX1_MUL_PRIVATEKEY_LIMB64
                        .map(|v| Expression::Constant(F::from(v.as_u64())));
                    cb.require_equal("a_limb0", a_limb0, a_limb[0].expr());
                    cb.require_equal("a_limb1", a_limb1, a_limb[1].expr());
                    cb.require_equal("a_limb2", a_limb2, a_limb[2].expr());
                    cb.require_equal("a_limb3", a_limb3, a_limb[3].expr());

                    // b == 1
                    let (b_limb0, b_limb1, b_limb2, b_limb3) = mul_add.b_limbs_cur(meta);
                    let b_limb = split_u256_limb64(&U256::one())
                        .map(|v| Expression::Constant(F::from(v.as_u64())));
                    cb.require_equal("b_limb0", b_limb0, b_limb[0].expr());
                    cb.require_equal("b_limb1", b_limb1, b_limb[1].expr());
                    cb.require_equal("b_limb2", b_limb2, b_limb[2].expr());
                    cb.require_equal("b_limb3", b_limb3, b_limb[3].expr());

                    // c == msg_hash
                    let c_lo_hi0 = meta.query_advice(sign_u128_acc, Rotation(16));
                    let c_lo_hi1 = meta.query_advice(sign_u128_acc, Rotation(32));
                    let (c_lo_cur, c_hi_cur) = mul_add.c_lo_hi_cur(meta);
                    cb.require_equal("c_lo_cur", c_lo_hi0, c_lo_cur);
                    cb.require_equal("c_hi_cur", c_lo_hi1, c_hi_cur);

                    // d == N
                    let (d_lo_cur, d_hi_cur) = mul_add.c_lo_hi_cur(meta);
                    let d_lo_cur_expr = Expression::Constant(F::from_u128(N_LO_HI.0.as_u128()));
                    let d_hi_cur_expr = Expression::Constant(F::from_u128(N_LO_HI.1.as_u128()));

                    cb.require_equal("d_lo_cur", d_lo_cur_expr, d_lo_cur);
                    cb.require_equal("d_hi_cur", d_hi_cur_expr, d_hi_cur);
                });
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

            q_u128_start,
            q_u128_step,
            q_u128_end,
            sign_u128_acc,

            q_check,
            mul_add,
        }
    }

    fn assign_field(
        &self,
        region: &mut Region<'_, F>,
        _annotation: &'static str,
        offset: &mut usize,
        tag: TxFieldTag,
        value: [u8; 32],
        need_check: bool,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut rlc_acc = Value::known(F::ZERO);
        let randomness = challenges.evm_word();

        let mut assign_u128 = |offset: &mut usize, value: &[u8]| -> Result<(), Error> {
            let mut u128_acc = Value::known(F::ZERO);
            for (idx, byte) in value.iter().enumerate() {
                let row_offset = *offset + idx;
                u128_acc = u128_acc * Value::known(F::from(BYTE_POW_BASE as u64))
                    + Value::known(F::from(*byte as u64));
                region.assign_advice(
                    || "sign_u128_acc",
                    self.sign_u128_acc,
                    row_offset,
                    || u128_acc,
                )?;
                // setup selector
                if idx == 0 {
                    self.q_u128_start.enable(region, row_offset)?;
                }
                // the last offset of field
                if idx == 15 {
                    self.q_u128_end.enable(region, row_offset)?;
                } else {
                    self.q_u128_step.enable(region, row_offset)?;
                }
            }
            Ok(())
        };

        let mut assign_u128_offset = *offset;
        assign_u128(&mut assign_u128_offset, &value[..16])?;
        assign_u128(&mut assign_u128_offset, &value[16..])?;

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
                if need_check {
                    self.q_check.enable(region, row_offset)?;
                }
            }
            // the last offset of field
            if idx == 31 {
                self.q_sign_end.enable(region, row_offset)?;
            } else {
                self.q_sign_step.enable(region, row_offset)?;
            }
        }
        *offset += 32;
        Ok(())
    }

    fn load_mul_add(&self, region: &mut Region<'_, F>, msg_hash: Word) -> Result<(), Error> {
        let chip = MulAddChip::construct(self.mul_add.clone());
        chip.assign(region, 0, [GX1_MUL_PRIVATEKEY, U256::one(), msg_hash, N])
    }

    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        anchor_tx: &Transaction,
        chain_id: u64,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "anchor sign verify",
            |ref mut region| {
                let sign_data = anchor_tx.sign_data(chain_id).map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", e);
                    Error::Synthesis
                })?;
                let msg_hash = U256::from_big_endian(sign_data.msg_hash.to_bytes().as_ref());
                self.load_mul_add(region, msg_hash)?;
                let mut offset = 0;
                for (annotation, tag, need_check, value) in [
                    ("msg_hash", TxFieldTag::TxSignHash, true, msg_hash),
                    ("sign_r", TxFieldTag::SigR, false, anchor_tx.r),
                ] {
                    self.assign_field(
                        region,
                        annotation,
                        &mut offset,
                        tag,
                        value.to_be_bytes(),
                        need_check,
                        challenges,
                    )?;
                }
                Ok(())
            },
        )
    }
}
