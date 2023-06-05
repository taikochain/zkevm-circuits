use halo2_proofs::plonk::{ConstraintSystem,Circuit, Error};
use halo2_proofs::circuit::{Layouter,SimpleFloorPlanner,Value};
use halo2_proofs::halo2curves::ff::PrimeField as FieldExt;
use halo2wrong_integer::{IntegerConfig, rns::Rns, IntegerChip, IntegerInstructions, rns::Integer, UnassignedInteger, Range, AssignedInteger};
use halo2wrong_maingate::{RangeChip, MainGate, RegionCtx};

/// THIS CIRCUIT PERFORMS A NON-NATIVE FUNCTION EVAL USING BARYCENTRIC-FORMULA
/// P(X) = (const) * sum (d_i * (w^i/x-w^i)) where const = (x^N - 1)/N where w^N = 1, for all X s.t. X^N != 1

#[derive(Clone, Debug)]
pub struct BlobKZGConfig {
    integer_config: IntegerConfig
}
// TODO: optim: remove w column, make wi column Fixed since it's always the same (like n_bits). BUT increases Verifier costs!!!

#[derive(Clone, Debug)]
pub struct BlobKZGCircuit<W, N>{ // W is the wrong field, N is the native field
    datapoints: [W; 4096],
    x: W, 
    w: W,
    n: W,
    _marker: std::marker::PhantomData<N>
}

impl<W: FieldExt, N:FieldExt> Default for BlobKZGCircuit<W,N> {
    fn default() -> Self {
        BlobKZGCircuit { datapoints: [W::default();4096], x: W::default(), w: W::default(), n: W::default(), _marker: std::marker::PhantomData }
    }
}
struct WitnessValues<F: FieldExt>{
    evals: [F;4098],
    wis: [F;4096],
    xns: [F;257],
    x2is: [F;256],
    nbits: [F;256] 
}
impl<W:FieldExt, N: FieldExt> BlobKZGCircuit<W,N> {
    fn generate_witnesses(&self) -> Result<WitnessValues<W>, Error> {
        let x2is: [W; 256] = {
            let mut x2is = [W::default(); 256];
            let mut state = self.x;
            for x in &mut x2is {
                *x = state;
                state *= state;
            }
            x2is
        };
        let nbits: [W; 256] = {
            let mut nbits = [W::default(); 256];
            let nbits_bool: [bool; 256] = {
                let mut nbits_bool = [false; 256];
                let repr: [u8; 32] = self.n.to_repr().as_ref().try_into().unwrap();
                for (j, byte) in repr.iter().enumerate() {
                    for i in 0..8 {
                        nbits_bool[j*8+i] = ((byte >> i) & 1) == 1;
                    }
                }
                nbits_bool
            };

            for (x, b) in nbits.iter_mut().zip(nbits_bool.iter()) {
                *x = if *b {W::ONE} else {W::ZERO};
            }
            nbits
        };
        let xns: [W;257] = {
            let mut xns = [W::default(); 257];
            let mut state = W::ONE;
            for (x, (x2i, nbit)) in xns.iter_mut().zip(x2is.iter().zip(nbits.iter())) {
                *x = state;
                state *= *x2i * *nbit + (W::ONE - *nbit);
            }
            xns[xns.len()-1] = state;
            xns
        };
        if xns[xns.len()-1] == W::ONE { 
            // ERROR: should never take an x inside the domain
            return Err(Error::Synthesis);
        }
        let wis: [W; 4096] = {
            let mut wis = [W::default(); 4096];
            let mut state = self.w;
            for x in &mut wis {
                *x = state;
                state *= self.w;
            }
            wis
        };
        let evals: [W; 4098] = {
            let mut evals = [W::default(); 4098];
            let mut state = W::ZERO;
            for (x, (di, wi)) in evals.iter_mut().zip(self.datapoints.iter().zip(wis.iter())) {
                *x = state;
                state += *di * *wi * (self.x-*wi).invert().unwrap();
            }
            evals[evals.len() - 2] = state;
            let xn = xns[xns.len() - 1];
            evals[evals.len() - 1] = evals[evals.len() - 2] * (xn - W::ONE) * self.n.invert().unwrap();
            evals
        };
        
        let witness_values = WitnessValues{
            evals,
            wis,
            xns,
            x2is,
            nbits
        };
        Ok(witness_values)
    }
}

impl<W: FieldExt, N:FieldExt> Circuit<N> for BlobKZGCircuit<W,N> {
    type Config = BlobKZGConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let integer_config = {
            const BIT_LEN_LIMB: usize = 68;
            const NUMBER_OF_LIMBS: usize = 4;
            let main_gate_config = MainGate::<N>::configure(meta);
            let range_config = {
                // let overflow_bit_lens = rns::<W, N, BIT_LEN_LIMB>().overflow_lengths();
                let overflow_bit_lens = Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct().overflow_lengths();
                // let composition_bit_len = IntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::sublimb_bit_len();
                let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];
                RangeChip::<N>::configure(
                    meta,
                    &main_gate_config,
                    composition_bit_lens,
                    overflow_bit_lens,
                )
            };
            IntegerConfig::new(range_config, main_gate_config)
        };

        BlobKZGConfig {
            integer_config
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        fn assign_wrong_integer<W: FieldExt, N: FieldExt>(
            integer_chip: &IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            ctx: &mut RegionCtx<N>,
            x: W
        ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
            let rc_rns: std::rc::Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = std::rc::Rc::new(Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct());
            let i: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = Integer::from_fe(x, rc_rns);
            let v: Value<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = Value::known(i);
            let u: UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = UnassignedInteger::from(v);
            // TODO: is Range::Operand a correct range here?
            let a: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = integer_chip.assign_integer(ctx, u, Range::Operand)?;
             Ok(a)
        }

        let WitnessValues{evals, wis, xns, x2is, nbits}: WitnessValues<W> = self.generate_witnesses()?;
        const BIT_LEN_LIMB: usize = 68;
        const NUMBER_OF_LIMBS: usize = 4;

        let integer_chip = {
            let rc_rns = std::rc::Rc::new(Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct());
            IntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config.integer_config, rc_rns)
        };
        use halo2wrong_maingate::RangeInstructions;
        integer_chip.range_chip().load_table(&mut layouter)?;

        layouter.assign_region(|| "BlobKZGCircuit Region", | region| {
            // FIRST ASSIGN ALL THE P(X) VALUES
                // d_i: Column<Advice>, // ordered function points
                // eval: Column<Advice>, // intermediate evaluation RESULT
                // wi: Column<Advice>,
            
                // x: Column<Advice>, // publc evaluation point
                // w: Column<Fixed>, // root of unity
                // n: Column<Fixed>, // root of unity order
            
                // xn: Column<Advice>, // exponentiation
                // x2i: Column<Advice>, // squarings for exponentiation
                // n_bits: Column<Fixed>, // bits of N for exponentiation

            let mut ctx = RegionCtx::new(region, 0);
            let assigned_x = assign_wrong_integer(&integer_chip, &mut ctx, self.x)?;
            let assigned_w = assign_wrong_integer(&integer_chip, &mut ctx, self.w)?;
            let assigned_zero = assign_wrong_integer(&integer_chip, &mut ctx, W::ZERO)?;
            let assigned_one = assign_wrong_integer(&integer_chip, &mut ctx, W::ONE)?;
            let assigned_n = assign_wrong_integer(&integer_chip, &mut ctx, self.n)?;

            let assigned_datapoints : Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>  = self.datapoints.iter().map(|d_i| { 
                let assigned_d_i = assign_wrong_integer(&integer_chip, &mut ctx, *d_i)?;
                ctx.next();
                Ok(assigned_d_i)
            }).collect::<Result<Vec<_>, Error>>()?;
            assert!(assigned_datapoints.len() == 4096);

            // ctx = RegionCtx::new(ctx.into_region(), 0);
            let assigned_wis: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = wis.iter().map(|w_i| { // limit: debug
                let assigned_w_i = assign_wrong_integer(&integer_chip, &mut ctx, *w_i)?;
                ctx.next();
                Ok(assigned_w_i)
            }).collect::<Result<Vec<_>, Error>>()?;
            assert!(assigned_wis.len() == 4096);

            // ctx = RegionCtx::new(ctx.into_region(), 0);
            let assigned_evals: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = evals.iter().map(|eval_i| {
                let assigned_eval_i = assign_wrong_integer(&integer_chip, &mut ctx, *eval_i)?;
                ctx.next();
                Ok(assigned_eval_i)
            }).collect::<Result<Vec<_>, Error>>()?;
            assert!(assigned_evals.len() == 4098);
            
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            let assigned_xns: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 257] = xns.iter().map(|x_i| {
                let assigned_x_i = assign_wrong_integer(&integer_chip, &mut ctx, *x_i)?;
                ctx.next();
                Ok(assigned_x_i)
            }).collect::<Result<Vec<_>, Error>>()?.try_into().unwrap();

            // ctx = RegionCtx::new(ctx.into_region(), 0);
            let assigned_x2is: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 256] = x2is.iter().map(|x2i| {
                let assigned_x2i = assign_wrong_integer(&integer_chip, &mut ctx, *x2i)?;
                ctx.next();
                Ok(assigned_x2i)
            }).collect::<Result<Vec<_>, Error>>()?.try_into().unwrap();

            // ctx = RegionCtx::new(ctx.into_region(), 0);
            let assigned_nbits: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 256] = nbits.iter().map(|nbit| {
                let assigned_nbit = assign_wrong_integer(&integer_chip, &mut ctx, *nbit)?;
                ctx.next();
                Ok(assigned_nbit)
            }).collect::<Result<Vec<_>, Error>>()?.try_into().unwrap();


            // THEN ADD ALL THE P(X) GATES BETWEEN THE ASSIGNED VALUES
                // q_first: Selector,

                // q_evalstep: Selector,
                // q_evallast: Selector,
                // q_wi: Selector,
                // q_xn: Selector,
                // q_xncopy: Selector,
                // q_x2i: Selector,
            // - FIRST eval=0, wi=w, xn=0, x2i=x
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            integer_chip.assert_equal(&mut ctx, &assigned_wis[0], &assigned_w)?;
            integer_chip.assert_equal(&mut ctx, &assigned_evals[0], &assigned_zero)?;
            integer_chip.assert_equal(&mut ctx, &assigned_xns[0], &assigned_one)?;
            integer_chip.assert_equal(&mut ctx, &assigned_x2is[0], &assigned_x)?;

            // - STEP eval
            // TODO: integer_chip operations (.mul, .sub) actually assigned NEW values to the circuit!!! how to fix? Because .assert_equal only seems to work between AssignedInteger<> values...
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            for i in 0..4096 {
                let eval_next = {
                    // TODO: should I remove the &s?
                    let (summand, _div_result) = {
                        let nominator = integer_chip.mul(&mut ctx, &assigned_datapoints[i], &assigned_wis[i])?;
                        let denominator = integer_chip.sub(&mut ctx, &assigned_x, &assigned_wis[i])?;
                        integer_chip.div(&mut ctx, &nominator, &denominator)?
                    };
                    // TODO: check _div_result?
                    integer_chip.add(&mut ctx, &assigned_evals[i], &summand)?
                };
                integer_chip.assert_equal(&mut ctx, &assigned_evals[i+1], &eval_next)?;
                // ctx.next();
            }
            // - LAST eval
            // TODO: is this correct with the ctx for 4096 but (last) xn for 256????
            {
                let eval_last = {
                    let (multiplier, _div_result) = {
                        let numerator = integer_chip.sub(&mut ctx, &assigned_xns[256], &assigned_one)?;
                        integer_chip.div(&mut ctx, &numerator, &assigned_n)?
                    };
                    integer_chip.mul(&mut ctx, &assigned_evals[4096], &multiplier)?
                };
                // ctx.next(); // WRONG????
                integer_chip.assert_equal(&mut ctx, &assigned_evals[4097], &eval_last)?;
            }

            // // - STEP w^i
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            for i in 0..4095 {
                let wi_next = integer_chip.mul(&mut ctx, &assigned_wis[i], &assigned_w)?;
                integer_chip.assert_equal(&mut ctx, &assigned_wis[i+1], &wi_next)?;
                // ctx.next();
            }

            // // - STEP x^N
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            for i in 0..256 {
                let xn_next = {
                    let multiplier = {
                        let important_bit = integer_chip.mul(&mut ctx, &assigned_x2is[i], &assigned_nbits[i])?;
                        let not_important_bit = integer_chip.sub(&mut ctx, &assigned_one, &assigned_nbits[i])?;
                        integer_chip.add(&mut ctx, &important_bit, &not_important_bit)?  
                    };
                    integer_chip.mul(&mut ctx, &assigned_xns[i], &multiplier)?
                };
                integer_chip.assert_equal(&mut ctx, &assigned_xns[i+1], &xn_next)?;
                // ctx.next();
            }

            // // - STEP x^(2^i)
            // ctx = RegionCtx::new(ctx.into_region(), 0);
            for i in 0..255 {
                let x2i_next = integer_chip.mul(&mut ctx, &assigned_x2is[i], &assigned_x2is[i])?;
                integer_chip.assert_equal(&mut ctx, &assigned_x2is[i+1], &x2i_next)?;
                // ctx.next();
            }
            Ok(())
            // TODO: check initial fixed values (nbits) are correct?
        })?;

        Ok(())
    }
}


type N = halo2_proofs::halo2curves::bn256::Fr; // Native Field
type W = halo2_proofs::halo2curves::bls12_381::Scalar; // Wrong Field
const ROOT_OF_UNITY: W = W::from_raw([
    0xb9b5_8d8c_5f0e_466a,
    0x5b1b_4c80_1819_d7ec,
    0x0af5_3ae3_52a3_1e64,
    0x5bf3_adda_19e9_b27b,
]);
const ROOT_OF_UNITY_ORDER: W = W::from_raw([
    0x0000_0000_0100_0000,
    0x0,
    0x0,
    0x0,
]);

fn main() {
    // use halo2_proofs::halo2curves::group::ff::PrimeField;
    // let (x,w,n, _marker) = (W::from(5), W::root_of_unity(), W::from(2_u64.pow(W::S)), std::marker::PhantomData::<N>);
    let (x, w, n, _marker) = (W::from(5), ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER, std::marker::PhantomData::<N>);
    println!("x: {x}, w: {w}, n: {n}, BLS_MODULUS: {}", <W as FieldExt>::MODULUS);
    let datapoints: [W; 4096] = std::array::from_fn(|i| W::from(i as u64 + 1));

    let circuit = BlobKZGCircuit::<W, N>{datapoints, x, w, n, _marker};
    // assert!(2_usize.pow(18) >= datapoints.len());
    let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
    println!("🥵🥵🥵 CIRCUIT TEST COMPLETED SUCCESSFULLY :-)")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn random_field_value() -> W {
        use halo2_proofs::arithmetic::Field;
        W::random(rand_core::OsRng)
    }

    #[test]
    fn random_datapoints() {
        let (x, w, n, _marker) = (W::from(5), ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER, std::marker::PhantomData::<N>);
        let datapoints: [W; 4096] = std::array::from_fn(|_| random_field_value());
        let circuit = super::BlobKZGCircuit::<W, N>{datapoints, x, w, n, _marker};
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    // #[test]
    // fn random_datapoints_10() {
    //     for _ in 0..10 {
    //         random_datapoints();
    //     }
    // }

    #[test]
    #[should_panic]
    fn wrong_x() {
        let (w, n, _marker) = (ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER, std::marker::PhantomData::<N>);
        let x = w*w*w;
        let datapoints: [W; 4096] = std::array::from_fn(|_| random_field_value());
        let circuit = super::BlobKZGCircuit::<W, N>{datapoints, x, w, n, _marker};
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_w() {
        let (x, w, n, _marker) = (W::from(5), random_field_value(), ROOT_OF_UNITY_ORDER, std::marker::PhantomData::<N>);
        let datapoints: [W; 4096] = std::array::from_fn(|_| random_field_value());
        let circuit = super::BlobKZGCircuit::<W, N>{datapoints, x, w, n, _marker};
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_n() {
        let (x, w, n, _marker) = (W::from(5), ROOT_OF_UNITY, random_field_value(), std::marker::PhantomData::<N>);
        let datapoints: [W; 4096] = std::array::from_fn(|_| random_field_value());
        let circuit = super::BlobKZGCircuit::<W, N>{datapoints, x, w, n, _marker};
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }
}