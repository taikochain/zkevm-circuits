use halo2_proofs::plonk::{ConstraintSystem,Circuit, Error};
use halo2_proofs::circuit::{Layouter,SimpleFloorPlanner,Value};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2wrong_integer::{IntegerConfig, rns::Rns, IntegerChip, IntegerInstructions, rns::Integer, UnassignedInteger, Range, AssignedInteger};
use halo2wrong_maingate::{RangeChip, MainGate, RegionCtx};

/// THIS CIRCUIT PERFORMS A NON-NATIVE FUNCTION EVAL USING BARYCENTRIC-FORMULA
/// P(X) = (const) * sum (d_i * (w^i/x-w^i)) where const = (x^N - 1)/N with w^N = 1 and X^N != 1

#[derive(Clone, Debug)]
pub struct BlobKZGConfig {
    integer_config: IntegerConfig
}

#[derive(Debug)]
pub struct BlobKZGCircuit<W: PrimeField, N: PrimeField>{ // W is the wrong field, N is the native field
    datapoints: [W; 4096],
    x: W, 
    w: W,
    n: W,
    witness_values: WitnessValues<W>,
    _marker: std::marker::PhantomData<N>
}

impl<W: PrimeField, N:PrimeField> Default for BlobKZGCircuit<W,N> {
    fn default() -> Self {
        BlobKZGCircuit { datapoints: [W::default();4096], x: W::default(), w: W::default(), n: W::default(), witness_values: WitnessValues::<W>::default(), _marker: std::marker::PhantomData }
    }
}
#[derive(Clone, Debug)]
struct WitnessValues<F: PrimeField>{
    evals: [F;4098],
    wis: [F;4096],
    xns: [F;257],
    x2is: [F;256],
    nbits: [F;256] 
}
impl<F: PrimeField> Default for WitnessValues<F> {
    fn default() -> Self {
        WitnessValues { evals: [F::default();4098], wis: [F::default();4096], xns: [F::default();257], x2is: [F::default();256], nbits: [F::default();256] }
    }
}
impl<W: PrimeField> WitnessValues<W> {
    fn new(x:&W, n:&W, w:&W, datapoints: &[W; 4096]) -> WitnessValues<W> {
        let x2is: [W; 256] = {
            let mut x2is = [W::default(); 256];
            let mut state = *x;
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
                let repr: [u8; 32] = n.to_repr().as_ref().try_into().unwrap();
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
        let wis: [W; 4096] = {
            let mut wis = [W::default(); 4096];
            let mut state = *w;
            for x in &mut wis {
                *x = state;
                state *= w;
            }
            wis
        };
        let evals: [W; 4098] = {
            let mut evals = [W::default(); 4098];
            let mut state = W::ZERO;
            for (eval, (di, wi)) in evals.iter_mut().zip(datapoints.iter().zip(wis.iter())) {
                *eval = state;
                state += *di * *wi * (*x-*wi).invert().unwrap();
            }
            evals[evals.len() - 2] = state;
            let xn = xns[xns.len() - 1];
            evals[evals.len() - 1] = evals[evals.len() - 2] * (xn - W::ONE) * n.invert().unwrap();
            evals
        };
        
        WitnessValues{
            evals,
            wis,
            xns,
            x2is,
            nbits
        }
    }

}

impl<W: PrimeField, N:PrimeField> BlobKZGCircuit<W,N> {
    fn new(datapoints: [W;4096], x: W, w: W, n: W) -> Self {
        BlobKZGCircuit { datapoints, x, w, n, witness_values: WitnessValues::<W>::new(&x, &n, &w, &datapoints),_marker: std::marker::PhantomData }
    }
}

impl<W: PrimeField, N:PrimeField> Circuit<N> for BlobKZGCircuit<W,N> {
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
                let overflow_bit_lens = Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct().overflow_lengths();
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
        fn assign_wrong_integer<W: PrimeField, N: PrimeField>(
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

        let WitnessValues{evals, wis, xns, x2is, nbits}: WitnessValues<W> = self.witness_values;
        // MAKE SURE X IS NOT IN THE ROOT-OF-UNITY DOMAIN
        if xns[xns.len()-1] == W::ONE { 
            return Err(Error::Synthesis);
        }
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


type N = halo2_proofs::halo2curves::bn256::Fr; // Native Field (BN256)
type W = halo2_proofs::halo2curves::bls12_381::Scalar; // Wrong Field (BLS12-381)
// ROOT OF UNITY WITH ORDER 4096: 0x564c_0a11_a0f7_04f4_fc3e_8acf_e0f8_245f_0ad1_347b_378f_bf96_e206_da11_a5d3_6306
const ROOT_OF_UNITY: W = W::from_raw([0xe206_da11_a5d3_6306, 0x0ad1_347b_378f_bf96, 0xfc3e_8acf_e0f8_245f, 0x564c_0a11_a0f7_04f4]);
const ROOT_OF_UNITY_ORDER: W = W::from_raw([0x1000, 0x0, 0x0, 0x0]);

fn main() {
    let datapoints: [W; 4096] = std::array::from_fn(|i| W::from(i as u64 + 1));
    let circuit = BlobKZGCircuit::<W, N>::new(datapoints, W::from(5), ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER);
    let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
}

#[cfg(test)]
mod tests {
    use super::*;
    fn random_field_value() -> W {
        use halo2_proofs::arithmetic::Field;
        W::random(rand_core::OsRng)
    }

    lazy_static::lazy_static! {
        static ref DEFAULT_DATAPOINTS: [W; 4096] = std::array::from_fn(|i| W::from(i as u64 + 1));
        static ref RANDOM_DATAPOINTS: [W; 4096] = std::array::from_fn(|_| random_field_value());
        static ref DEFAULT_X: W = W::from(5);
        static ref RANDOM_VALUE: W = random_field_value();
    }


    #[test]
    fn try_default() {
        let circuit = super::BlobKZGCircuit::<W, N>::new(*DEFAULT_DATAPOINTS, *DEFAULT_X, ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn try_random_datapoints() {
        let circuit = super::BlobKZGCircuit::<W, N>::new(*RANDOM_DATAPOINTS, *DEFAULT_X, ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_x() {
        // TRY EVALUATION INSIDE THE ROOT OF UNITY DOMAIN
        let circuit = super::BlobKZGCircuit::<W, N>::new(*DEFAULT_DATAPOINTS, ROOT_OF_UNITY*ROOT_OF_UNITY*ROOT_OF_UNITY, ROOT_OF_UNITY, ROOT_OF_UNITY_ORDER);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_w() {
        // TRY EVALUATION WITH A NON ROOT OF UNITY
        let circuit = super::BlobKZGCircuit::<W, N>::new(*DEFAULT_DATAPOINTS, *DEFAULT_X, *RANDOM_VALUE, ROOT_OF_UNITY_ORDER);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_n() {
        // TRY EVALUATION WITH A DIFFERENT ROOT OF UNITY ORDER
        let circuit = super::BlobKZGCircuit::<W, N>::new(*DEFAULT_DATAPOINTS, *DEFAULT_X, ROOT_OF_UNITY, *RANDOM_VALUE);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn wrong_witness_data() {
        unimplemented!(); // TODO
    }
}