use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use halo2wrong_integer::{
    rns::Integer, rns::Rns, AssignedInteger, IntegerChip, IntegerConfig, IntegerInstructions,
    Range, UnassignedInteger,
};
use halo2wrong_maingate::RangeInstructions;
use halo2wrong_maingate::{MainGate, RangeChip, RegionCtx};

/// THIS CIRCUIT PERFORMS A NON-NATIVE FUNCTION EVAL USING BARYCENTRIC-FORMULA
/// P(X) = (const) * sum (d_i * (w^i/x-w^i)) where const = (x^N - 1)/N with w^N = 1 and X^N != 1 and N=4096
///
/// PURPOSE:
/// This circuit is meant to enable the zkEVM to take advantage of Ethereum's EIP-4844 upgrade, which
/// makes it possible to stash large and cheap amounts of data into the EVM in the form of a KZG commitment
/// to 4096 scalar values over the BLS12-381 curve. This would enable the zkEVM to store eg. up to 4096 txs
/// in a single commitment on the EVM, which can then be opened using EVM precompiles.
/// If the same data is also used in the zkEVM circuits, then the two are linked and the ZKP constraints are validated
/// over the same data. To prove that the same data is used in the zkEVM circuits, we could either do a commitment-equivalency
/// test over that data, or just take the witness data directly and make a function evaluation over it, which is what a KZG
/// commitment or opening does anyway.
/// Of course, since we skip the commitment-equivalency test, we must also show elsewhere that the constraints of the zkEVM
/// apply to this data, which is likely done by sharing the txs witness data across the circuits in the zkEVM.
///
/// INPUTS:
/// The circuit requires the 4096 BLS datapoints to interpolate, as well as the point to evaluate on. A 4096-th root
/// is already provided in the code (computed by me, change it with Ethereum's one if necessary), and internal witness
/// data is computed automatically (see testcases).
///
/// APPROACH:
/// We are going to be implementing the above formula to at the same time interpolate and evaluate over many points
/// of a polynomial. The computations need to be performed in a different, non-native field, which is why we make use of Halo2wrong.
/// We need to use non-native field constraints because we will use the precompiles for KZG openings embedded in the EVM, which 
/// are cheapest to use in a smart contract bridge but are defined over the BLS field, which is not what the zkEVM uses 
/// to verify the constraints of the zkEVM over the same data.
/// The circuit itself is designed to contain one very long "halo2wrong column" (ie multiple columns that together host
/// one single halo2wrong integer), and it contains multiple states that get updated over time: the accumulator state for
/// the final computation (eval), the accumulator for all iterating roots of unity (wis) needed in the summation, the
/// accumulator state for the exponentiation of the formula's constant (xns) along with the accumulators for its related
/// values (x2is and nbits). Furthermore, due to how halo2wrong builds its constraints upon basic Plonk main gates, for
/// every operation that needs to be performed to apply our constraints there is a new row added to the circuit.
///

#[derive(Clone, Debug)]
pub struct BlobKZGConfig {
    integer_config: IntegerConfig,
}

/// W is the wrong (non-native) field, N is the native field
/// The circuit is defined over the "native" zkEVM field, but the "wrong" field is used for the KZG precompiles on the actual EVM
#[derive(Debug)]
pub struct BlobKZGCircuit<W: PrimeField, N: PrimeField> {
    input_values: InputValues<W>,
    witness_values: WitnessValues<W>,
    _marker: std::marker::PhantomData<N>,
}

/// PUBLIC INPUT VALUES FOR OUR CIRCUIT:
/// x: evaluation point
/// w: root of unity
/// n: root of unity order
#[derive(Clone, Debug)]
struct InputValues<F: PrimeField> {
    datapoints: [F; NUMBER_OF_POINTS],
    x: F,
    w: F,
    n: F,
}

/// PRIVATE WITNESS VALUES FOR OUR CIRCUIT:
/// evals: intermediate evaluation results
/// wis: w^i for i in 0..4096 for evaluation
/// xns: x^n intermediate exponentiation results
/// x2is: x^(2^i) for i in 0...256 for exponentiation
/// nbits: bits of n (4096) for exponentiation
#[derive(Clone, Debug)]
struct WitnessValues<F: PrimeField> {
    evals: [F; 4098],
    wis: [F; 4096],
    xns: [F; 257],
    x2is: [F; 256],
    nbits: [F; 256],
}

impl<W: PrimeField, N: PrimeField> Default for BlobKZGCircuit<W, N> {
    fn default() -> Self {
        BlobKZGCircuit {
            input_values: InputValues::<W>::default(),
            witness_values: WitnessValues::<W>::default(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> Default for InputValues<F> {
    fn default() -> Self {
        InputValues {
            datapoints: [F::default(); NUMBER_OF_POINTS],
            x: F::default(),
            w: F::default(),
            n: F::default(),
        }
    }
}

impl<F: PrimeField> Default for WitnessValues<F> {
    fn default() -> Self {
        WitnessValues {
            evals: [F::default(); 4098],
            wis: [F::default(); 4096],
            xns: [F::default(); 257],
            x2is: [F::default(); 256],
            nbits: [F::default(); 256],
        }
    }
}
impl<W: PrimeField> WitnessValues<W> {
    /// COMPUTATION OF PRIVATE WITNESS DATA
    /// we have two main long computations:
    /// a. the eval step
    /// b. the xns step
    ///
    /// for the eval step we apply the main formula
    /// to the datapoints, requiring the intermediate
    /// rots of unity (wis) to be computed, as well as
    /// the final exponentiation x^n (xns) to be computed.
    ///
    /// for the xns step we compute the square-and-multiply
    /// algorithm, putting together all the possible powers
    /// (x2is) to be computed and all the exponent's bits
    /// (nbits) to be computed such that only the necessary powers
    /// of x are multiplied together.
    fn new(
        InputValues {
            datapoints,
            x,
            w,
            n,
        }: &InputValues<W>,
    ) -> WitnessValues<W> {
        let x2is: [W; 256] = {
            let mut x2is = [W::ZERO; 256];
            let mut state = *x;
            for x in &mut x2is {
                *x = state;
                state *= state;
            }
            x2is
        };
        // the following is a helper for the square-and-multiply algorithm
        // we are taking the least significant bits of the exponent first
        // so that we can pair them with the x2is powers of x
        let nbits: [W; 256] = {
            let mut nbits = [W::ZERO; 256];
            let nbits_bool: [bool; 256] = {
                let mut nbits_bool = [false; 256];
                let repr: [u8; 32] = n.to_repr().as_ref().try_into().expect("could not automatically convert Wrong Field vlaue to u8 array. Do this step manually maybe.");
                for (j, byte) in repr.iter().enumerate() {
                    for i in 0..8 {
                        nbits_bool[j * 8 + i] = ((byte >> i) & 1) == 1;
                    }
                }
                nbits_bool
            };

            for (x, b) in nbits.iter_mut().zip(nbits_bool.iter()) {
                if *b {
                    *x = W::ONE
                }
            }
            nbits
        };
        let xns: [W; 257] = {
            let mut xns = [W::ZERO; 257];
            let mut state = W::ONE;
            // this iteration only covers the first 256 values of xns, due to the zipping of x2is and nbits
            for (x, (x2i, nbit)) in xns.iter_mut().zip(x2is.iter().zip(nbits.iter())) {
                *x = state;
                state *= *x2i * *nbit + (W::ONE - *nbit);
            }
            xns[xns.len() - 1] = state;
            xns
        };
        let wis: [W; 4096] = {
            let mut wis = [W::ZERO; 4096];
            let mut state = *w;
            // let mut state = W::ONE;// TODO: correct but broken
            for x in &mut wis {
                *x = state;
                state *= w;
            }
            wis
        };
        let evals: [W; 4098] = {
            let mut evals = [W::ZERO; 4098];
            let mut state = W::ZERO;
            for (eval, (di, wi)) in evals.iter_mut().zip(datapoints.iter().zip(wis.iter())) {
                *eval = state;
                state += *di * *wi * (*x - *wi).invert().unwrap();
            }
            evals[evals.len() - 2] = state;
            let xn = xns[xns.len() - 1];
            evals[evals.len() - 1] = evals[evals.len() - 2] * (xn - W::ONE) * n.invert().unwrap();
            evals
        };

        WitnessValues {
            evals,
            wis,
            xns,
            x2is,
            nbits,
        }
    }
}

impl<W: PrimeField, N: PrimeField> BlobKZGCircuit<W, N> {
    fn new(input_values: InputValues<W>) -> Self {
        let witness_values = WitnessValues::<W>::new(&input_values);
        BlobKZGCircuit {
            input_values,
            witness_values,
            _marker: std::marker::PhantomData,
        }
    }
}

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

impl<W: PrimeField, N: PrimeField> Circuit<N> for BlobKZGCircuit<W, N> {
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
                let overflow_bit_lens =
                    Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct().overflow_lengths();
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

        BlobKZGConfig { integer_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        fn assign_wrong_integer<W: PrimeField, N: PrimeField>(
            integer_chip: &IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            ctx: &mut RegionCtx<N>,
            x: W,
        ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
            let rc_rns = std::rc::Rc::new(Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct());
            let integer = Integer::from_fe(x, rc_rns);
            let value = Value::known(integer);
            let unassigned_integer = UnassignedInteger::from(value);
            let assigned_integer =
                integer_chip.assign_integer(ctx, unassigned_integer, Range::Operand)?;
            Ok(assigned_integer)
        }

        let integer_chip = {
            let rc_rns = std::rc::Rc::new(Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct());
            IntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config.integer_config, rc_rns)
        };
        integer_chip.range_chip().load_table(&mut layouter)?;

        let InputValues {
            datapoints,
            x,
            w,
            n,
        } = self.input_values;
        let WitnessValues {
            evals,
            wis,
            xns,
            x2is,
            nbits,
        } = self.witness_values;

        // 0. JUST MAKE SURE X IS NOT IN THE ROOT-OF-UNITY DOMAIN (otherwise formula doesn't work)
        if xns[xns.len() - 1] == W::ONE {
            return Err(Error::Synthesis);
        }

        layouter.assign_region(
            || "BlobKZGCircuit Region",
            |region| {
                // 1. FIRST ASSIGN ALL THE WITNESSES/INPUTS
                let mut ctx = RegionCtx::new(region, 0);
                let assigned_x = assign_wrong_integer(&integer_chip, &mut ctx, x)?;
                ctx.next();
                let assigned_w = integer_chip.assign_constant(&mut ctx, w)?;
                ctx.next();
                let assigned_zero = integer_chip.assign_constant(&mut ctx, W::ZERO)?;
                ctx.next();
                let assigned_one = integer_chip.assign_constant(&mut ctx, W::ONE)?;
                ctx.next();
                let assigned_n = integer_chip.assign_constant(&mut ctx, n)?;
                ctx.next();
                let assigned_datapoints: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> =
                    datapoints
                        .iter()
                        .map(|d_i| {
                            let assigned_d_i = assign_wrong_integer(&integer_chip, &mut ctx, *d_i)?;
                            ctx.next();
                            Ok(assigned_d_i)
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                assert!(assigned_datapoints.len() == NUMBER_OF_POINTS);
                let assigned_wis: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = wis
                    .iter()
                    .map(|w_i| {
                        let assigned_w_i = assign_wrong_integer(&integer_chip, &mut ctx, *w_i)?;
                        ctx.next();
                        Ok(assigned_w_i)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                assert!(assigned_wis.len() == 4096);
                let assigned_evals: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> =
                    evals
                        .iter()
                        .map(|eval_i| {
                            let assigned_eval_i =
                                assign_wrong_integer(&integer_chip, &mut ctx, *eval_i)?;
                            ctx.next();
                            Ok(assigned_eval_i)
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                assert!(assigned_evals.len() == 4098);
                let assigned_xns: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 257] = xns
                    .iter()
                    .map(|x_i| {
                        let assigned_x_i = assign_wrong_integer(&integer_chip, &mut ctx, *x_i)?;
                        ctx.next();
                        Ok(assigned_x_i)
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .try_into()
                    .unwrap();
                let assigned_x2is: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 256] =
                    x2is.iter()
                        .map(|x2i| {
                            let assigned_x2i = assign_wrong_integer(&integer_chip, &mut ctx, *x2i)?;
                            ctx.next();
                            Ok(assigned_x2i)
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                        .try_into()
                        .unwrap();
                let assigned_nbits: [AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>; 256] =
                    nbits
                        .iter()
                        .map(|nbit| {
                            let assigned_nbit =
                                assign_wrong_integer(&integer_chip, &mut ctx, *nbit)?;
                            ctx.next();
                            Ok(assigned_nbit)
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                        .try_into()
                        .unwrap();

                // 2. ADD CONSTRAINTS FOR PUBLIC INPUTS (eval=0, wi=w, xn=0, x2i=x)
                integer_chip.assert_equal(&mut ctx, &assigned_wis[0], &assigned_w)?;
                integer_chip.assert_equal(&mut ctx, &assigned_evals[0], &assigned_zero)?;
                integer_chip.assert_equal(&mut ctx, &assigned_xns[0], &assigned_one)?;
                integer_chip.assert_equal(&mut ctx, &assigned_x2is[0], &assigned_x)?;

                // 3. ADD CONSTRAINTS FOR INTERMEDIATE EVALUATION STEPS
                for i in 0..4096 {
                    let eval_next = {
                        let (summand, _) = {
                            let nominator = integer_chip.mul(
                                &mut ctx,
                                &assigned_datapoints[i],
                                &assigned_wis[i],
                            )?;
                            ctx.next();
                            let denominator =
                                integer_chip.sub(&mut ctx, &assigned_x, &assigned_wis[i])?;
                            ctx.next();
                            integer_chip.div(&mut ctx, &nominator, &denominator)?
                        };
                        ctx.next();
                        integer_chip.add(&mut ctx, &assigned_evals[i], &summand)?
                    };
                    ctx.next();
                    integer_chip.assert_equal(&mut ctx, &assigned_evals[i + 1], &eval_next)?;
                }
                // check last step separately as it's a special case
                {
                    let eval_last = {
                        let (multiplier, _) = {
                            let numerator =
                                integer_chip.sub(&mut ctx, &assigned_xns[256], &assigned_one)?;
                            ctx.next();
                            integer_chip.div(&mut ctx, &numerator, &assigned_n)?
                        };
                        ctx.next();
                        integer_chip.mul(&mut ctx, &assigned_evals[4096], &multiplier)?
                    };
                    ctx.next();
                    integer_chip.assert_equal(&mut ctx, &assigned_evals[4097], &eval_last)?;
                }

                // 3. ADD CONSTRAINTS FOR EACH ROOT OF UNITY STEP
                for i in 0..4095 {
                    let wi_next = integer_chip.mul(&mut ctx, &assigned_wis[i], &assigned_w)?;
                    ctx.next();
                    integer_chip.assert_equal(&mut ctx, &assigned_wis[i + 1], &wi_next)?;
                }

                // 4. ADD CONSTRAINTS FOR INTERMEDIATE EXPONENTIATION STEPS
                for i in 0..256 {
                    let xn_next = {
                        let multiplier = {
                            let important_bit = integer_chip.mul(
                                &mut ctx,
                                &assigned_x2is[i],
                                &assigned_nbits[i],
                            )?;
                            ctx.next();
                            let not_important_bit =
                                integer_chip.sub(&mut ctx, &assigned_one, &assigned_nbits[i])?;
                            ctx.next();
                            integer_chip.add(&mut ctx, &important_bit, &not_important_bit)?
                        };
                        ctx.next();
                        integer_chip.mul(&mut ctx, &assigned_xns[i], &multiplier)?
                    };
                    ctx.next();
                    integer_chip.assert_equal(&mut ctx, &assigned_xns[i + 1], &xn_next)?;
                }

                // 5. ADD CONSTRAINTS FOR EACH x^(2^i) STEP
                for i in 0..255 {
                    let x2i_next =
                        integer_chip.mul(&mut ctx, &assigned_x2is[i], &assigned_x2is[i])?;
                    ctx.next();
                    integer_chip.assert_equal(&mut ctx, &assigned_x2is[i + 1], &x2i_next)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Native Field (likely BN256)
type N = halo2_proofs::halo2curves::bn256::Fr;

/// Wrong Field (BLS12-381)
type W = halo2_proofs::halo2curves::bls12_381::Scalar;

/// ROOT OF UNITY WITH ORDER 4096: 0x564c_0a11_a0f7_04f4_fc3e_8acf_e0f8_245f_0ad1_347b_378f_bf96_e206_da11_a5d3_6306
const ROOT_OF_UNITY: W = W::from_raw([
    0xe206_da11_a5d3_6306,
    0x0ad1_347b_378f_bf96,
    0xfc3e_8acf_e0f8_245f,
    0x564c_0a11_a0f7_04f4,
]);
const ROOT_OF_UNITY_ORDER: W = W::from_raw([0x1000, 0x0, 0x0, 0x0]);

const NUMBER_OF_POINTS: usize = 4096;

fn main() {
    let datapoints: [W; NUMBER_OF_POINTS] = std::array::from_fn(|i| W::from(i as u64 + 1));
    let input_values = InputValues {
        datapoints,
        x: W::from(5),
        w: ROOT_OF_UNITY,
        n: ROOT_OF_UNITY_ORDER,
    };
    let circuit = BlobKZGCircuit::<W, N>::new(input_values);
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
    use rand::Rng;

    #[test]
    fn try_default() {
        let datapoints = std::array::from_fn(|i| W::from(i as u64 + 1));
        let input_values = InputValues {
            datapoints,
            x: W::from(5),
            w: ROOT_OF_UNITY,
            n: ROOT_OF_UNITY_ORDER,
        };
        let circuit = BlobKZGCircuit::<W, N>::new(input_values);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn try_random_datapoints() {
        let datapoints = std::array::from_fn(|_| random_field_value());
        let input_values = InputValues {
            datapoints,
            x: W::from(5),
            w: ROOT_OF_UNITY,
            n: ROOT_OF_UNITY_ORDER,
        };
        let circuit = BlobKZGCircuit::<W, N>::new(input_values);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_x() {
        // TRY EVALUATION INSIDE THE ROOT OF UNITY DOMAIN
        let datapoints = std::array::from_fn(|i| W::from(i as u64 + 1));
        let x = ROOT_OF_UNITY * ROOT_OF_UNITY * ROOT_OF_UNITY;
        let input_values = InputValues {
            datapoints,
            x,
            w: ROOT_OF_UNITY,
            n: ROOT_OF_UNITY_ORDER,
        };
        let circuit = BlobKZGCircuit::<W, N>::new(input_values);
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn wrong_witness_data() {
        let datapoints = std::array::from_fn(|i| W::from(i as u64 + 1));
        let input_values = InputValues {
            datapoints,
            x: W::from(5),
            w: ROOT_OF_UNITY,
            n: ROOT_OF_UNITY_ORDER,
        };
        let mut witness_values = WitnessValues::new(&input_values);
        let mut rng = rand::thread_rng();
        if (rng.gen::<u8>() % 2) == 1 {
            let taint_index = rng.gen::<usize>() % 4098;
            witness_values.evals[taint_index] = random_field_value();
        }
        if rng.gen::<bool>() {
            let taint_index = rng.gen::<usize>() % 4096;
            witness_values.wis[taint_index] = random_field_value();
        }
        if rng.gen::<bool>() {
            let taint_index = rng.gen::<usize>() % 257;
            witness_values.xns[taint_index] = random_field_value();
        }
        if rng.gen::<bool>() {
            let taint_index = rng.gen::<usize>() % 256;
            witness_values.x2is[taint_index] = random_field_value();
        }
        if rng.gen::<bool>() {
            let taint_index = rng.gen::<usize>() % 256;
            witness_values.nbits[taint_index] = random_field_value();
        }
        let circuit = BlobKZGCircuit {
            input_values,
            witness_values,
            _marker: std::marker::PhantomData::<N>,
        };
        let prover = halo2_proofs::dev::MockProver::<N>::run(20, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }
}
