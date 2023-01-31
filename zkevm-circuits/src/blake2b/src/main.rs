extern crate halo2_proofs;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation, dev::MockProver, halo2curves::bn256::Fr};
use std::{marker::PhantomData, array, convert::TryInto};

fn gf<F:FieldExt>(n: u64) -> Expression<F> {
    Expression::Constant(F::from(n))
}

fn advices_to_number<F:FieldExt>(meta: &mut VirtualCells<F>, columns: &[Column<Advice>]) -> Expression<F> {
    columns.iter().map(|c| meta.query_advice(*c, Rotation::cur())).
        rfold(gf(0), |e, b| { e * gf(256) + b })
}

fn set_byte_witnesses<F:FieldExt, const N:usize>(region: &mut Region<F>, name: &str, 
    row: usize, columns: &[Column<Advice>; N], bytes: &[u8; N]) -> Result<(), Error> {
        for (c, b) in columns.iter().zip(bytes.iter())  { 
            region.assign_advice(|| name, *c, row, || Value::known(F::from(*b as u64)))?;
        }
        return Ok(());
}

fn set_max_lookup<F:FieldExt>(region: &mut Region<F>, table: Column<Fixed>, max: u16) -> Result<(), Error> {
    for r in 0..=max {
        region.assign_fixed(|| format!("[0..{}] lookup table, row {}", max, r), table, r as usize, || Value::known(F::from(r as u64)))?;
    }
    return Ok(());
}

fn constrain_to_set<F:FieldExt>(meta: &mut ConstraintSystem<F>, table: Column<Fixed>, selector: Column<Fixed>, column: Column<Advice>) {
    meta.lookup_any("Set constraint", |meta| {
        let selector = meta.query_fixed(selector, Rotation::cur());
        return vec![(selector.clone() * meta.query_advice(column, Rotation::cur()), meta.query_fixed(table, Rotation::cur()))];
    });
}

fn constrain_to_bit<F:FieldExt>(meta: &mut ConstraintSystem<F>, selector: Column<Fixed>, column: Column<Advice>) {
    meta.create_gate("Bit constraint", |meta| {
        let selector = meta.query_fixed(selector, Rotation::cur());
        let bit = meta.query_advice(column, Rotation::cur());
        return vec![selector * bit.clone() * (gf(1) - bit)];
    });
}

fn set_byte_xor_lookup<F:FieldExt>(region: &mut Region<F>, table: &[Column<Fixed>; 3]) -> Result<(), Error> {
    for r in 0..65536 {
        let (first, second) = (r as u64 & 0xFF, r as u64 >> 8);
        region.assign_fixed(|| format!("Xor lookup table, row {}, the first", r), table[0], r, || Value::known(F::from(first)))?;
        region.assign_fixed(|| format!("Xor lookup table, row {}, the second", r), table[1], r, || Value::known(F::from(second)))?;
        region.assign_fixed(|| format!("Xor lookup table, row {}, the result", r), table[2], r, || Value::known(F::from(first ^ second)))?;
    }
    return Ok(());
}

fn constrain_to_byte_xor<F:FieldExt>(meta: &mut ConstraintSystem<F>, table: &[Column<Fixed>; 3], 
    selector: Column<Fixed>, first: Column<Advice>, second: Column<Advice>, result: Column<Advice>) {
        meta.lookup_any("Byte xor constraint", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            return vec![
                (selector.clone() * meta.query_advice(first, Rotation::cur()), meta.query_fixed(table[0], Rotation::cur())),
                (selector.clone() * meta.query_advice(second, Rotation::cur()), meta.query_fixed(table[1], Rotation::cur())),
                (selector.clone() * meta.query_advice(result, Rotation::cur()), meta.query_fixed(table[2], Rotation::cur()))];
        });
}

fn set_result_and_activate<F:FieldExt, const N:usize >(region: &mut Region<F>, name: &str, 
    row: usize, selector: Column<Fixed>, columns: &[Column<Advice>; N], result: u128) -> Result<(), Error> {
        set_byte_witnesses(region, &format!("{}, result", name), row, columns, result.to_le_bytes()[0..N].try_into().unwrap())?;     
        region.assign_fixed(|| format!("{}, selector", name), selector, row, || Value::known(F::one()))?;
        return Ok(());
}

#[derive(Debug, Clone)]
struct AddGate<F:FieldExt, const S:usize>{
    pub name: &'static str,
    pub selector: Column<Fixed>,
    pub bytes: Column<Fixed>,
    pub summands: [[Column<Advice>; 8]; S],
    pub sum: [Column<Advice>; 9],
    _marker: PhantomData<F>
}

impl<F:FieldExt, const S:usize> AddGate<F, S> {
    fn configure(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate(self.name, |meta| {
            let selector = meta.query_fixed(self.selector, Rotation::cur());
            let left = self.summands.iter().map(|s| advices_to_number(meta, s)).fold(gf(0), |e, s| e + s);
            let right = advices_to_number(meta, &self.sum);
            return vec![selector * (left - right)];
        });
        
        self.sum.iter().for_each(|c| constrain_to_set(meta, self.bytes, self.selector, *c));
    }

    fn put(&self, region: &mut Region<F>, row: usize, summands: [u64; S]) -> Result<u64, Error>{
        let name = format!("Gate {}, row {}", self.name, row);
        let sum = summands.iter().fold(0, |r, s| r  + (*s as u128));
        set_result_and_activate(region, &name, row, self.selector, &self.sum, sum)?;
        return Ok(sum as u64);
    }
}

#[derive(Debug, Clone)]
struct XorShiftByteGate<F:FieldExt, const S:usize>{
    pub name: &'static str,
    pub selector: Column<Fixed>,
    pub lookup: [Column<Fixed>; 3],
    pub first: [Column<Advice>; 8],
    pub second: [Column<Advice>; 8],   
    pub result: [Column<Advice>; 8],
    _marker: PhantomData<F>
}

impl<F:FieldExt, const S:usize> XorShiftByteGate<F, S> {
    fn configure(&self, meta: &mut ConstraintSystem<F>) {
        for i in 0..8 {
            let position = (i + 8 - S) % 8;
            constrain_to_byte_xor(meta, &self.lookup, self.selector, self.first[i], self.second[i], self.result[position]);
        }
    }

    fn put(&self, region: &mut Region<F>, row: usize, first: u64, second: u64) -> Result<u64, Error>{
        let name = format!("Gate {}, row {}", self.name, row);
        let result = (first ^ second).rotate_right(S as u32 * 8) as u128;
        set_result_and_activate(region, &name, row, self.selector, &self.result, result)?;
        return Ok(result as u64);
    }
}

#[derive(Debug, Clone)]
struct Shift63Gate<F:FieldExt>{
    pub name: &'static str,
    pub selector: Column<Fixed>,
    pub bytes: Column<Fixed>,
    pub septets: Column<Fixed>,
    pub bit: Column<Advice>,
    pub septet: Column<Advice>,
    pub input: [Column<Advice>; 8],
    pub result: [Column<Advice>; 8],   
    _marker: PhantomData<F>
}

impl<F:FieldExt> Shift63Gate<F> {
    fn configure(&self, meta: &mut ConstraintSystem<F>) {
        constrain_to_bit(meta, self.septets, self.bit);
        constrain_to_set(meta, self.septets, self.selector, self.septet);
        self.result.iter().for_each(|c| constrain_to_set(meta, self.bytes, self.selector, *c));
        
        meta.create_gate(self.name, |meta| {
            let selector = meta.query_fixed(self.selector, Rotation::cur());
            let septet = meta.query_advice(self.septet, Rotation::cur());
            let bit = meta.query_advice(self.bit, Rotation::cur());
            let high = meta.query_advice(self.input[7], Rotation::cur());

            let byte = bit.clone() * gf(128) + septet.clone();
            let left = septet * gf(1 << 57) + advices_to_number(meta, &self.input[0..7]) * gf(2) + bit;
            let right = advices_to_number(meta, &self.result);           

            return vec![selector.clone() * (byte - high), selector * (left - right)];
        });
    }

    fn put(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let name = format!("Gate {}, row {}", self.name, row);
        region.assign_advice(|| format!("{}, septet", name), self.septet, row, || Value::known(F::from((input >> 56) & 0x7F)))?;
        region.assign_advice(|| format!("{}, bit", name), self.bit, row, || Value::known(F::from(input >> 63)))?;

        let result = input.rotate_right(63) as u128;
        set_result_and_activate(region, &name, row, self.selector, &self.result, result)?;
        return Ok(result as u64);
    }
}

#[derive(Debug, Clone)]
struct TestGatesConfig<F:FieldExt>{
    pub add_3_gate: AddGate<F, 3>,
    pub xor_shift_32_gate: XorShiftByteGate<F, 4>,
    pub shift_63_gate: Shift63Gate<F>
}

#[derive(Default)]
struct TestGatesCircuit<F:FieldExt> {
     pub x: u64,
     pub y: u64,
     pub z: u64,
    _marker:PhantomData<F>
}

impl<F: FieldExt> Circuit<F> for TestGatesCircuit<F> {
    type Config = TestGatesConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {      
        let bytes = meta.fixed_column();
        let first: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        let second: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        let third: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());
        let sum: [Column<Advice>; 9] = array::from_fn(|_| meta.advice_column());
      
        let add_3_gate = AddGate::<F, 3> {
            name: "Add3Gate",
            selector: meta.fixed_column(),
            bytes: bytes,
            summands: [first, second, third],
            sum: sum,
            _marker: PhantomData
        };

        add_3_gate.configure(meta);

        let byte_xor_lookup: [Column<Fixed>; 3] = array::from_fn(|_| meta.fixed_column());
        let xor_shift_32_result: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let xor_shift_32_gate = XorShiftByteGate::<F, 4> {
            name: "XorShift32Gate",
            selector: meta.fixed_column(),
            lookup: byte_xor_lookup,
            first: first,
            second: second,
            result: xor_shift_32_result,
            _marker: PhantomData
        };

        xor_shift_32_gate.configure(meta);

        let shift_63_result: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let shift_63_gate = Shift63Gate::<F> {
            name: "Shift63Gate",
            selector: meta.fixed_column(),
            bytes: bytes,
            septets: meta.fixed_column(),
            bit: meta.advice_column(),
            septet: meta.advice_column(),
            input: xor_shift_32_result,
            result: shift_63_result,  
            _marker: PhantomData
        };

        shift_63_gate.configure(meta);


        return TestGatesConfig {add_3_gate, xor_shift_32_gate, shift_63_gate}; 
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(|| "Blake2b",
            |mut region| {
                set_max_lookup(&mut region, config.add_3_gate.bytes, 255)?;
                set_max_lookup(&mut region, config.shift_63_gate.septets, 127)?;
                set_byte_xor_lookup(&mut region, &config.xor_shift_32_gate.lookup)?;

                set_byte_witnesses(&mut region, "x_value", 0, &config.add_3_gate.summands[0], &self.x.to_le_bytes().try_into().unwrap())?;
                set_byte_witnesses(&mut region, "y_value", 0, &config.add_3_gate.summands[1],&self.y.to_le_bytes().try_into().unwrap())?;
                set_byte_witnesses(&mut region, "z_value", 0, &config.add_3_gate.summands[2], &self.z.to_le_bytes().try_into().unwrap())?;

                let sum = config.add_3_gate.put(&mut region, 0, [self.x, self.y, self.z])?;
                println!("Sum mod 2^64 is {}", sum);

                let xor = config.xor_shift_32_gate.put(&mut region, 0, self.x, self.y)?;
                println!("Xor shift 32 is {}", xor);

                let shift63 = config.shift_63_gate.put(&mut region, 0, xor)?;
                println!("Shift 63 is {}", shift63);
                Ok(())                
            }
        )?;

        Ok(())
    }
}

fn main() {
    let circuit = TestGatesCircuit::<Fr> {
        x: 1u64 << 63, y: 23334342, z: 34333434,
        _marker: PhantomData,
    };

    let prover = MockProver::run(18, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}