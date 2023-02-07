extern crate halo2_proofs;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation, dev::MockProver, halo2curves::bn256::Fr};
use std::{marker::PhantomData, array, convert::TryInto};

fn gf<F:FieldExt>(n: u64) -> Expression<F> {
    Expression::Constant(F::from(n))
}

fn array_refs_from_slice<T, const S: usize, const L: usize>(slice: &[T]) -> [&[T; S]; L] {
    array::from_fn(|i| slice[S * i..][..S].try_into().unwrap())
}

fn byte_cells_to_number<F:FieldExt>(meta: &mut VirtualCells<F>, cells: &[ACell<F>]) -> Expression<F> {
    cells.iter().map(|c| c.express(meta)).rfold(gf(0), |e, b| { e * gf(256) + b })
}

fn set_byte_witnesses<F:FieldExt, const N:usize>(region: &mut Region<F>, name: &str, 
    row: usize, cells: &[ACell<F>; N], bytes: &[u8; N]) -> Result<(), Error> {
        for (c, b) in cells.iter().zip(bytes.iter())  { 
            region.assign_advice(|| name, c.column, row + (c.offset as usize), || Value::known(F::from(*b as u64)))?;
        }
        return Ok(());
}

fn set_max_lookup<F:FieldExt>(region: &mut Region<F>, table: Column<Fixed>, max: u16) -> Result<(), Error> {
    for r in 0..=max {
        region.assign_fixed(|| format!("[0..{}] lookup table, row {}", max, r), table, r as usize, || Value::known(F::from(r as u64)))?;
    }
    return Ok(());
}

fn constrain_to_set<F:FieldExt>(meta: &mut ConstraintSystem<F>, table: Column<Fixed>, selector: Column<Fixed>, cell: ACell<F>) {
    meta.lookup_any("Set constraint", |meta| {
        let selector = meta.query_fixed(selector, Rotation::cur());
        return vec![(selector.clone() * cell.express(meta), meta.query_fixed(table, Rotation::cur()))];
    });
}

fn constrain_to_bit<F:FieldExt>(meta: &mut ConstraintSystem<F>, selector: Column<Fixed>, cell: ACell<F>) {
    meta.create_gate("Bit constraint", |meta| {
        let selector = meta.query_fixed(selector, Rotation::cur());
        let bit = cell.express(meta);
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
    selector: Column<Fixed>, first: ACell<F>, second: ACell<F>, result: ACell<F>) {
        meta.lookup_any("Byte xor constraint", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            return vec![
                (selector.clone() * first.express(meta), meta.query_fixed(table[0], Rotation::cur())),
                (selector.clone() * second.express(meta), meta.query_fixed(table[1], Rotation::cur())),
                (selector.clone() * result.express(meta), meta.query_fixed(table[2], Rotation::cur()))];
        });
}

fn set_result_and_activate<F:FieldExt, const N:usize >(region: &mut Region<F>, name: &str, 
    row: usize, selector: Column<Fixed>, cells: &[ACell<F>; N], result: u128) -> Result<(), Error> {
        set_byte_witnesses(region, &format!("{}, result", name), row, cells, result.to_le_bytes()[0..N].try_into().unwrap())?;     
        region.assign_fixed(|| format!("{}, selector", name), selector, row, || Value::known(F::one()))?;
        return Ok(());
}

#[derive(Debug, Copy, Clone)]
struct ACell<F:FieldExt> {
    pub column: Column<Advice>,
    pub offset: u16,
    _marker: PhantomData<F>
}

impl<F:FieldExt> ACell<F> {
    fn express(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset as i32))
    }
}

type U64ACells<F> = [ACell<F>; 8];

#[derive(Debug, Clone)]
struct AddGate<F:FieldExt, const S:usize>{
    pub selector: Column<Fixed>,
    pub sum: [ACell<F>; 9],
}

impl<F:FieldExt, const S:usize> AddGate<F, S> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selector: Column<Fixed>, 
                 bytes: Option<Column<Fixed>>, 
                 summands: &[&U64ACells<F>; S], 
                 result: &U64ACells<F>,
                 carry: ACell<F>) -> Self {
        let mut sum = result.to_vec(); sum.push(carry);

        meta.create_gate("AddGate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let left = summands.iter().map(|s| byte_cells_to_number(meta, *s)).fold(gf(0), |e, s| e + s);
            let right = byte_cells_to_number(meta, &sum);
            return vec![selector * (left - right)];
        });
        
        if let Some(b) = bytes { sum.iter().for_each(|c| constrain_to_set(meta, b, selector, *c)); }

        return AddGate {selector, sum: sum.try_into().unwrap() };
    }

    fn put(&self, region: &mut Region<F>, row: usize, summands: &[u64; S]) -> Result<u64, Error>{
        let name = format!("AddGate, {} row", row);
        let sum = summands.iter().fold(0, |r, s| r  + (*s as u128));
        set_result_and_activate(region, &name, row, self.selector, &self.sum, sum)?;
        return Ok(sum as u64);
    }
}

#[derive(Debug, Clone)]
struct XorShiftByteGate<F:FieldExt, const S:usize>{
    pub selector: Column<Fixed>, 
    pub result: U64ACells<F>,
}

impl<F:FieldExt, const S:usize> XorShiftByteGate<F, S> {
    fn configure(meta: &mut ConstraintSystem<F>, 
                 selector: Column<Fixed>, 
                 xlookup: &[Column<Fixed>; 3],
                 first: &U64ACells<F>,
                 second: &U64ACells<F>, 
                 result: &U64ACells<F>) -> Self  {
        for i in 0..8 {
            let position = (i + 8 - S) % 8;
            constrain_to_byte_xor(meta, xlookup, selector, first[i], second[i], result[position]);
        }

        return XorShiftByteGate { selector, result: *result };
    }

    fn put(&self, region: &mut Region<F>, row: usize, first: u64, second: u64) -> Result<u64, Error> {
        let name = format!("XorShiftByteGate, {} row", row);
        let result = (first ^ second).rotate_right(S as u32 * 8) as u128;
        set_result_and_activate(region, &name, row, self.selector, &self.result, result)?;
        return Ok(result as u64);
    }
}

#[derive(Debug, Clone)]
struct Shift63Gate<F:FieldExt>{
    pub selector: Column<Fixed>,
    pub bit: ACell<F>,
    pub septet: ACell<F>,
    pub result: U64ACells<F>
}

impl<F:FieldExt> Shift63Gate<F> {
    fn configure(meta: &mut ConstraintSystem<F>, 
                 selector: Column<Fixed>,
                 bytes: Column<Fixed>,
                 septets: Column<Fixed>,
                 input: &U64ACells<F>,
                 result: &U64ACells<F>,
                 septet: ACell<F>,
                 bit: ACell<F>) -> Self {
        constrain_to_bit(meta, selector, bit);
        constrain_to_set(meta, septets, selector, septet);
        result.iter().for_each(|c| constrain_to_set(meta, bytes, selector, *c));
        
        meta.create_gate("Shift63Gate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let septet = septet.express(meta);
            let bit = bit.express(meta);
            let high = input[7].express(meta);

            let byte = bit.clone() * gf(128) + septet.clone();
            let left = septet * gf(1 << 57) + byte_cells_to_number(meta, &input[0..7]) * gf(2) + bit;
            let right = byte_cells_to_number(meta, result);           

            return vec![selector.clone() * (byte - high), selector * (left - right)];
        });

        return Shift63Gate { selector, bit, septet, result: *result};
    }

    fn put(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let name = format!("Shift63Gate, {} row", row);
        region.assign_advice(|| format!("{}, septet", name), self.septet.column, 
            row + (self.septet.offset as usize), || Value::known(F::from((input >> 56) & 0x7F)))?;
        region.assign_advice(|| format!("{}, bit", name), self.bit.column, 
            row + (self.bit.offset as usize), || Value::known(F::from(input >> 63)))?;

        let result = input.rotate_right(63) as u128;
        set_result_and_activate(region, &name, row, self.selector, &self.result, result)?;
        return Ok(result as u64);
    }
}

#[derive(Debug, Clone)]
struct GGate<F:FieldExt>{
    pub add3f: AddGate<F, 3>,
    pub xshift32: XorShiftByteGate<F, 4>,
    pub add2f: AddGate<F, 2>,
    pub xshift24: XorShiftByteGate<F, 3>,
    pub add3l: AddGate<F, 3>,
    pub xshift16: XorShiftByteGate<F, 2>,
    pub add2l: AddGate<F, 2>,
    pub xshift0: XorShiftByteGate<F, 0>,
    pub shift63: Shift63Gate<F>
}

impl<F:FieldExt> GGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selector: Column<Fixed>,
                 bytes: Column<Fixed>,
                 septets: Column<Fixed>,
                 xlookup: &[Column<Fixed>; 3],
                 old: &[&U64ACells<F>; 4],
                 x: &U64ACells<F>,
                 y: &U64ACells<F>,
                 new: &[&U64ACells<F>; 4],
                 misc: &[ACell<F>; 46]) -> Self { 
        let [a, b, c, d, unrotated]: [&U64ACells<F>; 5] = array_refs_from_slice(misc);
        
        let add3f = AddGate::<F, 3>::configure(meta, selector, None, &[old[0], old[1], x], a, misc[40]);     
        let xshift32 = XorShiftByteGate::<F, 4>::configure(meta, selector, xlookup, old[3], a, d);
        let add2f = AddGate::<F, 2>::configure(meta, selector, None, &[old[2], d], c, misc[41]);
        let xshift24 = XorShiftByteGate::<F, 3>::configure(meta, selector, xlookup, old[1], c, b);
        
        let add3l = AddGate::<F, 3>::configure(meta, selector, None, &[a, b, y], new[0], misc[42]);
        let xshift16 = XorShiftByteGate::<F, 2>::configure(meta, selector, xlookup, d, new[0], new[3]);
        let add2l = AddGate::<F, 2>::configure(meta, selector, None, &[c, new[3]], new[2], misc[43]);
        let xshift0 = XorShiftByteGate::<F, 0>::configure(meta, selector, xlookup, b, new[2], unrotated);
        let shift63 = Shift63Gate::<F>::configure(meta, selector, bytes, septets, unrotated, new[1], misc[44], misc[45]);

        return GGate{ add3f, xshift32, add2f, xshift24, add3l, xshift16, add2l, xshift0, shift63 };
    }

    fn put(&self, region: &mut Region<F>, row: usize, v: &mut [u64; 16], 
        a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) -> Result<(), Error> {
        v[a] = self.add3f.put(region, row, &[v[a], v[b], x])?;
        v[d] = self.xshift32.put(region, row, v[d], v[a])?;
        v[c] = self.add2f.put(region, row, &[v[c], v[d]])?;
        v[b] = self.xshift24.put(region, row, v[b], v[c])?;

        v[a] = self.add3l.put(region, row, &[v[a], v[b], y])?;
        v[d] = self.xshift16.put(region, row, v[d], v[a])?;
        v[c] = self.add2l.put(region, row, &[v[c], v[d]])?;
        v[b] = self.xshift0.put(region, row, v[b], v[c])?;
        v[b] = self.shift63.put(region, row, v[b])?;
        return Ok(());
    }
}

#[derive(Debug, Clone)]
struct RoundGate<F: FieldExt>{
    pub g: [GGate<F>; 8]
}

impl<F:FieldExt> RoundGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selector: Column<Fixed>,
                 bytes: Column<Fixed>,
                 septets: Column<Fixed>,
                 xlookup: &[Column<Fixed>; 3],
                 old: &[&U64ACells<F>; 16],
                 msg: &[&U64ACells<F>; 16],
                 new: &[&U64ACells<F>; 16],
                 misc: &[ACell<F>; 496]) -> Self {
                
        let state: [&U64ACells<F>; 16] = array_refs_from_slice(misc);
        let miscs:  [&[ACell<F>; 46]; 8] = array_refs_from_slice(&misc[128..]);

        return RoundGate { g: [ 
            GGate::configure(meta, selector, bytes, septets, xlookup, &[old[0], old[4], old[8], old[12]], 
                msg[0], msg[1], &[state[0], state[4], state[8], state[12]], miscs[0]),
            GGate::configure(meta, selector, bytes, septets, xlookup, &[old[1], old[5], old[9], old[13]], 
                msg[2], msg[3], &[state[1], state[5], state[9], state[13]], miscs[1]),
            GGate::configure(meta, selector, bytes, septets, xlookup, &[old[2], old[6], old[10], old[14]], 
                msg[4], msg[5], &[state[2], state[6], state[10], state[14]], miscs[2]),
            GGate::configure(meta, selector, bytes, septets, xlookup, &[old[3], old[7], old[11], old[15]], 
                msg[6], msg[7], &[state[3], state[7], state[11], state[15]], miscs[3]),

            GGate::configure(meta, selector, bytes, septets, xlookup, &[state[0], state[5], state[10], state[15]], 
                msg[8], msg[9], &[new[0], new[5], new[10], new[15]], miscs[4]),
            GGate::configure(meta, selector, bytes, septets, xlookup, &[state[1], state[6], state[11], state[12]], 
                msg[10], msg[11], &[new[1], new[6], new[11], new[12]], miscs[5]),
            GGate::configure(meta, selector, bytes, septets, xlookup, &[state[2], state[7], state[8], state[13]], 
                msg[12], msg[13], &[new[2], new[7], new[8], new[13]], miscs[6]),                
            GGate::configure(meta, selector, bytes, septets, xlookup, &[state[3], state[4], state[9], state[14]], 
                msg[14], msg[15], &[new[3], new[4], new[9], new[14]], miscs[7])
        ]};
    }

    fn put(&self, region: &mut Region<F>, row: usize, v: &mut [u64; 16], msg: &[u64; 16]) -> Result<(), Error> {
        self.g[0].put(region, row, v, 0, 4, 8, 12, msg[0], msg[1])?;
        self.g[1].put(region, row, v, 1, 5, 9, 13, msg[2], msg[3])?;
        self.g[2].put(region, row, v, 2, 6, 10, 14, msg[4], msg[5])?;
        self.g[3].put(region, row, v, 3, 7, 11, 15, msg[6], msg[7])?;

        self.g[4].put(region, row, v, 0, 5, 10, 15, msg[8], msg[9])?;
        self.g[5].put(region, row, v, 1, 6, 11, 12, msg[10], msg[11])?;
        self.g[6].put(region, row, v, 2, 7, 8, 13, msg[12], msg[13])?;
        self.g[7].put(region, row, v, 3, 4, 9, 14, msg[14], msg[15])?;
        return Ok(());
    }
}

#[derive(Debug, Clone)]
struct TestGatesConfig<F:FieldExt>{
    pub round_gate: RoundGate<F>,
    pub bytes: Column<Fixed>,
    pub septets: Column<Fixed>,
    pub xlookup: [Column<Fixed>; 3],
    pub old: [U64ACells<F>; 16],
    pub msg: [U64ACells<F>; 16],
}

#[derive(Default)]
struct TestGatesCircuit<F:FieldExt> {
     pub v: [u64; 16],
     pub msg: [u64; 16],
    _marker:PhantomData<F>
}

impl<F: FieldExt> Circuit<F> for TestGatesCircuit<F> {
    type Config = TestGatesConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    // Testing RoundGate for the given layout:
    // - 4 rows with 32 columns to store the initial state
    // - 4 rows with 32 columns to store the messages state
    // - 16 rows with 32 columns to store the intermediate witnesses (the last 16 cells of the last row are not used)
    // - 4 rows with 32 columns to store the new state
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {      
        let selector = meta.fixed_column();
        let bytes = meta.fixed_column();
        let septets = meta.fixed_column();
        
        let xlookup: [Column<Fixed>; 3] = array::from_fn(|_| meta.fixed_column());
        let columns: [Column<Advice>; 32] = array::from_fn(|_| meta.advice_column());

        let old: [U64ACells<F>; 16] = array::from_fn(|o| array::from_fn(|i| 
            ACell::<F>{ column: columns[(i + 8 * o) % 32], 
            offset: ((i + 8 * o) / 32) as u16, _marker: PhantomData }));
        
        let msg: [U64ACells<F>; 16] = array::from_fn(|o| array::from_fn(|i| 
            ACell::<F>{ column: columns[(i + 8 * o) % 32], 
            offset: 4 + ((i + 8 * o) / 32) as u16, _marker: PhantomData }));
        
        let misc: [ACell<F>; 496] = array::from_fn(|i| ACell::<F>{ 
            column: columns[i % 32], offset: 8 + (i / 32) as u16, _marker: PhantomData });        

        let new: [U64ACells<F>; 16] = array::from_fn(|o| array::from_fn(|i| 
            ACell::<F>{ column: columns[(i + 8 * o) % 32], 
            offset: 24 + ((i + 8 * o) / 32) as u16, _marker: PhantomData }));

        let round_gate = RoundGate::<F>::configure(meta, selector, bytes, septets, &xlookup, 
            &old.iter().map(|a| a).collect::<Vec<&U64ACells<F>>>().try_into().unwrap(),
            &msg.iter().map(|a| a).collect::<Vec<&U64ACells<F>>>().try_into().unwrap(), 
            &new.iter().map(|a| a).collect::<Vec<&U64ACells<F>>>().try_into().unwrap(), 
            &misc);

        return TestGatesConfig {round_gate, bytes, septets, xlookup, old, msg}; 
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(|| "Blake2b",
            |mut region| {
                set_max_lookup(&mut region, config.bytes, 255)?;
                set_max_lookup(&mut region, config.septets, 127)?;
                set_byte_xor_lookup(&mut region, &config.xlookup)?;

                for (s, c) in self.v.iter().zip(config.old.iter()) {
                    set_byte_witnesses(&mut region, "state", 0, c, &s.to_le_bytes().try_into().unwrap())?;
                }

                for (m, c) in self.msg.iter().zip(config.msg.iter()) {
                    set_byte_witnesses(&mut region, "state", 0, c, &m.to_le_bytes().try_into().unwrap())?;
                }

                let mut v = self.v;
                config.round_gate.put(&mut region, 0, &mut v, &self.msg)?;
                println!("State is   {:?}", v);
                
                let mut v_correct = self.v;
                round(&mut v_correct, &self.msg);
                println!("Correct is {:?}", v_correct);

                Ok(())                
            }
        )?;

        Ok(())
    }
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);

    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);

    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16); 
    
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn round(v: &mut [u64; 16], m: &[u64; 16]) {
    g(v, 0, 4, 8, 12, m[0], m[1]);
    g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);
    g(v, 3, 7, 11, 15, m[6], m[7]);

    g(v, 0, 5, 10, 15, m[8], m[9]);
    g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]);
    g(v, 3, 4, 9, 14, m[14], m[15]);
}

fn main() {
    let circuit = TestGatesCircuit::<Fr> {
        v: [534542, 235, 325, 235, 53252, 532452, 235324, 25423, 2354, 235, 2354, 235, 532532, 52345, 325, 5235],
        msg: [5542, 23, 35, 35, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 5235, 35, 525],
        _marker: PhantomData,
    };

    let prover = MockProver::run(18, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}