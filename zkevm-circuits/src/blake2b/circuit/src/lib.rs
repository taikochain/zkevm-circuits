use halo2_proofs::{ arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation };
use std::{ marker::PhantomData, array, convert::TryInto};

const IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 
    0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

const SIGMA:[[usize; 16]; 10] = [ 
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];

mod permutation {
    pub fn compose<const L: usize>(first: &[usize; L], second: &[usize; L], result: &mut [usize; L]) {
        for i in 0..L {
            result[i] = first[second[i]];
        } 
    }

    pub fn invert<const L: usize>(element: &[usize; L], result: &mut [usize; L]) {
        for i in 0..L {
            result[element[i]] = i;
        } 
    }

    pub fn transition<const L: usize>(from: &[usize; L], to: &[usize; L], result: &mut [usize; L]) {
        let mut inverse = [0; L];
        invert(from, &mut inverse);
        compose(&inverse, to, result);
    }

    pub fn list_to_transitions<const L: usize, const N: usize>(list: &[[usize; L]; N], transitions: &mut [[usize; L]; N]) {
        for i in 0..N {
            transition(&list[(N + i - 1) % N], &list[i], &mut transitions[i]);
        }
    }
}

fn gf<F:FieldExt>(value: u128) -> Expression<F> {
    Expression::Constant(F::from_u128(value))
}

fn known<F:FieldExt>(value: u8) -> Value<F> {
    Value::known(F::from(value as u64))
}

fn offcut_to_number<F:FieldExt, const H:u8>(meta: &mut VirtualCells<F>, offcut: AChunk<F,H>) -> Expression<F> {
    (0..(H as usize)).map(|cell| offcut.expr(meta, cell)).rfold(gf(0), |sum, byte| { sum * gf(256) + byte })
}

fn activate<F:FieldExt>(region: &mut Region<F>, row: usize, selector: Column<Fixed>) -> Result<(), Error> {
    region.assign_fixed(|| "", selector, row, || known::<F>(1))?;
    Ok(())
}

fn arrefs_from_slice<T, const S: usize, const L: usize>(slice: &[T]) -> [&[T; S]; L] {
    array::from_fn(|i| slice[S * i..][..S].try_into().unwrap())
}

fn constrain_to_xor<F:FieldExt, const H:u8>(meta: &mut ConstraintSystem<F>, 
    name: &'static str, xlookup: &[Column<Fixed>; 3], selector: Column<Fixed>, 
    first: AChunk<F,H>, second: impl Chunk<F,H>, result: AChunk<F,H>) {
        meta.lookup_any(name, |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![(selector.clone() * first.expr(meta, 0), meta.query_fixed(xlookup[0], Rotation::cur())),
                 (selector.clone() * second.expr(meta, 0), meta.query_fixed(xlookup[1], Rotation::cur())),
                 (selector.clone() * result.expr(meta, 0), meta.query_fixed(xlookup[2], Rotation::cur()))]
        });
}

fn set_xor_lookup<F:FieldExt>(region: &mut Region<F>, xlookup: &[Column<Fixed>; 3]) -> Result<(), Error> {
    for row in 0..65536 {
        let (first, second) = (row as u8, (row >> 8) as u8);
        region.assign_fixed(|| "", xlookup[0], row, ||  known::<F>(first))?;
        region.assign_fixed(|| "", xlookup[1], row, || known::<F>(second))?;
        region.assign_fixed(|| "", xlookup[2], row, ||  known::<F>(first ^ second))?;
    }
    Ok(())
}

fn set_max_lookup<F:FieldExt>(region: &mut Region<F>, table: Column<Fixed>, max: u8) -> Result<(), Error> {
    for row in 0..=max {
        region.assign_fixed(|| "", table, row as usize, || known::<F>(row))?;
    }
    Ok(())
}

pub trait Chunk<F:FieldExt, const H:u8> {
    fn expr(&self, meta: &mut VirtualCells<F>, cell: usize) -> Expression<F>;
    fn assign(&self, region: &mut Region<F>, row: usize, value: u64) -> Result<(), Error>;
}

#[derive(Debug, Copy, Clone)]
pub struct AChunk<F:FieldExt, const H:u8> {
    column: Column<Advice>,
    offset: u16,
    _marker: PhantomData<F>
}

impl<F:FieldExt, const H:u8> AChunk<F, H> {
    pub fn new(column: Column<Advice>, offset: u16) -> Self {
        assert!(H <= 8, "Cannot create the AChunk of height {}. The maximum height is 8!", H);
        AChunk { column, offset, _marker: PhantomData }
    }

    pub fn truncate<const L:u8>(&self) -> AChunk<F, L> {
        assert!(L <= H, "Cannot truncate the AChunk of height {} to the AChunk of height {}!", H, L);
        AChunk { column: self.column, offset: self.offset, _marker: PhantomData }
    }
}

impl<F:FieldExt, const H:u8> Chunk<F,H> for AChunk<F, H> {
    fn expr(&self, meta: &mut VirtualCells<F>, cell: usize) -> Expression<F> {
        assert!(cell < H.into(), "Accessing the {}-th cell in the AChunk of height {}!", cell, H);
        let offset = (self.offset as i32) + (cell as i32);
        meta.query_advice(self.column, Rotation(offset))
    }

    fn assign(&self, region: &mut Region<F>, row: usize, value: u64) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        let offset = self.offset as usize + row;

        for i in 0..(H as usize) { 
            region.assign_advice(|| "", self.column, offset + i, || known::<F>(bytes[i]))?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FChunk<F:FieldExt, const H:u8> {
    column: Column<Fixed>,
    offset: u16,
    _marker: PhantomData<F>
}

impl<F:FieldExt, const H:u8> FChunk<F, H> {
    pub fn new(column: Column<Fixed>, offset: u16) -> Self {
        assert!(H <= 8, "Cannot create the FChunk of height {}. The maximum height is 8!", H);
        FChunk { column, offset, _marker: PhantomData }
    }

    pub fn truncate<const L:u8>(&self) -> FChunk<F, L> {
        assert!(L <= H, "Cannot truncate the FChunk of height {} to the FChunk of height {}!", H, L);
        FChunk { column: self.column, offset: self.offset, _marker: PhantomData }
    }
}

impl<F:FieldExt, const H:u8> Chunk<F,H> for FChunk<F, H> {
    fn expr(&self, meta: &mut VirtualCells<F>, cell: usize) -> Expression<F> {
        assert!(cell < H.into(), "Accessing the {}-th cell in the FChunk of height {}!", cell, H);
        let offset = (self.offset as i32) + (cell as i32);
        meta.query_fixed(self.column, Rotation(offset))
    }

    fn assign(&self, region: &mut Region<F>, row: usize, value: u64) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        let offset = self.offset as usize + row;

        for i in 0..(H as usize) { 
            region.assign_fixed(|| "", self.column, offset + i, || known::<F>(bytes[i]))?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ShortCell<F:FieldExt, const M:u8> {
    column: Column<Advice>,
    offset: u16,
    _marker: PhantomData<F>
}

impl<F:FieldExt, const M:u8> ShortCell<F, M> {
    pub fn new(column: Column<Advice>, offset: u16) -> Self {
        ShortCell { column, offset, _marker: PhantomData }
    }

    fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset as i32))
    }

    fn assign(&self, region: &mut Region<F>, row: usize, value: u8) -> Result<(), Error> {
        assert!(value <= M, "Cannot assign the value {} to a ShortCell with a maximum value of {}!", value, M);
        region.assign_advice(|| "", self.column, self.offset as usize + row, || known::<F>(value))?;
        Ok(())
    }

}

type AChunk64<F> = AChunk<F,8>;
type FChunk64<F> = FChunk<F,8>;
type AChunk8<F> = AChunk<F,1>; 
type FChunk8<F> = FChunk<F,1>; 

#[derive(Debug, Clone)]
pub struct AddGate<F:FieldExt, const S:usize> {
    selector: Column<Fixed>,
    result: AChunk64<F>,
    carry: AChunk8<F>
}

impl<F:FieldExt, const S:usize> AddGate<F,S> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 summands: &[AChunk64<F>; S],
                 carry: AChunk8<F>, 
                 result: AChunk64<F>) -> Self {
        assert!(S <= 256, "Cannot create AddGate with {} summands. The maximum number of summands is 256!", S);       
        let selector = meta.fixed_column();

        meta.create_gate("AddGate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let left = summands.iter().map(|term| offcut_to_number(meta, *term)).fold(gf(0), |sum, term| sum + term);
            let right = carry.expr(meta, 0) * gf(1u128 << 64) + offcut_to_number(meta, result);
            vec![selector * (left - right)]
        });
        
        AddGate { selector, result, carry }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, summands: &[u64; S]) -> Result<u64, Error>{
        let sum = summands.iter().fold(0, |sum, term| sum  + (*term as u128));
        let (result, carry) = (sum as u64, (sum >> 64) as u64);    
        self.result.assign(region, row, result)?;
        self.carry.assign(region, row, carry)?;
        activate(region, row, self.selector)?;
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct XorGate<F:FieldExt>{
    selector: Column<Fixed>, 
    result: AChunk64<F>
}

impl<F:FieldExt> XorGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>, 
                 xlookup: &[Column<Fixed>; 3],
                 first: AChunk64<F>,
                 second: AChunk64<F>, 
                 result: AChunk64<F>) -> Self {
        let selector = meta.fixed_column();
        constrain_to_xor(meta, "XorGate", xlookup, selector, first, second, result);
        XorGate { selector, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, first: u64, second: u64) -> Result<u64, Error> {
        let result = first ^ second;
        self.result.assign(region, row, result)?;
        for i in 0..8 {
            activate(region, row + i, self.selector)?;
        }
        Ok(result)
    }
}


#[derive(Debug, Clone)]
pub struct ShiftBytesGate<F:FieldExt, const B:usize>{
    selector: Column<Fixed>, 
    result: AChunk64<F>
}

impl<F:FieldExt, const B:usize> ShiftBytesGate<F,B> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 input: AChunk64<F>,
                 result: AChunk64<F>) -> Self  {
        let selector = meta.fixed_column();

        meta.create_gate("ByteShiftGate", |meta| {
            let mut constraints = vec![];
            let selector = meta.query_fixed(selector, Rotation::cur());

            for i in 0..8 {
                let position = (i + 8 - B) % 8;
                constraints.push(selector.clone() * (result.expr(meta, position) - input.expr(meta, i)));
            }

            constraints     
        });

        ShiftBytesGate { selector, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let result = input.rotate_right(B as u32 * 8);
        self.result.assign(region, row, result)?;
        activate(region, row, self.selector)?;
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct Shift63Gate<F:FieldExt>{
    selector: Column<Fixed>,
    bit: ShortCell<F,1>,
    septet: ShortCell<F,127>,
    result: AChunk64<F>
}

impl<F:FieldExt> Shift63Gate<F> {
    fn configure(meta: &mut ConstraintSystem<F>, 
                 input: AChunk64<F>,
                 bit: ShortCell<F,1>,
                 septet: ShortCell<F,127>,
                 result: AChunk64<F>) -> Self {
        let selector = meta.fixed_column();

        meta.create_gate("Shift63Gate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let septet = septet.expr(meta);
            let bit = bit.expr(meta);
            let high = input.expr(meta, 7);

            let byte = bit.clone() * gf(128) + septet.clone();
            let left = septet * gf(1 << 57) + offcut_to_number(meta, input.truncate::<7>()) * gf(2) + bit.clone();
            let right = offcut_to_number(meta, result); 

            vec![selector.clone() * (byte - high), selector * (left - right)]
        });

        Shift63Gate { selector, bit, septet, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let bit = (input >> 63) as u8; 
        let septet = ((input >> 56) & 0x7F) as u8;
        let result = input.rotate_right(63);
        self.result.assign(region, row, result)?;
        self.bit.assign(region, row, bit)?;
        self.septet.assign(region, row, septet)?;
        activate(region, row, self.selector)?;
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct PermuteGate<F:FieldExt, const L:usize>{
    selector: Column<Fixed>,
    permutation: [usize; L],
    result: [AChunk64<F>; L] 
}

impl<F:FieldExt, const L:usize> PermuteGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 permutation: Option<&[usize; L]>,
                 input: &[AChunk64<F>; L],
                 result: &[AChunk64<F>; L]) -> Self {
        let selector = meta.fixed_column();
        let permutation = match permutation {
            Some(value) => *value,
            None => array::from_fn(|i| i) 
        };

        meta.create_gate("PermuteGate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let mut constraints = vec![];
            for i in 0..L {
                let (left, right) = (result[i], input[permutation[i]]);
                constraints.push(selector.clone() * (left.expr(meta, 0) - right.expr(meta, 0)));
            }
            constraints      
        });

        PermuteGate { selector, permutation, result: *result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, data: &mut [u64; L]) -> Result<(), Error> {
        *data = array::from_fn(|i| data[self.permutation[i]]);
        for i in 0..L {
            self.result[i].assign(region, row, data[i])?;
        }
        for i in 0..8 {
            activate(region, row + i, self.selector)?;
        }
        Ok(()) 
    }
}

#[derive(Debug, Clone)]
pub struct GGate<F:FieldExt>{
    add3: [AddGate<F, 3>; 2],
    add2: [AddGate<F, 2>; 2],
    xor: [XorGate<F>; 4],
    shift32: ShiftBytesGate<F, 4>,
    shift24: ShiftBytesGate<F, 3>,
    shift16: ShiftBytesGate<F, 2>,
    shift63: Shift63Gate<F>
}

impl<F:FieldExt> GGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 xlookup: &[Column<Fixed>; 3],
                 input: &[AChunk64<F>; 4],
                 x: AChunk64<F>,
                 y: AChunk64<F>,
                 misc1: ShortCell<F,1>,
                 misc7: ShortCell<F,127>,
                 misc8: &[AChunk8<F>; 4],
                 misc64: &[AChunk64<F>; 8],                 
                 result: &[AChunk64<F>; 4]) -> Self { 
        let (a, b, c, d, xout) = (misc64[0], misc64[1], misc64[2], misc64[3], &misc64[4..8]);

        GGate {
            add3: [AddGate::<F, 3>::configure(meta, &[input[0], input[1], x], misc8[0], a),
                   AddGate::<F, 3>::configure(meta, &[a, b, y], misc8[1], result[0])],
            
            add2: [AddGate::<F, 2>::configure(meta, &[input[2], d], misc8[2], c),
                   AddGate::<F, 2>::configure(meta, &[c, result[3]], misc8[3], result[2])],
            
            xor: [XorGate::<F>::configure(meta, xlookup, input[3], a, xout[0]),
                  XorGate::<F>::configure(meta, xlookup, input[1], c, xout[1]),
                  XorGate::<F>::configure(meta, xlookup, d, result[0], xout[2]),
                  XorGate::<F>::configure(meta, xlookup, b, result[2], xout[3])],
            
            shift32: ShiftBytesGate::<F, 4>::configure(meta, xout[0], d),
            shift24: ShiftBytesGate::<F, 3>::configure(meta, xout[1], b),
            shift16: ShiftBytesGate::<F, 2>::configure(meta, xout[2], result[3]),      
            shift63: Shift63Gate::<F>::configure(meta, xout[3], misc1, misc7, result[1])
        }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, v: &mut [u64; 16], 
        a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) -> Result<(), Error> {
        v[a] = self.add3[0].assign(region, row, &[v[a], v[b], x])?;
        v[d] = self.xor[0].assign(region, row, v[d], v[a])?;
        v[d] = self.shift32.assign(region, row, v[d])?;
        v[c] = self.add2[0].assign(region, row, &[v[c], v[d]])?;
        v[b] = self.xor[1].assign(region, row, v[b], v[c])?;
        v[b] = self.shift24.assign(region, row, v[b])?;

        v[a] = self.add3[1].assign(region, row, &[v[a], v[b], y])?;
        v[d] = self.xor[2].assign(region, row, v[d], v[a])?;
        v[d] = self.shift16.assign(region, row, v[d])?;
        v[c] = self.add2[1].assign(region, row, &[v[c], v[d]])?;
        v[b] = self.xor[3].assign(region, row, v[b], v[c])?;
        v[b] = self.shift63.assign(region, row, v[b])?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RoundGate<F: FieldExt> {
    g: [GGate<F>; 8]
}

impl<F:FieldExt> RoundGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 xlookup: &[Column<Fixed>; 3],
                 input: &[AChunk64<F>; 16],
                 message: &[AChunk64<F>; 16],
                 misc1: &[ShortCell<F,1>; 8],
                 misc7: &[ShortCell<F,127>; 8],
                 misc8: &[AChunk8<F>; 32],
                 misc64: &[AChunk64<F>; 80],
                 result: &[AChunk64<F>; 16]) -> Self {
        let state = &misc64[64..];
        let miscs8: [&[AChunk8<F>; 4]; 8] = arrefs_from_slice(misc8);
        let miscs64: [&[AChunk64<F>; 8]; 8] = arrefs_from_slice(misc64);

        RoundGate { g: [ 
            GGate::configure(meta, xlookup, &[input[0], input[4], input[8], input[12]],  message[0], 
                message[1], misc1[0], misc7[0], miscs8[0], miscs64[0], &[state[0], state[4], state[8], state[12]]),
            GGate::configure(meta, xlookup, &[input[1], input[5], input[9], input[13]], message[2], 
                message[3], misc1[1], misc7[1], miscs8[1], miscs64[1], &[state[1], state[5], state[9], state[13]]),
            GGate::configure(meta, xlookup, &[input[2], input[6], input[10], input[14]], message[4], 
                message[5], misc1[2], misc7[2], miscs8[2], miscs64[2], &[state[2], state[6], state[10], state[14]]),
            GGate::configure(meta, xlookup, &[input[3], input[7], input[11], input[15]], message[6], 
                message[7], misc1[3], misc7[3], miscs8[3], miscs64[3], &[state[3], state[7], state[11], state[15]]),

            GGate::configure(meta, xlookup, &[state[0], state[5], state[10], state[15]], message[8], 
                message[9], misc1[4], misc7[4], miscs8[4], miscs64[4], &[result[0], result[5], result[10], result[15]]),
            GGate::configure(meta, xlookup, &[state[1], state[6], state[11], state[12]], message[10], 
                message[11], misc1[5], misc7[5], miscs8[5], miscs64[5], &[result[1], result[6], result[11], result[12]]),
            GGate::configure(meta, xlookup, &[state[2], state[7], state[8], state[13]], message[12], 
                message[13], misc1[6], misc7[6], miscs8[6], miscs64[6], &[result[2], result[7], result[8], result[13]]),                
            GGate::configure(meta, xlookup, &[state[3], state[4], state[9], state[14]], message[14], 
                message[15], misc1[7], misc7[7], miscs8[7], miscs64[7], &[result[3], result[4], result[9], result[14]])
        ]}
    }

    fn assign(&self, region: &mut Region<F>, row: usize, v: &mut [u64; 16], m: &[u64; 16]) -> Result<(), Error> {
        self.g[0].assign(region, row, v, 0, 4, 8, 12, m[0], m[1])?;
        self.g[1].assign(region, row, v, 1, 5, 9, 13, m[2], m[3])?;
        self.g[2].assign(region, row, v, 2, 6, 10, 14, m[4], m[5])?;
        self.g[3].assign(region, row, v, 3, 7, 11, 15, m[6], m[7])?;

        self.g[4].assign(region, row, v, 0, 5, 10, 15, m[8], m[9])?;
        self.g[5].assign(region, row, v, 1, 6, 11, 12, m[10], m[11])?;
        self.g[6].assign(region, row, v, 2, 7, 8, 13, m[12], m[13])?;
        self.g[7].assign(region, row, v, 3, 4, 9, 14, m[14], m[15])?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InitialGate<F: FieldExt> {
    bit: Column<Fixed>,
    xcopy: Column<Fixed>,
    iv: [FChunk64<F>; 8],   
    v: [AChunk64<F>; 16]
}

impl<F:FieldExt> InitialGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 xlookup: &[Column<Fixed>; 3],
                 iv: &[FChunk64<F>; 8], 
                 h: &[AChunk64<F>; 8],
                 t: &[AChunk64<F>; 2],
                 f: ShortCell<F,1>,
                 v: &[AChunk64<F>; 16]) -> Self {
        let (bit, xcopy) = (meta.fixed_column(), meta.fixed_column());

        meta.create_gate("InitialGate", |meta| {
            let mut constraints = vec![];          
            let (bit, f) = (meta.query_fixed(bit, Rotation::cur()), f.expr(meta));

            for i in 0..8 {
                let source = iv[6].expr(meta, i);
                let direct = (gf(1) - f.clone()) * source.clone();
                let inverse = f.clone() * (gf(255) - source.clone());
                constraints.push(bit.clone() * (v[14].expr(meta, i) - direct - inverse));
            }

            let xcopy = meta.query_fixed(xcopy, Rotation::cur());  
      
            for i in 0..8 {
                constraints.push(xcopy.clone() * (v[i].expr(meta, 0) - h[i].expr(meta, 0)));
            }

            for i in (8..12).chain(15..16) {
                constraints.push(xcopy.clone() * (v[i].expr(meta, 0) - iv[i - 8].expr(meta, 0)));
            }

            constraints
        });

        
        for ((first, second), result) in t.iter().zip(iv[4..6].iter()).zip(v[12..14].iter()) {
            constrain_to_xor(meta, "InitialGate", xlookup, xcopy, *first, *second, *result);
        }

        InitialGate { bit, xcopy, iv: *iv, v: *v }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, h: &[u64; 8], t: u128, f: bool, v: &mut [u64; 16]) -> Result<(), Error> {
        for i in 0..8 {       
            v[i] = h[i];
            v[i + 8] = IV[i];
        }
  
        v[12] ^= t as u64;
        v[13] ^= (t >> 64) as u64;
        
        if f { v[14] = !v[14]; }
        
        for i in 0..16 {
            self.v[i].assign(region, row, v[i])?;
        }

        activate(region, row, self.bit)?;

        for i in 0..8 {
            self.iv[i].assign(region, row, IV[i])?;
            activate(region, row + i, self.xcopy)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FinalGate<F:FieldExt> {
    selector: Column<Fixed>,
    result: [AChunk64<F>; 8],
}

impl<F:FieldExt> FinalGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 xlookup: &[Column<Fixed>; 3],
                 i1: Column<Advice>,
                 io: Column<Advice>) -> Self {
        let selector = meta.fixed_column();
        let result: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(io, (i as u16 + 8) * 8));
        constrain_to_xor(meta, "FinalGate", xlookup, selector, AChunk64::new(io, 0), AChunk64::new(i1, 0), result[0]);

        FinalGate { selector, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, i1: &[u64; 8], io: &mut [u64; 8]) -> Result<(), Error> {
        for i in 0..8 {
            io[i] ^= i1[i];
            self.result[i].assign(region, row, io[i])?;
        }

        for i in 0..64 {
            activate(region, row + i, self.selector)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AllocateGate<F:FieldExt, const P:usize> {
    selector: Column<Fixed>,
    bit: Column<Advice>,
    septet: Column<Advice>,
    pairs: [[Column<Advice>; 2]; P],
    _marker: PhantomData<F>
}

impl<F:FieldExt, const P:usize> AllocateGate<F,P> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 septets: Column<Fixed>,
                 bytes: &[Column<Fixed>; 2],
                 bit: Column<Advice>,
                 septet: Column<Advice>,
                 pairs: &[&[Column<Advice>; 2]; P]) -> Self {
        let selector = meta.fixed_column();

        meta.create_gate("AllocateGate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());
            vec![selector * bit.clone() * (gf(1) - bit)]   
        });

        meta.lookup_any("AllocateGate", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![(selector * meta.query_advice(septet, Rotation::cur()), meta.query_fixed(septets, Rotation::cur()))]
        });

        for pair in pairs {
            meta.lookup_any("AllocateGate", |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                vec![(selector.clone() * meta.query_advice(pair[0], Rotation::cur()), meta.query_fixed(bytes[0], Rotation::cur())),
                     (selector.clone() * meta.query_advice(pair[1], Rotation::cur()), meta.query_fixed(bytes[1], Rotation::cur()))]
            });
        }

        AllocateGate { selector, bit, septet, pairs: array::from_fn(|i| *pairs[i]), _marker: PhantomData }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, height: usize) -> Result<(), Error> {
        for i in row..(row + height) {
            for column in self.pairs.iter().flatten().chain(&[self.bit, self.septet]) {
                region.assign_advice(|| "", *column, i, || known::<F>(0))?;
            }
            activate(region, row, self.selector)?;
        }

        Ok(())
    }

}

#[derive(Debug, Clone)]
pub struct TestGatesConfig<F:FieldExt>{
    pub allocate_gate: AllocateGate<F, 20>,
    pub initial_gate: InitialGate<F>,
    pub final_gate: FinalGate<F>,
    pub round_gate: RoundGate<F>,
    pub m_gates: [PermuteGate<F, 16>; 10],
    pub h_gate: PermuteGate<F, 8>,
    pub h_column_gate: PermuteGate<F, 8>, 
    pub v_column_gate: PermuteGate<F, 16>, 
    pub septets: Column<Fixed>,
    pub xlookup: [Column<Fixed>; 3],
    pub h: [AChunk64<F>; 8],
    pub m: [AChunk64<F>; 16],
    pub t: [AChunk64<F>; 2],
    pub f: ShortCell<F,1>
}

#[derive(Default)]
pub struct TestGatesCircuit<F:FieldExt> {
     pub h: [u64; 8],
     pub m: [u64; 16],
     pub t: u128,
     pub f: bool,
     pub r: u32,
     pub _marker:PhantomData<F>
}

impl<F: FieldExt> Circuit<F> for TestGatesCircuit<F> {
    type Config = TestGatesConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // Layout:
    // - 8-row for the circuit input: t in the columns 0 and 1, f at the top of the septet column
    // - 8-row for the circuit input: 16 columns for m, 8 columns for h and 16 columns for v
    // - r layers:
    //     - 8-row for witness data of the RoundGate: 40 byte columns as well as the bit and septet columns as used
    //     - 8-row for witness data of the RoundGate: 40 byte columns are used
    //     - 1-row for witness data of the RoundGate: 32 byte columns are used
    //     - 8-row for the round output: 16 columns for m, 8 columns for h and 16 columns for v
    // - twenty four 8-rows for the final computation and the circuit output: column 0 contains v, 
    // column 1 is used to store h, h ^ v[0..8] and the the circuit output h ^ v[0..8] ^ v[8..16] 
    // Total: 42 advice columns, and 25 * r + 208 rows. The fixed columns are used for lookups, 
    // selectors of the basic gates and storing the IV values (1 column)  
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let septets = meta.fixed_column();     
        let xlookup: [Column<Fixed>; 3] = array::from_fn(|_| meta.fixed_column());
        let [bit, septet] = array::from_fn(|_| meta.advice_column());
        let columns: [Column<Advice>; 40] = array::from_fn(|_| meta.advice_column());

        let allocate_gate = AllocateGate::<F, 20>::configure(meta, septets, 
            &[xlookup[0], xlookup[1]], bit, septet, &arrefs_from_slice(&columns));        
        
        let f = ShortCell::<F, 1>::new(bit, 0);
        let t = [AChunk64::<F>::new(columns[0], 0), AChunk64::<F>::new(columns[1], 0)];

        let m: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i], 8));
        let h: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 16], 8));    
        let v: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 24], 8));
        
        let iv = meta.fixed_column();
        let iv: [FChunk64<F>; 8] = array::from_fn(|i| FChunk64::<F>::new(iv, i as u16 * 8));

        let initial_gate = InitialGate::<F>::configure(meta, &xlookup, &iv, &h, &t, f, &v);

        let mi: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i], 0));
        let mo: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i], 25));
        let m_gates: [PermuteGate<F, 16>; 10] = array::from_fn(|i| {
            let mut permutation = [0; 16];
            permutation::transition(&SIGMA[i % 10], &SIGMA[(i + 1) % 10], &mut permutation);
            PermuteGate::configure(meta, Some(&permutation), &mi, &mo) 
        });
        
        let hi: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 16], 0));
        let ho: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 16], 25));
        let h_gate = PermuteGate::<F, 8>::configure(meta, None, &hi, &ho); 
        
        let vi: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 24], 0));
        let vo: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 24], 25));
        
        let misc64: [AChunk64<F>; 80] = array::from_fn(|i| AChunk64::<F>::new(columns[i % 40], 8 * (i as u16 / 40 + 1)));
        let misc8: [AChunk8<F>; 32] = array::from_fn(|i| AChunk8::<F>::new(columns[i], 24));
        let misc7: [ShortCell<F, 127>; 8] = array::from_fn(|i| ShortCell::<F, 127>::new(septet, i as u16 + 8));
        let misc1: [ShortCell<F, 1>; 8] = array::from_fn(|i| ShortCell::<F, 1>::new(bit, i as u16 + 8));
        let round_gate = RoundGate::<F>::configure(meta, &xlookup, &vi, &mi, &misc1, &misc7, &misc8, &misc64, &vo);

        let hci: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 16], 0));
        let hco: [AChunk64<F>; 8] = array::from_fn(|i| AChunk64::<F>::new(columns[1], 8 * (i as u16 + 1)));
        let h_column_gate = PermuteGate::<F, 8>::configure(meta, None, &hci, &hco);

        let vci: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[i + 24], 0));
        let vco: [AChunk64<F>; 16] = array::from_fn(|i| AChunk64::<F>::new(columns[0], 8 * (i as u16 + 1)));     
        let v_column_gate = PermuteGate::<F, 16>::configure(meta, None, &vci, &vco);

        let final_gate = FinalGate::<F>::configure(meta, &xlookup, columns[0], columns[1]); 
        //////////////////////////////           
        println!("Gates: {}", meta.gates().len());
        println!("Lookups: {}", meta.lookups().len());
        println!("Advice columns: {}", meta.num_advice_columns());
        println!("Advice queries: {}", meta.advice_queries().len());
        println!("Fixed columns: {}", meta.num_fixed_columns());
        println!("Fixed queries: {}", meta.fixed_queries().len());
        /////////////////////////////
        TestGatesConfig { allocate_gate, initial_gate, final_gate, h_column_gate, 
            v_column_gate, h_gate, round_gate, m_gates, septets, xlookup, h, m, t, f }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(|| "Blake2b",
            |mut region| {
                set_xor_lookup(&mut region, &config.xlookup)?;
                set_max_lookup(&mut region, config.septets, 127)?;

                config.allocate_gate.assign(&mut region, 0, 25 * self.r as usize + 208)?;
                
                config.t[0].assign(&mut region, 0, self.t as u64)?;
                config.t[1].assign(&mut region, 0, (self.t >> 64) as u64)?;
                config.f.assign(&mut region, 0, self.f as u8)?;

                for (value, chunk) in self.h.iter().chain(self.m.iter()).zip(config.h.iter().chain(config.m.iter())) {
                    chunk.assign(&mut region, 0, *value)?;
                }

                let mut m = self.m;
                let mut h = self.h;
                let mut v = [0u64; 16];

                config.initial_gate.assign(&mut region, 0, &self.h, self.t, self.f, &mut v)?;

                for i in 0..(self.r as usize) {
                    let row = 8 + 25 * i;
                    config.round_gate.assign(&mut region, row, &mut v, &m)?;
                    config.h_gate.assign(&mut region, row, &mut h)?;
                    config.m_gates[i % 10].assign(&mut region, row, &mut m)?;
                }
                
                let row = 8 + 25 * self.r as usize;
                config.h_column_gate.assign(&mut region, row, &mut h)?;
                config.v_column_gate.assign(&mut region, row, &mut v)?;

                config.final_gate.assign(&mut region, row + 8, v[0..8].try_into().unwrap(), &mut h)?;
                config.final_gate.assign(&mut region, row + 72, v[8..16].try_into().unwrap(), &mut h)?;

                println!("State is   {:?}", h);

                let mut h_correct = self.h;       
                compress(&mut h_correct, &self.m, self.t, self.f, self.r);
                println!("Correct is {:?}", h_correct);

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

fn compress(h: &mut [u64; 8], m: &[u64; 16], t: u128, f: bool, r: u32) {
    let mut v = [0u64; 16];
    
    for i in 0..8 {       
        v[i] = h[i];
        v[i + 8] = IV[i];
    }

    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    
    if f { v[14] ^= 0xFFFF_FFFF_FFFF_FFFF; }

    for i in 0..(r as usize) {
        let s = &SIGMA[i % 10];

        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}
