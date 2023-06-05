/*  The basic building blocks of this circuit are called GATES. In this context a gate is a map between tuples of values, 
    which are stored in the circuit table, with the corresponding computation algorithm and the system of algebraic equations, 
    which are defined over the circuit's native field in varibales of the computation algorithm and express the sufficient 
    condition of integrity of the corresponding computation. 
    
    The position of a circuit table value used by a gate is determined by three parameters: 
    - a circuit column; 
    - a "point of reference" row for the gate (which is called an ASSIGNMENT ROW);
    - the integer offset reltive to this row. 
    
    The gates, which differ only in positions of the used values in the circuit table or constants of the associated algorithms 
    and equations, constitute a separate CLASS of gates. The gates of the same class, which differ only in assignment rows, 
    constitute a separate TYPE of gates. 
    
    The library contains the struct types defining the classes of the gates (their names end with "Gate"). The instances of these 
    structs describe the types of gates and are created during the circuit configuring by calling the function "configure", which is 
    associated with the corresponding struct type. This function receives the constant values, which are specific for the described 
    type of gates, and the struct instances, which describe the relative (to an assignment row) positions of the used circuit 
    table values (including combined selectors) and their types (i.e. "native field element", "byte array", "bit", etc.). The complex
    of relative positions of the circuit table cells used to store some value is called "RELATIVE PLACE".
    
    A gate instance of a certain type is created during the circuit synthesys by calling the method "assign" of the struct instance, 
    which describes the corresponding gate type. This method receives the assignment row index and information, which describes the 
    arguments of the map represented by the gate. The information returned by this method describes the value of the gate map and 
    indicates whether the gate was created successfully.

    Most columns of the circuit table are constrained in terms of stored data types in order to be usable by gates. The corresponding 
    constraint equations describe the possible content of a row as well as the set of the rows to constrain. This set is specified by 
    the "ALLOCATED" column, which is a fixed column used as a selector. The given collumn contains "1" in all usable rows and "0" in 
    all unusable ones. Also, any possible assignment row for any gate must have such an index that all circuit table values used by this 
    gate are in the rows, for which the "allocated" column contains "1" (otherwise, the integrity of the witness data cannot be assured). 
    For this reason, the set of possible assignment rows is specified by the the "ALLOWED" column (a fixed column used as a selector), 
    which contains "1" in all usable rows except for several sequential top and bottom ones (and "0" in all other rows). The aforesaid 
    circuit structure is prepared during the circuit synthesys by calling the method "assign" of the "CircuitPreparator" struct instance, 
    which is created during the circuit configuring by calling the function "configure" of the corresponding struct type. The constrained 
    columns (and their groups) created by the "CircuitPreparator" struct instance may be classified into the following categories:
    - byte-column pair: a pair of columns, which are allowed to contain only values in {0, 1, ..., 255} in usable rows;
    - septet column: a column, usable rows of which contain only values in {0, 1, ..., 127};
    - bit column: a column of usable cells containing either 0 or 1;
    - xor column triplet: a group of three columns with usable rows containing values in {0, 1, ..., 255}, the bitwise xor of which is 0. 

    Gates of this circuit use only combined selectors. Such a selector consists of two cells in the same row: the first cell is in the 
    "ALLOWED" collumn and the second one is in a certain advice column. The selector is active iff both cells contain non-zero values. 
    Relative places of combined selectors for a gate type is described by an array of "Combiselector" struct instances. A gate is 
    assigned at some row iff all of the corresponding combined selectors are active. They are called the CONTROL SELECTORS of the gate.

    In order to achieve better in-circuit integration, the approach called "random linear combintaion hashing" is used. The corresponding 
    hash of d, which is an array of n native field elements, for the challenge c and key k is designated as RLC(c, d) and computed as follows:
    RLC(k, c, d) = k * c^n + c^(n-1) * d[0] + c^(n-2) * d[1] + ... + c * d[n - 2] + d[n - 1]. It is not hard to verify that RLC has the given 
    useful property: RLC(0, c, a|b) = RLC(RLC(0, c, a), c, b), where a|b stands for the concatenation of arrays a and b.   
*/

use std::{ marker::PhantomData, array, convert::TryInto };
use halo2_proofs::{ arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation };

// Blake2 initialization vector
const IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
                      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

// Blake2 permutation table
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

// Optimal numbers of rows per round for the compression circuit. Optimality means that every 
// number is the smallest one among all that result in the same number of columns in the circuit 
const ROWS_PER_ROUND:[usize; 12] = [8, 16, 24, 32, 40, 48, 56, 64, 80, 88, 120, 128];

// A small module providing functions for performing operations in permutation groups
mod permutation {
    // Computes the permutation composition a * b, i.e. the permutation, which is 
    // equivalent to applying the permutations b and a in the corresponding order  
    pub fn compose<const L: usize>(a: &[usize; L], b: &[usize; L]) -> [usize; L] {
        let mut result = [0; L];
        for i in 0..L {
            result[i] = a[b[i]];
        }
        result
    }

    // Computes the inverse permutation for x
    pub fn invert<const L: usize>(x: &[usize; L]) -> [usize; L] {
        let mut result = [0; L];
        for i in 0..L {
            result[x[i]] = i;
        }
        result
    }
}

// Converts a specified value into an Expression instance
fn gf<F:FieldExt>(value: u128) -> Expression<F> {
    Expression::Constant(F::from_u128(value))
}

// Converts a specified value into a Value instance
fn known<F:FieldExt>(value: u64) -> Value<F> {
    Value::known(F::from(value))
}

// Computes the index of a row, using it's offset relative to the specified row 
fn shift_row(row: usize, offset: i32) -> usize {
    let offset = row as i64 + offset as i64;
    assert!(offset >= 0, "The row {} does not exist. Row indices are nonnegative!", offset);
    offset as usize
}

// Computes the expression equal to the number stored in the specified Chunk 
fn chunk_to_number<F:FieldExt, const H:u8>(meta: &mut VirtualCells<F>, chunk: Chunk<F,H>) -> Expression<F> {
    (0..(H as usize)).map(|cell| chunk.expr(meta, cell)).rfold(gf(0), |sum, byte| { sum * gf(256) + byte })
}

// Splits the specified slice into arrays without copying its elements 
fn arrefs_from_slice<T, const S: usize, const L: usize>(slice: &[T]) -> [&[T; S]; L] {
    array::from_fn(|i| slice[S * i..][..S].try_into().unwrap())
}

// Creates Chunks, the byte columns for which are specified by "pairs". The relative places of these Chunks can be considered as cells 
// of a table-like structure, for which columns are described by "pairs" and each row has a height of H cells. The cells of this structure
// are numbered from left to right row by row. The relative position of the first cell of the structure is the row "offset" of the column 
// "pairs[0][0]". The created chunks occupy the cells of a table-like structure, whose numbers are "skip", "skip" + 1, ..., "skip" + L - 1   
fn create_chuncks<F:FieldExt, const H:u8, const L:usize>(pairs: &[[Column<Advice>; 2]], offset: i32, skip: usize) -> [Chunk<F,H>; L] {
    array::from_fn(|i| {
        let i = i + skip;
        let column = pairs[i / 2 % pairs.len()][i % 2];
        let shift = i / 2 / pairs.len() * H as usize;
        Chunk::<F,H>::new(column, shift as i32 + offset)
    })
}

// Creates XChunks, the xor column triplets for which are specified by "xtriplets". The relative places of these XChunks can be considered 
// as cells of a table-like structure, for which columns are xor column triplets described by "xtriplets" and each row has a height of H
// cells. The cells of this structure are numbered from left to right row by row. The relative position of the first cell of the structure 
// is the row "offset" of the column "xtriplets[0]". The created chunks occupy the cells of a table-like structure, whose numbers are "skip", 
// "skip" + 1, ..., "skip" + L - 1
fn create_xchunks<F:FieldExt, const H:u8, const L:usize>(xtriplets: &[[Column<Advice>; 3]], offset: i32, skip: usize) -> [XChunk<F,H>; L] {
    array::from_fn(|i| {
        let i = i + skip;
        let xtriplet = xtriplets[i % xtriplets.len()];
        let shift = i / xtriplets.len() * H as usize;
        XChunk::<F,H>::new(xtriplet, shift as i32 + offset)
    })
}

// Creates the instance of Expression which is 1, if all the combined selectors stored in the specified relative 
// places are active, and 0 otherwise
fn combine_selectors<F:FieldExt>(meta: &mut VirtualCells<F>, selectors: &[Combiselector<F>]) -> Expression<F> {
    selectors.iter().fold(gf(1), |product, selector| product * selector.expr(meta))
}

// Sets the state of the combined selectors specified by their relative places and the assignment row
fn enable_selectors<F:FieldExt>(region: &mut Region<F>, row: usize, selectors: &[Combiselector<F>], active: bool) -> Result<(), Error> {
    for selector in selectors {
        selector.enable(region, row, active)?;
    }
    Ok(())
}

// Creates the constraint, which asserts that strictly one group of the combined selectors stored in the relative places specified by
// "targets" is completely active for each assignment row, for which the group of the combined selectors stored in the relative places 
// specified by "selectors" is completely active
fn assert_single_active<F:FieldExt>(meta: &mut ConstraintSystem<F>, selectors: &[Combiselector<F>], targets: &[&[Combiselector<F>]]) {
    meta.create_gate("SingleCombiselector", |meta| {
        vec![combine_selectors(meta, selectors) * targets.iter().fold(-gf(1), |sum, term| sum + combine_selectors(meta, term))]
    });
}

// Creates the constraint, which asserts that the value stored in the in the relative place specified by "cell" is 0
// for each assignment row, for which the group of the combined selectors stored in the relative places specified by 
// "selectors" is completely active
fn assert_zero<F:FieldExt,const P:u8>(meta: &mut ConstraintSystem<F>, selectors: &[Combiselector<F>], cell: GeneralCell<F,P>) {
    meta.create_gate("ZeroChunk", |meta| { 
        vec![combine_selectors(meta, selectors) * cell.expr(meta)] 
    });
}

// Describes the relative place of a byte-column chunk of height H
#[derive(Copy, Clone)]
pub struct Chunk<F:FieldExt, const H:u8> {
    column: Column<Advice>, // The column containing the chunk
    offset: i32, // The chunk offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field
}

impl<F:FieldExt, const H:u8> Chunk<F, H> {
    // Creates a Chunk for the specified byte column
    // and offset relative to the assignment row
    pub fn new(column: Column<Advice>, offset: i32) -> Self {
        assert!(H <= 8, "Cannot create the {}-cell Chunk. The maximum height is 8!", H);
        Chunk { column, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the specified cell of the Chunk
    pub fn expr(&self, meta: &mut VirtualCells<F>, cell: usize) -> Expression<F> {
        assert!(cell < H.into(), "Accessing the cell {} in the {}-cell Chunk!", cell, H);
        meta.query_advice(self.column, Rotation(self.offset + (cell as i32)))
    }

    // Assigns the little-endian representation of "value" to the byte-column chunk, which 
    // is described by the current Chunk instance and the specified assigment row
    pub fn assign(&self, region: &mut Region<F>, row: usize, value: u64) -> Result<(), Error> {
        let offset = shift_row(row, self.offset);
        for (i, v) in value.to_le_bytes()[0..H as usize].iter().enumerate() {
            region.assign_advice(|| "", self.column, offset + i, || known::<F>(*v as u64))?;
        }
        Ok(())
    }

    // Creates the L-cell Chunk, which is a part of the Chunk instance and starts at its ("skip" + 1)-th cell
    pub fn subchunk<const L:u8>(&self, skip: u8) -> Chunk<F, L> {
        assert!(skip + L <= H, "Cannot create the {}-cell subchunk from the {}-cell Chunk skipping {} cells!", L, H, skip);
        Chunk { column: self.column, offset: self.offset + skip as i32, _marker: PhantomData }
    }
}

// Describes the relative place of a cell of a column, usable 
// rows of which contain only values in {0, 1, ..., M}; 
#[derive(Copy, Clone)]
pub struct ShortCell<F:FieldExt, const M:u8> {
    column: Column<Advice>,  // The column containing the cell
    offset: i32, // The cell offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field
}

impl<F:FieldExt, const M:u8> ShortCell<F, M> {
    // Creates a ShortCell for the specified constrained  
    // column and offset relative to the assignment row
    pub fn new(column: Column<Advice>, offset: i32) -> Self {
        ShortCell { column, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the ShortCell
    pub fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset))
    }

    // Assigns "value" to the constrained column cell, which is described  
    // by the current ShortCell instance and the specified assigment row
    pub fn assign(&self, region: &mut Region<F>, row: usize, value: u8) -> Result<(), Error> {
        let offset = shift_row(row, self.offset);
        assert!(value <= M, "Cannot assign the value {} to a ShortCell with a maximum value of {}!", value, M);
        region.assign_advice(|| "", self.column, offset, || known::<F>(value as u64))?;
        Ok(())
    }
}

// Describes the relative place of a   
// xor column triplet chunk of height H
#[derive(Copy, Clone)]
pub struct XChunk<F:FieldExt, const H:u8> {
    xtriplet: [Column<Advice>; 3], // The xor column triplet containing the chunk
    offset: i32, // The chunk offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the native field of the columns
}

impl<F:FieldExt, const H:u8> XChunk<F, H> {
    // Creates an XChunk for the specified xor column 
    // triplet and offset relative to the assignment row
    pub fn new(xtriplet: [Column<Advice>; 3], offset: i32) -> Self {
        assert!(H <= 8, "Cannot create the XChunk of height {}. The maximum height is 8!", H);
        Self { xtriplet, offset, _marker: PhantomData }
    }

    // Creates the H-cell Chunk, which is the current XChunk instance part contained 
    // in the column specified by "index", the value of which can be 0, 1 or 2
    pub fn operand(&self, index: usize) -> Chunk<F,H> {
        assert!(index < 3, "The operand {} does not exist in XChunks!", index);
        Chunk::<F,H>::new(self.xtriplet[index], self.offset)
    }
}

// Describes the relative place of a cell   
// of an unconstrained column in the P-th phase 
#[derive(Copy, Clone)]
pub struct GeneralCell<F:FieldExt, const P:u8> {
    column: Column<Advice>, // The column containing the cell
    offset: i32, // The cell offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field

}

impl<F:FieldExt, const P:u8> GeneralCell<F, P> {
    // Creates a GeneralCell for the specified unconstrained 
    // column and offset relative to the assignment row
    pub fn new(column: Column<Advice>, offset: i32) -> Self {
        Self { column, offset, _marker: PhantomData }
    }
    
    // Creates the instance of Expression for the GeneralCell
    pub fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset))
    }

    // Assigns "value" to the unconstrained column cell, which is described  
    // by the current GeneralCell instance and the specified assigment row
    pub fn assign(&self, region: &mut Region<F>, row: usize, value: Value<F>) -> Result<(), Error> {
        region.assign_advice(|| "", self.column, shift_row(row, self.offset), || value)?;
        Ok(())
    }
}

// Describes the relative place of a combined selector
#[derive(Copy, Clone)]
pub struct Combiselector<F:FieldExt> {
    allowed: Column<Fixed>, // The "allowed" column containing the fixed cell of the combined selector
    selector: Column<Advice>, // The column containing the advice cell of the combined selector
    offset: i32, // The combined selector's offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the native field of the columns
}

impl<F:FieldExt> Combiselector<F> {
    // Creates a Combiselector for the specified "allowed" column, 
    // advice column and offset relative to the assignment row
    pub fn new(allowed: Column<Fixed>, selector: Column<Advice>, offset: i32) -> Self {
        Self { allowed, selector, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the Combiselector
    pub fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.allowed, Rotation(self.offset)) * meta.query_advice(self.selector, Rotation(self.offset))
    }

    // Activates or inactivates (depending on "active") the combined selector, which is    
    // described by the current Combiselector instance and the specified assigment row
    pub fn enable(&self, region: &mut Region<F>, row: usize, active: bool) -> Result<(), Error> {
        let offset = shift_row(row, self.offset);
        region.assign_advice(|| "", self.selector, offset, || known::<F>(active as u64))?;
        Ok(())
    }
}

type OctaChunk<F> = Chunk<F,8>;
type ByteChunk<F> = Chunk<F,1>; 
type BitCell<F> = ShortCell<F,1>;
type SeptaCell<F> = ShortCell<F,127>;

// Defines the gate class, whose representatives activate  
// or inactivate the specified target combined selector
#[derive(Clone)]
pub struct SelectorGate<F:FieldExt> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors 
    input: bool, // The flag specifying whether the target combined selector should be activated
    result: Combiselector<F> // The target Combiselector
}

impl<F:FieldExt> SelectorGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors 
                 selectors: &[Combiselector<F>],
                 // The flag specifying whether the target combined selector should be activated 
                 input: bool,
                 // The target Combiselector 
                 result: Combiselector<F>) -> Self {
        meta.create_gate("SelectorGate", |meta| {
            vec![combine_selectors(meta, selectors) * (result.expr(meta) - gf(input as u128))]
        });
    
        Self { selectors: selectors.to_vec(), input, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize) -> Result<bool, Error> {
        self.result.enable(region, row, self.input)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(self.input)
    }
}

// Defines the gate class, whose representatives assign the little-endian representation 
// of a certain constant to the specified target byte-column chunk of height 8 
#[derive(Clone)]
pub struct ConstantGate<F:FieldExt> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    input: u64, // The constant, whose little-endian representation is assigned
    result: OctaChunk<F> // The target Chunk
}

impl<F:FieldExt> ConstantGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors 
                 selectors: &[Combiselector<F>],
                 // The constant, whose little-endian representation is assigned
                 input: u64,
                 // The target Chunk
                 result: OctaChunk<F>) -> Self {   
        meta.create_gate("ConstantGate", |meta| {
            let mut constraints = vec![];
            let selector = combine_selectors(meta, selectors);
            let input = input.to_le_bytes();
            for c in 0..8 {
                constraints.push(selector.clone() * (result.expr(meta, c) - gf(input[c] as u128)));
            }
            constraints
        });

        Self { selectors: selectors.to_vec(), input, result }
    }

    fn assign(&self, region: &mut Region<F>, row: usize) -> Result<u64, Error> {
        self.result.assign(region, row, self.input)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(self.input)
    }
}

// Defines the gate class, whose representatives assign to the specified 
// target byte-column chunk of height 8 the little-endian representation 
// of a constant, which is сhosen from a certain pair in accordance with
// the value of the specified choosing bit cell 
#[derive(Clone)]
pub struct BiconstantGate<F:FieldExt> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    input: [u64; 2], // The constants pair, where the i-th entry is assigned iff the choosing bit cell contains i
    result: OctaChunk<F>, // The target Chunk
}

impl<F:FieldExt> BiconstantGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors 
                 selectors: &[Combiselector<F>],
                 // The constants pair, where the i-th entry is assigned iff the choosing bit cell contains i
                 input: [u64; 2],
                 // The relative place of the choosing bit cell
                 flag: BitCell<F>,
                 // The target Chunk
                 result: OctaChunk<F>) -> Self {
        meta.create_gate("BiconstantGate", |meta| { 
            let flag = flag.expr(meta);         
            let selector = combine_selectors(meta, selectors);
            let input = [input[0].to_le_bytes(), input[1].to_le_bytes()];
            let mut constraints = vec![];

            for i in 0..8 {
                let zero = (gf(1) - flag.clone()) * gf(input[0][i] as u128);
                let one = flag.clone() * gf(input[1][i] as u128);
                constraints.push(selector.clone() * (result.expr(meta, i) - zero - one));
            }

            constraints
        });

        Self { selectors: selectors.to_vec(), input, result }
    }

    // The value of the choosing bit cell is described by "flag"
    fn assign(&self, region: &mut Region<F>, row: usize, flag: bool) -> Result<u64, Error>{
        let result = if flag { self.input[1] } else { self.input[0] };
        self.result.assign(region, row, result)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives copy the value of
// the specified input byte-column chunk of height 8 to the target one
#[derive(Clone)]
pub struct CopyGate<F:FieldExt> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: OctaChunk<F> // The target Chunk
}

impl<F:FieldExt> CopyGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors 
                 selectors: &[Combiselector<F>],
                 // The input Chunk
                 input: OctaChunk<F>,
                 // The target Chunk
                 result: OctaChunk<F>) -> Self {   
        meta.create_gate("CopyGate", |meta| {
            let mut constraints = vec![];
            let selector = combine_selectors(meta, selectors);
            for c in 0..8 {
                constraints.push(selector.clone() * (result.expr(meta, c) - input.expr(meta, c)));
            }
            constraints
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The number, whose little-endian representation is stored  
    // in the input byte-column chunk, is specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error> {
        self.result.assign(region, row, input)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(input)
    }
}

// Defines the gate class, whose representatives copy the value of
// the specified input unconstrained column cell to the target one
#[derive(Clone)]
pub struct CopyGeneralGate<F:FieldExt, const P:u8> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,P> // The target GeneralCell
}

impl<F:FieldExt, const P:u8> CopyGeneralGate<F, P> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The input GeneralCell
                 input: GeneralCell<F,P>,
                 // The target GeneralCell
                 result: GeneralCell<F,P>) -> Self {   
        meta.create_gate("CopyGeneralGate", |meta| {
            vec![combine_selectors(meta, selectors) * (result.expr(meta) - input.expr(meta))]
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The value stored in the input unconstrained column cell is specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: Value<F>) -> Result<Value<F>, Error> {
        self.result.assign(region, row, input)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(input)
    }
}

// Defines the gate class, whose representatives assign to the specified 
// target unconstrained column cell the value of the input one minus 1 in 
// accordance with the native field arithmetic
#[derive(Clone)]
pub struct DownCounterGate<F:FieldExt, const P:u8> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,P> // The target GeneralCell
}

impl<F:FieldExt, const P:u8> DownCounterGate<F,P> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The input GeneralCell
                 input: GeneralCell<F,P>,
                 // The target GeneralCell
                 result: GeneralCell<F,P>) -> Self {
        meta.create_gate("DownCounterGate", |meta| {
            vec![combine_selectors(meta, selectors) * (result.expr(meta) + gf(1) - input.expr(meta))]
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The value stored in the input unconstrained column cell is specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: F) -> Result<F, Error> {
        let result = input - F::one();
        self.result.assign(region, row, Value::known(result))?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives compute the nine byte sum of up to 256 numbers, 
// whose little-endian representations are stored in the specified input byte-column chunks of 
// height 8, transform this sum into the little-endian representation, assign the first eight
// bytes of it to the specified target byte-column chunk of height 8 and save the last byte into
// the specified target one-byte-column chunk
#[derive(Clone)]
pub struct AddGate<F:FieldExt, const S:usize> {
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: OctaChunk<F>, // The target Chunk of height 8
    carry: ByteChunk<F> // The target ByteChunk
}

impl<F:FieldExt, const S:usize> AddGate<F,S> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The input Chunks of height 8
                 input: &[OctaChunk<F>; S],
                 // The target Chunk of height 8
                 result: OctaChunk<F>,
                 // The target ByteChunk
                 carry: ByteChunk<F>) -> Self {
        assert!(S <= 256, "Cannot create AddGate with {} summands. The maximum number of summands is 256!", S);

        meta.create_gate("AddGate", |meta| {
            let left = input.iter().map(|term| chunk_to_number(meta, *term)).fold(gf(0), |sum, term| sum + term);
            let right = carry.expr(meta, 0) * gf(1u128 << 64) + chunk_to_number(meta, result);
            vec![combine_selectors(meta, selectors) * (left - right)]
        });

        Self { selectors: selectors.to_vec(), result, carry }
    }

    // The summands are specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: &[u64; S]) -> Result<(u64, u8), Error>{
        let sum = input.iter().fold(0, |sum, term| sum  + (*term as u128));
        let (result, carry) = (sum as u64, (sum >> 64) as u64);    
        self.result.assign(region, row, result)?;
        self.carry.assign(region, row, carry)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok((result, carry as u8))
    }
}

// Defines the gate class, whose representatives compute the bitwise xor of two numbers, whose 
// little-endian representations are stored in the first and second subcolumns of the specified 
// xor column triplet chunk of height 8, and assigns its little-endian representation to the third
// subcolumn of the xor column triplet chunk
#[derive(Clone)]
pub struct XorGate<F:FieldExt>{ 
    result: OctaChunk<F> // The third subcolumn of the xor column triplet chunk 
}

impl<F:FieldExt> XorGate<F> {
    // The relative place of the xor column triplet chunk is specified by "xchunk"
    fn configure(xchunk: XChunk<F,8>) -> Self {
        Self { result: xchunk.operand(2) }
    }

    // The xored values are specified by "first" and "second"
    fn assign(&self, region: &mut Region<F>, row: usize, first: u64, second: u64) -> Result<u64, Error> {
        let result = first ^ second;
        self.result.assign(region, row, result)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives compute the B-byte circular right  
// shift of the number, whose little-endian representation is stored in the specified  
// input byte-column chunk of height 8, and assign the little-endian representation
// of the computation result to the specified target byte-column chunk
#[derive(Clone)]
pub struct ShiftBytesGate<F:FieldExt, const B:usize>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: OctaChunk<F> // The target Chunk
}

impl<F:FieldExt, const B:usize> ShiftBytesGate<F,B> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The input Chunk
                 input: OctaChunk<F>,
                 // The target Chunk
                 result: OctaChunk<F>) -> Self  {
        meta.create_gate("ShiftBytesGate", |meta| {
            let mut constraints = vec![];
            let selector = combine_selectors(meta, selectors);

            for i in 0..8 {
                let position = (i + 8 - B) % 8;
                constraints.push(selector.clone() * (result.expr(meta, position) - input.expr(meta, i)));
            }

            constraints     
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The shifted number is specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let result = input.rotate_right(B as u32 * 8);
        self.result.assign(region, row, result)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives compute the 63-bit circular right  
// shift of the number, whose little-endian representation is stored in the specified  
// input byte-column chunk of height 8, and assign the little-endian representation
// of the computation result to the specified target byte-column chunk
#[derive(Clone)]
pub struct Shift63Gate<F:FieldExt>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    bit: BitCell<F>, // The ShortCell of the copy of the highest bit of the shifted number  
    septet: SeptaCell<F>, // The ShortCell of the shifted number's highest-byte value modulo 128
    result: OctaChunk<F> // The target Chunk
}

impl<F:FieldExt> Shift63Gate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The input Chunk 
                 input: OctaChunk<F>,
                 // The ShortCell of the copy of the highest bit of the shifted number
                 bit: BitCell<F>,
                 // The ShortCell of the shifted number's highest-byte value modulo 128
                 septet: SeptaCell<F>,
                 // The target Chunk
                 result: OctaChunk<F>) -> Self {
        meta.create_gate("Shift63Gate", |meta| {
            let selector = combine_selectors(meta, selectors);
            let septet = septet.expr(meta);
            let bit = bit.expr(meta);
            let high = input.expr(meta, 7);

            let byte = bit.clone() * gf(128) + septet.clone();
            let left = septet * gf(1 << 57) + chunk_to_number(meta, input.subchunk::<7>(0)) * gf(2) + bit.clone();
            let right = chunk_to_number(meta, result); 

            vec![selector.clone() * (byte - high), selector * (left - right)]
        });

        Self { selectors: selectors.to_vec(), bit, septet, result }
    }

    // The shifted number is specified by "input"
    fn assign(&self, region: &mut Region<F>, row: usize, input: u64) -> Result<u64, Error>{
        let bit = (input >> 63) as u8; 
        let septet = ((input >> 56) & 0x7F) as u8;
        let result = input.rotate_right(63);
        self.result.assign(region, row, result)?;
        self.bit.assign(region, row, bit)?;
        self.septet.assign(region, row, septet)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives set the states  
// of the target combined selectors from the specified array 
#[derive(Clone)]
pub struct SelectorMultiGate<F:FieldExt, const L:usize> {
    selectors: [SelectorGate<F>; L] // The array of SelectorGates dealing with the corresponding target Combiselectors 
}

impl<F:FieldExt, const L:usize> SelectorMultiGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The flag array, where the i-th entry is true iff the i-th target combined selector should be activated
                 input: &[bool; L],
                 // The array of the target Combiselectors
                 result: &[Combiselector<F>; L]) -> Self {
        Self { selectors: array::from_fn(|i| SelectorGate::<F>::configure(meta, selectors, input[i], result[i])) }    
    }

    fn assign(&self, region: &mut Region<F>, row: usize) -> Result<([bool; L]), Error> {
        let mut result = [false; L];
        for i in 0..L {
            result[i] = self.selectors[i].assign(region, row)?;
        }
        Ok(result)    
    }
}

// Defines the gate class, whose representatives assign the little-endian 
// representations of constants from a certain array to the corresponding 
// the target byte-column chunks of height 8 from the specified list
#[derive(Clone)]
pub struct ConstantMultiGate<F:FieldExt, const L:usize> {
    constants: [ConstantGate<F>; L] // The array of ConstantGates dealing with the corresponding target Chunks
}

impl<F:FieldExt, const L:usize> ConstantMultiGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The little-endian representation of the i-th entry of this array is assigned to the i-th target byte-column chunk
                 input: &[u64; L],
                 // The array of the target Chunks
                 result: &[OctaChunk<F>; L]) -> Self {
        Self { constants: array::from_fn(|i| ConstantGate::<F>::configure(meta, selectors, input[i], result[i])) }    
    }

    fn assign(&self, region: &mut Region<F>, row: usize) -> Result<([u64; L]), Error> {
        let mut result = [0; L];
        for i in 0..L {
            result[i] = self.constants[i].assign(region, row)?;
        }
        Ok(result)    
    }
}

// Defines the gate class, whose representatives copy the values of the byte-column 
// chunks of height 8 from the specified input list to such chunks from a ceratin target 
// list in accordance with the specified permutation, which is described by the array, 
// where the i-th entry contains the index of the input list's chunk, whose value is
// assigned to the i-th chunk of the target list
#[derive(Clone)]
pub struct PermuteGate<F:FieldExt, const L:usize>{
    permutation: [usize; L], // The permutation array
    copy: [CopyGate<F>; L] // The array of CopyGates dealing with the corresponding target Chunks
}

impl<F:FieldExt, const L:usize> PermuteGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The permutation array or "None" for the identity permutation
                 permutation: Option<&[usize; L]>,
                 // The array of the input Chunks 
                 input: &[OctaChunk<F>; L],
                 // The array of the target Chunks
                 result: &[OctaChunk<F>; L]) -> Self {
        let permutation = match permutation { Some(value) => *value, None => array::from_fn(|i| i) };
        let copy = array::from_fn(|i| CopyGate::<F>::configure(meta, selectors, input[permutation[i]], result[i]));
        Self { permutation, copy }
    }
    
    // The i-th entry of "input" specifies the number, whose little-endian representation is stored in the i-th input byte-column chunk
    fn assign(&self, region: &mut Region<F>, row: usize, input: &[u64; L]) -> Result<([u64; L]), Error> {
        let mut result = [0; L];
        for i in 0..L {
            result[i] = self.copy[i].assign(region, row, input[self.permutation[i]])?;
        }
        Ok(result)
    }
}

// Defines the gate class, whose representatives set the states of the combined selectors from 
// the specified target list in such a way that the ((i + 1) mod L)-th selector of this list has 
// the same state as i-th combined selector of the specified input list
#[derive(Clone)]
pub struct SelectorShiftGate<F:FieldExt, const L:usize>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: [Combiselector<F>; L], // The array of the target Combiselectors
}

impl<F:FieldExt, const L:usize> SelectorShiftGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The array of the input Combiselectors
                 input: &[Combiselector<F>; L],
                 // The array of the target Combiselectors
                 result: &[Combiselector<F>; L]) -> Self {
        meta.create_gate("SelectorShiftGate", |meta| {
            let selector = combine_selectors(meta, selectors);
            let mut constraints = vec![];
            
            for i in 0..L {
                constraints.push(selector.clone() * (result[(i + 1) % L].expr(meta) - input[i].expr(meta)));
            }
            
            constraints
        });

        Self { selectors: selectors.to_vec(), result: *result }
    }

     // The i-th entry of "input" specifies whether the i-th input combined selector is active  
    fn assign(&self, region: &mut Region<F>, row: usize, input: &[bool; L]) -> Result<([bool; L]), Error> {
        let mut result = [false; L];
        for i in 0..L {
            let j = (i + 1) % L;
            self.result[j].enable(region, row, input[i])?;
            result[j] = input[i];
        }
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(result)
    }
}

// Defines the gate class, whose representatives assign to the specified target unconstrained 
// column cell the random linear combintaion hash of a certain BLAKE2b compression function 
// input. This hash is equal to RLC(0, c, field(r|h|m|(t mod 2^64)|(t div 2^64)|f)), where 
// c is the specfied challenge, r, h, m, t, f are defined as in RFC 7693 and field(d) maps 
// the number tuple d to the array of the naturally corresponding native field elements. The 
// little-endian representations of the 64-bit input values, including t mod 2^64 and t div 2^64,
// are taken from the specified input byte-column chunks of height 8. The field elements describing
// r and f are taken from the specified input unconstrained column cell and bit cell, respectively
#[derive(Clone)]
pub struct InitialRLCGate<F:FieldExt>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,2> // The target GeneralCell
}

impl<F:FieldExt> InitialRLCGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The challenge for hashing
                 challenge: Challenge,
                 // The GeneralCell of the number of rounds
                 r: GeneralCell<F,1>,
                 // The array of the Chunks of the initial state vector 
                 h: &[OctaChunk<F>; 8],
                 // The array of the Chunks of the message block vector 
                 m: &[OctaChunk<F>; 16],
                 // The array of the Chunks of the vector (t mod 2^64, t div 2^64) descibing the offset counter
                 t: &[OctaChunk<F>; 2],
                 // The ShortCell of the final block indicator flag
                 f: BitCell<F>,
                 // The target GeneralCell
                 result: GeneralCell<F,2>) -> Self {
        meta.create_gate("InitialRLCGate", |meta| {
            let challenge = meta.query_challenge(challenge);
            let (mut rlc, f) = (r.expr(meta), f.expr(meta));

            let terms = h.iter().chain(m.iter()).chain(t.iter()).map(|c| 
                chunk_to_number(meta, *c)).chain([f].into_iter());
            
            for term in terms {
                rlc = rlc * challenge.clone() + term;
            }

            vec![combine_selectors(meta, selectors) * (result.expr(meta) - rlc)]
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The challenge is specified by "challenge", the elements of the compression function input are specified according to RFC 7693  
    fn assign(&self, region: &mut Region<F>, row: usize, challenge: Value<F>, r: F, 
        h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> Result<Value<F>, Error> {
        
        let (t, f) = ([t as u64, (t >> 64) as u64], [f as u64]);
        let terms = h.iter().chain(m.iter()).chain(t.iter()).chain(f.iter()).map(|v| known::<F>(*v));
        
        let mut rlc = Value::known(r);
        for term in terms {
            rlc = rlc * challenge + term;
        }

        self.result.assign(region, row, rlc)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(rlc)
    }
}

// Defines the gate class, whose representatives assign to the specified target unconstrained 
// column cell the random linear combintaion hash of a certain BLAKE2b compression function 
// input and output. The hash is equal to RLC(0, c, field(r|h|m|(t mod 2^64)|(t div 2^64)|f|o)), 
// where c is the specfied challenge, r, h, m, t, f are defined as in RFC 7693, o is the output 
// state vector and field(d) maps the number tuple d to the array of the naturally corresponding 
// native field elements. The computation of this hash is based on the following relation:
// RLC(0, c, field(r|h|m|(t mod 2^64)|(t div 2^64)|f|o)) = RLC(i, c, field(o)), where i is the
// hash of the compression function input computed by an InitialRLCGate and taken from the specified 
// input unconstrained column cell.The little-endian representations of elements of o are taken from 
// the specified input byte-column chunks of height 8.   
#[derive(Clone)]
pub struct FinalRLCGate<F:FieldExt>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,2> // The target GeneralCell
}

impl<F:FieldExt> FinalRLCGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The challenge for hashing
                 challenge: Challenge,
                 // The GeneralCell of the hash of the compression function input
                 input: GeneralCell<F,2>,
                 // The array of the Chunks of the output state vector
                 h: &[OctaChunk<F>; 8],
                 // The target GeneralCell
                 result: GeneralCell<F,2>) -> Self {
        meta.create_gate("FinalRLCGate", |meta| {
            let challenge = meta.query_challenge(challenge);
                             
            let mut rlc = input.expr(meta);
            for term in h.iter().map(|c| chunk_to_number(meta, *c)) {
                rlc = rlc * challenge.clone() + term;
            }

            vec![combine_selectors(meta, selectors) * (result.expr(meta) - rlc)]
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The challenge is specified by "challenge", the hash of the compression function  
    // input is described by "input", the output state vector is specified by "h"
    fn assign(&self, region: &mut Region<F>, row: usize, challenge: Value<F>, input: Value<F>, h: &[u64; 8]) -> Result<Value<F>, Error> {             
        let mut rlc = input;
        for term in h.iter().map(|v| known::<F>(*v)) {
            rlc = rlc * challenge + term;
        }

        self.result.assign(region, row, rlc)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(rlc)
    }
}

#[derive(Clone)]
pub struct GGate<F:FieldExt>{
    copy: [CopyGate<F>; 4],
    add3: [AddGate<F, 3>; 2],
    add2: [AddGate<F, 2>; 2],
    xors: [XorGate<F>; 4],
    shift32: ShiftBytesGate<F, 4>,
    shift24: ShiftBytesGate<F, 3>,
    shift16: ShiftBytesGate<F, 2>,
    shift63: Shift63Gate<F>,
}

impl<F:FieldExt> GGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selectors: &[Combiselector<F>],
                 input: &[OctaChunk<F>; 4],
                 x: OctaChunk<F>,
                 y: OctaChunk<F>,
                 misc1: BitCell<F>,
                 misc7: SeptaCell<F>,
                 misc8: &[ByteChunk<F>; 4],
                 xchunks: &[XChunk<F,8>; 4],                 
                 result: &[OctaChunk<F>; 4]) -> Self { 
        let [a, c, d, b]: [OctaChunk<F>; 4] = array::from_fn(|i| xchunks[i].operand(0)); 
        let xout: [OctaChunk<F>; 4] = array::from_fn(|i| xchunks[i].operand(2));

        GGate {
            copy: [CopyGate::<F>::configure(meta, selectors, input[3], xchunks[0].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, input[1], xchunks[1].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, result[0], xchunks[2].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, result[2], xchunks[3].operand(1))],

            xors: [XorGate::<F>::configure(xchunks[0]), XorGate::<F>::configure(xchunks[1]), 
                  XorGate::<F>::configure(xchunks[2]), XorGate::<F>::configure(xchunks[3])],

            add3: [AddGate::<F, 3>::configure(meta, selectors, &[input[0], input[1], x], a, misc8[0]),
                   AddGate::<F, 3>::configure(meta, selectors, &[a, b, y], result[0], misc8[1])],
            
            add2: [AddGate::<F, 2>::configure(meta, selectors, &[d, input[2]], c, misc8[2]),
                   AddGate::<F, 2>::configure(meta, selectors, &[c, result[3]], result[2], misc8[3])],
            
            shift32: ShiftBytesGate::<F, 4>::configure(meta, selectors, xout[0], d),
            shift24: ShiftBytesGate::<F, 3>::configure(meta, selectors, xout[1], b),
            shift16: ShiftBytesGate::<F, 2>::configure(meta, selectors, xout[2], result[3]),      
            shift63: Shift63Gate::<F>::configure(meta, selectors, xout[3], misc1, misc7, result[1]),
        }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, v: &mut [u64; 16], 
        a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) -> Result<(), Error> {

        v[a] = self.add3[0].assign(region, row, &[v[a], v[b], x])?.0;
        self.copy[0].assign(region, row, v[d])?;
        v[d] = self.xors[0].assign(region, row, v[d], v[a])?;
        v[d] = self.shift32.assign(region, row, v[d])?;
        v[c] = self.add2[0].assign(region, row, &[v[c], v[d]])?.0;
        self.copy[1].assign(region, row, v[b])?; 
        v[b] = self.xors[1].assign(region, row, v[b], v[c])?;
        v[b] = self.shift24.assign(region, row, v[b])?;

        v[a] = self.add3[1].assign(region, row, &[v[a], v[b], y])?.0;
        self.copy[2].assign(region, row, v[a])?;
        v[d] = self.xors[2].assign(region, row, v[d], v[a])?;
        v[d] = self.shift16.assign(region, row, v[d])?;
        v[c] = self.add2[1].assign(region, row, &[v[c], v[d]])?.0;
        self.copy[3].assign(region, row, v[c])?;
        v[b] = self.xors[3].assign(region, row, v[b], v[c])?;
        v[b] = self.shift63.assign(region, row, v[b])?;
        
        Ok(())
    }
}

#[derive(Clone)]
pub struct RoundGate<F: FieldExt> {
    l: DownCounterGate<F,1>,
    h: PermuteGate<F,8>,
    p: SelectorShiftGate<F,10>,
    m: [PermuteGate<F,16>; 10],
    v: [GGate<F>; 8],
    rlc: CopyGeneralGate<F,2>
}

impl<F:FieldExt> RoundGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selectors: &[Combiselector<F>],
                 initial: &[Combiselector<F>],
                 round: &[Combiselector<F>],
                 left: [GeneralCell<F,1>; 2],
                 h: [&[OctaChunk<F>; 8]; 2],
                 m: [&[OctaChunk<F>; 16]; 2],
                 v: [&[OctaChunk<F>; 16]; 2],
                 rlc: [GeneralCell<F,2>; 2],
                 misc1: &[BitCell<F>; 8],
                 misc7: &[SeptaCell<F>; 8],
                 misc8: &[ByteChunk<F>; 32],
                 misc64: &[OctaChunk<F>; 16],
                 xchunks: &[XChunk<F,8>; 32],
                 permutators: [&[Combiselector<F>; 10]; 2]) -> Self {
        let miscs8: [&[ByteChunk<F>; 4]; 8] = arrefs_from_slice(misc8);
        let xors: [&[XChunk<F,8>; 4]; 8] = arrefs_from_slice(xchunks);
        let ([pi, po], [mi, mo], [vi, vo]) = (permutators, m, v);
        assert_single_active(meta, selectors, &[initial, round]);

        Self {
            l: DownCounterGate::<F,1>::configure(meta, selectors, left[0], left[1]),

            h: PermuteGate::<F, 8>::configure(meta, selectors, None, h[0], h[1]),

            p: SelectorShiftGate::<F, 10>::configure(meta, selectors, pi, po),

            m: array::from_fn(|i| {
                let permutation = permutation::compose(&permutation::invert(&SIGMA[i]), &SIGMA[(i + 1) % 10]);
                PermuteGate::configure(meta, &[selectors, &pi[i..i + 1]].concat(), Some(&permutation), &mi, &mo)
            }),

            v: [GGate::configure(meta, selectors, &[vi[0], vi[4], vi[8], vi[12]], mi[0], 
                    mi[1], misc1[0], misc7[0], miscs8[0], xors[0], &[misc64[0], misc64[4], misc64[8], misc64[12]]),
                GGate::configure(meta, selectors, &[vi[1], vi[5], vi[9], vi[13]], mi[2], 
                    mi[3], misc1[1], misc7[1], miscs8[1], xors[1], &[misc64[1], misc64[5], misc64[9], misc64[13]]),
                GGate::configure(meta, selectors, &[vi[2], vi[6], vi[10], vi[14]], mi[4], 
                    mi[5], misc1[2], misc7[2], miscs8[2], xors[2], &[misc64[2], misc64[6], misc64[10], misc64[14]]),
                GGate::configure(meta, selectors, &[vi[3], vi[7], vi[11], vi[15]], mi[6], 
                    mi[7], misc1[3], misc7[3], miscs8[3], xors[3], &[misc64[3], misc64[7], misc64[11], misc64[15]]),

                GGate::configure(meta, selectors, &[misc64[0], misc64[5], misc64[10], misc64[15]], mi[8], 
                    mi[9], misc1[4], misc7[4], miscs8[4], xors[4], &[vo[0], vo[5], vo[10], vo[15]]),
                GGate::configure(meta, selectors, &[misc64[1], misc64[6], misc64[11], misc64[12]], mi[10], 
                    mi[11], misc1[5], misc7[5], miscs8[5], xors[5], &[vo[1], vo[6], vo[11], vo[12]]),
                GGate::configure(meta, selectors, &[misc64[2], misc64[7], misc64[8], misc64[13]], mi[12], 
                    mi[13], misc1[6], misc7[6], miscs8[6], xors[6], &[vo[2], vo[7], vo[8], vo[13]]),                
                GGate::configure(meta, selectors, &[misc64[3], misc64[4], misc64[9], misc64[14]], mi[14], 
                    mi[15], misc1[7], misc7[7], miscs8[7], xors[7], &[vo[3], vo[4], vo[9], vo[14]])
            ],

            rlc: CopyGeneralGate::<F,2>::configure(meta, selectors, rlc[0], rlc[1])
        }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, rlc: Value<F>, round: &mut usize, 
        left: &mut F, h: &[u64; 8], m: &mut [u64; 16], v: &mut [u64; 16]) -> Result<(), Error> {
        
        *left = self.l.assign(region, row, *left)?;   
        self.h.assign(region, row, h)?;

        self.v[0].assign(region, row, v, 0, 4, 8, 12, m[0], m[1])?;
        self.v[1].assign(region, row, v, 1, 5, 9, 13, m[2], m[3])?;
        self.v[2].assign(region, row, v, 2, 6, 10, 14, m[4], m[5])?;
        self.v[3].assign(region, row, v, 3, 7, 11, 15, m[6], m[7])?;

        self.v[4].assign(region, row, v, 0, 5, 10, 15, m[8], m[9])?;
        self.v[5].assign(region, row, v, 1, 6, 11, 12, m[10], m[11])?;
        self.v[6].assign(region, row, v, 2, 7, 8, 13, m[12], m[13])?;
        self.v[7].assign(region, row, v, 3, 4, 9, 14, m[14], m[15])?;

        self.p.assign(region, row, &array::from_fn(|i| i == *round % 10))?;
        *m = self.m[*round % 10].assign(region, row, m)?;
        *round += 1;

        self.rlc.assign(region, row, rlc)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct InitialGate<F: FieldExt> {
    rlc: InitialRLCGate<F>,
    half: PermuteGate<F,8>,
    quarter: ConstantMultiGate<F,4>,
    x: ConstantMultiGate<F,2>,
    t: PermuteGate<F,2>,
    xors: [XorGate<F>; 2],
    xout: PermuteGate::<F,2>,
    not: BiconstantGate<F>,
    last: ConstantGate<F>,
    permutators: SelectorMultiGate<F,10>
}

impl<F:FieldExt> InitialGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selectors: &[Combiselector<F>],
                 challenge: Challenge,
                 r: GeneralCell<F,1>,
                 h: &[OctaChunk<F>; 8],
                 m: &[OctaChunk<F>; 16],
                 t: &[OctaChunk<F>; 2],
                 f: BitCell<F>,
                 xchunks: &[XChunk<F,8>; 2],
                 v: &[OctaChunk<F>; 16],
                 rlc: GeneralCell<F,2>,
                 permutators: &[Combiselector<F>; 10]) -> Self {       
        InitialGate {
            half: PermuteGate::<F,8>::configure(meta, selectors, 
                None, &h, &v[0..8].try_into().unwrap()),

            quarter: ConstantMultiGate::<F, 4>::configure(meta, selectors, 
                &IV[0..4].try_into().unwrap(), &v[8..12].try_into().unwrap()),
            
            x: ConstantMultiGate::<F, 2>::configure(meta, selectors, 
                &IV[4..6].try_into().unwrap(), &[xchunks[0].operand(0), xchunks[1].operand(0)]), 

            t: PermuteGate::<F,2>::configure(meta, selectors, None, 
                &t, &[xchunks[0].operand(1), xchunks[1].operand(1)]),

            xors: [XorGate::<F>::configure(xchunks[0]), XorGate::<F>::configure(xchunks[1])],

            xout: PermuteGate::<F,2>::configure(meta, selectors, None, 
                &[xchunks[0].operand(2), xchunks[1].operand(2)], &[v[12], v[13]]),

            not: BiconstantGate::<F>::configure(meta, selectors, [IV[6], !IV[6]], f, v[14]),

            last: ConstantGate::<F>::configure(meta, selectors, IV[7], v[15]),

            permutators: SelectorMultiGate::<F,10>::configure(meta, selectors, &array::from_fn(|i| i == 0), permutators),
            
            rlc: InitialRLCGate::<F>::configure(meta, selectors, challenge, r, h, m, t, f, rlc)
        }
    }

    fn assign(&self, region: &mut Region<F>, row: usize, challenge: Value<F>, r: F, 
        h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> Result<(Value<F>, [u64; 16]), Error> {
        
        let rlc = self.rlc.assign(region, row, challenge, r, h, m, t, f)?;
        
        let mut v = [0; 16];     
        v[0..8].clone_from_slice(&self.half.assign(region, row, h)?);
        v[8..12].clone_from_slice(&self.quarter.assign(region, row)?);
        
        let t = [t as u64, (t >> 64) as u64];
        let xins = [self.x.assign(region, row)?, 
                    self.t.assign(region, row, &t)?];
        let xouts = [self.xors[0].assign(region, row, xins[0][0], xins[1][0])?, 
                     self.xors[1].assign(region, row, xins[0][1], xins[1][1])?];  
        v[12..14].copy_from_slice(&self.xout.assign(region, row, &xouts)?);

        v[14] = self.not.assign(region, row, f)?;
        v[15] = self.last.assign(region, row)?;

        self.permutators.assign(region, row)?;

        Ok((rlc, v))
    }
}

#[derive(Clone)]
pub struct FinalGate<F:FieldExt> {
    h: PermuteGate<F,8>,
    v: PermuteGate<F,16>,
    xh: [XorGate<F>; 8],
    xv: [XorGate<F>; 8],
    xcopy: PermuteGate<F,8>,
    rlc: FinalRLCGate<F>
}

impl<F:FieldExt> FinalGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 selectors: &[Combiselector<F>],
                 challenge: Challenge,
                 initial: &[Combiselector<F>],
                 round: &[Combiselector<F>],
                 left: GeneralCell<F,1>,
                 h: &[OctaChunk<F>; 8],
                 v: &[OctaChunk<F>; 16],
                 xh: &[XChunk<F,8>; 8],
                 xv: &[XChunk<F,8>; 8],
                 rlc: [GeneralCell<F,2>; 2]) -> Self {
        assert_single_active(meta, selectors, &[initial, round]);
        assert_zero(meta, selectors, left);

        FinalGate {
            h: PermuteGate::<F, 8>::configure(meta, selectors, None, h, &array::from_fn(|i| xh[i].operand(1))),

            v: PermuteGate::<F, 16>::configure(meta, selectors, None, v, &array::from_fn(|i| xv[i % 8].operand(i / 8))),

            xh: array::from_fn(|i| XorGate::<F>::configure(xh[i])),

            xv: array::from_fn(|i| XorGate::<F>::configure(xv[i])),

            xcopy: PermuteGate::<F, 8>::configure(meta, selectors, None,
                 &array::from_fn(|i| xv[i].operand(2)), &array::from_fn(|i| xh[i].operand(0))),

            rlc: FinalRLCGate::configure(meta, selectors, challenge, rlc[0], &array::from_fn(|i| xh[i].operand(2)), rlc[1])
        }       
    }

    fn assign(&self, region: &mut Region<F>, row: usize, challenge: Value<F>, 
        rlc: Value<F>, h: &[u64; 8], v: &[u64; 16]) -> Result<([u64; 8], Value<F>), Error> {

        self.h.assign(region, row, h)?;
        self.v.assign(region, row, v)?;
        let mut xor = [0u64; 8];

        for i in 0..8 {
            xor[i] = self.xv[i].assign(region, row, v[i], v[i + 8])?;
        }

        self.xcopy.assign(region, row, &xor)?;
        
        for i in 0..8 {
            xor[i] = self.xh[i].assign(region, row, xor[i], h[i])?;
        }

        let rlc = self.rlc.assign(region, row, challenge, rlc, &xor)?;

        Ok((xor, rlc))
    }
}

#[derive(Clone)]
pub struct CircuitPreparator<F:FieldExt> {
    allocated: Column<Fixed>,
    allowed: Column<Fixed>,
    septalookup: Column<Fixed>,
    xlookup: [Column<Fixed>; 3],
    _marker: PhantomData<F>
}

impl<F:FieldExt> CircuitPreparator<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 allocated: Column<Fixed>,
                 allowed: Column<Fixed>,
                 septalookup: Column<Fixed>,
                 xlookup: [Column<Fixed>; 3],
                 bits: &[Column<Advice>],
                 septets: &[Column<Advice>],
                 pairs: &[[Column<Advice>; 2]],
                 xtriplets:  &[[Column<Advice>; 3]]) -> Self {
        meta.create_gate("CircuitPreparator", |meta| {
            let allocated = meta.query_fixed(allocated, Rotation::cur());
            let mut constraints = vec![];
            for bit in bits {
                let bit = meta.query_advice(*bit, Rotation::cur());
                constraints.push(allocated.clone() * bit.clone() * (gf(1) - bit)); 
            }
            constraints
        });

        for septet in septets {
            meta.lookup_any("CircuitPreparator", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated * meta.query_advice(*septet, Rotation::cur()), meta.query_fixed(septalookup, Rotation::cur()))]
            });
        }

        for pair in pairs {
            meta.lookup_any("CircuitPreparator", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated.clone() * meta.query_advice(pair[0], Rotation::cur()), meta.query_fixed(xlookup[0], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(pair[1], Rotation::cur()), meta.query_fixed(xlookup[1], Rotation::cur()))]
            });
        }

        for xtriplet in xtriplets {
            meta.lookup_any("CircuitPreparator", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated.clone() * meta.query_advice(xtriplet[0], Rotation::cur()), meta.query_fixed(xlookup[0], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(xtriplet[1], Rotation::cur()), meta.query_fixed(xlookup[1], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(xtriplet[2], Rotation::cur()), meta.query_fixed(xlookup[2], Rotation::cur()))]
            });
        }
        
        CircuitPreparator { allocated, allowed, septalookup, xlookup, _marker: PhantomData }
    }

    fn assign(&self, region: &mut Region<F>, k: u32, before: usize, after: usize, unusable: usize) -> Result<(), Error> {
        assert!(65536 + unusable <= (1 << k), "Not enough rows to prepare the lookup tables!");
        
        let disallowed = before + after + unusable;  
        assert!(disallowed < (1 << k), "Not enough rows to prepare the place for gates!");
        
        for row in 0..128 {
            region.assign_fixed(|| "", self.septalookup, row as usize, || known::<F>(row))?;
        }

        for row in 0..65536 {
            let (first, second) = (row as u64 & 0xFF, (row as u64 >> 8) & 0xFF);
            region.assign_fixed(|| "", self.xlookup[0], row, ||  known::<F>(first))?;
            region.assign_fixed(|| "", self.xlookup[1], row, || known::<F>(second))?;
            region.assign_fixed(|| "", self.xlookup[2], row, ||  known::<F>(first ^ second))?;
        }

        let allowed = (1 << k) - disallowed;

        for row in 0..(before + allowed + after)  {
            region.assign_fixed(|| "", self.allocated, row, || known::<F>(1))?;
        }

        for row in before..(allowed + before) {
            region.assign_fixed(|| "", self.allowed, row, || known::<F>(1))?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RLCTable<F:FieldExt> {
    pub allowed: Column<Fixed>,
    pub selector: Column<Advice>,
    pub rlc: Column<Advice>,
    pub challenge: Challenge,
    pub _marker: PhantomData<F>
}

impl<F:FieldExt> RLCTable<F> { 
    pub fn compute_rlc(challenge: Value<F>, hi: &[u64; 8], m: &[u64; 16], t: u128, f: bool, r: u32, ho: &[u64; 8]) -> Value<F> {
        let (t, f) = ([t as u64, (t >> 64) as u64], [f as u64]);
        let terms = hi.iter().chain(m.iter()).chain(t.iter()).
            chain(f.iter()).chain(ho.iter()).map(|v| known::<F>(*v));               
        let mut rlc = known::<F>(r as u64);
        for term in terms {
            rlc = rlc * challenge + term;
        }
        rlc
    }

    pub fn compress_with_rlc(challenge: Value<F>, h: &[u64; 8], m: &[u64; 16], t: u128, f: bool, r: u32) -> ([u64; 8], Value<F>) {
        let new = compress(r, h, m, t, f);
        let rlc = Self::compute_rlc(challenge, h, m, t, f, r, &new);
        (new, rlc)
    }
}

#[derive(Clone)]
pub struct CompressionInput {
    pub r: u32,
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: u128,
    pub f: bool
}

#[derive(Clone)]
pub struct CompressionConfig<F:FieldExt>{
    pub rlc_table: RLCTable<F>,
    pub circuit_preparator: CircuitPreparator<F>,
    pub initial_gate: InitialGate<F>,
    pub final_gate: FinalGate<F>,
    pub round_gate: RoundGate<F>,
    pub r: GeneralCell<F,1>,
    pub h: [OctaChunk<F>; 8],
    pub m: [OctaChunk<F>; 16],
    pub t: [OctaChunk<F>; 2],
    pub f: BitCell<F>,
    pub final_height: usize,
    pub unusable_rows: usize
}

#[derive(Default)]
pub struct CompressionCircuit<F:FieldExt, const R: usize> {
     pub k: u32,
     pub inputs: Vec<CompressionInput>,
     pub _marker: PhantomData<F>
}

impl <F:FieldExt, const R:usize> CompressionCircuit<F,R> {
    pub fn new(k: u32, inputs: &[CompressionInput]) -> Self {
        Self { k, inputs: inputs.to_vec(), _marker: PhantomData }
    }
    
    pub fn rows(inputs: &[CompressionInput]) -> usize {
        let config = Self::configure(&mut ConstraintSystem::<F>::default());
        let rounds = inputs.iter().fold(0, |sum, input| sum + input.r) as usize;
        let mut usable = (rounds + 2) * R + (8 + config.final_height) * (inputs.len() - 1) + 1;
        if usable < 65536 { usable = 65536; }
        usable + config.unusable_rows
    }

    pub fn k(inputs: &[CompressionInput]) -> u32 {
        (Self::rows(inputs) as f64).log2().ceil() as u32
    }

    pub fn optimums(inputs: &[CompressionInput]) -> [Option<usize>; 32] {
        let k = [ 
            CompressionCircuit::<F, {ROWS_PER_ROUND[0]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[1]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[2]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[3]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[4]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[5]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[6]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[7]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[8]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[9]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[10]}>::k(inputs),
            CompressionCircuit::<F, {ROWS_PER_ROUND[11]}>::k(inputs)];
        
        array::from_fn(|i| k.iter().enumerate().filter(|e| *e.1 <= i as u32).map(|e| ROWS_PER_ROUND[e.0]).max())
    }
}

impl<F:FieldExt, const R: usize> Circuit<F> for CompressionCircuit<F,R> {
    type Config = CompressionConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        assert!(ROWS_PER_ROUND.contains(&R), "Invalid number of rows per round!");
        
        let fixed = |meta: &mut ConstraintSystem<F>| meta.fixed_column();
        let advice = |meta: &mut ConstraintSystem<F>| meta.advice_column();

        let [allocated, allowed, septalookup] = array::from_fn(|_| fixed(meta));
        let xlookup: [Column<Fixed>; 3] = array::from_fn(|_| fixed(meta));
          
        let mut pairs = vec![];
        while pairs.len() * R < 240 {
            pairs.push([advice(meta), advice(meta)]);
        }

        let mut xors = vec![];
        while xors.len() * R < 256 {
            xors.push([advice(meta), advice(meta), advice(meta)]);       
        }

        let mut bits = vec![];
        for _ in 0..14 {
            bits.push(advice(meta));
        }

        let second = meta.advice_column_in(SecondPhase);
        let [septet, field] = array::from_fn(|_| advice(meta));

        let circuit_preparator = CircuitPreparator::configure(meta, allocated, allowed, septalookup, xlookup, &bits, &[septet], &pairs, &xors);

        let [initial_selector, round_selector, final_selector, bit] = array::from_fn(|_| bits.pop().unwrap());

        let hi: [OctaChunk<F>; 8] = create_chuncks(&pairs, 0, 0);
        let mi: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 8);
        let vi: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 24);
        let pi: [Combiselector<F>; 10] = array::from_fn(|i| Combiselector::<F>::new(allowed, bits[i], 0));
        let xchunks: [XChunk<F,8>; 32] = create_xchunks(&xors, 0, 0);
        let misc64: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 40);
        let misc7: [SeptaCell<F>; 8] = array::from_fn(|i| SeptaCell::<F>::new(septet, i as i32));
        let misc1: [BitCell<F>; 8] = array::from_fn(|i| BitCell::<F>::new(bit, i as i32));
        let misc: [OctaChunk<F>; 4] = create_chuncks(&pairs, 0, 56);
        let misc8: [ByteChunk<F>; 32] = array::from_fn(|i| misc[i / 8].subchunk((i % 8) as u8));
        let ho: [OctaChunk<F>; 8] = create_chuncks(&pairs, R as i32, 0);
        let mo: [OctaChunk<F>; 16] = create_chuncks(&pairs, R as i32, 8);
        let vo: [OctaChunk<F>; 16] = create_chuncks(&pairs, R as i32, 24);
        let po: [Combiselector<F>; 10] = array::from_fn(|i| Combiselector::<F>::new(allowed, bits[i], R as i32));
        let left = [GeneralCell::<F,1>::new(field, 0), GeneralCell::<F,1>::new(field, R as i32)]; 
        let rlc = [GeneralCell::<F,2>::new(second, 1), GeneralCell::<F,2>::new(second, R as i32 + 1)]; 
        let initial = Combiselector::<F>::new(allowed, initial_selector, 0);
        let round = Combiselector::<F>::new(allowed, round_selector, -(R as i32));
        let selector = Combiselector::<F>::new(allowed, round_selector, 0);
        let round_gate = RoundGate::<F>::configure(meta, &[selector], &[initial], &[round], left, [&hi, &ho], 
            [&mi, &mo], [&vi, &vo], rlc, &misc1, &misc7, &misc8, &misc64, &xchunks, [&pi, &po]);

        let challenge = meta.challenge_usable_after(FirstPhase);
        let r = GeneralCell::<F,1>::new(field, 0);
        let c = GeneralCell::<F,2>::new(second, 1);
        let h: [OctaChunk<F>; 8] = create_chuncks(&pairs, 0, 0);
        let m: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 8);
        let t: [OctaChunk<F>; 2] = create_chuncks(&pairs, -8, 0);
        let f = BitCell::<F>::new(bit, -8);
        let x: [XChunk<F, 8>; 2] = create_xchunks(&xors, -8, 0);
        let v: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 24);
        let p: [Combiselector<F>; 10] = array::from_fn(|i| Combiselector::<F>::new(allowed, bits[i], 0));
        let selector = Combiselector::<F>::new(allowed, initial_selector, 0);
        let initial_gate = InitialGate::<F>::configure(meta, &[selector], challenge, r, &h, &m, &t, f, &x, &v, c, &p);   

        let selector = Combiselector::<F>::new(allowed, final_selector, 0);
        let left = GeneralCell::<F,1>::new(field, 0);
        let [xv, xh]: [[XChunk<F,8>; 8]; 2] = array::from_fn(|i| create_xchunks(&xors, 0, 8 * i));
        let rlc = [GeneralCell::<F,2>::new(second, 1), GeneralCell::<F,2>::new(second, 0)]; 
        let final_gate = FinalGate::<F>::configure(meta, &[selector], challenge, &[initial], &[round], left, &hi, &vi, &xh, &xv, rlc);

        let final_height = 8 * (20.0 / pairs.len() as f64).ceil() as usize;
        let unusable_rows = meta.blinding_factors() + 1;

        let rlc_table = RLCTable { allowed, selector: final_selector, rlc: second, challenge, _marker: PhantomData };

        //////////////////////////////           
        //println!("Gates: {}", meta.gates().len());
        //println!("Lookups: {}", meta.lookups().len());
        //println!("Advice columns: {}", meta.num_advice_columns());
        //println!("Advice queries: {}", meta.advice_queries().len());
        //println!("Fixed columns: {}", meta.num_fixed_columns());
        //println!("Fixed queries: {}", meta.fixed_queries().len());
        //println!("Unusable rows: {}", meta.blinding_factors() + 1);
        //////////////////////////////

        CompressionConfig { rlc_table, circuit_preparator, initial_gate, final_gate, round_gate, r, h, m, t, f, final_height, unusable_rows }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let challenge = layouter.get_challenge(config.rlc_table.challenge);
        layouter.assign_region(|| "Blake2b",
            |mut region| {
                config.circuit_preparator.assign(&mut region, self.k, R, R, config.unusable_rows)?;
                let mut row = R;

                for input in &self.inputs {              
                    let mut left = F::from(input.r as u64);
                    config.r.assign(&mut region, row, Value::known(left))?;
                    config.t[0].assign(&mut region, row, input.t as u64)?;
                    config.t[1].assign(&mut region, row, (input.t >> 64) as u64)?;
                    config.f.assign(&mut region, row, input.f as u8)?;

                    for (value, chunk) in input.h.iter().chain(input.m.iter()).
                        zip(config.h.iter().chain(config.m.iter())) {
                        chunk.assign(&mut region, row, *value)?;
                    }

                    let (mut h, mut m) = (input.h, input.m);
                    let (mut rlc, mut v) = config.initial_gate.assign(&mut region, row, challenge, left, &h, &m, input.t, input.f)?;

                    let mut round = 0;
                    for _ in 0..(input.r as usize) {
                        config.round_gate.assign(&mut region, row, rlc, &mut round, &mut left, &mut h, &mut m, &mut v)?;   
                        row += R;
                    }

                    (h, rlc) = config.final_gate.assign(&mut region, row, challenge, rlc, &h, &v)?;

                    row += config.final_height + 8;
                    
                    //////////////////////////////
                    let (h_ex, rlc_ex) = RLCTable::compress_with_rlc(challenge, &input.h, &input.m, input.t, input.f, input.r);
                    let correctness = (h == h_ex) && (format!("{:?}", rlc) == format!("{:?}", rlc_ex));
                    assert!(correctness, "Computation of new state and RLC during synthesis is incorrect!");
                    //////////////////////////////
                }
                
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

pub fn compress(r: u32, h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut h = *h;
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

    h
}