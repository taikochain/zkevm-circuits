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
    the "ALLOCATED" column, which is a fixed column used as a selector. The given column contains "1" in all usable rows and "0" in
    all unusable ones. Also, any possible assignment row for any gate must have such an index that all circuit table values used by this
    gate are in the rows, for which the "allocated" column contains "1" (otherwise, the integrity of the witness data cannot be assured).
    For this reason, the set of possible assignment rows is specified by the the "ALLOWED" column (a fixed column used as a selector),
    which contains "1" in all usable rows except for top and bottom several sequential ones (and "0" in all other rows). The aforesaid
    CIRCUIT TABLE STRUCTURE is created during the circuit instance synthesys by calling the method "assign" of the CircuitPreparator
    struct instance, which is created during the circuit configuring by calling the function "configure" of the corresponding struct type.
    The constrained columns (and their groups) created by the CircuitPreparator instance may be classified into the following categories:
    - byte-column pair: a pair of columns, which are allowed to contain only values in {0, 1, ..., 255} in usable rows;
    - septet column: a column, usable rows of which contain only values in {0, 1, ..., 127};
    - bit column: a column of usable cells containing either 0 or 1;
    - xor column triplet: a group of three columns with usable rows containing values in {0, 1, ..., 255}, the bitwise xor of which is 0.

    Gates of this circuit use only combined selectors. Such a selector consists of two cells in the same row: the first cell is in the
    "ALLOWED" column and the second one is in a certain advice column. The selector is active iff both cells contain non-zero values.
    Relative places of combined selectors for a gate type is described by an array of "Combiselector" struct instances. A gate is
    assigned at some row iff all of the corresponding combined selectors are active. They are called the CONTROL SELECTORS of the gate.

    In order to achieve better inter-circuit integration, the approach called "random linear combination hashing" is used. The corresponding
    hash of d, which is an array of n native field elements, for the challenge c and key k is designated as RLC(c, d) and computed as follows:
    RLC(k, c, d) = k * c^n + c^(n - 1) * d[0] + c^(n - 2) * d[1] + ... + c * d[n - 2] + d[n - 1]. It is not hard to verify that RLC has the
    given useful property: RLC(0, c, a|b) = RLC(RLC(0, c, a), c, b), where a|b stands for the concatenation of arrays a and b.

    The random linear combination hash of the concatenation of BLAKE2b compression function input and output is computed as the expression
    RLC(0, c, field(r|h|m|(t mod 2^64)|(t div 2^64)|f|o)), where c is the challenge, r, h, m, t, f are defined as in RFC 7693, o is the output
    state vector and field(d) maps the number tuple d to the array of the naturally corresponding native field elements. Such a hash for only
    the compression function input is computed as the expression, which differs from the aforesaid one only in the absence of "|o". Therefore,
    using the aforementioned property of the RLC function, the hash of the concatenation of the compression function input and output can be
    expressed as RLC(i, c, field(o)), where i is the hash of the compression function input.

    Another circuit may use the computation results of the current one by adding a lookup argument, in which the table expressions are formed
    using the information specified by the RLC TABLE created during the circuit configuring. This table specifies the column, whose cell may
    store a computed random linear combination hash of the concatenation of the compression function input and output, the indicator pair of
    columns, which simultaneously contain 1 on thoses and only those rows, which contain the hashes, and the source of the challenge used for
    random linear combination hashing. The idea of this approach lies in random linear combination hashing of the unconstrained witness data,
    which describes the compression function input and output, and using the lookup argument to assert that the obtained hash is the part of
    the output data of the current circuit instance.

    The computation of the BLAKE2b compression function is described in the circuit instance by the sequence of the gates. The sequence starts
    with an InitialGate class gate followed by zero or more RoundGate class gates and ends with a FinalGate class gate. This sequence describes
    the state evolution of the abstract BLAKE2b compression function calculator described below. Its inputs are h, m, t and f defined in RFC 7693,
    and the number of rounds. The challenge used for random linear combination hashing is not a gate input, but a global circuit parameter. An
    InitialGate class gate uses the inputs to compute the pre-round state of the calculator. The pre-round, inter-round and post-round states
    have the same structure, which includes the amount of rounds left to be performed, the random linear combination hash of the corresponding
    compression function input, m permuted for the current round, h, v (defined in RFC 7693) and the array of 10 binary flags indicating the
    counted from 0 number of the current round modulo 10 by the only non-zero entry. A RoundGate class gate describes the transition between the
    calculator's states caused by performing a round, which changes the value of v in accordance with RFC 7693. A FinalGate class gate computes
    the final calculator's state including the output of the BLAKE2b compression function as well as the random linear combination hash of the
    concatenation of the input and output of this function.

    The circuit-table data of a gate may be classified into the CONTROL, INPUT, OUTPUT and INTERMEDIATE data. The control data is represented
    by combined selectors except for the ones used to store the aforesaid 10 binary flags in the case of gates of the InitialGate and RoundGate
    classes. These combined selectors are considered to be either input or output data.

    The input data of gates of the RoundGate and FinalGate classes are validated to be the output data of a gate of RoundGate or InitialGate
    classes. This validation is done by checking the states of the specified combined selectors, the activity of which imply the existence of
    the gates producing the input data for the current gate. The selectors checked by a gate this way and the gate's control selectors form the
    set of the gates control data. The amount of rounds left to be performed is checked by a FinalGate class gate to be zero.

    The circuit areas, over which the gates of the aforesaid sequences operate, overlap. For an InitialGate class gate the control selectors and
    the part of the calculator's pre-round state are stored in the assignment row and certain sequential ones. Its other data are stored in the
    previous 8 sequential rows. The for first RoundGate class gate the assignment row is the same as for the corresponding InitialGate class gate.
    The distance between the assignment rows of the adjacent gates of the RoundGate class is R, where R is the number of rows per round for the
    circuit instance. The control selectors as well as the input and intermediate data of a gate of the RoundGate class are stored in R sequential
    rows, the first of which is its assignment row. The output data of this gate are stored below in certain sequential rows. The assignment row of
    a FinalGate class gate is R rows below the corresponding row of the sequence's last gate of the RoundGate class, iff the the sequence contains
    this gate. If this sequence does not contain a gate of the RoundGate class, the gates of the InitialGate and FinalGate classes have the same
    assignment rows. The control selectors as well as the input, output and intermediate data of the FinalGate class gate are stored in T sequential
    rows, the first of which is its assignment row, where T is called the TAIL HEIGHT and determined by R in such a way that 8 <= T <= R. Thus, the
    sequence containing q gates of the RoundGate class is stored in q * R + T + 8 rows. Therefore, if a circuit instance processes n compression
    function inputs, for which the total number of rounds is q, then all the sequences are stored in q * R + n * (T + 8) rows. Since the last gate
    of a sequence belongs to the FinalGate class and T <= R, the sufficient amount of the usable rows of the circuit bottom, which are not allowed
    to be the assignment rows, is R - 1. The corresponding amount for the circuit top is R, since no gate operates on a row, which is more than R
    rows above the assignment one. The data of the first 8 rows of the first InitialGate class gate and last T - 1 rows of the last FinalGate class
    gate may be stored in the rows of these top and bottom areas of the circuit. Thus, the amount of the usable rows in the circuit instance cannot
    be less than (q + 2) * R + (n - 1) * (T + 8). Also, the circuit instance must contain at least 65536 rows to be able to store the lookup-table
    column triplet defining the possible values of the usable rows of a xor column triplet. Thus, the minimum value of the integer binary logarithm
    of the height of a circuit instance is ceil(log2(max((q + 2) * R + (n - 1) * (T + 8), 65536) + u)), where u is the amount of the unusable rows.

    For the gates of the InitialGate, RoundGate and FialGate classes the little-endian representations of the used or computed 64-bit values are
    taken from or assigned to the specified input byte-column chunks of height 8. For storing the amounts of rounds left to be performed and the
    random linear combination hashes the specified unconstrained column cells are used. The 10 binary flags for both the states are stored in the
    form of the specified combined selectors, which control the gates computing the m permuted for the next round. The value of f is taken from
    the specified bit cell. Some specified cells are used to store the intermediate results of the computation performed by a gate.

    The value of m permuted for the next round is computed by a RoundGate class gate from the value of m permuted for the current round. The new
    value is the result of applying a certain index permutation to the current one. An index permutation is an element of the group of permutations
    of the set {0, 1, ..., n - 1}, where the n is the array's length. Such a permutation can described by the n-element array, the i-th entry of
    which contains the value replacing i. The index permutation described by the array a is designated here as per(a). If an array is considered as
    the table with the rows of elements and their indexes, then applying an index permutation to the array means applying this permutation to the
    content of second row. So the value of m permuted for the (i + 1) round is the result of applying the index permutation P(i) = p(i + 1) * p'(i)
    to the value of m permuted for the i-th round, where p(j) is the index permutation applied to the value m to permute it for the j-th round,
    p'(j) is the inverse permutation for p(j) and p(j) * p(k) is the permutation composition, i.e. the permutation, which is equivalent to applying
    p(k) and then p(j). Since the value m permuted for the i-th round is (m[SIGMA[i % 10][0]], m[SIGMA[i % 10][1]], ..., m[SIGMA[i % 10][15]]),
    the value of SIGMA[i % 10][j] is replaced with j by p(i). On the other hand, per(SIGMA[i % 10]) replaces j with SIGMA[i % 10][j], therefore,
    p(i) is per'(SIGMA[i % 10]). So P(i) = per'(SIGMA[(i + 1) % 10]) * per(SIGMA[i % 10]). The permutations computed by this formula are used by
    RoundGate class gate to compute the values of m permuted for the next rounds without the need to access the value of m.
*/

use std::{ marker::PhantomData, array, convert::TryInto };
use halo2_proofs::{ arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation };

// Blake2 initialization vector
const IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

// Blake2 message schedule
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

// A small module providing the implementation of the BLAKE2b compression function
pub mod compression {
    //  Computes the mixing function G. The elements of the input are specified according to RFC 7693.
    //  The computation results are returned by means of updating the vector referenced by "v"
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

    // Computes the BLAKE2b compression function. The elements of the input are specified according to RFC 7693
    pub fn compress(r: u32, h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
        let mut h = *h;
        let mut v = [0u64; 16];

        for i in 0..8 {
            v[i] = h[i];
            v[i + 8] = super::IV[i];
        }

        v[12] ^= t as u64;
        v[13] ^= (t >> 64) as u64;

        if f { v[14] ^= 0xFFFF_FFFF_FFFF_FFFF; }

        for i in 0..(r as usize) {
            let s = &super::SIGMA[i % 10];

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
}

// A small module providing functions for performing operations in the group of permutations of
// the set {0, 1, ..., L - 1} for the specified L. A permutation, which a module function takes
// or returns, is represented by the array, the i-th entry of which contains the value replacing i
pub mod permutation {
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
    let row = row as i64 + offset as i64;
    assert!(row >= 0, "The row {} does not exist. Row indices are nonnegative!", row);
    row as usize
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
// "pairs[0][0]". The created Chunks occupy the cells of a table-like structure, whose numbers are "skip", "skip" + 1, ..., "skip" + L - 1
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
struct Chunk<F:FieldExt, const H:u8> {
    column: Column<Advice>, // The column containing the chunk
    offset: i32, // The chunk offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field
}

impl<F:FieldExt, const H:u8> Chunk<F, H> {
    // Creates a Chunk for the specified byte column
    // and offset relative to the assignment row
    fn new(column: Column<Advice>, offset: i32) -> Self {
        assert!(H <= 8, "Cannot create the {}-cell Chunk. The maximum height is 8!", H);
        Self { column, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the specified cell of the Chunk
    fn expr(&self, meta: &mut VirtualCells<F>, cell: usize) -> Expression<F> {
        assert!(cell < H.into(), "Accessing the cell {} in the {}-cell Chunk!", cell, H);
        meta.query_advice(self.column, Rotation(self.offset + (cell as i32)))
    }

    // Assigns the little-endian representation of "value" to the byte-column chunk, which
    // is described by the current Chunk instance and the specified assigment row
    fn assign(&self, region: &mut Region<F>, row: usize, value: u64) -> Result<(), Error> {
        let offset = shift_row(row, self.offset);
        for (i, v) in value.to_le_bytes()[0..H as usize].iter().enumerate() {
            region.assign_advice(|| "", self.column, offset + i, || known::<F>(*v as u64))?;
        }
        Ok(())
    }

    // Creates the L-cell Chunk, which is a part of the Chunk instance and starts at its ("skip" + 1)-th cell
    fn subchunk<const L:u8>(&self, skip: u8) -> Chunk<F, L> {
        assert!(skip + L <= H, "Cannot create the {}-cell subchunk from the {}-cell Chunk skipping {} cells!", L, H, skip);
        Chunk { column: self.column, offset: self.offset + skip as i32, _marker: PhantomData }
    }
}

// Describes the relative place of a cell of a column, usable
// rows of which contain only values in {0, 1, ..., M};
#[derive(Copy, Clone)]
struct ShortCell<F:FieldExt, const M:u8> {
    column: Column<Advice>,  // The column containing the cell
    offset: i32, // The cell offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field
}

impl<F:FieldExt, const M:u8> ShortCell<F, M> {
    // Creates a ShortCell for the specified constrained
    // column and offset relative to the assignment row
    fn new(column: Column<Advice>, offset: i32) -> Self {
        Self { column, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the ShortCell
    fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset))
    }

    // Assigns "value" to the constrained column cell, which is described
    // by the current ShortCell instance and the specified assigment row
    fn assign(&self, region: &mut Region<F>, row: usize, value: u8) -> Result<(), Error> {
        let offset = shift_row(row, self.offset);
        assert!(value <= M, "Cannot assign the value {} to a ShortCell with a maximum value of {}!", value, M);
        region.assign_advice(|| "", self.column, offset, || known::<F>(value as u64))?;
        Ok(())
    }
}

// Describes the relative place of a xor column triplet chunk of height H
#[derive(Copy, Clone)]
struct XChunk<F:FieldExt, const H:u8> {
    xtriplet: [Column<Advice>; 3], // The xor column triplet containing the chunk
    offset: i32, // The chunk offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the native field of the columns
}

impl<F:FieldExt, const H:u8> XChunk<F, H> {
    // Creates an XChunk for the specified xor column
    // triplet and offset relative to the assignment row
    fn new(xtriplet: [Column<Advice>; 3], offset: i32) -> Self {
        assert!(H <= 8, "Cannot create the XChunk of height {}. The maximum height is 8!", H);
        Self { xtriplet, offset, _marker: PhantomData }
    }

    // Creates the H-cell Chunk, which describes the "index"-th part of the current XChunk instance
    fn operand(&self, index: usize) -> Chunk<F,H> {
        assert!(index < 3, "The operand {} does not exist in XChunks!", index);
        Chunk::<F,H>::new(self.xtriplet[index], self.offset)
    }
}

// Describes the relative place of a cell
// of an unconstrained column in the P-th phase
#[derive(Copy, Clone)]
struct GeneralCell<F:FieldExt, const P:u8> {
    column: Column<Advice>, // The column containing the cell
    offset: i32, // The cell offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the column's native field

}

impl<F:FieldExt, const P:u8> GeneralCell<F, P> {
    // Creates a GeneralCell for the specified unconstrained
    // column and offset relative to the assignment row
    fn new(column: Column<Advice>, offset: i32) -> Self {
        Self { column, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the GeneralCell
    fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset))
    }

    // Assigns "value" to the unconstrained column cell, which is described
    // by the current GeneralCell instance and the specified assigment row
    fn assign(&self, region: &mut Region<F>, row: usize, value: Value<F>) -> Result<(), Error> {
        region.assign_advice(|| "", self.column, shift_row(row, self.offset), || value)?;
        Ok(())
    }
}

// Describes the relative place of a combined selector
#[derive(Copy, Clone)]
struct Combiselector<F:FieldExt> {
    allowed: Column<Fixed>, // The "allowed" column containing the fixed cell of the combined selector
    selector: Column<Advice>, // The column containing the advice cell of the combined selector
    offset: i32, // The combined selector's offset relative to the assignment row
    _marker: PhantomData<F> // The marker used to specify the native field of the columns
}

impl<F:FieldExt> Combiselector<F> {
    // Creates a Combiselector for the specified "allowed" column,
    // advice column and offset relative to the assignment row
    fn new(allowed: Column<Fixed>, selector: Column<Advice>, offset: i32) -> Self {
        Self { allowed, selector, offset, _marker: PhantomData }
    }

    // Creates the instance of Expression for the Combiselector
    fn expr(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.allowed, Rotation(self.offset)) * meta.query_advice(self.selector, Rotation(self.offset))
    }

    // Activates or inactivates (depending on "active") the combined selector, which is
    // described by the current Combiselector instance and the specified assigment row
    fn enable(&self, region: &mut Region<F>, row: usize, active: bool) -> Result<(), Error> {
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
struct SelectorGate<F:FieldExt> {
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
struct ConstantGate<F:FieldExt> {
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
struct BiconstantGate<F:FieldExt> {
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
struct CopyGate<F:FieldExt> {
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
struct CopyGeneralGate<F:FieldExt, const P:u8> {
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
struct DownCounterGate<F:FieldExt, const P:u8> {
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
struct AddGate<F:FieldExt, const S:usize> {
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
        assert!(S <= 256, "Cannot create the AddGate with {} inputs. The maximum number of inputs is 256!", S);

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
struct XorGate<F:FieldExt>{
    result: OctaChunk<F> // The third part of the XChunk instance used by the gate
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
struct ShiftBytesGate<F:FieldExt, const B:usize>{
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
struct Shift63Gate<F:FieldExt>{
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
struct SelectorMultiGate<F:FieldExt, const L:usize> {
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
struct ConstantMultiGate<F:FieldExt, const L:usize> {
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

// Defines the gate class, whose representatives copy the values of the byte-column chunks
// of height 8 from the specified input list to such chunks from a certain target list in
// accordance with the index permutation described by the specified array, the i-th entry
// of which contains the value replacing i, i.e. the value of the j-th chunk of the input
// list is assigned to the chunk, whose index in the target list equals to the value of
// the j-th entry of the array describing the index permutation
#[derive(Clone)]
struct PermuteGate<F:FieldExt, const L:usize>{
    permutation: [usize; L], // The array describing the index permutation
    copy: [CopyGate<F>; L] // The array of CopyGates dealing with the corresponding target Chunks
}

impl<F:FieldExt, const L:usize> PermuteGate<F,L> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The array describing the index permutation or "None" indicating the identity index permutation
                 permutation: Option<&[usize; L]>,
                 // The array of the input Chunks
                 input: &[OctaChunk<F>; L],
                 // The array of the target Chunks
                 result: &[OctaChunk<F>; L]) -> Self {
        let permutation = match permutation { Some(value) => *value, None => array::from_fn(|i| i) };
        let copy = array::from_fn(|i| CopyGate::<F>::configure(meta, selectors, input[i], result[permutation[i]]));
        Self { permutation, copy }
    }

    // The i-th entry of "input" specifies the number, whose little-endian representation is stored in the i-th input byte-column chunk
    fn assign(&self, region: &mut Region<F>, row: usize, input: &[u64; L]) -> Result<([u64; L]), Error> {
        let mut result = [0; L];
        for i in 0..L {
            result[self.permutation[i]] = self.copy[i].assign(region, row, input[i])?;
        }
        Ok(result)
    }
}

// Defines the gate class, whose representatives set the states of the combined selectors from
// the specified target list in such a way that the ((i + 1) mod L)-th selector of this list
// has the same state as i-th combined selector of the specified input list
#[derive(Clone)]
struct SelectorShiftGate<F:FieldExt, const L:usize>{
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
// column cell the random linear combination hash of certain BLAKE2b compression function
// input. The little-endian representations of the 64-bit input values, including t mod 2^64
// and t div 2^64, are taken from the specified input byte-column chunks of height 8. The
// field elements describing r and f are taken from the specified input unconstrained column
// cell and bit cell
#[derive(Clone)]
struct InitialRLCGate<F:FieldExt>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,2> // The target GeneralCell
}

impl<F:FieldExt> InitialRLCGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The source of the challenge used for hashing
                 challenge: Challenge,
                 // The GeneralCell of the number of rounds
                 r: GeneralCell<F,1>,
                 // The array of the Chunks of the initial state vector
                 h: &[OctaChunk<F>; 8],
                 // The array of the Chunks of the message block vector
                 m: &[OctaChunk<F>; 16],
                 // The array of the Chunks of the vector (t mod 2^64, t div 2^64), where t is the message byte offset
                 t: &[OctaChunk<F>; 2],
                 // The ShortCell of the flag indicating the last block
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

    // The challenge is specified by "c", the elements of the compression function input are specified according to RFC 7693
    fn assign(&self, region: &mut Region<F>, row: usize, c: Value<F>, r: F,
        h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> Result<Value<F>, Error> {

        let (t, f) = ([t as u64, (t >> 64) as u64], [f as u64]);
        let terms = h.iter().chain(m.iter()).chain(t.iter()).chain(f.iter()).map(|v| known::<F>(*v));

        let mut rlc = Value::known(r);
        for term in terms {
            rlc = rlc * c + term;
        }

        self.result.assign(region, row, rlc)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(rlc)
    }
}

// Defines the gate class, whose representatives assign to the specified target unconstrained
// column cell the random linear combination hash of the concatenation of certain BLAKE2b
// compression function input and output. The computation of the hash is based on the formula
// RLC(i, c, field(o)) mentioned above. The value of i is taken from the specified input
// unconstrained column cell. The little-endian representations of elements of o are taken
// from the specified input byte-column chunks of height 8
#[derive(Clone)]
struct FinalRLCGate<F:FieldExt>{
    selectors: Vec<Combiselector<F>>, // The control Combiselectors
    result: GeneralCell<F,2> // The target GeneralCell
}

impl<F:FieldExt> FinalRLCGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The source of the challenge used for random linear combination hashing
                 challenge: Challenge,
                 // The GeneralCell of the hash of the compression function input
                 i: GeneralCell<F,2>,
                 // The array of the Chunks of the output state vector
                 o: &[OctaChunk<F>; 8],
                 // The target GeneralCell
                 result: GeneralCell<F,2>) -> Self {
        meta.create_gate("FinalRLCGate", |meta| {
            let challenge = meta.query_challenge(challenge);

            let mut rlc = i.expr(meta);
            for term in o.iter().map(|c| chunk_to_number(meta, *c)) {
                rlc = rlc * challenge.clone() + term;
            }

            vec![combine_selectors(meta, selectors) * (result.expr(meta) - rlc)]
        });

        Self { selectors: selectors.to_vec(), result }
    }

    // The challenge is specified by "c", the hash of the compression function
    // input is described by "i", the output state vector is specified by "o"
    fn assign(&self, region: &mut Region<F>, row: usize, c: Value<F>, i: Value<F>, o: &[u64; 8]) -> Result<Value<F>, Error> {
        let mut rlc = i;
        for term in o.iter().map(|v| known::<F>(*v)) {
            rlc = rlc * c + term;
        }

        self.result.assign(region, row, rlc)?;
        enable_selectors(region, row, &self.selectors, true)?;
        Ok(rlc)
    }
}

// Defines the gate class, whose representatives compute the new values of four entries of the local state vector v,
// which are used by the mixing function G in accordance with RFC 7693. The little-endian representations of the 64-bit
// values of the four affected entries of v and two entries of the message block vector m, which are used by G, are taken
// from the specified input byte-column chunks of height 8. The results of computation are assigned to the specified such
// chunks. Some specified cells are used to store the intermediate results of the computation
#[derive(Clone)]
struct GGate<F:FieldExt> {
    copy: [CopyGate<F>; 4], // The gate types used for copying the values to subcolumns of xor column triplet chunks
    add3: [AddGate<F, 3>; 2], // The gate types used for computing (v[a] + v[b] + x) mod 2**w and (v[a] + v[b] + y) mod 2**w
    add2: [AddGate<F, 2>; 2], // The gate types used for computing (v[c] + v[d]) mod 2**w
    xors: [XorGate<F>; 4], // The gate types used for computing the expressions involving the bitwise xor operation
    shift32: ShiftBytesGate<F, 4>, // The gate type used for computing (v[d] ^ v[a]) >>> R1, where R1 = 32
    shift24: ShiftBytesGate<F, 3>, // The gate type used for computing (v[b] ^ v[c]) >>> R2, where R2 = 24
    shift16: ShiftBytesGate<F, 2>, // The gate type used for computing (v[d] ^ v[a]) >>> R3, where R3 = 16
    shift63: Shift63Gate<F> // The gate type used for computing (v[b] ^ v[c]) >>> R4, where R4 = 63
}

impl<F:FieldExt> GGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The array of the Chunks of the initial values of v[a], v[b], v[c] and v[d]
                 input: &[OctaChunk<F>; 4],
                 // The Chunk of x
                 x: OctaChunk<F>,
                 // The Chunk of y
                 y: OctaChunk<F>,
                 // The ShortCell of the intermediate results of the computation
                 bit: BitCell<F>,
                 // The ShortCell of the intermediate results of the computation
                 septet: SeptaCell<F>,
                 // The array of the Chunks of the intermediate results of the computation
                 bytes: &[ByteChunk<F>; 4],
                 // The array of the XChunks of the intermediate results of the computation
                 xchunks: &[XChunk<F,8>; 4],
                 // The array of the Chunks of the new values of v[a], v[b], v[c] and v[d]
                 result: &[OctaChunk<F>; 4]) -> Self {
         // The Chunks of the intermediate values of v[a], v[b], v[c] and v[d] in the middle of the computation of G
        let [a, c, d, b]: [OctaChunk<F>; 4] = array::from_fn(|i| xchunks[i].operand(0));
        let xout: [OctaChunk<F>; 4] = array::from_fn(|i| xchunks[i].operand(2));

        Self {
            copy: [CopyGate::<F>::configure(meta, selectors, input[3], xchunks[0].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, input[1], xchunks[1].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, result[0], xchunks[2].operand(1)),
                   CopyGate::<F>::configure(meta, selectors, result[2], xchunks[3].operand(1))],

            xors: [XorGate::<F>::configure(xchunks[0]), XorGate::<F>::configure(xchunks[1]),
                   XorGate::<F>::configure(xchunks[2]), XorGate::<F>::configure(xchunks[3])],

            add3: [AddGate::<F, 3>::configure(meta, selectors, &[input[0], input[1], x], a, bytes[0]),
                   AddGate::<F, 3>::configure(meta, selectors, &[a, b, y], result[0], bytes[1])],

            add2: [AddGate::<F, 2>::configure(meta, selectors, &[d, input[2]], c, bytes[2]),
                   AddGate::<F, 2>::configure(meta, selectors, &[c, result[3]], result[2], bytes[3])],

            shift32: ShiftBytesGate::<F, 4>::configure(meta, selectors, xout[0], d),
            shift24: ShiftBytesGate::<F, 3>::configure(meta, selectors, xout[1], b),
            shift16: ShiftBytesGate::<F, 2>::configure(meta, selectors, xout[2], result[3]),
            shift63: Shift63Gate::<F>::configure(meta, selectors, xout[3], bit, septet, result[1]),
        }
    }

    // The input of the function G is specified according to RFC 7693. The computation
    // results are returned by means of updating the vector referenced by "v"
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

// Defines the gate class, whose representatives compute the pre-round
// state of the abstract BLAKE2b compression function calculator
#[derive(Clone)]
struct InitialGate<F: FieldExt> {
    rlc: InitialRLCGate<F>, // The gate type for computing the random linear combination hash
    half: PermuteGate<F,8>, // The gate type for computing the first half of the local work vector
    quarter: ConstantMultiGate<F,4>, // The gate type for computing the third quarter of the local work vector
    x: ConstantMultiGate<F,2>, // The gate types for assigning the Blake2 initialization vector data to subcolumns of xor column triplet chunks
    t: PermuteGate<F,2>, // The gate types for copying the data of the vector (t mod 2^64, t div 2^64) to subcolumns of xor column triplet chunks
    xors: [XorGate<F>; 2], // The gate types for computing the 12-th and 13-th elements of the local work vector
    xout: PermuteGate::<F,2>, // The gate types for copying the values from the third subcolumns of xor column triplet chunks
    not: BiconstantGate<F>, // The gate type for computing the 14-th element of the local work vector
    last: ConstantGate<F>, // The gate type for computing the 15-th element of the local work vector
    p: SelectorMultiGate<F,10> // The gate type used for setting the states of the 10 "binary flags" combined selectors
}

impl<F:FieldExt> InitialGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The source of the challenge used for random linear combination hashing
                 challenge: Challenge,
                 // The GeneralCell of the number of rounds. It is also a part of the calculator's pre-round state
                 r: GeneralCell<F,1>,
                 // The array of the Chunks of the initial state vector. It is also a part of the calculator'spre-round  state
                 h: &[OctaChunk<F>; 8],
                 // The array of the Chunks of the message block vector. It is also a part of the calculator's pre-round state
                 m: &[OctaChunk<F>; 16],
                 // The array of the Chunks of the vector (t mod 2^64, t div 2^64), where t is the message byte offset
                 t: &[OctaChunk<F>; 2],
                 // The ShortCell of the flag indicating the last block
                 f: BitCell<F>,
                 // The array of the XChunks of the intermediate results of the computation
                 xchunks: &[XChunk<F,8>; 2],
                 // The array of the Chunks of the local work vector computed for the calculator's pre-round state
                 v: &[OctaChunk<F>; 16],
                 // The Combiselector array of the 10 "binary flags" combined selectors computed for the calculator's pre-round state
                 p: &[Combiselector<F>; 10],
                 // The GeneralCell of the random linear combination hash computed for the calculator's pre-round state
                 rlc: GeneralCell<F,2>) -> Self {
        Self {
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

            p: SelectorMultiGate::<F,10>::configure(meta, selectors, &array::from_fn(|i| i == 0), p),

            rlc: InitialRLCGate::<F>::configure(meta, selectors, challenge, r, h, m, t, f, rlc)
        }
    }

    // The challenge is specified by "c", the compression function input is specified according to RFC 7693
    fn assign(&self, region: &mut Region<F>, row: usize, c: Value<F>, r: F, h: &[u64; 8],
        m: &[u64; 16], t: u128, f: bool) -> Result<(Value<F>, [u64; 16]), Error> {

        let rlc = self.rlc.assign(region, row, c, r, h, m, t, f)?;

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

        self.p.assign(region, row)?;

        Ok((rlc, v))
    }
}

// Defines the gate class, whose representatives compute the new state of the
// abstract BLAKE2b compression function calculator after it performs a round
#[derive(Clone)]
struct RoundGate<F: FieldExt> {
    l: DownCounterGate<F,1>, // The gate type for computing the new amount of rounds left to be performed
    h: PermuteGate<F,8>, // The gate type for copying the value of h, since it is unchanged
    p: SelectorShiftGate<F,10>, // The gate type for computing the new states of the 10 "binary flags" combined selectors
    m: [PermuteGate<F,16>; 10], // The gate type for computing the value of m permuted for the next round
    v: [GGate<F>; 8], // The gate types for computing the expressions involving the mixing function G
    rlc: CopyGeneralGate<F,2> // The gate type for copying the random linear combination hash, since it is unchanged
}

impl<F:FieldExt> RoundGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The Combiselectors, whose activity imply the existence of the InitialGate class gate producing the input data for this gate
                 initial: &[Combiselector<F>],
                 // The Combiselectors, whose activity imply the existence of the RoundGate class gate producing the input data for this gate
                 round: &[Combiselector<F>],
                 // The GeneralCells of the current and new amounts of rounds left to be performed
                 left: [GeneralCell<F,1>; 2],
                 // The Chunk arrays of h for the current and new states of the calculator
                 h: [&[OctaChunk<F>; 8]; 2],
                 // The Chunk arrays of the m values permuted for the current and next rounds
                 m: [&[OctaChunk<F>; 16]; 2],
                 // The Chunk arrays of the current and new values of v
                 v: [&[OctaChunk<F>; 16]; 2],
                 // The Combiselector arrays of the 10 "binary flags" combined selectors for the current and new states of the calculator
                 p: [&[Combiselector<F>; 10]; 2],
                 // The GeneralCells of the random linear combination hash for the current and new states of the calculator
                 rlc: [GeneralCell<F,2>; 2],
                 // The array of the ShortCells of the intermediate results of the computation
                 bits: &[BitCell<F>; 8],
                 // The array of the ShortCells of the intermediate results of the computation
                 septets: &[SeptaCell<F>; 8],
                 // The array of the Chunks of the intermediate results of the computation
                 bytes: &[ByteChunk<F>; 32],
                 // The array of the Chunks of the intermediate results of the computation
                 qwords: &[OctaChunk<F>; 16],
                 // The array of the XChunks of the intermediate results of the computation
                 xchunks: &[XChunk<F,8>; 32]) -> Self {
        let bytes: [&[ByteChunk<F>; 4]; 8] = arrefs_from_slice(bytes);
        let xors: [&[XChunk<F,8>; 4]; 8] = arrefs_from_slice(xchunks);
        let ([pi, po], [mi, mo], [vi, vo]) = (p, m, v);
        assert_single_active(meta, selectors, &[initial, round]);

        Self {
            l: DownCounterGate::<F,1>::configure(meta, selectors, left[0], left[1]),

            h: PermuteGate::<F, 8>::configure(meta, selectors, None, h[0], h[1]),

            p: SelectorShiftGate::<F, 10>::configure(meta, selectors, pi, po),

            m: array::from_fn(|i| {
                // Using the formula P(i) = per'(SIGMA[(i + 1) % 10]) * per(SIGMA[i % 10])
                let permutation = permutation::compose(&permutation::invert(&SIGMA[(i + 1) % 10]), &SIGMA[i]);
                PermuteGate::configure(meta, &[selectors, &pi[i..i + 1]].concat(), Some(&permutation), &mi, &mo)
            }),

            v: [GGate::configure(meta, selectors, &[vi[0], vi[4], vi[8], vi[12]], mi[0],
                    mi[1], bits[0], septets[0], bytes[0], xors[0], &[qwords[0], qwords[4], qwords[8], qwords[12]]),
                GGate::configure(meta, selectors, &[vi[1], vi[5], vi[9], vi[13]], mi[2],
                    mi[3], bits[1], septets[1], bytes[1], xors[1], &[qwords[1], qwords[5], qwords[9], qwords[13]]),
                GGate::configure(meta, selectors, &[vi[2], vi[6], vi[10], vi[14]], mi[4],
                    mi[5], bits[2], septets[2], bytes[2], xors[2], &[qwords[2], qwords[6], qwords[10], qwords[14]]),
                GGate::configure(meta, selectors, &[vi[3], vi[7], vi[11], vi[15]], mi[6],
                    mi[7], bits[3], septets[3], bytes[3], xors[3], &[qwords[3], qwords[7], qwords[11], qwords[15]]),

                GGate::configure(meta, selectors, &[qwords[0], qwords[5], qwords[10], qwords[15]], mi[8],
                    mi[9], bits[4], septets[4], bytes[4], xors[4], &[vo[0], vo[5], vo[10], vo[15]]),
                GGate::configure(meta, selectors, &[qwords[1], qwords[6], qwords[11], qwords[12]], mi[10],
                    mi[11], bits[5], septets[5], bytes[5], xors[5], &[vo[1], vo[6], vo[11], vo[12]]),
                GGate::configure(meta, selectors, &[qwords[2], qwords[7], qwords[8], qwords[13]], mi[12],
                    mi[13], bits[6], septets[6], bytes[6], xors[6], &[vo[2], vo[7], vo[8], vo[13]]),
                GGate::configure(meta, selectors, &[qwords[3], qwords[4], qwords[9], qwords[14]], mi[14],
                    mi[15], bits[7], septets[7], bytes[7], xors[7], &[vo[3], vo[4], vo[9], vo[14]])
            ],

            rlc: CopyGeneralGate::<F,2>::configure(meta, selectors, rlc[0], rlc[1])
        }
    }

    // The hash of the compression function input is specified by "rlc", the counted from 0 number of the current round modulo 10 is
    // described by "round", the amount of rounds left to be performed for the state, which preceeds the current round, is specified
    // by "left", "h", "m" and "v" describe the corresponding elements of the calculator's state. After a successful execution of the
    // method, the aforesaid variables describe the calculator's computed state
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


// Defines the gate class, whose representatives compute the final state of the abstract BLAKE2b compression function calculator.
// This state includes the output of the BLAKE2b compression function as well as the random linear combination hash of the
// concatenation of the input and output of this function
#[derive(Clone)]
struct FinalGate<F:FieldExt> {
    h: PermuteGate<F,8>,  // The gate types for copying the data of the initial state vector to subcolumns of xor column triplet chunks
    v: PermuteGate<F,16>, // The gate types for copying the data of the current local work vector to subcolumns of xor column triplet chunks
    xh: [XorGate<F>; 8], // The gate types for computing the compression function output
    xv: [XorGate<F>; 8], // The gate types for computing the bitwise xor of the halves of the current local work vector
    xcopy: PermuteGate<F,8>, // The gate types for data copying between the subcolumns of xor column triplet chunks
    rlc: FinalRLCGate<F> // The gate type for computing the hash of the concatenation of the input and output of the compression function
}

impl<F:FieldExt> FinalGate<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The control Combiselectors
                 selectors: &[Combiselector<F>],
                 // The source of the challenge used for random linear combination hashing
                 challenge: Challenge,
                  // The Combiselectors, whose activity imply the existence of the InitialGate class gate producing the input data for this gate
                 initial: &[Combiselector<F>],
                 // The Combiselectors, whose activity imply the existence of the RoundGate class gate producing the input data for this gate
                 round: &[Combiselector<F>],
                 // The GeneralCell of the current amount of rounds left to be performed
                 left: GeneralCell<F,1>,
                 // The Chunk array of the initial state vector
                 h: &[OctaChunk<F>; 8],
                 // The Chunk array of the current local work vector
                 v: &[OctaChunk<F>; 16],
                 // The array of the XChunks, whose default-ordered third parts constitute the Chunk array of the compression function output
                 xh: &[XChunk<F,8>; 8],
                 // The array of the XChunks of the intermediate results of the computation
                 xv: &[XChunk<F,8>; 8],
                 // The GeneralCells of the random linear combination hash of the compression function input and the computed hash
                 rlc: [GeneralCell<F,2>; 2]) -> Self {
        assert_single_active(meta, selectors, &[initial, round]);
        assert_zero(meta, selectors, left);

        Self {
            h: PermuteGate::<F, 8>::configure(meta, selectors, None, h, &array::from_fn(|i| xh[i].operand(1))),

            v: PermuteGate::<F, 16>::configure(meta, selectors, None, v, &array::from_fn(|i| xv[i % 8].operand(i / 8))),

            xh: array::from_fn(|i| XorGate::<F>::configure(xh[i])),

            xv: array::from_fn(|i| XorGate::<F>::configure(xv[i])),

            xcopy: PermuteGate::<F, 8>::configure(meta, selectors, None,
                 &array::from_fn(|i| xv[i].operand(2)), &array::from_fn(|i| xh[i].operand(0))),

            rlc: FinalRLCGate::configure(meta, selectors, challenge, rlc[0], &array::from_fn(|i| xh[i].operand(2)), rlc[1])
        }
    }

    // The challenge is specified by "c", the hash of the compression function input is specified
    // by "rlc", "h" and "v" describe the corresponding elements of the calculator's current state
    fn assign(&self, region: &mut Region<F>, row: usize, c: Value<F>,
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

        let rlc = self.rlc.assign(region, row, c, rlc, &xor)?;

        Ok((xor, rlc))
    }
}

// An instance of this struct creates the circuit table structure
#[derive(Clone)]
struct CircuitPreparator<F:FieldExt> {
    allocated: Column<Fixed>, // The "allocated" column
    allowed: Column<Fixed>, // The "allowed" column
    septalookup: Column<Fixed>, // The lookup-table column defining the possible values of the usable rows of a septet column
    xlookup: [Column<Fixed>; 3], // The lookup-table column triplet defining the possible values of the usable rows of a xor column triplet
    _marker: PhantomData<F> // The marker used to specify the circuit's native field
}

impl<F:FieldExt> CircuitPreparator<F> {
    fn configure(meta: &mut ConstraintSystem<F>,
                 // The "allocated" column
                 allocated: Column<Fixed>,
                 // The "allowed" column
                 allowed: Column<Fixed>,
                 // The lookup-table column defining the possible values of the usable rows of a septet column
                 septalookup: Column<Fixed>,
                 // The lookup-table column triplet defining the possible values of the usable rows of a xor column triplet
                 xlookup: [Column<Fixed>; 3],
                 // The bit columns
                 binary: &[Column<Advice>],
                 // The septet columns
                 septenary: &[Column<Advice>],
                 // The byte-column pairs
                 pairs: &[[Column<Advice>; 2]],
                 // The xor column triplets
                 xtriplets: &[[Column<Advice>; 3]]) -> Self {
        meta.create_gate("CircuitPreparatorBinary", |meta| {
            let allocated = meta.query_fixed(allocated, Rotation::cur());
            let mut constraints = vec![];
            for column in binary {
                let column = meta.query_advice(*column, Rotation::cur());
                constraints.push(allocated.clone() * column.clone() * (gf(1) - column));
            }
            constraints
        });

        for column in septenary {
            meta.lookup_any("CircuitPreparatorSeptenary", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated * meta.query_advice(*column, Rotation::cur()), meta.query_fixed(septalookup, Rotation::cur()))]
            });
        }

        for pair in pairs {
            meta.lookup_any("CircuitPreparatorPairs", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated.clone() * meta.query_advice(pair[0], Rotation::cur()), meta.query_fixed(xlookup[0], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(pair[1], Rotation::cur()), meta.query_fixed(xlookup[1], Rotation::cur()))]
            });
        }

        for xtriplet in xtriplets {
            meta.lookup_any("CircuitPreparatorXTriplets", |meta| {
                let allocated = meta.query_fixed(allocated, Rotation::cur());
                vec![(allocated.clone() * meta.query_advice(xtriplet[0], Rotation::cur()), meta.query_fixed(xlookup[0], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(xtriplet[1], Rotation::cur()), meta.query_fixed(xlookup[1], Rotation::cur())),
                     (allocated.clone() * meta.query_advice(xtriplet[2], Rotation::cur()), meta.query_fixed(xlookup[2], Rotation::cur()))]
            });
        }

        Self { allocated, allowed, septalookup, xlookup, _marker: PhantomData }
    }

    // The binary logarithm of the circuit's height is specified by "k", "before" and "after" specify the amounts
    // of the top and bottom sequential usable rows, for which the "allowed"-column cell contain 0, the amount of
    // the unusable rows is specified by "unusable"
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

        let usable = (1 << k) - unusable;
        let allowed = (1 << k) - disallowed;

        for row in 0..usable  {
            region.assign_fixed(|| "", self.allocated, row, || known::<F>(1))?;
        }

        for row in before..(before + allowed) {
            region.assign_fixed(|| "", self.allowed, row, || known::<F>(1))?;
        }

        Ok(())
    }
}

// An instance of this struct describes an RLC table
#[derive(Clone)]
pub struct RLCTable<F:FieldExt> {
    pub allowed: Column<Fixed>, // The column of the indicator pair
    pub selector: Column<Advice>, // The column of the indicator pair
    pub rlc: Column<Advice>, // The column, whose cell may store a computed random linear combination hash
    pub challenge: Challenge, // The source of the challenge used for random linear combination hashing
    pub _marker: PhantomData<F> // The marker used to specify the circuit's native field
}

impl<F:FieldExt> RLCTable<F> {
    // Computes the random linear combination hash of the concatenation of BLAKE2b compression function input and output
    pub fn compute_rlc(c: Value<F>, h: &[u64; 8], m: &[u64; 16], t: u128, f: bool, r: u32, o: &[u64; 8]) -> Value<F> {
        let (t, f) = ([t as u64, (t >> 64) as u64], [f as u64]);
        let terms = h.iter().chain(m.iter()).chain(t.iter()).
            chain(f.iter()).chain(o.iter()).map(|v| known::<F>(*v));
        let mut rlc = known::<F>(r as u64);
        for term in terms {
            rlc = rlc * c + term;
        }
        rlc
    }

    // Computes the BLAKE2b compression function and the random linear combination hash of the concatenation
    // of the corresponding input and output
    pub fn compress_with_rlc(c: Value<F>, h: &[u64; 8], m: &[u64; 16], t: u128, f: bool, r: u32) -> ([u64; 8], Value<F>) {
        let o = compression::compress(r, h, m, t, f);
        let rlc = Self::compute_rlc(c, h, m, t, f, r, &o);
        (o, rlc)
    }
}

// An instrance of this struct describes
// the BLAKE2b compression function input
#[derive(Clone, Debug)]
pub struct CompressionInput {
    pub r: u32, // The number of rounds
    pub h: [u64; 8], // The initial state vector
    pub m: [u64; 16], // The message block vector
    pub t: u128, // The message byte offset
    pub f: bool // The flag indicating the last block
}

// An instance of this struct describes the relative places of the
// elements of the input for a gate type of the InitialGate class
#[derive(Clone)]
struct InitialInput<F:FieldExt> {
    r: GeneralCell<F,1>, // The GeneralCell of the number of rounds
    h: [OctaChunk<F>; 8], // The array of the Chunks of the initial state vector
    m: [OctaChunk<F>; 16], // The array of the Chunks of the message block vector
    t: [OctaChunk<F>; 2], // The array of the Chunks of the vector (t mod 2^64, t div 2^64), where t is the message byte offset
    f: BitCell<F> // The ShortCell of the flag indicating the last block
}

// An instrance of this struct describes the configuration of the circuit using R rows per round
#[derive(Clone)]
pub struct CompressionConfig<F:FieldExt, const R: usize> {
    pub rlc_table: RLCTable<F>, // The RLC table
    circuit_preparator: CircuitPreparator<F>, // The CircuitPreparator instance
    initial_gate: InitialGate<F>, // The gate type of the InitialGate class gates
    round_gate: RoundGate<F>, // The gate type of the RoundGate class gates
    final_gate: FinalGate<F>, // The gate type of the FinalGate class gates
    initial_input: InitialInput<F>, // The relative places of the elements of the input for the gate type of the InitialGate class gates
    tail_height: usize, // The tail height
    unusable_rows: usize // The amount of the unusable rows
}

// An instrance of this struct describes the height and input
// parameters of the circuit instance using R rows per round
#[derive(Default)]
pub struct CompressionCircuit<F:FieldExt, const R: usize> {
    k: u32, // The binary logarithm of the circuit's height
    inputs: Vec<CompressionInput>, // The BLAKE2b compression function inputs
    _marker: PhantomData<F>  // The marker used to specify the circuit's native field
}

impl <F:FieldExt, const R:usize> CompressionCircuit<F,R> {
    // Creates a CompressionCircuit for the specified binary logarithm
    // of the circuit's height and BLAKE2b compression function inputs
    pub fn new(k: u32, inputs: &[CompressionInput]) -> Self {
        Self { k, inputs: inputs.to_vec(), _marker: PhantomData }
    }

    // Computes the minimum value of the integer binary logarithm of the height
    // of a circuit instance, whose input parameters are specified by "inputs"
    pub fn k(inputs: &[CompressionInput]) -> u32 {
        let config = Self::configure(&mut ConstraintSystem::<F>::default());
        let rounds = inputs.into_iter().fold(0, |sum, input| sum + input.r) as usize;
        // Using the formula ceil(log2(max((q + 2) * R + (n - 1) * (T + 8), 65536) + u))
        let mut usable = (rounds + 2) * R + (inputs.len() - 1) * ( config.tail_height + 8);
        if usable < 65536 { usable = 65536; }
        ((usable + config.unusable_rows) as f64).log2().ceil() as u32
    }

    // Computes the array describing the optimal amounts of rows per round for the specified input parameters
    // of a circuit instance and all possible circuit heights. The k-th entry of this array is either the
    // amount of rows per round, which corresponds to a possible circuit instance with the minimum number
    // of columns among all circuit instances of height 2^k, which may be created for these input parameters,
    // or None, iff a circuit instance of height 2^k is not possible for the given parameters
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
    type Config = CompressionConfig<F,R>;
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

        // Allocating the byte-column pairs required for storing the input and intermediate data of
        // a RoundGate class gate in R sequential rows. Storing these data requires 56 byte-column chunks
        // of height 8 and 32 byte-column cells. Thus, 56 * 8 + 32 cells or 240 cell pairs are required
        let mut pairs = vec![];
        while pairs.len() * R < 240 {
            pairs.push([advice(meta), advice(meta)]);
        }

        // Allocating the xor column triplets required for storing the intermediate data of a RoundGate class
        // gate in R sequential rows. Storing these data requires 32 xor column triplet chunks of height 8
        let mut xors = vec![];
        while xors.len() * R < 256 {
            xors.push([advice(meta), advice(meta), advice(meta)]);
        }

        // 14 bit columns are required: 10 collumns for 10 "binary flags" Combiselectors, a column for
        // the intermediate binary results of the computations of the RoundGate class gates as well as
        // for the flag indicating the last block in the case of the InitialGate class gates and 3 columns
        // for the control selectors of the gates of the InitialGate, RoundGate and FinalGate classes
        let mut binary = vec![];
        for _ in 0..14 {
            binary.push(advice(meta));
        }

        let second = meta.advice_column_in(SecondPhase);
        let [septenary, field] = array::from_fn(|_| advice(meta));
        let challenge = meta.challenge_usable_after(FirstPhase);

        let circuit_preparator = CircuitPreparator::configure(meta, allocated,
            allowed, septalookup, xlookup, &binary, &[septenary], &pairs, &xors);

        let [initial_selector, round_selector, final_selector, bit] = array::from_fn(|_| binary.pop().unwrap());

        let hi: [OctaChunk<F>; 8] = create_chuncks(&pairs, 0, 0);
        let ho: [OctaChunk<F>; 8] = create_chuncks(&pairs, R as i32, 0);
        let mi: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 8);
        let mo: [OctaChunk<F>; 16] = create_chuncks(&pairs, R as i32, 8);
        let vi: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 24);
        let vo: [OctaChunk<F>; 16] = create_chuncks(&pairs, R as i32, 24);
        let pi: [Combiselector<F>; 10] = array::from_fn(|i| Combiselector::<F>::new(allowed, binary[i], 0));
        let po: [Combiselector<F>; 10] = array::from_fn(|i| Combiselector::<F>::new(allowed, binary[i], R as i32));
        let left = [GeneralCell::<F,1>::new(field, 0), GeneralCell::<F,1>::new(field, R as i32)];
        let rlc = [GeneralCell::<F,2>::new(second, 1), GeneralCell::<F,2>::new(second, R as i32 + 1)];

        let xchunks: [XChunk<F,8>; 32] = create_xchunks(&xors, 0, 0);
        let qwords: [OctaChunk<F>; 16] = create_chuncks(&pairs, 0, 40);
        let bytes: [OctaChunk<F>; 4] = create_chuncks(&pairs, 0, 56);
        let bytes: [ByteChunk<F>; 32] = array::from_fn(|i| bytes[i / 8].subchunk((i % 8) as u8));
        let septets: [SeptaCell<F>; 8] = array::from_fn(|i| SeptaCell::<F>::new(septenary, i as i32));
        let bits: [BitCell<F>; 8] = array::from_fn(|i| BitCell::<F>::new(bit, i as i32));

        let initial = Combiselector::<F>::new(allowed, initial_selector, 0);
        let round = Combiselector::<F>::new(allowed, round_selector, -(R as i32));
        let selector = Combiselector::<F>::new(allowed, round_selector, 0);

        let round_gate = RoundGate::<F>::configure(meta, &[selector], &[initial], &[round], left, [&hi, &ho],
            [&mi, &mo], [&vi, &vo], [&pi, &po], rlc, &bits, &septets, &bytes, &qwords, &xchunks);

        let f = BitCell::<F>::new(bit, -8);
        let t: [OctaChunk<F>; 2] = create_chuncks(&pairs, -8, 0);
        let top: [XChunk<F, 8>; 2] = create_xchunks(&xors, -8, 0);

        let selector = Combiselector::<F>::new(allowed, initial_selector, 0);

        let initial_gate = InitialGate::<F>::configure(meta, &[selector],
            challenge, left[0], &hi, &mi, &t, f, &top, &vi, &pi, rlc[0]);

        let xv: &[XChunk<F,8>; 8] = xchunks[0..8].try_into().unwrap();
        let xh: &[XChunk<F,8>; 8] = xchunks[8..16].try_into().unwrap();
        let out = GeneralCell::<F,2>::new(second, 0);
        let selector = Combiselector::<F>::new(allowed, final_selector, 0);

        let final_gate = FinalGate::<F>::configure(meta, &[selector], challenge,
            &[initial], &[round], left[0], &hi, &vi, &xh, &xv, [rlc[0], out]);

        // Computing the tail height. The input data of a FinalGate class gate, which
        // are stored in the byte-column cells, have the same layout as the corresponding
        // RoundGate class gate input data, storing of which requires 40 byte-column chunks
        // of height 8. The data of a FinalGate class gate, which are stored in xor column
        // triplet chunks, do not affect the gate's height (a hint: pairs.len() <= xors.len(),
        // so 20.0 / pairs.len() > 16.0 / xors.len())
        let tail_height = 8 * (20.0 / pairs.len() as f64).ceil() as usize;
        let unusable_rows = meta.blinding_factors() + 1;

        let initial_input = InitialInput { r: left[0], h: hi, m: mi, t, f };
        let rlc_table = RLCTable { allowed, selector: final_selector, rlc: second, challenge, _marker: PhantomData };

        Self::Config { rlc_table, circuit_preparator, initial_gate, final_gate, round_gate, initial_input, tail_height, unusable_rows }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let initial = &config.initial_input;
        let challenge = layouter.get_challenge(config.rlc_table.challenge);

        layouter.assign_region(|| "BLAKE2b compression function computation",
            |mut region| {
                config.circuit_preparator.assign(&mut region, self.k, R, R - 1, config.unusable_rows)?;
                let mut row = R;

                for input in &self.inputs {
                    let mut left = F::from(input.r as u64);

                    initial.r.assign(&mut region, row, Value::known(left))?;
                    initial.t[0].assign(&mut region, row, input.t as u64)?;
                    initial.t[1].assign(&mut region, row, (input.t >> 64) as u64)?;
                    initial.f.assign(&mut region, row, input.f as u8)?;

                    let pairs = input.h.iter().chain(input.m.iter()).zip(initial.h.iter().chain(initial.m.iter()));

                    for (value, chunk) in pairs {
                        chunk.assign(&mut region, row, *value)?;
                    }

                    let (mut h, mut m) = (input.h, input.m);
                    let (mut rlc, mut v) = config.initial_gate.assign(&mut region, row, challenge, left, &h, &m, input.t, input.f)?;

                    let mut round = 0;
                    for _ in 0..(input.r as usize) {
                        config.round_gate.assign(&mut region, row, rlc, &mut round, &mut left, &mut h, &mut m, &mut v)?;
                        row += R;
                    }

                    // Checking the correctness of the computation
                    if cfg!(test) {
                        (h, rlc) = config.final_gate.assign(&mut region, row, challenge, rlc, &h, &v)?;
                        let (h_ex, rlc_ex) = RLCTable::compress_with_rlc(challenge, &input.h, &input.m, input.t, input.f, input.r);
                        let correctness = (h == h_ex) && (format!("{:?}", rlc) == format!("{:?}", rlc_ex));
                        assert!(correctness, "Processing of a BLAKE2b compression function input was incorrect! This input is {:?}", input);
                    } else {
                        config.final_gate.assign(&mut region, row, challenge, rlc, &h, &v)?;
                    }
                    
                    // A gate of the InitialGate class is to be created next, and some of its
                    // data are to be stored in the 8 sequential rows before the assignment row
                    row += config.tail_height + 8;
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use hex::decode_to_slice;
    use std::{ array, convert::TryInto };
    use halo2_proofs::{ halo2curves::bn256::Fr, dev::MockProver };
    use super::{ CompressionCircuit, CompressionInput, compression::compress };
    
    // EIP-152 test vectors 4-7 describing the BLAKE2b compression function inputs with the corresponding outputs. The vectors 1-3
    // do not describe the correct inputs and are not representable in the format used in the tested library. The number of rounds
    // for the vector 8 is 2^32 - 1, so the corresponding input cannot be processed by a circuit instance
    const EIP152_VECTORS: [[&str; 2]; 4] = [
        ["0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
         "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"],
        ["0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
         "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"],
        ["0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000",
         "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735"],
        ["0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
         "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421"]
    ];
    
    // Creates the description of a BLAKE2b compression function input, which corresponds to the
    // specified EIP-152 test vector, in accordance with the format used in the tested library
    pub fn hex_to_input(v: &str) -> CompressionInput {
        let mut buffer = [0u8; 213];
        decode_to_slice(v, &mut buffer).expect("Hex input must be correct!");
        assert!(buffer[212] <= 1, "Incorrect final block indicator flag!");
    
        CompressionInput {
            r: u32::from_be_bytes(buffer[0..4].try_into().unwrap()),
            h: array::from_fn(|i| u64::from_le_bytes(buffer[4 + 8 * i..][..8].try_into().unwrap())),
            m: array::from_fn(|i| u64::from_le_bytes(buffer[68 + 8 * i..][..8].try_into().unwrap())),
            t: u128::from_le_bytes(buffer[196..212].try_into().unwrap()),
            f: buffer[212] == 1
        }
    }
    
    // Tests the circuit instance, which has height 2^17 and processes the BLAKE2b
    // compression function inputs corresponding to the EIP-152 test vectors 4-7
    #[test]
    fn circuit_check() {
        let k = 17;
        let vectors: Vec<CompressionInput> = EIP152_VECTORS.iter().map(|v| hex_to_input(v[0])).collect();
        let circuit = CompressionCircuit::<Fr,128>::new(k, &vectors);
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
    
    // Tests the implementation of the BLAKE2b compression function. The inputs
    // with the corresponding outputs are described by the EIP-152 test vectors 4-7
    #[test]
    fn compression_check() {
        let mut expected = [0u8; 64];
        for vector in &EIP152_VECTORS {
            let input = hex_to_input(vector[0]);
            let result = compress(input.r, &input.h, &input.m, input.t, input.f);
            decode_to_slice(vector[1], &mut expected).expect("Hex expected value must be correct!");
            let expected: [u64; 8] =  array::from_fn(|i| u64::from_le_bytes(expected[8 * i..][..8].try_into().unwrap()));
            assert_eq!(result, expected);
        }
    }
    
    // Tests the implementation of the "optimums" function,
    // which associated with the CompressionCircuit struct
    #[test]
    fn optimums_check() {
        let inputs = [
            CompressionInput { r: 200, h: [0; 8], m: [1; 16], t: 2, f: true },
            CompressionInput { r: 9000, h: [1; 8], m: [3; 16], t: 1, f: true },
            CompressionInput { r: 10000, h: [2; 8], m: [6; 16], t: 0, f: true }];
        let optimums = CompressionCircuit::<Fr, 8>::optimums(&inputs);
        assert_eq!(optimums[0..18], [None; 18]);
        assert_eq!(optimums[18..22], [Some(8), Some(24), Some(48), Some(88)]);
        assert_eq!(optimums[22..32], [Some(128); 10]);
    }
}

#[cfg(test)]
mod benchmark {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use ark_std::{ start_timer, end_timer };
    use halo2_proofs:: {
        plonk::{ create_proof, keygen_vk, keygen_pk, verify_proof },
        poly::kzg::{
            commitment::{ KZGCommitmentScheme, ParamsKZG },
            multiopen::{ ProverSHPLONK, VerifierSHPLONK },
            strategy::SingleStrategy
        },
        poly::commitment::ParamsProver,
        halo2curves::bn256::{ Bn256, Fr, G1Affine },
        transcript::{ Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer }
    };
    use super::{ CompressionCircuit, CompressionInput };
    
    // Binary logarithm of the height of a circuit instance
    const K: u32 = 18;
    // Number of rows per round
    const R: usize = 8;
    // BLAKE2b compression function inputs. Their total round number is the maximum one for
    // the chosen k, number of rows per round and amount of the compression function inputs
    const INPUTS:[CompressionInput; 5] = [
       CompressionInput {
            r: 32600,
            h: [534542, 235, 325, 235, 53252, 532452, 235324, 25423],
            m: [5542, 23, 35, 35, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 5235, 35, 525],
            t: 1234,
            f: true,
        },
        CompressionInput {
            r: 13,
            h: [532, 235, 325, 235, 53252, 5324654452, 235324, 25423],
            m: [55142, 23, 35, 31115, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 5235, 35, 525],
            t: 123784,
            f: false,
        },
        CompressionInput {
            r: 90,
            h: [532, 235, 325, 235, 53252, 0, 235324, 25423],
            m: [55142, 0, 35, 31115, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 0, 35, 525],
            t: 0,
            f: true,
        },
        CompressionInput {
            r: 0,
            h: [53200, 235, 325, 235, 53252, 0, 235324, 25423],
            m: [55142, 0, 35, 31115, 5252, 52452, 232400, 2523, 254, 35, 354, 235, 5532, 0, 350, 52500],
            t: 5345435,
            f: true
        },
        CompressionInput {
            r: 51,
            h: [53200, 235, 325, 235, 53252, 0, 235324, 25423],
            m: [55142, 0, 35, 31115, 5252, 52452, 232400, 2523, 254, 35, 354, 235, 5532, 0, 350, 52500],
            t: 5345435,
            f: true,
        }
    ];
    
    // Runs the test bench for the BLAKE2b compression function circuit. In order to obtain correct
    // results, it is recommended to run the tests by executing "cargo test --release -- --nocapture"
    #[test]
    #[ignore]
    fn bench() {
        println!("The test bench for the BLAKE2b compression function circuit:");
    
        let mut more = INPUTS;
        more[0].r += 1;
        assert!(CompressionCircuit::<Fr,R>::k(&more) > K,
            "The total round number must be the maximum one for the chosen k, number of rows per round and amount of the compression function inputs!");
    
        let circuit = CompressionCircuit::<Fr,R>::new(K, &INPUTS);
    
        let timer = start_timer!(|| "KZG setup");
        let mut random = XorShiftRng::from_seed([0xC; 16]);
        let general_kzg_params = ParamsKZG::<Bn256>::setup(K, &mut random);
        let verifier_kzg_params = general_kzg_params.verifier_params().clone();
        end_timer!(timer);
    
        let verifying_key = keygen_vk(&general_kzg_params, &circuit).expect("The verifying key must be generated successfully!");
        let proving_key = keygen_pk(&general_kzg_params, verifying_key, &circuit).expect("The proving key must be generated successfully!");
        let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<_>>::init(vec![]);
    
        let timer = start_timer!(|| "Proof generation");
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(&general_kzg_params,
            &proving_key, &[circuit], &[&[]], random, &mut transcript).expect("The proof must be generated successfully!");
        let transcripted = transcript.finalize();
        end_timer!(timer);
    
        let performance = 1000 * INPUTS.iter().fold(0, |sum, input| sum + input.r) as u128 / timer.time.elapsed().as_millis();
        println!("The prover's performace is {} rounds/second", performance);
    
        let timer = start_timer!(|| "Proof verification");
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&transcripted[..]);
        let strategy = SingleStrategy::new(&general_kzg_params);
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(&verifier_kzg_params,
            proving_key.get_vk(), strategy, &[&[]], &mut transcript).expect("The proof must be verified successfully!");
        end_timer!(timer);
    }
}