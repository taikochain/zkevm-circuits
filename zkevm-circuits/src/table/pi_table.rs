use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiFieldTag {
    Null = 0,
    MethodSign,
    L1Hash,
    L1SignalRoot,
    L1Height,
    ParentGasUsed,
}
impl_expr!(PiFieldTag);

#[derive(Clone, Debug)]
pub struct PiTable {
    pub tag: Column<Fixed>,
    pub value: Column<Advice>,
}
