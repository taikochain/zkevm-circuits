use gadgets::util::{and, not, or, Expr};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Expression;
#[test]
fn test_bool_with_call_expr() {
    let a: Expression<Fr> = 1.expr();
    let b: Expression<Fr> = 0.expr();
    let c: Expression<Fr> = 1.expr();
    println!(
        "bool expr and: {:?}",
        expr_macros::bool!(a.expr() && b.expr())
    );
    println!("bool expr not: {:?}", expr_macros::bool!(!c.expr()));
    println!("bool expr not: {:?}", expr_macros::bool!(c.expr()));
    println!(
        "bool expr and or: {:?}",
        expr_macros::bool!(a.expr() && b.expr() || c.expr())
    );
}

#[test]
fn test_bool() {
    let a: Expression<Fr> = 1.expr();
    let b: Expression<Fr> = 0.expr();
    let c: Expression<Fr> = 1.expr();
    println!("{:?}", expr_macros::bool!(a && b || c));
}
