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
    println!(
        "bool expr and or: {:?}",
        expr_macros::bool!(a.expr() && b.expr() || c.expr())
    );
}

#[test]
fn test_index() {
    let a: [Expression<Fr>; 2] = [1.expr(), 0.expr()];
    println!("in struct: {:?}", expr_macros::bool!(!a[0].expr()));
}

#[test]
fn test_field() {
    struct A {
        a: Expression<Fr>,
    }
    let a = A { a: 1.expr() };
    println!("in struct {:?}", expr_macros::bool!(!a.a));
}

#[test]
fn test_call() {
    fn a() -> Expression<Fr> {
        1.expr()
    }
    println!("in struct {:?}", expr_macros::bool!(!a()));
}

#[test]
fn test_method_call() {
    struct A {
        a: Expression<Fr>,
    }
    impl A {
        fn foo(&self) -> Expression<Fr> {
            self.a.clone()
        }
    }
    let a = A { a: 1.expr() };
    println!("in struct {:?}", expr_macros::bool!(!a.foo()));
}

#[test]
fn test_bool() {
    let a: Expression<Fr> = 1.expr();
    let b: Expression<Fr> = 0.expr();
    let c: Expression<Fr> = 1.expr();
    println!("{:?}", expr_macros::bool!(a && b || c));
}
