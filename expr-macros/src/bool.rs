use proc_macro2::TokenStream;
use quote::quote;
use quote::ToTokens;
use syn::parse::Parse;
use syn::parse_macro_input;
use syn::visit::Visit;

struct Ast(syn::Expr);

impl Parse for Ast {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ast = input.parse()?;
        match ast {
            // 1. selectorA &&(||) selectorB
            syn::Expr::Binary(ref expr) => match expr.op {
                // only support && and ||
                syn::BinOp::And(_) | syn::BinOp::Or(_) => (),
                _ => {
                    let message = format!("unsupported binop: {:?}", expr.op);
                    return Err(syn::Error::new_spanned(expr, message));
                }
            },
            // 2. !selectorA
            syn::Expr::Unary(ref expr) => match expr.op {
                // only support !
                syn::UnOp::Not(_) => (),
                _ => {
                    let message = format!("unsupported unop: {:?}", expr.op);
                    return Err(syn::Error::new_spanned(expr, message));
                }
            },
            // 3. (selectorA && selectorB)
            // 4. selectorA
            syn::Expr::Paren(_)
            | syn::Expr::Path(_)
            | syn::Expr::MethodCall(_)
            | syn::Expr::Call(_)
            | syn::Expr::Reference(_)
            | syn::Expr::Field(_)
            | syn::Expr::Index(_) => (),
            _ => {
                let message = format!("unsupported expr: {:?}", ast);
                return Err(syn::Error::new_spanned(ast, message));
            }
        }
        Ok(Ast(ast))
    }
}

#[derive(Default, Debug)]
struct Model {
    expr: TokenStream,
}

impl<'ast> Visit<'ast> for Model {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        self.visit_expr(&*node.left);
        let left_expr = self.expr.clone();
        self.visit_expr(&*node.right);
        let right_expr = self.expr.clone();
        match node.op {
            syn::BinOp::And(_) => {
                self.expr = quote! {and::expr([#left_expr, #right_expr])};
            }
            syn::BinOp::Or(_) => {
                self.expr = quote! {or::expr([#left_expr, #right_expr])};
            }
            _ => unreachable!(),
        }
    }

    fn visit_expr_unary(&mut self, node: &'ast syn::ExprUnary) {
        self.visit_expr(&*node.expr);
        let expr = self.expr.clone();
        match node.op {
            syn::UnOp::Not(_) => {
                self.expr = quote! {not::expr(#expr)};
            }
            _ => unreachable!(),
        }
    }

    // a.expr()
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.expr = node.to_token_stream();
    }

    // a()
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.expr = node.to_token_stream();
    }

    // a
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.expr = node.to_token_stream();
    }

    // a.b
    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        self.expr = node.to_token_stream();
    }

    // &a
    fn visit_expr_reference(&mut self, node: &'ast syn::ExprReference) {
        self.expr = node.to_token_stream();
    }

    // a[0]
    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        self.expr = node.to_token_stream();
    }
}

fn analyze(ast: Ast) -> Model {
    let mut model = Model::default();
    model.visit_expr(&ast.0);
    model
}

pub(crate) fn impl_bool_expr(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // 1. parse ast
    let ast = parse_macro_input!(item as Ast);
    // 2. analyze ast tree
    let model = analyze(ast);
    // 3. generate code from model
    model.expr.into()
}
