mod r#bool;

#[proc_macro]
pub fn r#bool(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    r#bool::impl_bool_expr(item)
}
