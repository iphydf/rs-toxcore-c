mod deserialize;
mod serialize;
mod size;
mod variants;

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(ToxSerialize, attributes(tox))]
pub fn derive_tox_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let mut expanded = size::derive_tox_size_impl(input.clone());
    expanded.extend(serialize::derive_tox_serialize_impl(input));
    expanded = quote! {
        const _: () = {
            #[allow(unused_imports)]
            use ::tox_proto::{ToxSerialize as _, ToxSize as _};
            #[allow(unused_imports)]
            use ::std::io::Write as _;
            #expanded
        };
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(ToxDeserialize, attributes(tox))]
pub fn derive_tox_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let mut expanded = size::derive_tox_size_impl(input.clone());
    expanded.extend(deserialize::derive_tox_deserialize_impl(input));
    expanded = quote! {
        const _: () = {
            #[allow(unused_imports)]
            use ::tox_proto::{ToxDeserialize as _, ToxSize as _};
            #[allow(unused_imports)]
            use ::std::io::Read as _;
            #expanded
        };
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(ToxProto, attributes(tox))]
pub fn derive_tox_proto(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let mut expanded = size::derive_tox_size_impl(input.clone());
    expanded.extend(serialize::derive_tox_serialize_impl(input.clone()));
    expanded.extend(variants::derive_variants_impl(&input));
    expanded.extend(deserialize::derive_tox_deserialize_impl(input));
    expanded = quote! {
        const _: () = {
            #[allow(unused_imports)]
            use ::tox_proto::{ToxSerialize as _, ToxDeserialize as _, ToxSize as _};
            #[allow(unused_imports)]
            use ::std::io::{Read as _, Write as _};
            #expanded
        };
    };
    TokenStream::from(expanded)
}

/// Each variant's discriminant: its explicit one, or one more than the
/// variant before it. The `catch_all` variant has none of its own (its tag
/// is the one it holds), so it takes no tag from the others; it reads as 0.
pub(crate) fn discriminants<'a>(variants: impl IntoIterator<Item = &'a syn::Variant>) -> Vec<u8> {
    let mut next: u16 = 0;
    variants
        .into_iter()
        .map(|v| {
            if has_tox_flag(&v.attrs, "catch_all") {
                return 0;
            }
            if let Some((_, expr)) = &v.discriminant {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(lit),
                    ..
                }) = expr
                else {
                    panic!("Only integer discriminants are supported");
                };
                next = lit
                    .base10_parse::<u8>()
                    .expect("Discriminant must be u8")
                    .into();
            }
            let value = u8::try_from(next).expect("Discriminant must be u8");
            next += 1;
            value
        })
        .collect()
}

pub(crate) fn has_tox_flag(attrs: &[syn::Attribute], flag: &str) -> bool {
    let mut found = false;
    for attr in attrs {
        if attr.path().is_ident("tox") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident(flag) {
                    found = true;
                }
                Ok(())
            });
        }
    }
    found
}
