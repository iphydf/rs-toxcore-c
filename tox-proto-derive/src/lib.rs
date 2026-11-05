#![deny(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm
)]
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
    if let Err(e) = check_flags(&input) {
        return e.to_compile_error().into();
    }
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
    if let Err(e) = check_flags(&input) {
        return e.to_compile_error().into();
    }
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
    if let Err(e) = check_flags(&input) {
        return e.to_compile_error().into();
    }
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
pub(crate) fn discriminants<'a>(
    variants: impl IntoIterator<Item = &'a syn::Variant>,
) -> syn::Result<Vec<u8>> {
    let mut next: u16 = 0;
    variants
        .into_iter()
        .map(|v| {
            if has_tox_flag(&v.attrs, "catch_all") {
                return Ok(0);
            }
            if let Some((_, expr)) = &v.discriminant {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(lit),
                    ..
                }) = expr
                else {
                    return Err(syn::Error::new_spanned(
                        expr,
                        "only integer discriminants are supported",
                    ));
                };
                next = lit.base10_parse::<u8>()?.into();
            }
            let value = u8::try_from(next)
                .map_err(|_| syn::Error::new_spanned(&v.ident, "discriminants must fit in a u8"))?;
            next += 1;
            Ok(value)
        })
        .collect()
}

const FLAGS: &[&str] = &["catch_all", "default", "flat", "lenient", "skip"];

/// The flags in `#[tox(...)]` attributes. A misspelt flag is an error.
fn tox_flags(attrs: &[syn::Attribute]) -> syn::Result<Vec<syn::Ident>> {
    let mut flags = Vec::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("tox")) {
        attr.parse_nested_meta(|meta| {
            let flag = meta.path.require_ident()?;
            if !FLAGS.iter().any(|known| flag == known) {
                return Err(meta.error(format!("unknown flag; expected one of {FLAGS:?}")));
            }
            flags.push(flag.clone());
            Ok(())
        })?;
    }
    Ok(flags)
}

/// Checks the `#[tox(...)]` attributes of the item and all its fields and
/// variants, so `has_tox_flag` only ever sees valid ones.
fn check_flags(input: &DeriveInput) -> syn::Result<()> {
    tox_flags(&input.attrs)?;
    let fields: Vec<&syn::Field> = match &input.data {
        syn::Data::Struct(s) => s.fields.iter().collect(),
        syn::Data::Enum(e) => {
            for variant in &e.variants {
                tox_flags(&variant.attrs)?;
            }
            e.variants.iter().flat_map(|v| &v.fields).collect()
        }
        syn::Data::Union(u) => u.fields.named.iter().collect(),
    };
    for field in fields {
        tox_flags(&field.attrs)?;
    }
    Ok(())
}

pub(crate) fn has_tox_flag(attrs: &[syn::Attribute], flag: &str) -> bool {
    tox_flags(attrs).is_ok_and(|flags| flags.iter().any(|f| f == flag))
}
