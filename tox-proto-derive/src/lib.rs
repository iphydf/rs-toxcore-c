mod deserialize;
mod serialize;
mod size;

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
