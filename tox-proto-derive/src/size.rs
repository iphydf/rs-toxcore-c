use crate::has_tox_flag;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput};

pub fn derive_tox_size_impl(input: DeriveInput) -> TokenStream {
    let name = &input.ident;
    let is_flat = has_tox_flag(&input.attrs, "flat");

    let mut generics = input.generics.clone();
    for param in &mut generics.params {
        if let syn::GenericParam::Type(t) = param {
            t.bounds.push(syn::parse_quote!(::tox_proto::ToxSize));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let size_body = match &input.data {
        Data::Struct(s) => {
            if s.fields.is_empty() {
                (quote! { Some(0) }, quote! { true })
            } else {
                let mut size_expr = quote! { Some(0) };
                let mut byte_like_expr = quote! { true };
                for f in s.fields.iter().rev() {
                    let skip = has_tox_flag(&f.attrs, "skip");

                    if skip {
                        continue;
                    }

                    let ty = &f.ty;
                    size_expr = quote! {
                        match (<#ty as ::tox_proto::ToxSize>::SIZE, #size_expr) {
                            (Some(s1), Some(s2)) => Some(s1 + s2),
                            _ => None,
                        }
                    };
                    byte_like_expr = quote! {
                        <#ty as ::tox_proto::ToxSize>::IS_BYTE_LIKE && #byte_like_expr
                    };
                }
                (size_expr, byte_like_expr)
            }
        }
        Data::Enum(_) => (quote! { None }, quote! { false }),
        _ => (quote! { None }, quote! { false }),
    };

    let (const_size, const_byte_like) = size_body;

    if is_flat {
        quote! {
            #[automatically_derived]
            impl #impl_generics ::tox_proto::ToxSize for #name #ty_generics #where_clause {
                const SIZE: Option<usize> = #const_size;
                const IS_BYTE_LIKE: bool = #const_byte_like;
            }
        }
    } else {
        quote! {
            #[automatically_derived]
            impl #impl_generics ::tox_proto::ToxSize for #name #ty_generics #where_clause {
                const SIZE: Option<usize> = None;
                const IS_BYTE_LIKE: bool = false;
            }
        }
    }
}
