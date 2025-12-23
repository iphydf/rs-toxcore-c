use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput};

pub fn derive_tox_size_impl(input: DeriveInput) -> TokenStream {
    let name = &input.ident;
    let mut is_flat = false;
    let mut is_bits = false;
    let mut bits_type: Option<syn::Type> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("tox") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("flat") {
                    is_flat = true;
                }
                if meta.path.is_ident("bits") {
                    is_bits = true;
                    if meta.input.peek(syn::Token![=]) {
                        let s: syn::LitStr = meta.value()?.parse()?;
                        bits_type = Some(s.parse()?);
                    }
                }
                Ok(())
            });
        }
    }

    let mut generics = input.generics.clone();
    for param in &mut generics.params {
        if let syn::GenericParam::Type(t) = param {
            t.bounds.push(syn::parse_quote!(::tox_proto::ToxSize));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let size_body = if is_bits {
        let ty = bits_type.unwrap_or_else(|| syn::parse_quote!(u32));
        (
            quote! { <#ty as ::tox_proto::ToxSize>::SIZE },
            quote! { <#ty as ::tox_proto::ToxSize>::IS_BYTE_LIKE },
        )
    } else {
        match &input.data {
            Data::Struct(s) => {
                if s.fields.is_empty() {
                    (quote! { Some(0) }, quote! { true })
                } else {
                    let mut size_expr = quote! { Some(0) };
                    let mut byte_like_expr = quote! { true };
                    for f in s.fields.iter().rev() {
                        let mut skip = false;
                        for attr in &f.attrs {
                            if attr.path().is_ident("tox") {
                                let _ = attr.parse_nested_meta(|meta| {
                                    if meta.path.is_ident("skip") {
                                        skip = true;
                                    }
                                    Ok(())
                                });
                            }
                        }

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
        }
    };

    let (const_size, const_byte_like) = size_body;

    if is_flat || is_bits {
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
