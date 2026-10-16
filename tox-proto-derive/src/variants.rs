use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::has_tox_flag;

/// `Fields` for a struct encoded as an array of its fields; for an enum with
/// a `catch_all` variant, `kind()`; for a `#[tox(lenient)]` enum, the typed
/// access to its variants.
pub fn derive_variants_impl(input: &DeriveInput) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let lenient = has_tox_flag(&input.attrs, "lenient");
    let e = match &input.data {
        Data::Struct(_) if !has_tox_flag(&input.attrs, "flat") => {
            return quote! {
                #[automatically_derived]
                impl #impl_generics ::tox_proto::Fields for #name #ty_generics #where_clause {}
            };
        }
        Data::Enum(e) => e,
        _ => return quote! {},
    };
    let Some(catch_all) = e
        .variants
        .iter()
        .find(|v| has_tox_flag(&v.attrs, "catch_all"))
    else {
        return if lenient {
            error(
                name,
                "a #[tox(lenient)] enum needs a #[tox(catch_all)] variant",
            )
        } else {
            quote! {}
        };
    };
    let catch_all = &catch_all.ident;

    let known: Vec<_> = e
        .variants
        .iter()
        .zip(crate::discriminants(&e.variants))
        .filter(|(v, _)| v.ident != *catch_all)
        .map(|(v, idx)| (v, u32::from(idx)))
        .collect();
    let kinds = known.iter().map(|(v, idx)| {
        let v_ident = &v.ident;
        match &v.fields {
            Fields::Unit => quote! { Self::#v_ident => #idx, },
            Fields::Unnamed(_) => quote! { Self::#v_ident(..) => #idx, },
            Fields::Named(_) => quote! { Self::#v_ident { .. } => #idx, },
        }
    });
    let kind = quote! {
        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            /// The tag of the variant, or of the unknown one.
            pub fn kind(&self) -> u32 {
                match self {
                    #(#kinds)*
                    Self::#catch_all { discriminant, .. } => *discriminant,
                }
            }
        }
    };
    if !lenient {
        return kind;
    }

    if !input.generics.params.is_empty() {
        return error(name, "a #[tox(lenient)] enum can't be generic");
    }
    let mut access = Vec::new();
    for (v, idx) in &known {
        let v_ident = &v.ident;
        let ty = match &v.fields {
            Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0].ty,
            _ => return error(v, "a #[tox(lenient)] enum's variants each wrap one struct"),
        };
        access.push(quote! {
            const _: fn() = || {
                fn fields<T: ::tox_proto::Fields>() {}
                fields::<#ty>();
            };

            #[automatically_derived]
            impl ::tox_proto::Variant<#name> for #ty {
                const KIND: u32 = #idx;

                fn of(value: &#name) -> ::core::option::Option<&Self> {
                    match value {
                        #name::#v_ident(inner) => ::core::option::Option::Some(inner),
                        _ => ::core::option::Option::None,
                    }
                }
            }

            #[automatically_derived]
            impl ::core::convert::From<#ty> for #name {
                fn from(inner: #ty) -> Self {
                    #name::#v_ident(inner)
                }
            }

            #[automatically_derived]
            impl ::core::convert::From<#ty> for ::tox_proto::Kept<#name> {
                fn from(inner: #ty) -> Self {
                    #name::#v_ident(inner).into()
                }
            }
        });
    }
    quote! {
        #kind
        #(#access)*
    }
}

fn error(tokens: impl quote::ToTokens, message: &str) -> TokenStream {
    syn::Error::new_spanned(tokens, message).to_compile_error()
}
