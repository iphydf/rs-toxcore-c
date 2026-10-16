use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index};

pub fn derive_tox_serialize_impl(input: DeriveInput) -> TokenStream {
    let name = &input.ident;
    let mut is_flat = false;

    for attr in &input.attrs {
        if attr.path().is_ident("tox") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("flat") {
                    is_flat = true;
                }
                Ok(())
            });
        }
    }
    let mut generics = input.generics.clone();
    for param in &mut generics.params {
        if let syn::GenericParam::Type(t) = param {
            t.bounds.push(syn::parse_quote!(::tox_proto::ToxSize));
            t.bounds.push(syn::parse_quote!(::tox_proto::ToxSerialize));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (serialize_body, serialize_flat_body) = match &input.data {
        Data::Struct(s) => {
            let mut active_fields = Vec::new();
            for (i, f) in s.fields.iter().enumerate() {
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
                if !skip {
                    let accessor = if let Some(ident) = &f.ident {
                        quote!(self.#ident)
                    } else {
                        let index = Index::from(i);
                        quote!(self.#index)
                    };
                    active_fields.push((accessor, &f.ty));
                }
            }

            let field_count = active_fields.len();
            let field_accessors: Vec<_> = active_fields.iter().map(|(a, _)| a.clone()).collect();
            let field_types: Vec<_> = active_fields.iter().map(|(_, t)| *t).collect();

            let serialize_flat_fields: Vec<_> = field_accessors
                .iter()
                .map(|accessor| {
                    quote! { #accessor.serialize_flat(writer)?; }
                })
                .collect();

            let serialize_flat = quote! {
                #(#serialize_flat_fields)*
                Ok(())
            };

            let serialize = if is_flat {
                if field_count == 1 {
                    // Rule 1: Transparent Wrapping
                    let accessor = &field_accessors[0];
                    quote! {
                        #accessor.serialize(writer)
                    }
                } else {
                    // Multiple fields
                    let last_field_type = field_types.last().unwrap();
                    let last_field_accessor = field_accessors.last().unwrap();

                    let all_but_last_byte_like = if field_count > 1 {
                        let other_types = &field_types[..field_count - 1];
                        quote! {
                            true #(&& <#other_types as ::tox_proto::ToxSize>::IS_BYTE_LIKE)*
                        }
                    } else {
                        quote! { true }
                    };

                    let is_binary_concatenation = quote! {
                        #all_but_last_byte_like && <#last_field_type as ::tox_proto::ToxSize>::IS_BYTE_LIKE
                    };

                    let field_serialization: Vec<_> = field_accessors
                        .iter()
                        .map(|accessor| {
                            quote! { #accessor.serialize(writer)?; }
                        })
                        .collect();

                    let other_types = if field_count > 1 {
                        &field_types[..field_count - 1]
                    } else {
                        &[]
                    };

                    quote! {
                        if #is_binary_concatenation {
                            // Rule 2: Binary Concatenation
                            let other_fields_size = 0 #(+ <#other_types as ::tox_proto::ToxSize>::SIZE.expect("Field must be flat"))*;
                            let total_size = other_fields_size + (&#last_field_accessor).flat_len();
                            ::tox_proto::rmp::encode::write_bin_len(writer, total_size as u32)
                                .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                            self.serialize_flat(writer)
                        } else {
                            // Rule 4: Default Fallback
                            ::tox_proto::rmp::encode::write_array_len(writer, #field_count as u32)
                                .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                            #(#field_serialization)*
                            Ok(())
                        }
                    }
                }
            } else {
                let field_serialization: Vec<_> = field_accessors
                    .iter()
                    .map(|accessor| {
                        quote! { #accessor.serialize(writer)?; }
                    })
                    .collect();
                quote! {
                    ::tox_proto::rmp::encode::write_array_len(writer, #field_count as u32)
                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                    #(#field_serialization)*
                    Ok(())
                }
            };

            (serialize, serialize_flat)
        }
        Data::Enum(e) => {
            let idxs = crate::discriminants(&e.variants);
            let arms: Vec<_> = e
                .variants
                .iter()
                .zip(idxs)
                .map(|(v, idx)| {
                    let v_ident = &v.ident;

                    // Detect #[tox(catch_all)]
                    let mut is_catch_all = false;
                    for attr in &v.attrs {
                        if attr.path().is_ident("tox") {
                            let _ = attr.parse_nested_meta(|meta| {
                                if meta.path.is_ident("catch_all") {
                                    is_catch_all = true;
                                }
                                Ok(())
                            });
                        }
                    }

                    if is_catch_all {
                        // Serialize with stored discriminant, not compile-time idx
                        return quote! {
                            #name::#v_ident { discriminant, data } => {
                                if data.is_empty() {
                                    (*discriminant as u8).serialize(writer)?;
                                } else {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    (*discriminant as u8).serialize(writer)?;
                                    writer.write_all(data)?;
                                }
                            }
                        };
                    }

                    match &v.fields {
                        Fields::Unit => quote! {
                            #name::#v_ident => {
                                #idx.serialize(writer)?;
                            }
                        },
                        Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                            quote! {
                                #name::#v_ident(f0) => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer)?;
                                    f0.serialize(writer)?;
                                }
                            }
                        }
                        Fields::Unnamed(f) => {
                            let bindings: Vec<_> = (0..f.unnamed.len())
                                .map(|i| quote::format_ident!("f{}", i))
                                .collect();
                            let inner_count = f.unnamed.len() as u32;
                            quote! {
                                #name::#v_ident(#(#bindings),*) => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer)?;
                                    ::tox_proto::rmp::encode::write_array_len(writer, #inner_count)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #(#bindings.serialize(writer)?;)*
                                }
                            }
                        }
                        Fields::Named(f) if f.named.len() == 1 => {
                            let ident = f.named[0].ident.as_ref().unwrap();
                            quote! {
                                #name::#v_ident { #ident } => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer)?;
                                    #ident.serialize(writer)?;
                                }
                            }
                        }
                        Fields::Named(f) => {
                            let idents: Vec<_> = f.named.iter().map(|f| &f.ident).collect();
                            let inner_count = f.named.len() as u32;
                            quote! {
                                #name::#v_ident { #(#idents),* } => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer)?;
                                    ::tox_proto::rmp::encode::write_array_len(writer, #inner_count)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #(#idents.serialize(writer)?;)*
                                }
                            }
                        }
                    }
                })
                .collect();

            let serialize = quote! {
                match self { #(#arms)* }
                Ok(())
            };
            let serialize_flat = quote! {
                Err(::tox_proto::Error::Serialize("Enums do not support flat serialization".into()))
            };
            (serialize, serialize_flat)
        }
        _ => (
            quote! { compile_error!("ToxSerialize only supports structs and enums"); },
            quote! { Ok(()) },
        ),
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::tox_proto::ToxSerialize for #name #ty_generics #where_clause {
            #[inline]
            fn serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::tox_proto::Result<()> {
                #serialize_body
            }

            #[inline]
            fn serialize_flat<W: ::std::io::Write>(&self, writer: &mut W) -> ::tox_proto::Result<()> {
                #serialize_flat_body
            }
        }
    }
}
