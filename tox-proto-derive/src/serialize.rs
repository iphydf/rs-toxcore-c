use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index};

pub fn derive_tox_serialize_impl(input: DeriveInput) -> TokenStream {
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
            t.bounds.push(syn::parse_quote!(::tox_proto::ToxSerialize));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (serialize_body, serialize_flat_body) = if is_bits {
        (
            quote! { self.bits().serialize(writer, ctx) },
            quote! { self.bits().serialize_flat(writer, ctx) },
        )
    } else {
        match &input.data {
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
                let field_accessors: Vec<_> =
                    active_fields.iter().map(|(a, _)| a.clone()).collect();
                let field_types: Vec<_> = active_fields.iter().map(|(_, t)| *t).collect();

                let serialize_flat_fields: Vec<_> = field_accessors
                    .iter()
                    .map(|accessor| {
                        quote! { #accessor.serialize_flat(writer, ctx)?; }
                    })
                    .collect();

                let serialize_flat = if is_bits {
                    quote! {
                        self.bits().serialize_flat(writer, ctx)
                    }
                } else {
                    quote! {
                        #(#serialize_flat_fields)*
                        Ok(())
                    }
                };

                let serialize = if is_bits {
                    quote! {
                        self.bits().serialize(writer, ctx)
                    }
                } else if is_flat {
                    if field_count == 1 {
                        // Rule 1: Transparent Wrapping
                        let accessor = &field_accessors[0];
                        quote! {
                            #accessor.serialize(writer, ctx)
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
                                quote! { #accessor.serialize(writer, ctx)?; }
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
                                self.serialize_flat(writer, ctx)
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
                            quote! { #accessor.serialize(writer, ctx)?; }
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
                let mut next_idx = 0u8;
                let arms: Vec<_> = e
                .variants
                .iter()
                .map(|v| {
                    let idx = if let Some((_, expr)) = &v.discriminant {
                        let lit = match expr {
                            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit), .. }) => lit,
                            _ => panic!("Only integer discriminants are supported"),
                        };
                        let val = lit.base10_parse::<u8>().expect("Discriminant must be u8");
                        next_idx = val + 1;
                        val
                    } else {
                        let val = next_idx;
                        next_idx += 1;
                        val
                    };

                    let v_ident = &v.ident;

                    match &v.fields {
                        Fields::Unit => quote! {
                            #name::#v_ident => {
                                #idx.serialize(writer, ctx)?;
                            }
                        },
                        Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                            quote! {
                                #name::#v_ident(f0) => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer, ctx)?;
                                    f0.serialize(writer, ctx)?;
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
                                    #idx.serialize(writer, ctx)?;
                                    ::tox_proto::rmp::encode::write_array_len(writer, #inner_count)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #(#bindings.serialize(writer, ctx)?;)*
                                }
                            }
                        }
                        Fields::Named(f) if f.named.len() == 1 => {
                            let ident = f.named[0].ident.as_ref().unwrap();
                            quote! {
                                #name::#v_ident { #ident } => {
                                    ::tox_proto::rmp::encode::write_array_len(writer, 2)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #idx.serialize(writer, ctx)?;
                                    #ident.serialize(writer, ctx)?;
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
                                    #idx.serialize(writer, ctx)?;
                                    ::tox_proto::rmp::encode::write_array_len(writer, #inner_count)
                                        .map_err(|e| ::tox_proto::Error::Serialize(e.to_string()))?;
                                    #(#idents.serialize(writer, ctx)?;)*
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
        }
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::tox_proto::ToxSerialize for #name #ty_generics #where_clause {
            #[inline]
            fn serialize<W: ::std::io::Write>(&self, writer: &mut W, ctx: &::tox_proto::ToxContext) -> ::tox_proto::Result<()> {
                #serialize_body
            }

            #[inline]
            fn serialize_flat<W: ::std::io::Write>(&self, writer: &mut W, ctx: &::tox_proto::ToxContext) -> ::tox_proto::Result<()> {
                #serialize_flat_body
            }
        }
    }
}
