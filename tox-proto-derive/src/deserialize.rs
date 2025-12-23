use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields};

pub fn derive_tox_deserialize_impl(input: DeriveInput) -> TokenStream {
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
            t.bounds
                .push(syn::parse_quote!(::tox_proto::ToxDeserialize));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (deserialize_body, deserialize_flat_body) = match &input.data {
        Data::Struct(s) => {
            let mut active_fields = Vec::new();
            let mut all_fields = Vec::new();

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

                let name = if let Some(ident) = &f.ident {
                    quote!(#ident)
                } else {
                    let idx = format_ident!("field{}", i);
                    quote!(#idx)
                };

                if skip {
                    all_fields.push((name, &f.ty, true));
                } else {
                    active_fields.push((name.clone(), &f.ty));
                    all_fields.push((name, &f.ty, false));
                }
            }

            let field_count = active_fields.len();
            let field_names: Vec<_> = active_fields.iter().map(|(n, _)| n.clone()).collect();
            let field_types: Vec<_> = active_fields.iter().map(|(_, t)| *t).collect();

            let deserialize_flat_fields: Vec<_> = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
                quote! { let #name = <#ty as ::tox_proto::ToxDeserialize>::deserialize_flat(reader, ctx)?; }
            }).collect();

            let construction = {
                let fields = all_fields.iter().map(|(name, _, skip)| {
                    if *skip {
                        quote! { #name: Default::default() }
                    } else {
                        quote! { #name }
                    }
                });
                match &s.fields {
                    Fields::Named(_) => quote! { #name { #(#fields),* } },
                    Fields::Unnamed(_) => {
                        let values = all_fields.iter().map(|(name, _, skip)| {
                            if *skip {
                                quote! { Default::default() }
                            } else {
                                quote! { #name }
                            }
                        });
                        quote! { #name ( #(#values),* ) }
                    }
                    Fields::Unit => quote! { #name },
                }
            };

            let deserialize_flat = if is_bits {
                let ty = bits_type.clone().unwrap_or_else(|| field_types[0].clone());
                quote! {
                    let bits = <#ty as ::tox_proto::ToxDeserialize>::deserialize_flat(reader, ctx)?;
                    Ok(Self::from_bits_retain(bits))
                }
            } else {
                quote! {
                    #(#deserialize_flat_fields)*
                    Ok(#construction)
                }
            };

            let deserialize = if is_bits {
                let ty = bits_type.unwrap_or_else(|| field_types[0].clone());
                quote! {
                    let bits = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?;
                    Ok(Self::from_bits_retain(bits))
                }
            } else if is_flat {
                if field_count == 1 {
                    // Rule 1: Transparent Wrapping
                    let ty = &field_types[0];
                    let field_name = &field_names[0];
                    let construction = match &s.fields {
                        Fields::Named(_) => quote! { #name { #field_name: val } },
                        Fields::Unnamed(_) => quote! { #name ( val ) },
                        Fields::Unit => quote! { #name },
                    };
                    quote! {
                        let val = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?;
                        Ok(#construction)
                    }
                } else {
                    let last_field_type = &field_types[field_count - 1];
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

                    let field_deserializers: Vec<_> = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
                        quote! { let #name = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?; }
                    }).collect();

                    quote! {
                        if #is_binary_concatenation {
                            // Rule 2: Binary Concatenation
                            let bin_len = ::tox_proto::rmp::decode::read_bin_len(reader)
                                .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                            let mut limited_reader = reader.by_ref().take(bin_len as u64);
                            let result = Self::deserialize_flat(&mut limited_reader, ctx)?;
                            if limited_reader.limit() > 0 {
                                ::std::io::copy(&mut limited_reader, &mut ::std::io::sink())?;
                            }
                            Ok(result)
                        } else {
                            // Rule 4: Default Fallback
                            let len = ::tox_proto::rmp::decode::read_array_len(reader)
                                .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                            if (len as usize) < #field_count {
                                return Err(::tox_proto::Error::Deserialize(format!("Too few fields for {}: expected {}, got {}", stringify!(#name), #field_count, len)));
                            }
                            #(#field_deserializers)*
                            for _ in #field_count..(len as usize) { ::tox_proto::skip_value(reader)?; }
                            Ok(#construction)
                        }
                    }
                }
            } else {
                let field_deserializers: Vec<_> = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
                    quote! { let #name = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?; }
                }).collect();

                quote! {
                    let len = ::tox_proto::rmp::decode::read_array_len(reader)
                        .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                    if (len as usize) < #field_count {
                        return Err(::tox_proto::Error::Deserialize(format!("Too few fields for {}: expected {}, got {}", stringify!(#name), #field_count, len)));
                    }
                    #(#field_deserializers)*
                    for _ in #field_count..(len as usize) { ::tox_proto::skip_value(reader)?; }
                    Ok(#construction)
                }
            };

            (deserialize, deserialize_flat)
        }
        Data::Enum(e) => {
            let mut next_idx = 0u8;
            let arms: Vec<_> = e.variants.iter().map(|v| {
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
                let expected_fields = v.fields.len() as u32;

                match &v.fields {
                    Fields::Unit => quote!(#idx => {
                        if len != 1 {
                            return Err(::tox_proto::Error::Deserialize(format!("Enum unit variant {} must have len 1, got {}", stringify!(#v_ident), len)));
                        }
                        Ok(#name::#v_ident)
                    },),
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        let ty = &f.unnamed[0].ty;
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with payload must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let val = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?;
                                Ok(#name::#v_ident(val))
                            }
                        }
                    }
                    Fields::Unnamed(f) => {
                        let bindings: Vec<_> = (0..f.unnamed.len()).map(|i| format_ident!("f{}", i)).collect();
                        let bindings_copy = bindings.clone();
                        let field_deserializers: Vec<_> = f.unnamed.iter().enumerate().map(|(i, field)| {
                            let ty = &field.ty;
                            let binding = &bindings[i];
                            quote! { let #binding = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?; }
                        }).collect();
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with multiple payload fields must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let inner_len = ::tox_proto::rmp::decode::read_array_len(reader)
                                    .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                                if inner_len < #expected_fields {
                                    return Err(::tox_proto::Error::Deserialize(format!("Too few fields for enum variant {} payload: expected {}, got {}", stringify!(#v_ident), #expected_fields, inner_len)));
                                }
                                #(#field_deserializers)*
                                for _ in #expected_fields..inner_len { ::tox_proto::skip_value(reader)?; }
                                Ok(#name::#v_ident(#(#bindings_copy),*))
                            }
                        }
                    }
                    Fields::Named(f) if f.named.len() == 1 => {
                        let ident = f.named[0].ident.as_ref().unwrap();
                        let ty = &f.named[0].ty;
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with payload must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let #ident = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?;
                                Ok(#name::#v_ident { #ident })
                            }
                        }
                    }
                    Fields::Named(f) => {
                        let idents: Vec<_> = f.named.iter().map(|f| &f.ident).collect();
                        let idents_copy = idents.clone();
                        let field_deserializers: Vec<_> = f.named.iter().map(|f| {
                            let ident = f.ident.as_ref().unwrap();
                            let ty = &f.ty;
                            quote! { let #ident = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader, ctx)?; }
                        }).collect();
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with multiple payload fields must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let inner_len = ::tox_proto::rmp::decode::read_array_len(reader)
                                    .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                                if inner_len < #expected_fields {
                                    return Err(::tox_proto::Error::Deserialize(format!("Too few fields for enum variant {} payload: expected {}, got {}", stringify!(#v_ident), #expected_fields, inner_len)));
                                }
                                #(#field_deserializers)*
                                for _ in #expected_fields..inner_len { ::tox_proto::skip_value(reader)?; }
                                Ok(#name::#v_ident { #(#idents_copy),* })
                            }
                        }
                    }
                }
            }).collect();

            let deserialize = quote! {
                let (idx, len) = ::tox_proto::read_enum_header(reader, ctx)?;
                match idx {
                    #(#arms)*
                    _ => Err(::tox_proto::Error::Deserialize(format!("Unknown variant: {}", idx))),
                }
            };
            let deserialize_flat = quote! {
                Err(::tox_proto::Error::Deserialize("Enums do not support flat deserialization".into()))
            };
            (deserialize, deserialize_flat)
        }
        _ => (
            quote! { compile_error!("ToxDeserialize only supports structs and enums"); },
            quote! { Err(::tox_proto::Error::Deserialize("Unsupported type".into())) },
        ),
    };

    quote! {
        #[automatically_derived]
        impl #impl_generics ::tox_proto::ToxDeserialize for #name #ty_generics #where_clause {
            #[inline]
            fn deserialize<R: ::std::io::Read>(reader: &mut R, ctx: &::tox_proto::ToxContext) -> ::tox_proto::Result<Self> {
                #deserialize_body
            }

            #[inline]
            fn deserialize_flat<R: ::std::io::Read>(reader: &mut R, ctx: &::tox_proto::ToxContext) -> ::tox_proto::Result<Self> {
                #deserialize_flat_body
            }
        }
    }
}
