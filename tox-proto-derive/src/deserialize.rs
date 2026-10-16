use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields};

use crate::has_tox_flag;

pub fn derive_tox_deserialize_impl(input: DeriveInput) -> TokenStream {
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
                    active_fields.push((name.clone(), &f.ty, has_tox_flag(&f.attrs, "default")));
                    all_fields.push((name, &f.ty, false));
                }
            }

            let field_count = active_fields.len();
            let field_names: Vec<_> = active_fields.iter().map(|(n, _, _)| n.clone()).collect();
            let field_types: Vec<_> = active_fields.iter().map(|(_, t, _)| *t).collect();
            let struct_reads =
                read_fields(&active_fields, &quote!(len), &quote!(stringify!(#name)));

            let deserialize_flat_fields: Vec<_> = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
                quote! { let #name = <#ty as ::tox_proto::ToxDeserialize>::deserialize_flat(reader)?; }
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

            let deserialize_flat = quote! {
                #(#deserialize_flat_fields)*
                Ok(#construction)
            };

            let deserialize = if is_flat {
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
                        let val = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader)?;
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

                    quote! {
                        if #is_binary_concatenation {
                            // Rule 2: Binary Concatenation
                            let bin_len = ::tox_proto::rmp::decode::read_bin_len(reader)
                                .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                            let mut limited_reader = reader.by_ref().take(bin_len as u64);
                            let result = Self::deserialize_flat(&mut limited_reader)?;
                            if limited_reader.limit() > 0 {
                                ::std::io::copy(&mut limited_reader, &mut ::std::io::sink())?;
                            }
                            Ok(result)
                        } else {
                            // Rule 4: Default Fallback
                            let len = ::tox_proto::rmp::decode::read_array_len(reader)
                                .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                            #struct_reads
                            Ok(#construction)
                        }
                    }
                }
            } else {
                quote! {
                    let len = ::tox_proto::rmp::decode::read_array_len(reader)
                        .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                    #struct_reads
                    Ok(#construction)
                }
            };

            (deserialize, deserialize_flat)
        }
        Data::Enum(e) => {
            let idxs = crate::discriminants(&e.variants);
            let mut catch_all_ident: Option<syn::Ident> = None;
            let lenient = e
                .variants
                .iter()
                .find(|v| has_tox_flag(&v.attrs, "catch_all"))
                .filter(|_| has_tox_flag(&input.attrs, "lenient"))
                .map(|v| &v.ident);
            let arms: Vec<_> = e.variants.iter().zip(idxs).filter_map(|(v, idx)| {

                // Detect #[tox(catch_all)] to skip generating a match arm.
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
                    catch_all_ident = Some(v.ident.clone());
                    return None;
                }

                let v_ident = &v.ident;

                // A variant that doesn't decode is kept as unknown.
                if let (Some(catch_all), Fields::Unnamed(f)) = (lenient, &v.fields) {
                    let ty = &f.unnamed[0].ty;
                    return Some(quote! {
                        #idx => {
                            let mut data = Vec::new();
                            for _ in 1..len {
                                data.extend(::tox_proto::capture_value(reader)?);
                            }
                            let known = if len == 2 {
                                ::tox_proto::deserialize_exact::<#ty>(&data).ok()
                            } else {
                                None
                            };
                            Ok(match known {
                                Some(val) => #name::#v_ident(val),
                                None => #name::#catch_all { discriminant: u32::from(#idx), data },
                            })
                        }
                    });
                }

                Some(match &v.fields {
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
                                let val = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader)?;
                                Ok(#name::#v_ident(val))
                            }
                        }
                    }
                    Fields::Unnamed(f) => {
                        let bindings: Vec<_> = (0..f.unnamed.len()).map(|i| format_ident!("f{}", i)).collect();
                        let bindings_copy = bindings.clone();
                        let fields: Vec<_> = f.unnamed.iter().enumerate().map(|(i, field)| {
                            let binding = &bindings[i];
                            (quote!(#binding), &field.ty, has_tox_flag(&field.attrs, "default"))
                        }).collect();
                        let reads = read_fields(&fields, &quote!(inner_len), &quote!(stringify!(#v_ident)));
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with multiple payload fields must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let inner_len = ::tox_proto::rmp::decode::read_array_len(reader)
                                    .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                                #reads
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
                                let #ident = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader)?;
                                Ok(#name::#v_ident { #ident })
                            }
                        }
                    }
                    Fields::Named(f) => {
                        let idents: Vec<_> = f.named.iter().map(|f| &f.ident).collect();
                        let idents_copy = idents.clone();
                        let fields: Vec<_> = f.named.iter().map(|f| {
                            let ident = f.ident.as_ref().unwrap();
                            (quote!(#ident), &f.ty, has_tox_flag(&f.attrs, "default"))
                        }).collect();
                        let reads = read_fields(&fields, &quote!(inner_len), &quote!(stringify!(#v_ident)));
                        quote! {
                            #idx => {
                                if len != 2 {
                                    return Err(::tox_proto::Error::Deserialize(format!("Enum variant {} with multiple payload fields must have len 2, got {}", stringify!(#v_ident), len)));
                                }
                                let inner_len = ::tox_proto::rmp::decode::read_array_len(reader)
                                    .map_err(|e| ::tox_proto::Error::Deserialize(e.to_string()))?;
                                #reads
                                Ok(#name::#v_ident { #(#idents_copy),* })
                            }
                        }
                    }
                })
            }).collect();

            let fallthrough = if let Some(catch_all) = &catch_all_ident {
                quote! {
                    unknown_idx => {
                        let mut data = Vec::new();
                        for _ in 1..len {
                            data.extend(::tox_proto::capture_value(reader)?);
                        }
                        Ok(#name::#catch_all { discriminant: unknown_idx as u32, data })
                    }
                }
            } else {
                quote! {
                    _ => Err(::tox_proto::Error::Deserialize(format!("Unknown variant: {}", idx)))
                }
            };

            let deserialize = quote! {
                let (idx, len) = ::tox_proto::read_enum_header(reader)?;
                match idx {
                    #(#arms)*
                    #fallthrough
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
            fn deserialize<R: ::std::io::Read>(reader: &mut R) -> ::tox_proto::Result<Self> {
                #deserialize_body
            }

            #[inline]
            fn deserialize_flat<R: ::std::io::Read>(reader: &mut R) -> ::tox_proto::Result<Self> {
                #deserialize_flat_body
            }
        }
    }
}

/// Reads `fields` (binding, type, whether it defaults) from an array of
/// `len` items. Fields marked `#[tox(default)]`, which must come last, may be
/// missing from older encodings. Items after the known fields are skipped.
fn read_fields(
    fields: &[(TokenStream, &syn::Type, bool)],
    len: &TokenStream,
    what: &TokenStream,
) -> TokenStream {
    let count = fields.len();
    let required = fields.iter().take_while(|(_, _, default)| !default).count();
    if fields[required..].iter().any(|(_, _, default)| !default) {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[tox(default)] fields must come after all others",
        )
        .to_compile_error();
    }
    let reads = fields.iter().enumerate().map(|(i, (binding, ty, default))| {
        if *default {
            quote! {
                let #binding = if (#len as usize) > #i {
                    <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader)?
                } else {
                    ::core::default::Default::default()
                };
            }
        } else {
            quote! { let #binding = <#ty as ::tox_proto::ToxDeserialize>::deserialize(reader)?; }
        }
    });
    quote! {
        if (#len as usize) < #required {
            return Err(::tox_proto::Error::Deserialize(format!("Too few fields for {}: expected {}, got {}", #what, #required, #len)));
        }
        #(#reads)*
        for _ in #count..(#len as usize) { ::tox_proto::skip_value(reader)?; }
    }
}
