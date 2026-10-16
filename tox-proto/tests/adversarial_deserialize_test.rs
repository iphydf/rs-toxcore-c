//! Safety of deserializing what a peer sends.
//!
//! Generic `ToxDeserialize` impls in `tox-proto` read a peer-supplied
//! length prefix and then either (a) allocate a byte buffer of that
//! size or (b) call `Vec::with_capacity` / `HashMap::with_capacity` /
//! etc. with the claimed length as the hint. Before this hardening,
//! a single 5-byte msgpack header could demand a 4GB allocation,
//! killing the process before any handler guard ran.
//!
//! The semantic requirement is: a claim of `u32::MAX` length on a
//! byte container — which cannot possibly be legitimate, since the
//! body would need to be 4 GB — must be rejected by the deserialiser
//! itself, *before* the allocator is asked for that much memory.
//! These tests assert on the *error message*, not just `is_err()`:
//! without the cap, the error bubbles up from `read_exact` ("failed
//! to fill whole buffer") *after* the 4 GB allocation; with the cap,
//! the error comes from the explicit length check before any
//! allocation.
//!
//! For element containers (`Vec<T>`, `HashMap`, …) the same
//! reasoning applies to `Vec::with_capacity(len)` — but there the
//! allocation is an opaque hint and the only directly-testable
//! property is that a hostile length doesn't panic, hang, or error
//! *via* OOM. Discrimination of the cap-hint fix is manual
//! (temporarily remove the `.min` and rerun).

use std::collections::{HashMap, HashSet, VecDeque};
use tox_proto::MAX_MESSAGE_SIZE;

fn bytes_with_str_len(len: u32) -> Vec<u8> {
    // msgpack str 32 family: 0xdb, then u32 BE length.
    let mut buf = vec![0xdb];
    buf.extend_from_slice(&len.to_be_bytes());
    buf
}

fn bytes_with_bin_len(len: u32) -> Vec<u8> {
    // msgpack bin 32: 0xc6, then u32 BE length.
    let mut buf = vec![0xc6];
    buf.extend_from_slice(&len.to_be_bytes());
    buf
}

fn bytes_with_array_len(len: u32) -> Vec<u8> {
    // msgpack array 32: 0xdd, then u32 BE length.
    let mut buf = vec![0xdd];
    buf.extend_from_slice(&len.to_be_bytes());
    buf
}

fn bytes_with_map_len(len: u32) -> Vec<u8> {
    // msgpack map 32: 0xdf, then u32 BE length.
    let mut buf = vec![0xdf];
    buf.extend_from_slice(&len.to_be_bytes());
    buf
}

fn err_msg<T>(r: tox_proto::Result<T>) -> String {
    format!("{}", r.err().expect("must fail"))
}

/// `String` deserialiser must reject a length prefix that
/// exceeds `MAX_MESSAGE_SIZE` *before* allocating the buffer. The
/// error message must reference the cap so it's clear the reject
/// happened at the schema boundary, not via a late I/O short-read.
#[test]
fn string_rejects_oversized_length_pre_allocation() {
    let bytes = bytes_with_str_len(u32::MAX);
    let msg = err_msg(tox_proto::deserialize::<String>(&bytes));
    assert!(
        msg.contains("oversized") || msg.contains("exceeds") || msg.contains("MAX_MESSAGE_SIZE"),
        "String deserialiser must reject oversized len with a cap-error, \
         not a downstream I/O error; got: {}",
        msg,
    );
}

/// The reject must fire at `MAX_MESSAGE_SIZE + 1`, not at
/// some allocator-dependent threshold.
#[test]
fn string_reject_boundary_is_max_message_size() {
    let bytes = bytes_with_str_len(MAX_MESSAGE_SIZE as u32 + 1);
    let msg = err_msg(tox_proto::deserialize::<String>(&bytes));
    assert!(
        msg.contains("oversized") || msg.contains("exceeds") || msg.contains("MAX_MESSAGE_SIZE"),
        "String with len = MAX_MESSAGE_SIZE + 1 must be rejected by the cap; got: {}",
        msg,
    );
}

/// `Vec<u8>` fast path has the same shape — `read_exact(len)`
/// after a hostile `len` prefix would allocate `len` bytes up-front.
#[test]
fn vec_u8_rejects_oversized_length_pre_allocation() {
    let bytes = bytes_with_bin_len(u32::MAX);
    let msg = err_msg(tox_proto::deserialize::<Vec<u8>>(&bytes));
    assert!(
        msg.contains("oversized") || msg.contains("exceeds") || msg.contains("MAX_MESSAGE_SIZE"),
        "Vec<u8> must reject oversized len at the cap; got: {}",
        msg,
    );
}

/// Element containers (`Vec<T>`) must not panic, hang, or
/// emit an allocation-OOM when fed a hostile array length. This is
/// the weaker guarantee — the `with_capacity` *hint* is capped, but
/// the outer return path is still an error (the body is truncated).
#[test]
fn vec_t_does_not_panic_on_hostile_length() {
    let bytes = bytes_with_array_len(u32::MAX);
    let result = std::panic::catch_unwind(|| tox_proto::deserialize::<Vec<u32>>(&bytes));
    assert!(
        result.is_ok(),
        "Vec<u32> deserialiser panicked on hostile array length",
    );
    assert!(result.unwrap().is_err(), "truncated array must error");
}

/// `VecDeque<T>` — same shape.
#[test]
fn vecdeque_does_not_panic_on_hostile_length() {
    let bytes = bytes_with_array_len(u32::MAX);
    let result = std::panic::catch_unwind(|| tox_proto::deserialize::<VecDeque<u32>>(&bytes));
    assert!(result.is_ok(), "VecDeque panicked");
    assert!(result.unwrap().is_err(), "truncated VecDeque must error");
}

/// `HashMap<K, V>` preallocates an internal hash table
/// sized for the claimed entry count.
#[test]
fn hashmap_does_not_panic_on_hostile_length() {
    let bytes = bytes_with_map_len(u32::MAX);
    let result = std::panic::catch_unwind(|| tox_proto::deserialize::<HashMap<u32, u32>>(&bytes));
    assert!(result.is_ok(), "HashMap panicked");
    assert!(result.unwrap().is_err(), "truncated HashMap must error");
}

/// `HashSet<T>` — array-like length header, same defence.
#[test]
fn hashset_does_not_panic_on_hostile_length() {
    let bytes = bytes_with_array_len(u32::MAX);
    let result = std::panic::catch_unwind(|| tox_proto::deserialize::<HashSet<u32>>(&bytes));
    assert!(result.is_ok(), "HashSet panicked");
    assert!(result.unwrap().is_err(), "truncated HashSet must error");
}

/// The caps must not break legitimate happy-path round-trips.
#[test]
fn happy_path_still_works() {
    let v: Vec<u32> = vec![1, 2, 3, 4, 5];
    let bytes = tox_proto::serialize(&v).unwrap();
    let decoded: Vec<u32> = tox_proto::deserialize(&bytes).unwrap();
    assert_eq!(decoded, v);

    let s = "hello, world".to_string();
    let bytes = tox_proto::serialize(&s).unwrap();
    let decoded: String = tox_proto::deserialize(&bytes).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_bytes_are_not_read_as_other_one_byte_types() {
    // A `bin` of arbitrary bytes, which are no valid `bool`s.
    let wire = [0xc4, 0x02, 0x07, 0xff];
    assert!(tox_proto::deserialize::<Vec<bool>>(&wire).is_err());
    assert!(tox_proto::deserialize::<[bool; 2]>(&wire).is_err());
    assert_eq!(
        tox_proto::deserialize::<Vec<u8>>(&wire).unwrap(),
        vec![0x07, 0xff]
    );
    assert_eq!(
        tox_proto::serialize(&vec![true, false]).unwrap(),
        [0x92, 0xc3, 0xc2]
    );
}

#[test]
fn test_skipping_a_value_neither_recurses_nor_allocates_what_it_claims() {
    // Nested deeper than a stack could recurse.
    let mut nested = vec![0x91u8; 1_000_000];
    nested.push(0x00);
    tox_proto::skip_value(&mut nested.as_slice()).unwrap();
    assert_eq!(
        tox_proto::capture_value(&mut nested.as_slice()).unwrap(),
        nested
    );

    // A length no message holds fails where the data ends.
    let mut overlong = bytes_with_bin_len(u32::MAX);
    overlong.extend([1, 2, 3]);
    assert!(tox_proto::skip_value(&mut overlong.as_slice()).is_err());
    assert!(tox_proto::capture_value(&mut overlong.as_slice()).is_err());
}

/// Reads `bytes`, keeping the largest buffer it was asked to fill.
struct Watched<'a> {
    bytes: &'a [u8],
    largest: usize,
}

impl std::io::Read for Watched<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.largest = self.largest.max(buf.len());
        self.bytes.read(buf)
    }
}

#[test]
fn claimed_lengths_get_room_only_for_bytes_there_are() {
    let claim = MAX_MESSAGE_SIZE as u32;
    for header in [bytes_with_bin_len(claim), bytes_with_str_len(claim)] {
        let mut reader = Watched {
            bytes: &header,
            largest: 0,
        };
        let read = if header[0] == 0xc6 {
            <Vec<u8> as tox_proto::ToxDeserialize>::deserialize(&mut reader).map(|_| ())
        } else {
            <String as tox_proto::ToxDeserialize>::deserialize(&mut reader).map(|_| ())
        };
        assert!(read.is_err());
        assert!(reader.largest < claim as usize, "{}", reader.largest);
    }
}
