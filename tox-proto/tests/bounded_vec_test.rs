//! Tests for `BoundedVec<T, N>`'s wire-deserialise contract.
//!
//! The security property under test: when a peer sends a wire array
//! whose length exceeds `N`, the deserialiser rejects the payload
//! before allocating or iterating. This is the type-system fix for
//! the privilege-amplification DoS class where an authenticated peer
//! crafts ACK packets with thousands of SACK entries (each
//! individually well-formed) to drive O(len) work on the receiver per
//! packet. Historically the cap on these wire fields was a
//! writer-side discipline (the type was `SmallVec<T, N>`, whose `N`
//! is only an inline-buffer hint). The `ToxProto` impls for
//! `SmallVec<T, N>` have since been removed (see
//! `tox-proto/src/lib.rs`), so the only structurally-capped wire
//! collection type is `BoundedVec<T, N>`.

use std::io::Cursor;
use std::sync::Arc;
use tox_proto::{BoundedVec, ToxContext, ToxDeserialize, ToxSerialize};

fn ctx() -> ToxContext {
    ToxContext::new(Arc::new(tox_proto::SystemTimeProvider))
}

fn rmp_array_header(len: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_array_len(&mut buf, len).expect("write_array_len");
    buf
}

#[test]
fn deserialize_accepts_at_cap() {
    const N: usize = 8;
    let mut buf = rmp_array_header(N as u32);
    for i in 0..N as u32 {
        rmp::encode::write_uint(&mut buf, i as u64).expect("encode");
    }

    let mut reader = Cursor::new(buf);
    let result: tox_proto::Result<BoundedVec<u32, N>> =
        BoundedVec::deserialize(&mut reader, &ctx());
    let bv = result.expect("len == N must deserialise");
    assert_eq!(bv.len(), N);
    assert_eq!(bv.iter().copied().collect::<Vec<_>>(), (0..N as u32).collect::<Vec<_>>());
}

#[test]
fn deserialize_accepts_below_cap() {
    const N: usize = 8;
    let mut buf = rmp_array_header(3);
    for i in 0..3u32 {
        rmp::encode::write_uint(&mut buf, i as u64).expect("encode");
    }

    let mut reader = Cursor::new(buf);
    let bv: BoundedVec<u32, N> = BoundedVec::deserialize(&mut reader, &ctx()).expect("ok");
    assert_eq!(bv.len(), 3);
}

#[test]
fn deserialize_rejects_over_cap_no_allocation() {
    // The actual security property: a wire claim of len > N must be
    // rejected before any payload bytes are consumed. We supply ONLY
    // the array header and zero payload — if the deserialiser tried
    // to read items, it would error with an EOF-class error on
    // `read_exact`. Pre-fix path on `SmallVec<T, N>` would have
    // allocated `Vec::with_capacity(bounded_capacity(len))` first
    // (cap-clamped, but still observable) and then errored on the
    // first item read. Post-fix on `BoundedVec`, we expect the
    // explicit cap-violation error message before any allocation.
    const N: usize = 8;
    let buf = rmp_array_header(400); // way over cap

    let mut reader = Cursor::new(buf);
    let result: tox_proto::Result<BoundedVec<u32, N>> =
        BoundedVec::deserialize(&mut reader, &ctx());
    let err = result.expect_err("len 400 > cap 8 must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("BoundedVec wire length 400") && msg.contains("cap 8"),
        "expected cap-violation message, got: {msg}"
    );
}

#[test]
fn deserialize_rejects_just_over_cap() {
    // Boundary: len == N+1. Make sure the test isn't lulled into
    // success only when len is wildly large.
    const N: usize = 8;
    let buf = rmp_array_header(N as u32 + 1);

    let mut reader = Cursor::new(buf);
    let result: tox_proto::Result<BoundedVec<u32, N>> =
        BoundedVec::deserialize(&mut reader, &ctx());
    let err = result.expect_err("len N+1 must fail");
    assert!(
        format!("{err}").contains("BoundedVec wire length"),
        "boundary case should produce a cap-violation error, got: {err}"
    );
}

#[test]
fn round_trip_within_cap() {
    const N: usize = 8;
    let mut original: BoundedVec<u32, N> = BoundedVec::new();
    for i in 0..6u32 {
        original.try_push(i).unwrap();
    }

    let mut buf = Vec::new();
    original.serialize(&mut buf, &ctx()).expect("serialize");

    let mut reader = Cursor::new(buf);
    let restored: BoundedVec<u32, N> = BoundedVec::deserialize(&mut reader, &ctx()).expect("ok");
    assert_eq!(restored.len(), original.len());
    assert_eq!(restored.as_slice(), original.as_slice());
}

#[test]
fn try_push_rejects_at_cap() {
    let mut v: BoundedVec<u32, 3> = BoundedVec::new();
    v.try_push(1).unwrap();
    v.try_push(2).unwrap();
    v.try_push(3).unwrap();
    let result = v.try_push(4);
    assert!(result.is_err(), "try_push at cap must fail");
}

#[test]
fn try_from_iter_rejects_oversize() {
    let result: std::result::Result<BoundedVec<u32, 3>, _> =
        BoundedVec::try_from_iter([1u32, 2, 3, 4]);
    assert!(result.is_err());
}
