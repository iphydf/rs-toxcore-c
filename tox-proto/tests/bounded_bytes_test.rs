//! Tests for `BoundedBytes<N>`'s wire-deserialise contract.
//!
//! `BoundedBytes<N>` is the byte-array companion to `BoundedVec<T, N>`:
//! same structural-cap-at-deserialise pattern, but the wire format
//! is msgpack `bin` (length prefix + raw bytes), matching `Vec<u8>`'s
//! existing format so on-wire compatibility with peers that respect
//! the cap is preserved.
//!
//! The `Vec<u8>` deserialiser in `tox-proto` already enforces a 1 MiB
//! ceiling via `MAX_MESSAGE_SIZE`, so the security gain from
//! `BoundedBytes` is *tighter* per-field caps. The most concrete
//! example: `cas::BlobData.proof` is empirically ≤ 540 B (a Merkle
//! proof for the 4 GB-blob worst case at chunk-tree depth 16 × 32 B
//! per sibling), but the `Vec<u8>` floor admits 1 MiB — an ~1850×
//! amplification per packet that any authenticated peer can drive.
//!
//! These tests pin the type contract:
//!   - construction past `N` errors at `try_from_*`
//!   - wire deserialise rejects `len > N` before allocating
//!   - serialise format matches `Vec<u8>` byte-for-byte
//!   - round-trip preserves the inner bytes
//!
//! This test file MUST fail to compile until `BoundedBytes<N>` exists
//! in `tox-proto`.  That is the TDD-red signal.

use std::io::Cursor;
use std::sync::Arc;
use tox_proto::{BoundedBytes, ToxContext, ToxDeserialize, ToxSerialize};

fn ctx() -> ToxContext {
    ToxContext::new(Arc::new(tox_proto::SystemTimeProvider))
}

fn rmp_bin_header(len: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_bin_len(&mut buf, len).expect("write_bin_len");
    buf
}

#[test]
fn deserialize_accepts_at_cap() {
    const N: usize = 64;
    let mut buf = rmp_bin_header(N as u32);
    buf.extend(std::iter::repeat_n(0xABu8, N));

    let mut reader = Cursor::new(buf);
    let bb: BoundedBytes<N> = BoundedBytes::deserialize(&mut reader, &ctx()).expect("at-cap");
    assert_eq!(bb.as_slice().len(), N);
}

#[test]
fn deserialize_accepts_below_cap() {
    const N: usize = 64;
    let mut buf = rmp_bin_header(7);
    buf.extend([1u8, 2, 3, 4, 5, 6, 7]);

    let mut reader = Cursor::new(buf);
    let bb: BoundedBytes<N> = BoundedBytes::deserialize(&mut reader, &ctx()).expect("below cap");
    assert_eq!(bb.as_slice(), &[1u8, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn deserialize_rejects_over_cap_no_allocation() {
    // The actual security property: a wire claim of len > N must be
    // rejected before any payload bytes are consumed. Supply only the
    // bin-32 header — if the deserialiser tried to read payload, it
    // would error with an EOF-class error on `read_exact`. Pre-fix on
    // `Vec<u8>`, this would be admitted up to `MAX_MESSAGE_SIZE = 1 MiB`.
    const N: usize = 64;
    let buf = rmp_bin_header(4096); // way over cap

    let mut reader = Cursor::new(buf);
    let result: tox_proto::Result<BoundedBytes<N>> =
        BoundedBytes::deserialize(&mut reader, &ctx());
    let err = result.expect_err("len 4096 > cap 64 must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("BoundedBytes wire length 4096") && msg.contains("cap 64"),
        "expected cap-violation message, got: {msg}"
    );
}

#[test]
fn deserialize_rejects_just_over_cap() {
    const N: usize = 64;
    let buf = rmp_bin_header(N as u32 + 1);

    let mut reader = Cursor::new(buf);
    let result: tox_proto::Result<BoundedBytes<N>> =
        BoundedBytes::deserialize(&mut reader, &ctx());
    let err = result.expect_err("len N+1 must fail");
    assert!(
        format!("{err}").contains("BoundedBytes wire length"),
        "boundary case should produce a cap-violation error, got: {err}"
    );
}

#[test]
fn round_trip_within_cap() {
    const N: usize = 256;
    let original: BoundedBytes<N> =
        BoundedBytes::try_from_slice(&[0x42u8; 100]).expect("under cap");

    let mut buf = Vec::new();
    original.serialize(&mut buf, &ctx()).expect("serialize");

    let mut reader = Cursor::new(buf);
    let restored: BoundedBytes<N> =
        BoundedBytes::deserialize(&mut reader, &ctx()).expect("ok");
    assert_eq!(restored.as_slice(), original.as_slice());
}

#[test]
fn try_from_slice_rejects_oversize() {
    let result: std::result::Result<BoundedBytes<8>, _> =
        BoundedBytes::try_from_slice(&[0u8; 16]);
    assert!(result.is_err(), "try_from_slice past cap must fail");
}

#[test]
fn try_from_vec_rejects_oversize() {
    let result: std::result::Result<BoundedBytes<8>, _> =
        BoundedBytes::try_from_vec(vec![0u8; 16]);
    assert!(result.is_err(), "try_from_vec past cap must fail");
}

#[test]
fn wire_format_matches_vec_u8() {
    // Critical for forward/backward compatibility: a peer build that
    // hasn't migrated a field from Vec<u8> to BoundedBytes<N> must
    // still interop with one that has. Same wire bytes → check that
    // `Vec<u8>` and `BoundedBytes<N>` serialise to identical bytes
    // for the same input.
    const N: usize = 256;
    let payload = vec![0xCDu8; 100];

    let mut buf_vec = Vec::new();
    payload.serialize(&mut buf_vec, &ctx()).expect("vec ok");

    let bb: BoundedBytes<N> =
        BoundedBytes::try_from_slice(&payload).expect("under cap");
    let mut buf_bb = Vec::new();
    bb.serialize(&mut buf_bb, &ctx()).expect("bb ok");

    assert_eq!(
        buf_vec, buf_bb,
        "BoundedBytes wire format must be byte-identical to Vec<u8>"
    );
}
