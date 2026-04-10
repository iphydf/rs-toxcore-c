//! Tests for `tox_proto::Untrusted<T>`.
//!
//! Two invariants matter:
//!   1. Wire format is transparent — `Untrusted<T>` and `T`
//!      round-trip to identical bytes. Migrating a struct field
//!      from `T` to `Untrusted<T>` must not change the on-wire
//!      format for any peer.
//!   2. The clamping and checked-access API preserves the
//!      peer-supplied value when it is in range and rejects or
//!      clamps when it is out of range.

use tox_proto::{Claimed, ToxProto, Untrusted, deserialize, serialize};

#[test]
fn wire_format_is_transparent_for_primitives() {
    // The whole point of the wrapper is that downstream peers are
    // unaware of the migration. Serialise both as a plain value and
    // as an `Untrusted` and demand byte-for-byte equality.
    let plain = 0x1234_5678u32;
    let tainted = Untrusted::new(plain);
    assert_eq!(
        serialize(&plain).unwrap(),
        serialize(&tainted).unwrap(),
        "serialisation bytes must match plain u32",
    );

    let bytes = serialize(&tainted).unwrap();
    let round: Untrusted<u32> = deserialize(&bytes).unwrap();
    assert_eq!(round, tainted);

    // And the cross-migration case: bytes produced from a plain u32
    // must still deserialise into `Untrusted<u32>` at the receiver.
    let plain_bytes = serialize(&plain).unwrap();
    let cross: Untrusted<u32> = deserialize(&plain_bytes).unwrap();
    assert_eq!(*cross.expose_unchecked(), plain);
}

#[test]
fn wire_format_survives_in_derived_struct() {
    // Deriving `ToxProto` on a struct that mixes plain and tainted
    // fields must produce the same bytes as the all-plain version.
    #[derive(ToxProto, Debug, PartialEq, Eq)]
    struct AckPlain {
        base_seq: u32,
        recv_bytes: u64,
    }

    #[derive(ToxProto, Debug, PartialEq, Eq)]
    struct AckTainted {
        base_seq: Untrusted<u32>,
        recv_bytes: Untrusted<u64>,
    }

    let plain = AckPlain {
        base_seq: 42,
        recv_bytes: 1_000_000,
    };
    let tainted = AckTainted {
        base_seq: Untrusted::new(42),
        recv_bytes: Untrusted::new(1_000_000),
    };

    assert_eq!(
        serialize(&plain).unwrap(),
        serialize(&tainted).unwrap(),
        "mixed-field struct must round-trip identically",
    );

    let bytes = serialize(&plain).unwrap();
    let round: AckTainted = deserialize(&bytes).unwrap();
    assert_eq!(round, tainted);
}

#[test]
fn clamp_max_returns_min_of_value_and_bound() {
    // In-bound values pass through unchanged.
    let small: Untrusted<u64> = Untrusted::new(10);
    assert_eq!(small.clamp_max(100), 10);

    // Out-of-bound values are silently clipped to the bound. This
    // matches the `recv_bytes` clamping used in the ACK handler:
    // the peer may lie about receiving more than we sent, but we
    // never believe more than we sent.
    let huge: Untrusted<u64> = Untrusted::new(u64::MAX);
    assert_eq!(huge.clamp_max(100), 100);

    // Boundary: exactly the bound is preserved.
    let exact: Untrusted<u64> = Untrusted::new(100);
    assert_eq!(exact.clamp_max(100), 100);
}

#[test]
fn clamp_to_clips_both_ends() {
    assert_eq!(Untrusted::new(5u32).clamp_to(10, 100), 10);
    assert_eq!(Untrusted::new(200u32).clamp_to(10, 100), 100);
    assert_eq!(Untrusted::new(50u32).clamp_to(10, 100), 50);
}

#[test]
fn checked_le_rejects_above_bound() {
    assert_eq!(Untrusted::new(10u32).checked_le(100), Some(10));
    assert_eq!(Untrusted::new(100u32).checked_le(100), Some(100));
    // Over-bound value returns None — caller should drop the message.
    assert_eq!(Untrusted::new(101u32).checked_le(100), None);
}

#[test]
fn checked_lt_is_strict() {
    assert_eq!(Untrusted::new(99u32).checked_lt(100), Some(99));
    assert_eq!(Untrusted::new(100u32).checked_lt(100), None);
}

#[test]
fn checked_in_is_half_open() {
    // [0, num_chunks) reads naturally for chunk-index bounds.
    let num_chunks = 4u64;
    assert_eq!(Untrusted::new(0u64).checked_in(0, num_chunks), Some(0));
    assert_eq!(Untrusted::new(3u64).checked_in(0, num_chunks), Some(3));
    // At `num_chunks` itself, out of range — matches
    // `chunk_idx >= num_chunks` checks in the CAS layer.
    assert_eq!(Untrusted::new(4u64).checked_in(0, num_chunks), None);
    assert_eq!(Untrusted::new(u64::MAX).checked_in(0, num_chunks), None);
}

#[test]
fn debug_formatter_marks_the_taint() {
    // Debug output must make it obvious that a value is untrusted,
    // so audit tooling and log readers can spot unclamped access
    // that reached a formatter.
    let tainted: Untrusted<u32> = Untrusted::new(42);
    assert_eq!(format!("{:?}", tainted), "Untrusted(42)");
}

#[test]
fn expose_unchecked_returns_inner_reference() {
    let tainted: Untrusted<u64> = Untrusted::new(7);
    assert_eq!(*tainted.expose_unchecked(), 7);
}

// ── Claimed<T> ─────────────────────────────────────────────────────

#[test]
fn claimed_wire_format_is_transparent() {
    // A PhysicalDevicePk's wire form is a 32-byte bin, and wrapping
    // it in Claimed<T> must produce byte-identical output.
    let plain = 0xDEAD_BEEFu32;
    let claimed = Claimed::new(plain);
    assert_eq!(
        serialize(&plain).unwrap(),
        serialize(&claimed).unwrap(),
        "Claimed<T> must serialise identically to T",
    );

    // Bytes produced from a plain T must deserialise into Claimed<T>.
    let plain_bytes = serialize(&plain).unwrap();
    let cross: Claimed<u32> = deserialize(&plain_bytes).unwrap();
    assert_eq!(*cross.expose_unchecked(), plain);
}

#[test]
fn claimed_wire_format_survives_in_derived_struct() {
    #[derive(ToxProto, Debug, PartialEq, Eq)]
    struct Plain {
        recipient_pk: [u8; 32],
    }

    #[derive(ToxProto, Debug, PartialEq, Eq)]
    struct Tagged {
        recipient_pk: Claimed<[u8; 32]>,
    }

    let plain = Plain {
        recipient_pk: [0xAAu8; 32],
    };
    let tagged = Tagged {
        recipient_pk: Claimed::new([0xAAu8; 32]),
    };

    assert_eq!(
        serialize(&plain).unwrap(),
        serialize(&tagged).unwrap(),
        "derive-integration must be wire-compatible",
    );

    let bytes = serialize(&plain).unwrap();
    let round: Tagged = deserialize(&bytes).unwrap();
    assert_eq!(round, tagged);
}

#[test]
fn verify_returns_inner_when_claim_matches_trusted() {
    let trusted = 0xBEEF_CAFEu32;
    let claim: Claimed<u32> = Claimed::new(trusted);
    assert_eq!(claim.verify(&trusted), Some(trusted));
}

#[test]
fn verify_returns_none_when_claim_differs_from_trusted() {
    let trusted = 0xBEEF_CAFEu32;
    let lying_claim: Claimed<u32> = Claimed::new(0xDEAD_DEADu32);
    assert_eq!(lying_claim.verify(&trusted), None);
}

#[test]
fn verify_catches_partial_match_of_byte_arrays() {
    // A typical use: device PKs. 32-byte arrays where even a single
    // bit flip must fail verification.
    let trusted = [0xABu8; 32];
    let mut lying = trusted;
    lying[17] ^= 0x01;
    let claim: Claimed<[u8; 32]> = Claimed::new(lying);
    assert_eq!(claim.verify(&trusted), None);
}

#[test]
fn claimed_debug_formatter_marks_the_taint() {
    // Readers of log output must see the tag so they know the
    // value is peer-supplied and wasn't automatically verified.
    let claim: Claimed<u32> = Claimed::new(42);
    assert_eq!(format!("{:?}", claim), "Claimed(42)");
}
