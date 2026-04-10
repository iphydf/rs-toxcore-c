//! Taint wrapper for peer-supplied wire values.
//!
//! Fields deserialised from the network cannot be used directly in
//! arithmetic or comparisons that trust them: a malicious or buggy
//! peer can set them to any value the type admits. The Rust type
//! system offers no automatic distinction between "verified" and
//! "peer-supplied" values of the same underlying type; developers
//! have to remember to clamp or reject. That memory has failed
//! before (see the ACK poisoning and BlobProgress range-explosion
//! bugs in the 2026-04-22 audit).
//!
//! `Untrusted<T>` makes the boundary explicit. Its only constructor
//! (aside from the test-visible `new`) is deserialisation. It
//! exposes no `Deref`, `AsRef`, or arithmetic; to use the inner
//! value, callers must clamp it against a self-known bound or
//! explicitly `expose_unchecked`. Arithmetic on a peer-supplied
//! field now requires a deliberate unwrap that an auditor can see.
//!
//! Wire format is transparent: `Untrusted<T>` serialises and
//! deserialises bit-identically to `T`. Migrating a field from `T`
//! to `Untrusted<T>` is a source-level refactor only.

use crate::{Result, ToxContext, ToxDeserialize, ToxSerialize, ToxSize};
use std::io::{Read, Write};

/// Wire value supplied by an untrusted peer. Access the inner `T` by
/// clamping it against a self-known bound (`clamp_max`, `clamp_to`),
/// by checking a predicate (`checked_le`, `checked_lt`, `checked_in`),
/// or — when the caller is taking explicit responsibility for the
/// trust decision — by calling `expose_unchecked`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Construct directly. Available for tests and for callers who
    /// are explicitly marking a value as peer-supplied (e.g. a test
    /// harness that feeds wire packets into a handler).
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Named escape hatch returning a reference to the inner value
    /// **without trust validation**. Use when:
    ///   - the caller is about to feed the value into structural
    ///     validation that the `clamp_*` / `checked_*` helpers
    ///     cannot express (e.g. iterating a `SmallVec`, comparing
    ///     `base_seq` modulo 2³² for in-window-ness),
    ///   - or when the value is needed for `Debug` formatters, log
    ///     lines, and metrics — paths that don't make a trust
    ///     decision.
    ///
    /// Auditors grep for this name to find every site that bypasses
    /// the type-level clamp/check helpers; treat each call site as
    /// requiring a justifying validation step elsewhere in the same
    /// function, or a clear comment for the diagnostic case.
    pub fn expose_unchecked(&self) -> &T {
        &self.0
    }
}

impl<T: Ord + Copy> Untrusted<T> {
    /// Clamp the inner value to the inclusive upper bound `max` and
    /// return the clamped result. Used when the peer-supplied value
    /// has no lower bound of interest (e.g. `recv_bytes <= bytes_sent`).
    pub fn clamp_max(self, max: T) -> T {
        if self.0 <= max { self.0 } else { max }
    }

    /// Clamp the inner value to `[lo, hi]` inclusive. `lo` must be
    /// `<= hi`; this is `debug_assert`ed, not guarded at runtime.
    pub fn clamp_to(self, lo: T, hi: T) -> T {
        debug_assert!(lo <= hi, "clamp_to: lo must be <= hi");
        if self.0 < lo {
            lo
        } else if self.0 > hi {
            hi
        } else {
            self.0
        }
    }

    /// Returns `Some(inner)` when `inner <= max`, `None` otherwise.
    /// Prefer this to `clamp_max` when an out-of-bound value should
    /// reject the whole message, not silently clip.
    pub fn checked_le(self, max: T) -> Option<T> {
        if self.0 <= max { Some(self.0) } else { None }
    }

    /// Returns `Some(inner)` when `inner < max`, `None` otherwise.
    pub fn checked_lt(self, max: T) -> Option<T> {
        if self.0 < max { Some(self.0) } else { None }
    }

    /// Returns `Some(inner)` when `lo <= inner < hi`, `None` otherwise.
    /// Half-open so `checked_in(0, num_chunks)` reads naturally.
    pub fn checked_in(self, lo: T, hi: T) -> Option<T> {
        if self.0 >= lo && self.0 < hi {
            Some(self.0)
        } else {
            None
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Untrusted({:?})", self.0)
    }
}

impl<T: ToxSize> ToxSize for Untrusted<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;

    fn flat_len(&self) -> usize {
        self.0.flat_len()
    }
}

impl<T: ToxSerialize> ToxSerialize for Untrusted<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.0.serialize(writer, ctx)
    }

    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.0.serialize_flat(writer, ctx)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Untrusted<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Self(T::deserialize(reader, ctx)?))
    }

    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Self(T::deserialize_flat(reader, ctx)?))
    }
}

/// Peer-supplied identity claim. Where `Untrusted<T>` tags a numeric
/// field that must be clamped against a self-known bound,
/// `Claimed<T>` tags an identity field (a `PhysicalDevicePk`,
/// `LogicalIdentityPk`, `NodeHash`, …) that must be cross-checked
/// against a trusted reference before it can drive any authorisation
/// decision.
///
/// Typical usage: a wire packet carries both a transport-authenticated
/// sender PK (bound to the friend-connection session key, trusted) and
/// a payload-supplied identity field (peer-claimed, untrusted). Past
/// bugs have mixed them up — the handler authorised based on the
/// claim, then acted on the transport sender, or vice versa.
///
/// The only way to extract the inner value with trust is
/// `verify(&trusted)`, which returns `Some(v)` iff the claim matches
/// the trusted reference. There is no `Deref`, no `AsRef`, no
/// arithmetic — every callsite is greppable.
///
/// Wire format is transparent: `Claimed<T>` serialises identically
/// to `T`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Claimed<T>(T);

impl<T> Claimed<T> {
    /// Construct directly. Test fixtures and ProtocolMessage
    /// construction sites use this to tag payload fields.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Named escape hatch returning a reference to the claimed
    /// value **without verification**. See `Untrusted::expose_unchecked`
    /// for the full contract — same name and semantics.
    pub fn expose_unchecked(&self) -> &T {
        &self.0
    }
}

impl<T: PartialEq + Copy> Claimed<T> {
    /// Returns the inner value only if it matches the trusted
    /// reference. The sole gate for turning a claim into a
    /// verified identity.
    pub fn verify(&self, trusted: &T) -> Option<T> {
        if self.0 == *trusted { Some(self.0) } else { None }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Claimed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Claimed({:?})", self.0)
    }
}

impl<T: ToxSize> ToxSize for Claimed<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;

    fn flat_len(&self) -> usize {
        self.0.flat_len()
    }
}

impl<T: ToxSerialize> ToxSerialize for Claimed<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.0.serialize(writer, ctx)
    }

    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.0.serialize_flat(writer, ctx)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Claimed<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Self(T::deserialize(reader, ctx)?))
    }

    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Self(T::deserialize_flat(reader, ctx)?))
    }
}
