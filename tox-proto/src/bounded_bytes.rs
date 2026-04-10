//! Length-capped byte container.  The byte-array companion to
//! `BoundedVec<T, N>`.
//!
//! `Vec<u8>` already has a 1 MiB ceiling at deserialise time
//! (see `lib.rs::ToxDeserialize for Vec<u8>`, which gates on
//! `MAX_MESSAGE_SIZE`).  That ceiling is fine as a hard upper
//! bound, but it admits per-field amplification: a field whose
//! legitimate size is hundreds of bytes (e.g. an AEAD-wrapped
//! 32-byte key, or a Merkle proof for a 4 GB blob: ~540 B) gets
//! allocated up to 1 MiB on the wire.  An authenticated peer can
//! drive that floor on every received packet of that variant, with
//! per-packet amplification up to ~1850×.
//!
//! `BoundedBytes<N>` makes the per-field cap a structural property
//! of the type:
//!   * Construction past `N` is impossible — `try_from_slice` and
//!     `try_from_vec` return `Err` past the limit; there is no
//!     other way to grow the buffer.
//!   * `ToxDeserialize::deserialize` reads the wire length, checks
//!     `len <= N`, and returns `Err(Error::Deserialize(...))` on
//!     violation.  No payload bytes are consumed.
//!   * `ToxSerialize::serialize` matches the existing `Vec<u8>`
//!     wire format byte-for-byte (msgpack `bin`), so introducing
//!     `BoundedBytes<N>` on a field is wire-compatible with peers
//!     that emit no more than `N` bytes (the protocol contract).

use crate::{Error, Result, ToxContext, ToxDeserialize, ToxSerialize, ToxSize};
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BoundedBytes<const N: usize> {
    inner: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedBytesError {
    CapacityExceeded { cap: usize, attempted: usize },
}

impl fmt::Display for BoundedBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundedBytesError::CapacityExceeded { cap, attempted } => write!(
                f,
                "BoundedBytes capacity exceeded: cap={cap} attempted={attempted}"
            ),
        }
    }
}

impl std::error::Error for BoundedBytesError {}

impl<const N: usize> BoundedBytes<N> {
    pub const fn cap() -> usize {
        N
    }

    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Construct from an owned `Vec<u8>`, returning `Err` if it
    /// exceeds `N`.
    pub fn try_from_vec(inner: Vec<u8>) -> std::result::Result<Self, BoundedBytesError> {
        if inner.len() > N {
            return Err(BoundedBytesError::CapacityExceeded {
                cap: N,
                attempted: inner.len(),
            });
        }
        Ok(Self { inner })
    }

    /// Construct by copying from a slice, returning `Err` if the
    /// slice exceeds `N`.
    pub fn try_from_slice(slice: &[u8]) -> std::result::Result<Self, BoundedBytesError> {
        if slice.len() > N {
            return Err(BoundedBytesError::CapacityExceeded {
                cap: N,
                attempted: slice.len(),
            });
        }
        Ok(Self {
            inner: slice.to_vec(),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Mutable slice access. Always safe — length unchanged.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Clear all bytes. Always safe — length only decreases.
    pub fn clear(&mut self) {
        self.inner.clear()
    }

    /// Internal constructor — caller has already validated
    /// `inner.len() <= N`. Used by deserialise after the wire-length
    /// check.
    fn from_vec_checked(inner: Vec<u8>) -> Self {
        debug_assert!(inner.len() <= N, "BoundedBytes::from_vec_checked called with oversize Vec");
        Self { inner }
    }
}

impl<const N: usize> Default for BoundedBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for BoundedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBytes")
            .field("cap", &N)
            .field("len", &self.inner.len())
            .finish()
    }
}

impl<const N: usize> Deref for BoundedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl<const N: usize> AsRef<[u8]> for BoundedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<const N: usize> std::ops::Index<usize> for BoundedBytes<N> {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        &self.inner[index]
    }
}

impl<const N: usize> std::ops::IndexMut<usize> for BoundedBytes<N> {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.inner[index]
    }
}

// ------------- ToxProto wire impl -------------
//
// Wire format must match `Vec<u8>` byte-for-byte (msgpack `bin`) so
// migrating a field from `Vec<u8>` to `BoundedBytes<N>` is on-wire
// transparent for any peer that respects the per-field cap.

impl<const N: usize> ToxSize for BoundedBytes<N> {}

impl<const N: usize> ToxSerialize for BoundedBytes<N> {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_bin(writer, &self.inner)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
}

impl<const N: usize> ToxDeserialize for BoundedBytes<N> {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_bin_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        if len > N {
            return Err(Error::Deserialize(format!(
                "BoundedBytes wire length {len} exceeds cap {N}"
            )));
        }
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Deserialize(e.to_string()))?;
        Ok(Self::from_vec_checked(buf))
    }
}
