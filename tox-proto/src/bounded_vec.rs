//! A length-capped `Vec` whose `ToxDeserialize` impl rejects oversize
//! inputs.
//!
//! Background: `tox-proto` ships `ToxDeserialize` for `Vec<T>` and
//! `SmallVec<T, N>`. Both read a length prefix from the wire and then
//! push `len` items, with `N` (when present) interpreted only as the
//! `SmallVec` *inline-buffer hint* — not as a cap. A peer authenticated
//! at the friend layer can therefore craft a packet whose array fields
//! deserialise to arbitrary length up to whatever fits in
//! `MAX_DATAGRAM_SIZE`. For wire types that document a maximum count
//! (e.g. `MAX_SACK_RANGES = 8`) this turns the cap into a writer-side
//! discipline rather than a structural property of the type, and lets
//! a misbehaving authorised peer drive O(len) work on the receiver per
//! packet.
//!
//! `BoundedVec<T, const N: usize>` is the structural answer:
//!   * Construction past `N` entries is impossible — `try_push` returns
//!     `Err(BoundedVecError::CapacityExceeded)` and there is no other
//!     way to grow the buffer.
//!   * `ToxDeserialize::deserialize` reads the wire length, checks
//!     `len <= N`, and returns `Err(Error::Deserialize(...))` on
//!     violation. The packet is rejected before any per-element work.
//!   * `ToxSerialize::serialize` matches the existing `Vec`/`SmallVec`
//!     wire format byte-for-byte, so introducing `BoundedVec` on a
//!     field is wire-compatible with peers that emit no more than `N`
//!     entries (which is the protocol contract).

use crate::{Error, Result, ToxContext, ToxDeserialize, ToxSerialize, ToxSize};
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;

/// A `Vec<T>` whose length is statically capped at `N`.
///
/// All construction paths enforce `len <= N`. The deserialiser
/// rejects over-cap input at parse time.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BoundedVec<T, const N: usize> {
    inner: Vec<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedVecError {
    CapacityExceeded { cap: usize, attempted: usize },
}

impl fmt::Display for BoundedVecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundedVecError::CapacityExceeded { cap, attempted } => write!(
                f,
                "BoundedVec capacity exceeded: cap={cap} attempted={attempted}"
            ),
        }
    }
}

impl std::error::Error for BoundedVecError {}

impl<T, const N: usize> BoundedVec<T, N> {
    pub const fn cap() -> usize {
        N
    }

    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Construct from an iterator, returning `Err` if the iterator
    /// yields more than `N` items.
    pub fn try_from_iter<I: IntoIterator<Item = T>>(
        iter: I,
    ) -> std::result::Result<Self, BoundedVecError> {
        let mut out = Self::new();
        for item in iter {
            out.try_push(item)?;
        }
        Ok(out)
    }

    /// Push one item; errors if at capacity.
    pub fn try_push(&mut self, value: T) -> std::result::Result<(), BoundedVecError> {
        if self.inner.len() >= N {
            return Err(BoundedVecError::CapacityExceeded {
                cap: N,
                attempted: self.inner.len() + 1,
            });
        }
        self.inner.push(value);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.inner.iter()
    }

    /// Mutable iterator. Always safe — length doesn't change.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.inner.iter_mut()
    }

    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Remove and return the last element, if any.  Always safe — the
    /// length only decreases.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Remove and return the element at `index`, shifting subsequent
    /// elements left by one.  Panics if `index >= len()` (matching
    /// `Vec::remove`).  Always safe w.r.t. the cap — the length only
    /// decreases.
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }

    /// Extend by an iterator, returning `Err` at the first item that
    /// would exceed `N`. Items consumed before the failure remain in
    /// the vector — the caller is expected to either treat the cap
    /// breach as a hard error and discard the partial state, or
    /// pre-validate the iterator length.
    ///
    /// Note: deliberately not `impl Extend` because `Extend::extend`
    /// is infallible — panicking inside it would be a footgun. Use
    /// this explicitly named method when you need cap-aware
    /// extension.
    pub fn try_extend<I: IntoIterator<Item = T>>(
        &mut self,
        iter: I,
    ) -> std::result::Result<(), BoundedVecError> {
        for item in iter {
            self.try_push(item)?;
        }
        Ok(())
    }

    /// Escape hatch for callers that already enforce the cap. Panics
    /// if `inner.len() > N`. Used by deserialise after the wire-length
    /// check.
    fn from_vec_checked(inner: Vec<T>) -> Self {
        debug_assert!(
            inner.len() <= N,
            "BoundedVec::from_vec_checked called with oversize Vec"
        );
        Self { inner }
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for BoundedVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedVec")
            .field("cap", &N)
            .field("items", &self.inner)
            .finish()
    }
}

impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a BoundedVec<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

// ------------- ToxProto wire impl -------------

impl<T: ToxSize, const N: usize> ToxSize for BoundedVec<T, N> {}

impl<T: ToxSerialize, const N: usize> ToxSerialize for BoundedVec<T, N> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, self.inner.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in &self.inner {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
}

impl<T: ToxDeserialize, const N: usize> ToxDeserialize for BoundedVec<T, N> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        if len > N {
            return Err(Error::Deserialize(format!(
                "BoundedVec wire length {len} exceeds cap {N}"
            )));
        }
        let mut inner = Vec::with_capacity(len);
        for _ in 0..len {
            inner.push(T::deserialize(reader, ctx)?);
        }
        Ok(Self::from_vec_checked(inner))
    }
}

/// Convenience macro for constructing a `BoundedVec` from a literal
/// list. The cap `N` is inferred from the assignment context. Panics
/// at runtime if the literal exceeds `N` — typically only used in
/// test/bench fixtures where the cap is statically known.
///
/// ```ignore
/// let v: BoundedVec<u32, 4> = bounded_vec![1, 2, 3];
/// ```
#[macro_export]
macro_rules! bounded_vec {
    () => {
        $crate::BoundedVec::new()
    };
    ($($e:expr),+ $(,)?) => {
        $crate::BoundedVec::try_from_iter([$($e),+])
            .expect("bounded_vec! literal exceeded BoundedVec capacity")
    };
}
