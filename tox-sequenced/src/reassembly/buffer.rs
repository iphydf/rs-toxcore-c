use crate::bitset::BitSet;
use crate::error::SequencedError;
use crate::protocol::{BITSET_WORDS, FragmentCount, FragmentIndex};
use std::mem;
use tox_proto::ToxProto;

/// A buffer for message reassembly.
///
/// This implementation uses a vector of optional fragments to store received data.
/// It tracks received fragments using a bitset for efficient validity checking.
#[derive(Debug, Clone, ToxProto)]
pub struct FragmentBuffer {
    /// Fragments stored individually to support variable sizes.
    pub fragments: Vec<Option<Vec<u8>>>,
    /// The number of fragments in this message.
    pub total_fragments: FragmentCount,
    /// Bitset tracking received fragments.
    pub received_mask: BitSet<BITSET_WORDS>,
    /// Total fragments currently received.
    pub received_count: FragmentCount,
    /// Total bytes currently stored.
    pub current_size: usize,
    /// The size of a full fragment (non-last).
    pub full_fragment_size: Option<usize>,
    /// The size of the last fragment.
    pub last_fragment_size: Option<usize>,
    /// The index of the first missing fragment.
    pub base_index: FragmentIndex,
    /// The highest fragment index received so far.
    pub highest_index: FragmentIndex,
}

impl FragmentBuffer {
    /// Creates a new `FragmentBuffer` for a message with a known number of fragments.
    pub fn new(total_fragments: FragmentCount) -> Self {
        Self {
            fragments: vec![None; total_fragments.0 as usize],
            total_fragments,
            received_mask: BitSet::new(),
            received_count: FragmentCount(0),
            current_size: 0,
            full_fragment_size: None,
            last_fragment_size: None,
            base_index: FragmentIndex(0),
            highest_index: FragmentIndex(0),
        }
    }

    /// Adds a fragment to the buffer.
    ///
    /// Returns `Ok(true)` if the buffer is now complete.
    pub fn add_fragment(
        &mut self,
        index: FragmentIndex,
        data: Vec<u8>,
    ) -> Result<bool, SequencedError> {
        if index.0 >= self.total_fragments.0 {
            return Err(SequencedError::InvalidFragmentIndex);
        }

        if self.received_mask.get(index.0 as usize) {
            return Ok(self.is_complete());
        }

        let len = data.len();
        if index.0 == self.total_fragments.0 - 1 {
            self.last_fragment_size = Some(len);
        } else {
            match self.full_fragment_size {
                None => self.full_fragment_size = Some(len),
                Some(current) if len > current => self.full_fragment_size = Some(len),
                _ => {}
            }
        }

        self.current_size += len;
        self.fragments[index.0 as usize] = Some(data);
        self.received_mask.set(index.0 as usize);
        self.received_count.0 += 1;

        if index == self.base_index {
            self.base_index.0 += 1;
            while self.base_index.0 < self.total_fragments.0
                && self.received_mask.get(self.base_index.0 as usize)
            {
                self.base_index.0 += 1;
            }
        }

        if index > self.highest_index {
            self.highest_index = index;
        }

        Ok(self.is_complete())
    }

    /// Returns the total number of fragments received.
    pub fn received_count(&self) -> FragmentCount {
        self.received_count
    }

    /// Returns true if all fragments have been received.
    pub fn is_complete(&self) -> bool {
        self.received_count.0 == self.total_fragments.0
    }

    /// Consumes the buffer and returns the fully assembled message.
    pub fn assemble(self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut result = Vec::with_capacity(self.current_size);
        for frag in self.fragments.into_iter().flatten() {
            result.extend_from_slice(&frag);
        }
        Some(result)
    }

    /// Returns the current total size of stored data.
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Returns the total physical memory allocated by this buffer.
    pub fn total_allocated_size(&self) -> usize {
        self.current_size + (self.received_count.0 as usize * PER_FRAGMENT_OVERHEAD)
    }

    pub fn received_mask(&self) -> &BitSet<BITSET_WORDS> {
        &self.received_mask
    }

    pub fn base_index(&self) -> FragmentIndex {
        self.base_index
    }

    pub fn highest_index(&self) -> FragmentIndex {
        self.highest_index
    }

    /// Returns the total expected size of this message when fully assembled.
    ///
    /// If the exact size is not yet known, a conservative estimate is returned
    /// based on the fragments received so far.
    pub fn planned_total_size(&self) -> usize {
        if self.total_fragments.0 == 0 {
            return 0;
        }

        let full_size = self
            .full_fragment_size
            .unwrap_or(crate::protocol::ESTIMATED_PAYLOAD_SIZE);
        let last_size = self.last_fragment_size.unwrap_or(full_size);

        let estimated_payload = if self.total_fragments.0 == 1 {
            last_size
        } else {
            (self.total_fragments.0 as usize - 1) * full_size + last_size
        };

        let overhead = self.total_fragments.0 as usize * PER_FRAGMENT_OVERHEAD;

        (estimated_payload + overhead).max(self.total_allocated_size())
    }
}

const FRAGMENT_STRUCT_OVERHEAD: usize = mem::size_of::<Option<Vec<u8>>>();
const HEAP_OVERHEAD_ESTIMATE: usize = 32;
const PER_FRAGMENT_OVERHEAD: usize = FRAGMENT_STRUCT_OVERHEAD + HEAP_OVERHEAD_ESTIMATE;
