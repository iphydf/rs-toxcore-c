use crate::bitset::BitSet;
use std::mem;
use tox_proto::ToxProto;

/// Number of 64-bit words needed for a bitset covering max fragments.
/// MAX_FRAGMENT_MESSAGE (1MB) / ESTIMATED_PAYLOAD_SIZE (1300) ≈ 793 fragments.
const BITSET_WORDS: usize = 1024usize.div_ceil(64);

/// A buffer for fragment reassembly.
///
/// Stores received fragments using a vector of optional buffers.
/// Tracks received fragments using a bitset for efficient validity checking.
#[derive(Debug, Clone, ToxProto)]
pub struct FragmentBuffer {
    /// Fragments stored individually to support variable sizes.
    pub fragments: Vec<Option<Vec<u8>>>,
    /// The number of fragments in this message.
    pub total_fragments: u16,
    /// Bitset tracking received fragments.
    pub received_mask: BitSet<BITSET_WORDS>,
    /// Total fragments currently received.
    pub received_count: u16,
    /// Total bytes currently stored.
    pub current_size: usize,
    /// The size of a full fragment (non-last).
    pub full_fragment_size: Option<usize>,
    /// The size of the last fragment.
    pub last_fragment_size: Option<usize>,
}

impl FragmentBuffer {
    /// Creates a new `FragmentBuffer` for a message with a known number of fragments.
    pub fn new(total_fragments: u16) -> Self {
        Self {
            fragments: vec![None; total_fragments as usize],
            total_fragments,
            received_mask: BitSet::new(),
            received_count: 0,
            current_size: 0,
            full_fragment_size: None,
            last_fragment_size: None,
        }
    }

    /// Adds a fragment to the buffer.
    ///
    /// Returns `Ok(true)` if the buffer is now complete.
    /// Adds a fragment. Returns true if the buffer is now complete.
    /// Returns false if the index is out of range.
    pub fn add_fragment(
        &mut self,
        index: u16,
        data: Vec<u8>,
    ) -> Option<bool> {
        if index >= self.total_fragments {
            return None;
        }

        if self.received_mask.get(index as usize) {
            return Some(self.is_complete());
        }

        let len = data.len();
        if index == self.total_fragments - 1 {
            self.last_fragment_size = Some(len);
        } else {
            match self.full_fragment_size {
                None => self.full_fragment_size = Some(len),
                Some(current) if len > current => self.full_fragment_size = Some(len),
                _ => {}
            }
        }

        self.current_size += len;
        self.fragments[index as usize] = Some(data);
        self.received_mask.set(index as usize);
        self.received_count += 1;

        Some(self.is_complete())
    }

    /// Returns true if all fragments have been received.
    pub fn is_complete(&self) -> bool {
        self.received_count == self.total_fragments
    }

    /// Consumes the buffer and returns the assembled message.
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
        self.current_size + (self.received_count as usize * PER_FRAGMENT_OVERHEAD)
    }

    /// Returns the total expected size of this message when assembled.
    pub fn planned_total_size(&self) -> usize {
        if self.total_fragments == 0 {
            return 0;
        }

        let full_size = self
            .full_fragment_size
            .unwrap_or(crate::protocol::ESTIMATED_PAYLOAD_SIZE);
        let last_size = self.last_fragment_size.unwrap_or(full_size);

        let estimated_payload = if self.total_fragments == 1 {
            last_size
        } else {
            (self.total_fragments as usize - 1) * full_size + last_size
        };

        let overhead = self.total_fragments as usize * PER_FRAGMENT_OVERHEAD;

        (estimated_payload + overhead).max(self.total_allocated_size())
    }
}

const FRAGMENT_STRUCT_OVERHEAD: usize = mem::size_of::<Option<Vec<u8>>>();
const HEAP_OVERHEAD_ESTIMATE: usize = 32;
const PER_FRAGMENT_OVERHEAD: usize = FRAGMENT_STRUCT_OVERHEAD + HEAP_OVERHEAD_ESTIMATE;
