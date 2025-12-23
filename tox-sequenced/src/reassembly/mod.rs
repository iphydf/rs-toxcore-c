pub mod buffer;

use self::buffer::FragmentBuffer;
use crate::error::SequencedError;
use crate::protocol::{
    FragmentCount, FragmentIndex, MAX_FRAGMENTS_PER_MESSAGE, MAX_MESSAGE_SIZE, MessageId, Nack,
    Priority, SelectiveAck,
};
use smallvec::SmallVec;
use std::time::Instant;
use tox_proto::ToxProto;

/// A reliable, fragmented message being reassembled.
#[derive(Debug, Clone, ToxProto)]
pub struct MessageReassembler {
    pub message_id: MessageId,
    pub total_fragments: FragmentCount,
    pub priority: Priority,
    pub buffer: FragmentBuffer,
    pub reserved_bytes: usize,
    pub last_activity: Instant,
}

impl MessageReassembler {
    pub fn new(
        message_id: MessageId,
        total_fragments: FragmentCount,
        priority: Priority,
        reserved_bytes: usize,
        now: Instant,
    ) -> Result<Self, SequencedError> {
        if total_fragments.0 == 0 || total_fragments.0 > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(SequencedError::InvalidTotalFragments);
        }
        Ok(Self {
            message_id,
            total_fragments,
            priority,
            buffer: FragmentBuffer::new(total_fragments),
            reserved_bytes,
            last_activity: now,
        })
    }

    pub fn is_received(&self, index: FragmentIndex) -> bool {
        if index.0 >= self.total_fragments.0 {
            return false;
        }
        self.buffer.received_mask().get(index.0 as usize)
    }

    pub fn add_fragment(
        &mut self,
        index: FragmentIndex,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<bool, SequencedError> {
        self.last_activity = now;
        if self.buffer.current_size() + data.len() > MAX_MESSAGE_SIZE {
            return Err(SequencedError::MessageTooLarge);
        }

        self.buffer.add_fragment(index, data)
    }

    pub fn assemble(self) -> Option<Vec<u8>> {
        self.buffer.assemble()
    }

    pub fn create_ack(&self, rwnd_fragments: FragmentCount) -> SelectiveAck {
        let base_index = self.buffer.base_index();
        let bitmask = self.buffer.received_mask().sack_mask(base_index.0 as usize);

        SelectiveAck {
            message_id: self.message_id,
            base_index,
            bitmask,
            rwnd: rwnd_fragments,
        }
    }

    pub fn create_nack(&self, base_index: FragmentIndex) -> Option<Nack> {
        let mut missing = SmallVec::new();
        let mut curr = base_index.0;
        let limit = self.buffer.highest_index().0 as usize;
        while let Some(zero_idx) = self.buffer.received_mask().next_zero(curr as usize, limit) {
            let zero_idx = zero_idx as u16;
            missing.push(FragmentIndex(zero_idx));
            if missing.len() >= 128 {
                break;
            }
            curr = zero_idx + 1;
        }

        if !missing.is_empty() {
            Some(Nack {
                message_id: self.message_id,
                missing_indices: missing,
            })
        } else {
            None
        }
    }

    pub fn received_count(&self) -> FragmentCount {
        self.buffer.received_count()
    }

    pub fn current_size(&self) -> usize {
        self.buffer.current_size()
    }

    pub fn planned_total_size(&self) -> usize {
        self.buffer.planned_total_size()
    }
}
