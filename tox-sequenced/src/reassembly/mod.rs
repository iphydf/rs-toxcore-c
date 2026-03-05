pub mod buffer;

use self::buffer::FragmentBuffer;
use crate::protocol::Priority;
use std::time::Instant;
use tox_proto::ToxProto;

/// A fragment reassembly entry for a fragmented message.
#[derive(Debug, Clone, ToxProto)]
pub struct FragmentReassembly {
    pub frag_id: u32,
    pub frag_total: u16,
    pub msg_type: crate::protocol::MessageType,
    pub priority: Priority,
    pub buffer: FragmentBuffer,
    pub reserved_bytes: usize,
    pub created_at: Instant,
    pub last_activity: Instant,
}

impl FragmentReassembly {
    pub fn new(
        frag_id: u32,
        frag_total: u16,
        msg_type: crate::protocol::MessageType,
        reserved_bytes: usize,
        now: Instant,
    ) -> Self {
        Self {
            frag_id,
            frag_total,
            msg_type,
            priority: msg_type.priority(),
            buffer: FragmentBuffer::new(frag_total),
            reserved_bytes,
            created_at: now,
            last_activity: now,
        }
    }

    pub fn add_fragment(&mut self, index: u16, data: Vec<u8>, now: Instant) -> bool {
        self.last_activity = now;
        if index >= self.frag_total {
            return false;
        }
        if self.buffer.current_size() + data.len() > crate::protocol::MAX_FRAGMENT_MESSAGE {
            return false;
        }
        self.buffer.add_fragment(index, data).unwrap_or_default()
    }

    pub fn is_complete(&self) -> bool {
        self.buffer.is_complete()
    }

    pub fn assemble(self) -> Option<Vec<u8>> {
        self.buffer.assemble()
    }

    pub fn current_size(&self) -> usize {
        self.buffer.current_size()
    }

    pub fn planned_total_size(&self) -> usize {
        self.buffer.planned_total_size()
    }
}
