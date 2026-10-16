//! Sync messages split into Tox custom lossless packets, and joined again.

use std::collections::{HashMap, VecDeque};

use toxcore::tox::FriendNumber;
use toxcore::types::MAX_CUSTOM_PACKET_SIZE;

pub const PACKET_ID: u8 = 0xb0;
pub const MAX_MESSAGE: usize = 1 << 20;

const FLAG_FINAL: u8 = 1;
const FLAG_FIRST: u8 = 2;
const HEADER: usize = 2;
const MAX_PAYLOAD: usize = MAX_CUSTOM_PACKET_SIZE - HEADER;

pub fn frames(message: &[u8]) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = message.chunks(MAX_PAYLOAD).collect();
    let last = chunks.len().saturating_sub(1);
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let first = if i == 0 { FLAG_FIRST } else { 0 };
            let flags = first | if i == last { FLAG_FINAL } else { 0 };
            [&[PACKET_ID, flags][..], chunk].concat()
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Malformed,
    TooLong,
}

#[derive(Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    discarding: bool,
}

impl Reassembler {
    /// Returns the message once its final frame has arrived.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        let [PACKET_ID, flags, payload @ ..] = packet else {
            return Err(FrameError::Malformed);
        };
        let last = flags & FLAG_FINAL != 0;
        // Left from a connection that ended mid-message.
        if flags & FLAG_FIRST != 0 {
            self.buffer.clear();
            self.discarding = false;
        }
        if self.discarding {
            self.discarding = !last;
            return Ok(None);
        }
        if self.buffer.len() + payload.len() > MAX_MESSAGE {
            self.buffer.clear();
            self.discarding = !last;
            return Err(FrameError::TooLong);
        }
        self.buffer.extend_from_slice(payload);
        Ok(last.then(|| std::mem::take(&mut self.buffer)))
    }
}

pub enum SendError {
    Full,
    Gone,
}

#[derive(Default)]
pub struct Outbox {
    queues: HashMap<FriendNumber, VecDeque<Vec<u8>>>,
}

impl Outbox {
    pub fn push(&mut self, friend: FriendNumber, message: &[u8]) {
        self.queues
            .entry(friend)
            .or_default()
            .extend(frames(message));
    }

    pub fn remove(&mut self, friend: FriendNumber) {
        self.queues.remove(&friend);
    }

    /// Sends queued packets until toxcore's send queue is full.
    pub fn flush(&mut self, mut send: impl FnMut(FriendNumber, &[u8]) -> Result<(), SendError>) {
        self.queues.retain(|&friend, queue| {
            while let Some(packet) = queue.front() {
                match send(friend, packet) {
                    Ok(()) => {
                        queue.pop_front();
                    }
                    Err(SendError::Full) => return true,
                    Err(SendError::Gone) => return false,
                }
            }
            false
        });
    }
}
