//! # Tox Sequenced
//!
//! A reliable, congestion-controlled transport layer built on top of Tox custom lossy packets.
//!
//! This library provides a "Reliable UDP" style protocol that handles fragmentation,
//! retransmission (ARQ), and congestion control for large messages (up to 1MB).
//!
//! ## Architecture
//!
//! - **Reliability**: Uses Selective Repeat ARQ (Selective ACKs and NACKs).
//! - **Congestion Control**: Pluggable algorithms including BBR, Cubic, and AIMD.
//! - **Memory Management**: Shared reassembly quotas to prevent memory exhaustion.
//! - **Serialization**: Built on `rmp-serde` for efficient MessagePack encoding.

pub mod bitset;
pub mod congestion;
pub mod error;
pub mod flat_map;
pub mod outgoing;
pub mod protocol;
pub mod quota;
pub mod reassembly;
pub mod rtt;
pub mod scheduler;
pub mod session;
pub mod time;

use tox_proto::ToxProto;

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub enum SessionEvent {
    /// A complete message has been received.
    MessageCompleted(protocol::MessageId, MessageType, Vec<u8>),
    /// A message that was being sent has failed (e.g., timed out).
    MessageFailed(protocol::MessageId, String),
    /// An outgoing message has been fully acknowledged by the peer.
    MessageAcked(protocol::MessageId),
    /// An outgoing message slot has become available.
    ReadyToSend,
    /// The congestion window has changed.
    CongestionWindowChanged(usize),
}

pub use bitset::BitSet;
pub use congestion::aimd::Aimd;
pub use congestion::bbrv1::Bbrv1;
pub use congestion::bbrv2::Bbrv2;
pub use congestion::cubic::Cubic;
pub use congestion::{Algorithm, AlgorithmType, CongestionControl};
pub use error::SequencedError;
pub use protocol::{MessageType, Packet};
pub use reassembly::MessageReassembler;
pub use session::SequenceSession;
