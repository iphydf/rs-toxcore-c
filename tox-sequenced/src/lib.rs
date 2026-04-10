//! # Tox Sequenced
//!
//! A congestion-controlled datagram transport built on top of Tox custom lossy packets.
//!
//! This library provides sequenced datagrams with congestion control, pacing,
//! and priority scheduling. It does NOT provide reliability — the application
//! handles retransmission based on its semantic knowledge (content addressing,
//! DAG structure, chunk bitmasks).
//!
//! ## Architecture
//!
//! - **Congestion Control**: Pluggable algorithms including BBR, Cubic, and AIMD.
//! - **Priority Scheduling**: Deficit Round Robin across 5 priority levels.
//! - **Fragment Reassembly**: Drop-on-timeout reassembly for large messages.
//! - **Serialization**: Built on `rmp-serde` for efficient MessagePack encoding.

pub mod bitset;
pub mod congestion;
pub mod error;
pub mod flat_map;
pub mod protocol;
pub mod quota;
pub mod reassembly;
pub mod rtt;
pub mod scheduler;
pub mod session;
pub mod time;

use tox_proto::ToxProto;

/// Events emitted by the transport session to the application.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub enum SessionEvent {
    /// A single-packet DATA datagram was received.
    DataReceived(u32, MessageType, Vec<u8>),
    /// An outgoing sequenced datagram was acknowledged by the peer.
    DatagramDelivered(u32),
    /// An outgoing sequenced datagram was not acknowledged within 2×RTT.
    DatagramLost(u32),
    /// A fragmented message was fully reassembled.
    MessageCompleted(u32, MessageType, Vec<u8>),
    /// A fragmented message timed out (missing fragments after 5s).
    MessageDropped(u32),
    /// Send window has capacity for new datagrams.
    ReadyToSend,
}

pub use bitset::BitSet;
pub use congestion::aimd::Aimd;
pub use congestion::bbrv1::Bbrv1;
pub use congestion::bbrv2::Bbrv2;
pub use congestion::cubic::Cubic;
pub use congestion::{Algorithm, AlgorithmType, CongestionControl};
pub use error::SequencedError;
pub use protocol::{MessageType, Packet};
pub use session::{FlushDiag, SequenceSession};
