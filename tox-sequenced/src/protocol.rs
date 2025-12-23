use smallvec::SmallVec;
use std::time::Duration;
use tox_proto::ToxProto;
pub use tox_proto::constants::{
    MAX_TOTAL_REASSEMBLY_BUFFER, MAX_TOX_PACKET_SIZE, MIN_TRANSPORT_SLOTS,
};

macro_rules! protocol_newtype {
    ($name:ident, $inner:ty, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, ToxProto)]
        #[tox(flat)]
        pub struct $name(pub $inner);

        impl From<$inner> for $name {
            fn from(val: $inner) -> Self {
                $name(val)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

protocol_newtype!(
    MessageId,
    u32,
    "Unique identifier for a reliable message within a session."
);

impl MessageId {
    pub fn wrapping_add(self, val: u32) -> Self {
        MessageId(self.0.wrapping_add(val))
    }
    pub fn wrapping_sub(self, other: MessageId) -> u32 {
        self.0.wrapping_sub(other.0)
    }
}

protocol_newtype!(
    FragmentIndex,
    u16,
    "Index of a fragment within a message (0 to total_fragments - 1)."
);

impl FragmentIndex {
    pub fn wrapping_add(self, val: u16) -> Self {
        FragmentIndex(self.0.wrapping_add(val))
    }
}

protocol_newtype!(
    FragmentCount,
    u16,
    "Total number of fragments in a message."
);
protocol_newtype!(
    TimestampMs,
    i64,
    "NTP-style timestamp (milliseconds since epoch) for protocol timing."
);

/// Priority levels for memory reservation and transmission scheduling.
/// Values match the scheduler's levels (0=Highest, 4=Lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ToxProto)]
pub enum Priority {
    /// Critical protocol maintenance (Handshakes, Admin updates).
    Critical = 0,
    /// Standard synchronization and DAG reconciliation.
    High = 1,
    /// Standard chat messages and DAG nodes.
    Standard = 2,
    /// Bulk metadata transfers.
    Low = 3,
    /// Large data transfers (Blobs, bulk sync). Rejected first when memory is low.
    Bulk = 4,
}

/// The transport-level packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x00,
    Ack = 0x01,
    Nack = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Datagram = 0x05,
}

/// A selective acknowledgment for fragments of a message.
///
/// It uses a combination of a cumulative base index and a bitmask to acknowledge
/// received fragments efficiently even in the presence of packet reordering or loss.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub struct SelectiveAck {
    /// The message being acknowledged.
    pub message_id: MessageId,
    /// The index where all previous fragments have been received.
    pub base_index: FragmentIndex,
    /// A bitmask of received fragments starting from `base_index + 1`.
    /// Bit 0 corresponds to `base_index + 1`, Bit 1 to `base_index + 2`, etc.
    pub bitmask: u64,
    /// The current receive window (rwnd) in fragments available at the receiver.
    pub rwnd: FragmentCount,
}

/// Explicit request for a range of fragments.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub struct Nack {
    pub message_id: MessageId,
    pub missing_indices: SmallVec<FragmentIndex, 8>,
}

/// Estimated average payload size for a fragment, used for metrics and pacing.
pub const ESTIMATED_PAYLOAD_SIZE: usize = 1300;

/// Maximum total size of a reassembled message (1MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
/// Maximum number of fragments per message (MAX_MESSAGE_SIZE / ESTIMATED_PAYLOAD_SIZE).
pub const MAX_FRAGMENTS_PER_MESSAGE: u16 = 1024;
/// Number of 64-bit words needed for a bitset covering MAX_FRAGMENTS_PER_MESSAGE.
pub const BITSET_WORDS: usize = (MAX_FRAGMENTS_PER_MESSAGE as usize).div_ceil(64);
/// Maximum concurrent outgoing messages per session.
pub const MAX_CONCURRENT_OUTGOING: usize = MIN_TRANSPORT_SLOTS;
/// Maximum concurrent incoming reassemblies per session.
pub const MAX_CONCURRENT_INCOMING: usize = MIN_TRANSPORT_SLOTS;
/// Maximum number of completed messages to keep in the cache for duplicate detection.
pub const MAX_COMPLETED_INCOMING: usize = 1024;
/// Maximum number of unreliable datagrams to queue for transmission.
pub const MAX_DATAGRAM_QUEUE: usize = 128;
/// Time after which an incomplete reassembly is discarded (seconds).
pub const REASSEMBLY_TIMEOUT_SECS: u64 = 30;

/// Overhead for Packet::Data variant serialization (conservative estimate).
pub const PACKET_OVERHEAD: usize = 20;

/// Pacing gain used by AIMD and Cubic (2.0x).
pub const PACING_GAIN: f32 = 2.0;

/// Timeout for delayed ACKs (milliseconds).
pub const DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(40);

/// A raw packet that can be sent over Tox.
/// Serialized as a positional array (fixarray) for efficiency.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub enum Packet {
    Data {
        message_id: MessageId,
        fragment_index: FragmentIndex,
        total_fragments: FragmentCount,
        data: Vec<u8>,
    },
    Ack(SelectiveAck),
    Nack(Nack),
    /// NTP-style (RFC 5905) timestamps for RTT and clock offset calculation.
    Ping {
        /// T1: Transmit timestamp of the PING request (Origin).
        t1: TimestampMs,
    },
    /// NTP-style (RFC 5905) timestamps for RTT and clock offset calculation.
    Pong {
        /// T1: Transmit timestamp of the PING request (copied from Ping).
        t1: TimestampMs,
        /// T2: Receive timestamp of the PING request (Receive).
        t2: TimestampMs,
        /// T3: Transmit timestamp of the PONG response (Transmit).
        t3: TimestampMs,
    },
    /// A single-packet, unreliable message (Type 0x05).
    /// Used for gossip, multicast, and low-latency signals.
    Datagram {
        message_type: MessageType,
        data: Vec<u8>,
    },
}

/// High-level message types carried in the reassembled DATA payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum MessageType {
    CapsAnnounce = 0x01,
    CapsAck = 0x02,
    SyncHeads = 0x03,
    FetchBatchReq = 0x04,
    MerkleNode = 0x05,
    BlobQuery = 0x06,
    BlobAvail = 0x07,
    BlobReq = 0x08,
    BlobData = 0x09,
    SyncSketch = 0x0A,
    SyncReconFail = 0x0B,
    SyncShardChecksums = 0x0C,
    HandshakeError = 0x0D,
    ReconPowChallenge = 0x0E,
    ReconPowSolution = 0x0F,
}

impl MessageType {
    pub fn priority(&self) -> Priority {
        match self {
            MessageType::CapsAnnounce | MessageType::CapsAck => Priority::Critical,
            MessageType::SyncHeads | MessageType::FetchBatchReq => Priority::High,
            MessageType::SyncSketch
            | MessageType::SyncReconFail
            | MessageType::SyncShardChecksums
            | MessageType::ReconPowChallenge
            | MessageType::ReconPowSolution => Priority::High,
            MessageType::HandshakeError => Priority::High,
            MessageType::MerkleNode => Priority::Standard,
            MessageType::BlobQuery | MessageType::BlobAvail | MessageType::BlobReq => Priority::Low,
            MessageType::BlobData => Priority::Bulk,
        }
    }
}

/// Internal envelope used to serialize application messages for sending.
#[derive(tox_proto::ToxSerialize)]
pub struct OutboundEnvelope<'a> {
    pub message_type: MessageType,
    pub payload: &'a [u8],
}

/// Owned version of the message envelope for reassembly and receiving.
#[derive(ToxProto)]
pub struct InboundEnvelope {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

pub use tox_proto::{deserialize, serialize};
