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

/// Estimated average payload size for a DATA packet, used for metrics and pacing.
pub const ESTIMATED_PAYLOAD_SIZE: usize = 1300;

/// Maximum payload in a single DATA packet (~1350 bytes after overhead).
pub const MAX_DATAGRAM_SIZE: usize = 1350;
/// Maximum total size of a reassembled fragmented message (1MB).
pub const MAX_FRAGMENT_MESSAGE: usize = 1024 * 1024;
/// Maximum concurrent incoming fragment reassemblies per session.
pub const MAX_CONCURRENT_REASSEMBLY: usize = 32;
/// Time after which incomplete fragment reassembly is dropped.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Initial send window in bytes. Large enough to allow bulk transfers
/// to start flowing before the CC has estimated bandwidth.
pub const INITIAL_WINDOW: usize = 256 * 1024;
/// Maximum send window in bytes.
pub const MAX_WINDOW: usize = 1024 * 1024;
/// Minimum gap between paced sends.
pub const MIN_PACING_INTERVAL: Duration = Duration::from_micros(200);

/// Overhead for Packet::Data variant serialization (conservative estimate).
pub const PACKET_OVERHEAD: usize = 20;

/// Pacing gain used by AIMD and Cubic (2.0x).
pub const PACING_GAIN: f32 = 2.0;

/// Maximum number of sent datagrams to track for loss detection.
pub const MAX_SENT_TRACKING: usize = 4096;

/// Maximum number of `(start_seq, length)` pairs in an ACK's `sack_ranges`
/// list. With 8 ranges × 8 bytes/pair + framing ≈ 80 bytes — bounds the
/// ACK packet well under MAX_DATAGRAM_SIZE.
pub const MAX_SACK_RANGES: usize = 8;

/// Maximum length of a single SACK range, to bound per-range work on the
/// sender. Beyond this, the receiver should split the range into multiple
/// entries (or rely on cumulative `base_seq` advance).
pub const MAX_SACK_RANGE_LENGTH: u32 = 65536;

/// A raw packet that can be sent over Tox.
/// Serialized as a positional array (fixarray) for efficiency.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub enum Packet {
    /// DATA (0x00) — Sequenced datagram with congestion control tracking.
    Data {
        seq: u32,
        msg_type: MessageType,
        data: Vec<u8>,
    },
    /// ACK (0x01) — Cumulative + SACK congestion control feedback.
    ///
    /// `base_seq` is the next-expected seq; all seqs strictly less are
    /// implicitly delivered (cumulative ack). `recv_bytes` is the
    /// cumulative byte counter feeding delivery rate estimation.
    /// `sack_ranges` is a bounded list of `(start_seq, length)` pairs
    /// reporting non-contiguous receipts above `base_seq` — the
    /// equivalent of TCP SACK blocks. The list is capped at
    /// `MAX_SACK_RANGES` entries; total wire size is bounded so the
    /// ACK packet never approaches MAX_DATAGRAM_SIZE.
    ///
    /// All three peer-supplied fields are tagged `Untrusted<T>` (the
    /// list itself, since each pair shares the same trust scope);
    /// consumers must clamp against self-state.
    Ack {
        base_seq: tox_proto::Untrusted<u32>,
        recv_bytes: tox_proto::Untrusted<u64>,
        sack_ranges: tox_proto::Untrusted<tox_proto::BoundedVec<(u32, u32), MAX_SACK_RANGES>>,
    },
    /// PING (0x02) — NTP-style RTT probe.
    Ping { t1: TimestampMs },
    /// PONG (0x03) — NTP-style RTT response.
    Pong {
        t1: TimestampMs,
        t2: TimestampMs,
        t3: TimestampMs,
    },
    /// FRAGMENT (0x04) — Fragment of a large message, drop-on-timeout reassembly.
    Fragment {
        frag_id: u32,
        frag_index: u16,
        frag_total: u16,
        msg_type: MessageType,
        data: Vec<u8>,
    },
}

/// High-level message types carried in DATA/FRAGMENT packets.
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
    SyncRateLimited = 0x0E,
    KeywrapAck = 0x0F,
    ReinclusionRequest = 0x10,
    ReinclusionResponse = 0x11,
    ReconPowChallenge = 0x12,
    ReconPowSolution = 0x13,
    AdminGossip = 0x14,
    BlobFetch = 0x15,
    BlobProgress = 0x16,
    BlobCancel = 0x17,
}

impl MessageType {
    pub fn priority(&self) -> Priority {
        match self {
            MessageType::CapsAnnounce | MessageType::CapsAck => Priority::Critical,
            MessageType::SyncHeads | MessageType::FetchBatchReq => Priority::High,
            MessageType::SyncSketch
            | MessageType::SyncReconFail
            | MessageType::SyncShardChecksums
            | MessageType::SyncRateLimited
            | MessageType::ReconPowChallenge
            | MessageType::ReconPowSolution => Priority::High,
            MessageType::HandshakeError | MessageType::KeywrapAck => Priority::High,
            MessageType::MerkleNode => Priority::Standard,
            MessageType::BlobQuery
            | MessageType::BlobAvail
            | MessageType::BlobReq
            | MessageType::BlobFetch
            | MessageType::BlobProgress
            | MessageType::BlobCancel => Priority::Low,
            MessageType::BlobData => Priority::Bulk,
            MessageType::ReinclusionRequest | MessageType::ReinclusionResponse => Priority::High,
            MessageType::AdminGossip => Priority::High,
        }
    }
}

pub use tox_proto::{deserialize, serialize};
