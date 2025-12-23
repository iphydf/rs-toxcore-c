//! Fundamental and derived constants for the Tox ecosystem and Merkle-Tox protocol.

// --- Physical Limits ---

/// The maximum size of a single Tox custom packet.
pub const MAX_TOX_PACKET_SIZE: usize = 1373;

/// The size of a Blake3 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// The size of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// The size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

// --- Transport Layer (tox-sequenced) ---

/// Estimated overhead per fragment for tox-sequenced transport headers.
pub const TRANSPORT_HEADER_OVERHEAD: usize = 20;

/// The usable payload size in a single Tox packet.
pub const USABLE_PACKET_MTU: usize = MAX_TOX_PACKET_SIZE - TRANSPORT_HEADER_OVERHEAD;

// --- Protocol Layer (merkle-tox) ---

/// Estimated overhead for protocol-level framing (ConversationId, Flags, Array tags).
pub const PROTOCOL_FRAMING_OVERHEAD: usize = 45;

/// Target number of packets to use for a single synchronization message burst.
/// Two packets provide a good balance between data density and retransmission overhead.
pub const MAX_PACKETS_PER_SYNC_BURST: usize = 2;

/// The maximum number of DAG heads to reconcile in a single protocol step.
/// Derived as the largest power of 2 that fits within the target packet burst.
/// Calculation: floor((USABLE_PACKET_MTU * MAX_PACKETS - FRAMING) / HASH_SIZE)
/// floor((1353 * 2 - 45) / 32) = 83.
/// 64 is the largest power of 2 <= 83.
pub const MAX_HEADS_SYNC: usize = 64;

/// The maximum number of nodes to request in a single FetchBatchReq.
pub const MAX_BATCH_SIZE: usize = MAX_HEADS_SYNC;

/// The minimum number of transport slots required to handle a full protocol burst.
pub const MIN_TRANSPORT_SLOTS: usize = 32;

/// Maximum total memory used for reassembly across all messages (16MB).
/// Derived to allow 8 peers to fully saturate their 32-slot windows with 64KB blob chunks.
/// Calculation: 8 peers * 32 slots * 64KB = 16MB.
/// This also protects mobile devices from excessive background memory usage.
pub const MAX_TOTAL_REASSEMBLY_BUFFER: usize = 8 * 32 * 64 * 1024;

/// Maximum depth of the hierarchical authorization chain.
pub const MAX_AUTH_DEPTH: usize = 16;

/// Maximum number of unverified (speculative) nodes to store per conversation
/// to prevent memory/storage exhaustion from malicious peers.
pub const MAX_SPECULATIVE_NODES_PER_CONVERSATION: usize = 1000;

/// Maximum number of verified nodes to keep per device in a conversation.
/// This prevents a compromised device from exhausting local storage.
pub const MAX_VERIFIED_NODES_PER_DEVICE: u64 = 1000;

/// The minimum size of the padding bin for encrypted payloads to prevent traffic analysis.
pub const MIN_PADDING_BIN: usize = 128;
