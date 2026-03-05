pub mod builder;
pub mod cas;
pub mod clock;
pub mod crypto;
pub mod dag;
pub mod engine;
pub mod error;
pub mod identity;
pub mod node;
pub mod sync;
pub mod testing;
pub mod vfs;
pub mod viz;

use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk, PowNonce, ShardHash};
use std::io;
use tox_proto::ToxProto;

/// Transport layer errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Other error: {0}")]
    Other(String),
}

/// Generic trait for sending raw protocol packets.
pub trait Transport: Send + Sync {
    /// Returns local transport instance Public Key.
    fn local_pk(&self) -> PhysicalDevicePk;

    /// Sends raw lossy packet to destination.
    fn send_raw(&self, to: PhysicalDevicePk, data: Vec<u8>) -> Result<(), TransportError>;
}

/// High-level message types for Merkle-Tox protocol.
///
/// Marked `#[non_exhaustive]` so external pattern matchers (in
/// downstream FFI consumers — `go-toxcore-c`, `jvm-toxcore-c`,
/// `qtox`, etc.) cannot accidentally rely on a closed variant set,
/// and the `Unknown` catch-all variant absorbs deserialise of any
/// future on-wire variant from a newer peer without dropping the
/// packet outright. Together these let the protocol grow without a
/// SemVer-major break for in-flight upgrades.
#[derive(Debug, Clone, ToxProto, PartialEq)]
#[non_exhaustive]
pub enum ProtocolMessage {
    CapsAnnounce {
        version: u32,
        features: u64,
    },
    CapsAck {
        version: u32,
        features: u64,
    },
    SyncHeads(sync::SyncHeads),
    SyncSketch(tox_reconcile::SyncSketch),
    SyncShardChecksums {
        conversation_id: ConversationId,
        /// Shard checksums, capped at `MAX_SYNC_SHARDS = 4096` at the
        /// type level: oversize wire payloads are rejected by the
        /// deserialiser before any per-shard scan/sketch work.
        shards: tox_proto::BoundedVec<
            (tox_reconcile::SyncRange, ShardHash),
            { tox_proto::constants::MAX_SYNC_SHARDS },
        >,
    },
    SyncReconFail {
        conversation_id: ConversationId,
        range: tox_reconcile::SyncRange,
    },
    /// Per-peer CPU budget exhausted; includes retry delay in ms.
    /// `retry_after_ms` is peer-supplied; the handler clamps it against
    /// `SYNC_RATE_LIMITED_MAX_MS` before applying it as a local timeout,
    /// preventing a malicious peer from silencing our sync for weeks.
    SyncRateLimited {
        conversation_id: ConversationId,
        retry_after_ms: tox_proto::Untrusted<u32>,
    },
    /// Confirms successful WrappedKey entry decryption (off-DAG).
    /// `recipient_pk` is a peer-supplied identity claim; the handler
    /// must verify it matches the transport-authenticated `sender_pk`
    /// before applying any side-effect (see §3 handlers).
    KeywrapAck {
        keywrap_hash: NodeHash,
        recipient_pk: tox_proto::Claimed<PhysicalDevicePk>,
    },
    ReconPowChallenge {
        conversation_id: ConversationId,
        nonce: PowNonce,
        difficulty: u32,
    },
    ReconPowSolution {
        conversation_id: ConversationId,
        nonce: PowNonce,
        solution: u64,
    },
    FetchBatchReq(sync::FetchBatchReq),
    MerkleNode {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::WireNode,
    },
    BlobQuery(NodeHash),
    BlobAvail(cas::BlobInfo),
    BlobReq(cas::BlobReq),
    BlobData(cas::BlobData),
    BlobFetch(cas::BlobFetch),
    BlobProgress(cas::BlobProgress),
    BlobCancel(NodeHash),
    /// Off-DAG request from trust-restored device asking admin for re-inclusion.
    /// `sender_pk` is a peer-supplied identity claim used by the
    /// handler to drive the snapshot-membership check. It must
    /// verify against the transport-authenticated sender before the
    /// rotation side-effect fires — otherwise the admin becomes a
    /// membership oracle and any peer can trigger k_conv rotations.
    ReinclusionRequest {
        conversation_id: ConversationId,
        sender_pk: tox_proto::Claimed<PhysicalDevicePk>,
        healing_snapshot_hash: NodeHash,
    },
    /// Off-DAG admin response indicating if reinclusion was accepted.
    ReinclusionResponse {
        conversation_id: ConversationId,
        accepted: bool,
    },
    /// Off-DAG error during handshake (e.g. OPK exhausted, bad cert).
    HandshakeError {
        conversation_id: ConversationId,
        reason: String,
    },
    /// Immediate notification of a new admin node hash for priority fetch.
    AdminGossip {
        conversation_id: ConversationId,
        hash: NodeHash,
    },
    /// Forward-compat catch-all for unrecognised protocol-message
    /// discriminants from a newer peer.  `tox_proto`'s deserialiser
    /// routes any unknown discriminant here, preserving the wire bytes
    /// in `data` so the packet round-trips losslessly. We never
    /// *emit* this variant ourselves — `get_message_type` panics if
    /// asked to classify it for transit. The handler arm for
    /// `Unknown` is a no-op + `debug!` log: an old peer cannot
    /// meaningfully act on a message type it doesn't understand, but
    /// dropping the packet at deserialise would lose forward-compat.
    /// See `Content::Unknown` in `dag.rs` for the same pattern.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// Events emitted by Merkle-Tox engine/node for orchestration.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// New node verified and added to DAG.
    NodeVerified {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::MerkleNode,
    },
    /// New node received but not yet verified.
    NodeSpeculative {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::MerkleNode,
    },
    /// Node verified but conversation identity unconfirmed.
    /// Content needs warning until admin chain is verified.
    NodeIdentityPending {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::MerkleNode,
    },
    /// Node retroactively invalidated (e.g., due to revocation).
    NodeInvalidated {
        conversation_id: ConversationId,
        hash: NodeHash,
    },
    /// Handshake with peer completed.
    PeerHandshakeComplete { peer_pk: PhysicalDevicePk },
    /// Blob downloaded and verified.
    BlobAvailable { hash: NodeHash },
    /// Equivocation detected: same device authored two nodes at same sequence number.
    EquivocationDetected {
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
        seq: u64,
        existing_hash: NodeHash,
        conflicting_hash: NodeHash,
    },
    /// Application should create a history snapshot for CAS upload.
    HistorySnapshotNeeded { conversation_id: ConversationId },
}

/// Trait for receiving engine events.
pub trait NodeEventHandler: Send + Sync {
    fn handle_event(&self, event: NodeEvent);
}
