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
#[derive(Debug, Clone, ToxProto, PartialEq)]
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
        shards: Vec<(tox_reconcile::SyncRange, ShardHash)>,
    },
    SyncReconFail {
        conversation_id: ConversationId,
        range: tox_reconcile::SyncRange,
    },
    /// Per-peer CPU budget exhausted; includes retry delay in ms.
    SyncRateLimited {
        conversation_id: ConversationId,
        retry_after_ms: u32,
    },
    /// Confirms successful WrappedKey entry decryption (off-DAG).
    KeywrapAck {
        keywrap_hash: NodeHash,
        recipient_pk: PhysicalDevicePk,
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
    /// Off-DAG request from trust-restored device asking admin for re-inclusion.
    ReinclusionRequest {
        conversation_id: ConversationId,
        sender_pk: PhysicalDevicePk,
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
}

/// Trait for receiving engine events.
pub trait NodeEventHandler: Send + Sync {
    fn handle_event(&self, event: NodeEvent);
}
