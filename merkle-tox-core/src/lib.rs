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

/// Errors that can occur in the transport layer.
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

/// A generic trait for sending raw protocol packets.
pub trait Transport: Send + Sync {
    /// Returns the Public Key of the local transport instance.
    fn local_pk(&self) -> PhysicalDevicePk;

    /// Sends a raw, lossy packet to a destination.
    fn send_raw(&self, to: PhysicalDevicePk, data: Vec<u8>) -> Result<(), TransportError>;
}

/// High-level message types for the Merkle-Tox protocol.
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
}

/// Events emitted by the Merkle-Tox engine/node for orchestration.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A new node has been verified and added to the DAG.
    NodeVerified {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::MerkleNode,
    },
    /// A new node has been received but is not yet verified.
    NodeSpeculative {
        conversation_id: ConversationId,
        hash: NodeHash,
        node: dag::MerkleNode,
    },
    /// A node has been retroactively invalidated (e.g. due to revocation).
    NodeInvalidated {
        conversation_id: ConversationId,
        hash: NodeHash,
    },
    /// A handshake with a peer has been completed.
    PeerHandshakeComplete { peer_pk: PhysicalDevicePk },
    /// A blob has been fully downloaded and verified.
    BlobAvailable { hash: NodeHash },
}

/// A trait for receiving engine events.
pub trait NodeEventHandler: Send + Sync {
    fn handle_event(&self, event: NodeEvent);
}
