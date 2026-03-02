use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk, PowNonce};
use crate::sync::{SyncRange, Tier};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

pub mod active;
pub mod handshake;

pub use active::Active;
pub use handshake::Handshake;

pub struct SessionCommon {
    pub reachable: bool,
    pub shallow: bool,
    pub min_rank: u64,
    pub min_timestamp: i64,
    pub local_heads: HashSet<NodeHash>,
    pub remote_heads: HashSet<NodeHash>,
    /// Hot-window missing nodes (priority). Fetched before cold.
    pub missing_nodes_hot: VecDeque<NodeHash>,
    /// Cold-window missing nodes.
    pub missing_nodes_cold: VecDeque<NodeHash>,
    pub in_flight_fetches: HashSet<NodeHash>,
    pub missing_blobs: HashSet<NodeHash>,
    pub peer_features: u64,
    pub time_samples: Vec<i64>,
    pub vouchers: HashMap<NodeHash, HashSet<PhysicalDevicePk>>,
    pub iblt_tiers: HashMap<SyncRange, Tier>,
    pub exhausted_iblt_ranges: HashSet<SyncRange>,
    pub heads_dirty: bool,
    pub recon_dirty: bool,
    pub last_recon_time: Instant,
    pub effective_difficulty: u32,
    pub difficulty_votes: HashMap<PhysicalDevicePk, u32>,
    pub pending_challenges: HashMap<PowNonce, Instant>,
    pub pending_sketches: HashMap<PowNonce, tox_reconcile::SyncSketch>,
    /// When set, recon/sketch activity with this peer is paused until this instant.
    pub rate_limited_until: Option<Instant>,
    /// When > 0, limit backfill to this many content nodes from heads.
    pub max_backfill_nodes: u64,
    /// Counter: number of content nodes fetched during shallow backfill.
    pub backfill_count: u64,
    /// Earliest admin head advertised by remote peer (for divergence detection).
    pub remote_anchor_hash: Option<NodeHash>,
}

pub struct SyncSession<S> {
    pub conversation_id: ConversationId,
    pub common: SessionCommon,
    pub state: S,
}

impl<S> SyncSession<S> {
    pub fn with_limits(mut self, min_rank: u64, min_timestamp: i64) -> Self {
        self.common.min_rank = min_rank;
        self.common.min_timestamp = min_timestamp;
        self
    }
}

/// Type-erased session for use in engine's session map.
pub enum PeerSession {
    Handshake(SyncSession<Handshake>),
    Active(SyncSession<Active>),
}

impl PeerSession {
    pub fn conversation_id(&self) -> ConversationId {
        match self {
            PeerSession::Handshake(s) => s.conversation_id,
            PeerSession::Active(s) => s.conversation_id,
        }
    }

    pub fn common(&self) -> &SessionCommon {
        match self {
            PeerSession::Handshake(s) => &s.common,
            PeerSession::Active(s) => &s.common,
        }
    }

    pub fn common_mut(&mut self) -> &mut SessionCommon {
        match self {
            PeerSession::Handshake(s) => &mut s.common,
            PeerSession::Active(s) => &mut s.common,
        }
    }

    pub fn on_node_received(
        &mut self,
        node: &crate::dag::MerkleNode,
        store: &dyn crate::sync::NodeStore,
        blob_store: Option<&dyn crate::sync::BlobStore>,
    ) {
        match self {
            PeerSession::Handshake(s) => s.on_node_received(node, store, blob_store),
            PeerSession::Active(s) => s.on_node_received(node, store, blob_store),
        }
    }

    pub fn on_wire_node_received(
        &mut self,
        hash: NodeHash,
        wire: &crate::dag::WireNode,
        store: &dyn crate::sync::NodeStore,
    ) {
        match self {
            PeerSession::Handshake(_) => {}
            PeerSession::Active(s) => s.on_wire_node_received(hash, wire, store),
        }
    }

    pub fn record_vouch(&mut self, node_hash: NodeHash, peer: PhysicalDevicePk) {
        match self {
            PeerSession::Handshake(s) => s.record_vouch(node_hash, peer),
            PeerSession::Active(s) => s.record_vouch(node_hash, peer),
        }
    }

    pub fn make_sync_heads(&self, flags: u64) -> crate::sync::SyncHeads {
        match self {
            PeerSession::Handshake(s) => s.make_sync_heads(flags),
            PeerSession::Active(s) => s.make_sync_heads(flags),
        }
    }
}
