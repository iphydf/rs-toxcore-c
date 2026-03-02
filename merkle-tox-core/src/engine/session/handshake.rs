use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use crate::engine::session::{SessionCommon, SyncSession};
use crate::sync::{NodeStore, SyncHeads};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tox_proto::constants::MAX_HEADS_SYNC;

pub struct Handshake;

impl SyncSession<Handshake> {
    pub fn new(
        conversation_id: ConversationId,
        store: &dyn NodeStore,
        shallow: bool,
        now: Instant,
    ) -> Self {
        let heads = store.get_heads(&conversation_id);
        Self {
            conversation_id,
            common: SessionCommon {
                reachable: true,
                shallow,
                min_rank: 0,
                min_timestamp: 0,
                local_heads: heads.into_iter().collect(),
                remote_heads: HashSet::new(),
                missing_nodes_hot: VecDeque::new(),
                missing_nodes_cold: VecDeque::new(),
                in_flight_fetches: HashSet::new(),
                missing_blobs: HashSet::new(),
                peer_features: 0,
                time_samples: Vec::new(),
                vouchers: HashMap::new(),
                iblt_tiers: HashMap::new(),
                exhausted_iblt_ranges: HashSet::new(),
                heads_dirty: true,
                recon_dirty: true,
                last_recon_time: now,
                effective_difficulty: crate::sync::DEFAULT_RECON_DIFFICULTY,
                difficulty_votes: HashMap::new(),
                pending_challenges: HashMap::new(),
                pending_sketches: HashMap::new(),
                rate_limited_until: None,
                max_backfill_nodes: 0,
                backfill_count: 0,
                remote_anchor_hash: None,
            },
            state: Handshake,
        }
    }

    pub fn on_node_received(
        &mut self,
        node: &crate::dag::MerkleNode,
        store: &dyn NodeStore,
        _blob_store: Option<&dyn crate::sync::BlobStore>,
    ) {
        let hash = node.hash();
        self.common.in_flight_fetches.remove(&hash);

        for parent in &node.parents {
            self.common.local_heads.remove(parent);
        }

        if !store.has_children(&hash) {
            self.common.local_heads.insert(hash);
        }
        self.common.heads_dirty = true;

        // Basic parent tracking for bootstrap: admin parents get hot priority
        let is_admin = node.node_type() == crate::dag::NodeType::Admin;
        for parent in &node.parents {
            if !store.has_node(parent)
                && !self.common.missing_nodes_hot.contains(parent)
                && !self.common.missing_nodes_cold.contains(parent)
                && !self.common.in_flight_fetches.contains(parent)
            {
                if is_admin {
                    self.common.missing_nodes_hot.push_front(*parent);
                } else {
                    self.common.missing_nodes_hot.push_back(*parent);
                }
            }
        }
    }

    pub fn record_vouch(&mut self, node_hash: NodeHash, peer: PhysicalDevicePk) {
        self.common
            .vouchers
            .entry(node_hash)
            .or_default()
            .insert(peer);
    }

    pub fn next_wakeup(&self, now: Instant) -> Instant {
        now + Duration::from_secs(3600)
    }

    pub fn make_sync_heads(&self, flags: u64) -> SyncHeads {
        let mut heads: Vec<NodeHash> = self.common.local_heads.iter().cloned().collect();
        if heads.len() > MAX_HEADS_SYNC {
            heads.truncate(MAX_HEADS_SYNC);
        }
        SyncHeads {
            conversation_id: self.conversation_id,
            heads,
            flags,
            anchor_hash: None,
        }
    }

    pub fn activate(self, features: u64) -> SyncSession<crate::engine::session::active::Active> {
        let mut common = self.common;
        common.peer_features = features;
        SyncSession {
            conversation_id: self.conversation_id,
            common,
            state: crate::engine::session::active::Active,
        }
    }
}
