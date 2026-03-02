use crate::dag::{LogicalIdentityPk, MerkleNode, NodeHash, PhysicalDevicePk, PowNonce, ShardHash};
use crate::engine::session::SyncSession;
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::{
    BlobStore, DecodingResult, FetchBatchReq, NodeStore, SyncHeads, SyncRange, Tier,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tox_proto::constants::MAX_HEADS_SYNC;
use tox_reconcile::IbltSketch;
use tracing::{debug, info};

pub struct Active;

impl SyncSession<Active> {
    pub fn get_iblt_tier(&self, range: &SyncRange) -> Option<Tier> {
        if self.common.exhausted_iblt_ranges.contains(range) {
            return None;
        }
        Some(
            self.common
                .iblt_tiers
                .get(range)
                .copied()
                .unwrap_or(Tier::Small),
        )
    }

    pub fn promote_iblt_tier(&mut self, range: &SyncRange) {
        if self.common.exhausted_iblt_ranges.contains(range) {
            return;
        }

        let current = self.get_iblt_tier(range).unwrap_or(Tier::Small);
        let next = match current {
            Tier::Tiny => Some(Tier::Small),
            Tier::Small => Some(Tier::Medium),
            Tier::Medium => Some(Tier::Large),
            Tier::Large => None, // Exhausted
        };

        if let Some(n) = next {
            self.common.iblt_tiers.insert(range.clone(), n);
        } else {
            self.common.exhausted_iblt_ranges.insert(range.clone());
            self.common.iblt_tiers.remove(range);
        }
    }

    pub fn record_vouch(&mut self, node_hash: NodeHash, peer: PhysicalDevicePk) {
        self.common
            .vouchers
            .entry(node_hash)
            .or_default()
            .insert(peer);
    }

    pub fn on_wire_node_received(
        &mut self,
        hash: NodeHash,
        wire: &crate::dag::WireNode,
        store: &dyn NodeStore,
    ) {
        self.common.in_flight_fetches.remove(&hash);

        for parent in &wire.parents {
            if !store.has_node(parent)
                && !self.common.missing_nodes_hot.contains(parent)
                && !self.common.missing_nodes_cold.contains(parent)
                && !self.common.in_flight_fetches.contains(parent)
            {
                // Type unknown for wire nodes; default to hot (optimistic).
                self.common.missing_nodes_hot.push_back(*parent);
            }
        }
    }

    /// Enqueues a missing hash into hot or cold queue based on rank relative to max head.
    pub fn enqueue_missing(
        &mut self,
        hash: NodeHash,
        hint_rank: Option<u64>,
        store: &dyn NodeStore,
    ) {
        if self.common.in_flight_fetches.contains(&hash) {
            return;
        }
        if self.common.missing_nodes_hot.contains(&hash)
            || self.common.missing_nodes_cold.contains(&hash)
        {
            return;
        }
        let max_head_rank = self
            .common
            .local_heads
            .iter()
            .chain(self.common.remote_heads.iter())
            .filter_map(|h| store.get_rank(h))
            .max()
            .unwrap_or(0);
        let is_hot =
            hint_rank.is_none_or(|r| r + tox_proto::constants::HOT_WINDOW_RANKS >= max_head_rank);
        if is_hot {
            self.common.missing_nodes_hot.push_back(hash);
        } else {
            self.common.missing_nodes_cold.push_back(hash);
        }
    }

    pub fn handle_sync_heads(&mut self, heads: SyncHeads, store: &dyn NodeStore) {
        if heads.conversation_id != self.conversation_id {
            return;
        }

        if let Some(anchor) = heads.anchor_hash {
            self.common.remote_anchor_hash = Some(anchor);
        }

        for head in heads.heads {
            let known = self.common.remote_heads.contains(&head);
            if !known {
                self.common.remote_heads.insert(head);
            }
            if !store.has_node(&head)
                && !self.common.missing_nodes_hot.contains(&head)
                && !self.common.missing_nodes_cold.contains(&head)
                && !self.common.in_flight_fetches.contains(&head)
            {
                // Heads are tips (always hot).
                self.common.missing_nodes_hot.push_back(head);
            }
        }
    }

    pub fn handle_sync_sketch(
        &mut self,
        sketch: tox_reconcile::SyncSketch,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<DecodingResult> {
        self.handle_sync_sketch_keyed(sketch, store, None)
    }

    pub fn handle_sync_sketch_keyed(
        &mut self,
        sketch: tox_reconcile::SyncSketch,
        store: &dyn NodeStore,
        k_iblt: Option<[u8; 32]>,
    ) -> MerkleToxResult<DecodingResult> {
        if sketch.conversation_id != self.conversation_id {
            return Ok(DecodingResult::Failed);
        }

        let mut local_iblt = IbltSketch::new_keyed(sketch.cells.len(), k_iblt);
        let local_hashes = store.get_node_hashes_in_range(&self.conversation_id, &sketch.range)?;
        for hash in local_hashes {
            local_iblt.insert(hash.as_ref());
        }

        let mut remote_iblt = IbltSketch::from_cells_keyed(sketch.cells, k_iblt);
        remote_iblt.subtract(&local_iblt).map_err(|e| {
            MerkleToxError::Reconciliation(format!("Sketch subtraction failed: {}", e))
        })?;

        match remote_iblt.decode() {
            Ok((missing_locally, missing_remotely, _stats)) => {
                debug!(
                    "IBLT decoding success for {:?}: missing_locally={}, missing_remotely={}",
                    self.conversation_id,
                    missing_locally.len(),
                    missing_remotely.len()
                );
                for hash in &missing_locally {
                    if !store.has_node(hash)
                        && !self.common.missing_nodes_hot.contains(hash)
                        && !self.common.missing_nodes_cold.contains(hash)
                        && !self.common.in_flight_fetches.contains(hash)
                    {
                        // Sketch-discovered nodes: rank unknown, assume hot.
                        self.common.missing_nodes_hot.push_back(*hash);
                    }
                }
                Ok(DecodingResult::Success {
                    missing_locally,
                    missing_remotely,
                })
            }
            Err(e) => {
                info!("IBLT decoding failed for {:?}: {}", self.conversation_id, e);
                self.promote_iblt_tier(&sketch.range);
                Ok(DecodingResult::Failed)
            }
        }
    }

    pub fn handle_sync_recon_fail(&mut self, range: SyncRange) {
        self.promote_iblt_tier(&range);
    }

    pub fn next_fetch_batch(&mut self, batch_size: usize) -> Option<FetchBatchReq> {
        let mut hashes = Vec::with_capacity(batch_size);
        // Hot first
        while hashes.len() < batch_size {
            if let Some(hash) = self.common.missing_nodes_hot.pop_front() {
                if !self.common.in_flight_fetches.contains(&hash) {
                    hashes.push(hash);
                    self.common.in_flight_fetches.insert(hash);
                }
            } else {
                break;
            }
        }
        // Then cold
        while hashes.len() < batch_size {
            if let Some(hash) = self.common.missing_nodes_cold.pop_front() {
                if !self.common.in_flight_fetches.contains(&hash) {
                    hashes.push(hash);
                    self.common.in_flight_fetches.insert(hash);
                }
            } else {
                break;
            }
        }

        if hashes.is_empty() {
            None
        } else {
            Some(FetchBatchReq {
                conversation_id: self.conversation_id,
                hashes,
            })
        }
    }

    pub fn on_node_received(
        &mut self,
        node: &MerkleNode,
        store: &dyn NodeStore,
        blob_store: Option<&dyn BlobStore>,
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

        if let crate::dag::Content::Blob { hash, .. } = &node.content
            && let Some(bs) = blob_store
            && !bs.has_blob(hash)
        {
            self.common.missing_blobs.insert(*hash);
        }

        if matches!(
            &node.content,
            crate::dag::Content::Control(
                crate::dag::ControlAction::Snapshot(_)
                    | crate::dag::ControlAction::AnchorSnapshot { .. }
            )
        ) && self.common.shallow
        {
            return;
        }

        if self.common.shallow
            && (node.topological_rank <= self.common.min_rank
                || node.network_timestamp <= self.common.min_timestamp)
        {
            return;
        }

        // Backfill count check for "last N messages" shallow sync
        let is_admin = node.node_type() == crate::dag::NodeType::Admin;
        if self.common.shallow && self.common.max_backfill_nodes > 0 {
            if !is_admin {
                self.common.backfill_count += 1;
            }
            if self.common.backfill_count >= self.common.max_backfill_nodes {
                return;
            }
        }

        for parent in &node.parents {
            if !store.has_node(parent)
                && !self.common.missing_nodes_hot.contains(parent)
                && !self.common.missing_nodes_cold.contains(parent)
                && !self.common.in_flight_fetches.contains(parent)
            {
                if is_admin {
                    self.common.missing_nodes_hot.push_front(*parent);
                } else {
                    // Use rank-based classification for content nodes
                    let parent_rank = node.topological_rank.saturating_sub(1);
                    self.enqueue_missing(*parent, Some(parent_rank), store);
                }
            }
        }
    }

    pub fn make_sync_heads(&self, flags: u64) -> SyncHeads {
        self.make_sync_heads_with_store(flags, None)
    }

    pub fn make_sync_heads_with_store(
        &self,
        flags: u64,
        store: Option<&dyn NodeStore>,
    ) -> SyncHeads {
        let mut heads: Vec<NodeHash> = self.common.local_heads.iter().cloned().collect();
        if heads.len() > MAX_HEADS_SYNC {
            heads.truncate(MAX_HEADS_SYNC);
        }
        let anchor_hash =
            store.and_then(|s| s.get_admin_heads(&self.conversation_id).first().cloned());
        SyncHeads {
            conversation_id: self.conversation_id,
            heads,
            flags,
            anchor_hash,
        }
    }

    pub fn make_sync_sketch(
        &self,
        range: SyncRange,
        tier: Tier,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<tox_reconcile::SyncSketch> {
        self.make_sync_sketch_keyed(range, tier, store, None)
    }

    pub fn make_sync_sketch_keyed(
        &self,
        range: SyncRange,
        tier: Tier,
        store: &dyn NodeStore,
        k_iblt: Option<[u8; 32]>,
    ) -> MerkleToxResult<tox_reconcile::SyncSketch> {
        let mut iblt = IbltSketch::new_keyed(tier.cell_count(), k_iblt);
        let hashes = store.get_node_hashes_in_range(&self.conversation_id, &range)?;
        for hash in hashes {
            iblt.insert(hash.as_ref());
        }

        Ok(tox_reconcile::SyncSketch {
            conversation_id: self.conversation_id,
            cells: iblt.into_cells(),
            range,
        })
    }

    pub fn make_sync_shard_checksums(
        &self,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<(SyncRange, ShardHash)>> {
        let mut shards = Vec::new();
        let heads = store.get_heads(&self.conversation_id);
        let max_rank = heads
            .iter()
            .filter_map(|h| store.get_rank(h))
            .max()
            .unwrap_or(0);

        for start_rank in (0..=max_rank).step_by(crate::sync::SHARD_SIZE as usize) {
            let range = SyncRange {
                min_rank: start_rank,
                max_rank: start_rank + crate::sync::SHARD_SIZE - 1,
            };
            let mut hashes = store.get_node_hashes_in_range(&self.conversation_id, &range)?;
            hashes.sort_unstable();
            let mut hasher = blake3::Hasher::new();
            for hash in hashes {
                hasher.update(hash.as_ref());
            }
            shards.push((range, ShardHash::from(*hasher.finalize().as_bytes())));
        }
        Ok(shards)
    }

    pub fn handle_sync_shard_checksums(
        &mut self,
        remote_shards: Vec<(SyncRange, ShardHash)>,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<SyncRange>> {
        let mut different_shards = Vec::new();
        let local_shards = self.make_sync_shard_checksums(store)?;
        let local_map: HashMap<_, _> = local_shards.into_iter().collect();

        for (range, remote_checksum) in remote_shards {
            if let Some(local_checksum) = local_map.get(&range) {
                if local_checksum != &remote_checksum {
                    different_shards.push(range);
                }
            } else {
                different_shards.push(range);
            }
        }
        Ok(different_shards)
    }

    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut wakeup = now + Duration::from_secs(3600);

        let has_fetchable_missing = self
            .common
            .missing_nodes_hot
            .iter()
            .chain(self.common.missing_nodes_cold.iter())
            .any(|h| !self.common.in_flight_fetches.contains(h));

        if self.common.heads_dirty || self.common.recon_dirty || has_fetchable_missing {
            wakeup = now;
        }

        for &expiry in self.common.pending_challenges.values() {
            wakeup = wakeup.min(expiry.max(now));
        }

        let next_recon = self.common.last_recon_time + crate::sync::RECONCILIATION_INTERVAL;
        if next_recon > now {
            wakeup = wakeup.min(next_recon);
        }

        // Account for rate_limited_until in wakeup scheduling
        if let Some(until) = self.common.rate_limited_until
            && until > now
        {
            wakeup = wakeup.min(until);
        }

        wakeup
    }

    pub fn generate_challenge(
        &mut self,
        sketch: tox_reconcile::SyncSketch,
        now: Instant,
        rng: &mut rand::rngs::StdRng,
    ) -> PowNonce {
        use rand::Rng;
        let nonce: [u8; 32] = rng.r#gen();
        let nonce = PowNonce::from(nonce);
        self.common
            .pending_challenges
            .insert(nonce, now + crate::sync::POW_CHALLENGE_TIMEOUT);
        self.common.pending_sketches.insert(nonce, sketch);
        nonce
    }

    pub fn take_pending_sketch(&mut self, nonce: PowNonce) -> Option<tox_reconcile::SyncSketch> {
        self.common.pending_sketches.remove(&nonce)
    }

    pub fn verify_solution(&mut self, nonce: PowNonce, solution: u64, now: Instant) -> bool {
        if let Some(expiry) = self.common.pending_challenges.get(&nonce) {
            if *expiry < now {
                self.common.pending_challenges.remove(&nonce);
                return false;
            }
        } else {
            return false;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(nonce.as_bytes());
        hasher.update(&solution.to_le_bytes());
        let hash = hasher.finalize();

        let mut leading_zeros = 0;
        for &byte in hash.as_bytes().iter() {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }

        let success = leading_zeros >= self.common.effective_difficulty;
        if success {
            self.common.pending_challenges.remove(&nonce);
        }
        success
    }

    pub fn update_difficulty_consensus(&mut self, voter: PhysicalDevicePk, difficulty: u32) {
        self.common.difficulty_votes.insert(voter, difficulty);
        let mut votes: Vec<_> = self.common.difficulty_votes.values().copied().collect();
        if votes.is_empty() {
            self.common.effective_difficulty = crate::sync::DEFAULT_RECON_DIFFICULTY;
            return;
        }
        votes.sort_unstable();
        self.common.effective_difficulty = votes[votes.len() / 2];
    }

    /// Prepares new MerkleNode with automatic parent merging and rank calculation.
    #[allow(clippy::too_many_arguments)]
    pub fn create_node(
        &self,
        author_pk: LogicalIdentityPk,
        sender_pk: PhysicalDevicePk,
        content: crate::dag::Content,
        metadata: Vec<u8>,
        timestamp: i64,
        sequence_number: u64,
        store: &dyn NodeStore,
    ) -> MerkleNode {
        let parents: Vec<NodeHash> = self.common.local_heads.iter().cloned().collect();
        let max_parent_rank = parents
            .iter()
            .filter_map(|p| store.get_rank(p))
            .max()
            .unwrap_or(0);

        MerkleNode {
            parents: parents.clone(),
            author_pk,
            sender_pk,
            sequence_number,
            topological_rank: if parents.is_empty() {
                0
            } else {
                max_parent_rank + 1
            },
            network_timestamp: timestamp,
            content,
            metadata,
            authentication: crate::dag::NodeAuth::EphemeralSignature(
                crate::dag::Ed25519Signature::from([0u8; 64]),
            ), // Placeholder
            pow_nonce: 0,
        }
    }
}

pub fn solve_challenge(nonce: PowNonce, difficulty: u32) -> u64 {
    let mut solution = 0u64;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(nonce.as_bytes());
        hasher.update(&solution.to_le_bytes());
        let hash = hasher.finalize();

        let mut leading_zeros = 0;
        for &byte in hash.as_bytes().iter() {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }

        if leading_zeros >= difficulty {
            return solution;
        }
        solution += 1;
    }
}
