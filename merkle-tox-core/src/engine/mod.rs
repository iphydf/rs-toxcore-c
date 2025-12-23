use self::session::{Handshake, PeerSession, SyncSession};
use crate::ProtocolMessage;
use crate::cas::SwarmSync;
use crate::clock::{NetworkClock, TimeProvider};
use crate::crypto::ed25519_sk_to_x25519;
use crate::dag::{
    ChainKey, Content, ControlAction, ConversationId, EphemeralX25519Pk, EphemeralX25519Sk, KConv,
    LogicalIdentityPk, NodeHash, NodeType, PhysicalDeviceDhSk, PhysicalDevicePk, PhysicalDeviceSk,
};
use crate::error::MerkleToxResult;
use crate::identity::IdentityManager;
use crate::sync::NodeStore;
pub mod authoring;
pub mod conversation;
pub mod handlers;
pub mod processor;
pub mod session;
pub use self::conversation::{Conversation, ConversationData};
pub use self::processor::{VerificationStatus, VerifiedNode};
use parking_lot::Mutex;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

pub struct MerkleToxEngine {
    pub self_pk: PhysicalDevicePk,
    pub self_logical_pk: LogicalIdentityPk,
    pub self_sk: Option<PhysicalDeviceSk>,
    pub self_dh_sk: Option<PhysicalDeviceDhSk>,
    pub identity_manager: IdentityManager,
    pub clock: NetworkClock,
    /// (Peer PK, Conversation ID) -> SyncSession
    pub sessions: HashMap<(PhysicalDevicePk, ConversationId), PeerSession>,
    pub conversations: HashMap<ConversationId, Conversation>,
    pub blob_syncs: HashMap<NodeHash, SwarmSync>,
    /// Our generated ephemeral private keys: Public Key -> Private Key
    pub ephemeral_keys: HashMap<EphemeralX25519Pk, EphemeralX25519Sk>,
    /// peer_pk -> Last seen announcement
    pub peer_announcements: HashMap<PhysicalDevicePk, crate::dag::ControlAction>,
    pub rng: Mutex<StdRng>,
    /// Transient cache for nodes and state that have been "written" as effects
    /// but not yet committed to the store. Used for internal consistency.
    pub(crate) pending_cache: Mutex<PendingCache>,
}

pub(crate) struct PendingCache {
    pub nodes: HashMap<NodeHash, crate::dag::MerkleNode>,
    pub wire_nodes: HashMap<NodeHash, (ConversationId, crate::dag::WireNode)>,
    pub verified: HashSet<NodeHash>,
    pub heads: HashMap<ConversationId, Vec<NodeHash>>,
    pub admin_heads: HashMap<ConversationId, Vec<NodeHash>>,
    pub last_verified_sequences: HashMap<(ConversationId, PhysicalDevicePk), u64>,
}

impl PendingCache {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            wire_nodes: HashMap::new(),
            verified: HashSet::new(),
            heads: HashMap::new(),
            admin_heads: HashMap::new(),
            last_verified_sequences: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.wire_nodes.clear();
        self.verified.clear();
        self.heads.clear();
        self.admin_heads.clear();
        self.last_verified_sequences.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    RotationCheck(ConversationId),
    Reconciliation(PhysicalDevicePk, ConversationId),
    FetchMissing(PhysicalDevicePk, ConversationId),
    SwarmSync(NodeHash),
    SessionPoll(PhysicalDevicePk, ConversationId),
}

#[derive(Debug, Clone)]
pub enum Effect {
    SendPacket(PhysicalDevicePk, ProtocolMessage),
    WriteStore(ConversationId, crate::dag::MerkleNode, bool),
    WriteWireNode(ConversationId, NodeHash, crate::dag::WireNode),
    DeleteWireNode(ConversationId, NodeHash),
    WriteRatchetKey(ConversationId, NodeHash, ChainKey),
    DeleteRatchetKey(ConversationId, NodeHash),
    UpdateHeads(ConversationId, Vec<NodeHash>, bool), // cid, heads, is_admin
    WriteConversationKey(ConversationId, u64, KConv),
    WriteEpochMetadata(ConversationId, u32, i64),
    WriteBlobInfo(crate::cas::BlobInfo),
    WriteChunk(ConversationId, NodeHash, u64, Vec<u8>, Option<Vec<u8>>), // cid, hash, offset, data, proof
    EmitEvent(crate::NodeEvent),
    ScheduleWakeup(Task, Instant),
}

impl MerkleToxEngine {
    pub fn new(
        self_pk: PhysicalDevicePk,
        self_logical_pk: LogicalIdentityPk,
        rng: StdRng,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Self {
        Self {
            self_pk,
            self_logical_pk,
            self_sk: None,
            self_dh_sk: None,
            identity_manager: IdentityManager::new(),
            clock: NetworkClock::new(time_provider),
            sessions: HashMap::new(),
            conversations: HashMap::new(),
            blob_syncs: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            peer_announcements: HashMap::new(),
            rng: Mutex::new(rng),
            pending_cache: Mutex::new(PendingCache::new()),
        }
    }

    pub fn with_sk(
        self_pk: PhysicalDevicePk,
        self_logical_pk: LogicalIdentityPk,
        self_sk: PhysicalDeviceSk,
        rng: StdRng,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Self {
        let mut engine = Self::new(self_pk, self_logical_pk, rng, time_provider);
        engine.self_sk = Some(self_sk.clone());
        engine.self_dh_sk = Some(PhysicalDeviceDhSk::from(ed25519_sk_to_x25519(
            self_sk.as_bytes(),
        )));
        engine
    }

    pub fn with_full_keys(
        self_pk: PhysicalDevicePk,
        self_logical_pk: LogicalIdentityPk,
        self_sk: PhysicalDeviceSk,
        self_dh_sk: PhysicalDeviceDhSk,
        rng: StdRng,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Self {
        let mut engine = Self::new(self_pk, self_logical_pk, rng, time_provider);
        engine.self_sk = Some(self_sk);
        engine.self_dh_sk = Some(self_dh_sk);
        engine
    }

    /// Loads conversation keys and metadata from the store.
    pub fn load_conversation_state(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<()> {
        // 1. Reconstruct Identity state from verified Admin nodes
        let admin_nodes = store.get_verified_nodes_by_type(&conversation_id, NodeType::Admin)?;
        for node in &admin_nodes {
            if let Content::Control(action) = &node.content {
                match action {
                    ControlAction::Genesis {
                        creator_pk,
                        created_at,
                        ..
                    } => {
                        self.identity_manager.add_member(
                            conversation_id,
                            *creator_pk,
                            0,
                            *created_at,
                        );
                    }
                    ControlAction::AuthorizeDevice { cert } => {
                        let _ = self.identity_manager.authorize_device(
                            conversation_id,
                            node.author_pk,
                            cert,
                            node.network_timestamp,
                            node.topological_rank,
                        );
                    }
                    ControlAction::RevokeDevice {
                        target_device_pk, ..
                    } => {
                        self.identity_manager.revoke_device(
                            conversation_id,
                            *target_device_pk,
                            node.topological_rank,
                        );
                    }
                    ControlAction::Invite(invite) => {
                        self.identity_manager.add_member(
                            conversation_id,
                            invite.invitee_pk,
                            invite.role,
                            node.network_timestamp,
                        );
                    }
                    ControlAction::Leave(logical_pk) => {
                        self.identity_manager.remove_member(
                            conversation_id,
                            *logical_pk,
                            node.topological_rank,
                        );
                    }
                    ControlAction::Announcement { .. } => {
                        self.peer_announcements
                            .insert(node.sender_pk, action.clone());
                    }
                    _ => {}
                }
            }
        }

        // 2. Reconstruct last_verified_sequences for all devices
        let content_nodes =
            store.get_verified_nodes_by_type(&conversation_id, NodeType::Content)?;
        let mut all_nodes = admin_nodes;
        all_nodes.extend(content_nodes);

        let mut cache = self.pending_cache.lock();
        for node in all_nodes {
            let entry = cache
                .last_verified_sequences
                .entry((conversation_id, node.sender_pk))
                .or_insert(0);
            if node.sequence_number > *entry {
                *entry = node.sequence_number;
            }
        }
        drop(cache);

        // 3. Load Conversation Keys and Ratchet State
        let keys = store.get_conversation_keys(&conversation_id)?;
        if !keys.is_empty() {
            let now = self.clock.network_time_ms();
            let metadata = store.get_epoch_metadata(&conversation_id)?;
            let (count, rotation_time) = metadata.unwrap_or((0, now));

            let mut em = ConversationData::<conversation::Established>::new(
                conversation_id,
                keys[0].1.clone(),
                rotation_time,
            );
            for (epoch, k_conv) in keys.into_iter().skip(1) {
                em.add_epoch(epoch, k_conv);
            }
            em.state.message_count = count;

            // Load ratchet keys for current heads
            let heads = store.get_heads(&conversation_id);
            for head in heads {
                if let Some(key) = store.get_ratchet_key(&conversation_id, &head)? {
                    em.commit_node_key(head, &[], key);
                }
            }

            let admin_heads = store.get_admin_heads(&conversation_id);
            for head in admin_heads {
                if let Some(key) = store.get_ratchet_key(&conversation_id, &head)? {
                    em.commit_node_key(head, &[], key);
                }
            }

            self.conversations
                .insert(conversation_id, Conversation::Established(em));
        } else {
            self.conversations.insert(
                conversation_id,
                Conversation::Pending(ConversationData::<conversation::Pending>::new(
                    conversation_id,
                )),
            );
        }
        Ok(())
    }

    /// Registers a conversation and optionally initiates sync with a peer.
    pub fn start_sync(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: Option<PhysicalDevicePk>,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        self.start_shallow_sync(conversation_id, peer_pk, store, 0, 0)
    }

    /// Initiates a shallow sync with depth limits.
    pub fn start_shallow_sync(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: Option<PhysicalDevicePk>,
        store: &dyn NodeStore,
        min_rank: u64,
        min_timestamp: i64,
    ) -> Vec<Effect> {
        self.clear_pending();
        let _ = self.load_conversation_state(conversation_id, store);

        let mut effects = Vec::new();
        if let Some(peer) = peer_pk {
            let now = self.clock.time_provider().now_instant();
            let session = self
                .sessions
                .entry((peer, conversation_id))
                .or_insert_with(|| {
                    PeerSession::Handshake(
                        SyncSession::<Handshake>::new(
                            conversation_id,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            min_rank > 0 || min_timestamp > 0,
                            now,
                        )
                        .with_limits(min_rank, min_timestamp),
                    )
                });

            // Update limits if session already existed
            if min_rank > 0 || min_timestamp > 0 {
                let common = session.common_mut();
                common.shallow = true;
                common.min_rank = min_rank;
                common.min_timestamp = min_timestamp;
            }

            effects.push(Effect::SendPacket(
                peer,
                ProtocolMessage::CapsAnnounce {
                    version: 1,
                    features: 0,
                },
            ));
        }
        effects
    }

    // Periodic background tasks (e.g. CAS swarm requests, background reconciliation).
    pub fn poll(&mut self, now: Instant, store: &dyn NodeStore) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        let mut effects = Vec::new();
        let mut next_wakeup = now + Duration::from_secs(3600);

        // 0. Check for automatic rotation
        let now_ms = self.clock.network_time_ms();
        let conv_ids: Vec<ConversationId> = self.conversations.keys().cloned().collect();
        for cid in conv_ids {
            if self.check_rotation_triggers(cid) {
                // Only rotate if we are admin
                let is_admin = self.identity_manager.is_admin(
                    cid,
                    &self.self_pk,
                    &self.self_pk.to_logical(), // Assuming self-admin means master of self
                    now_ms,
                    u64::MAX,
                );

                if is_admin {
                    info!("Automatic rotation triggered for conversation {:?}", cid);
                    let conv_effects = self.rotate_conversation_key(cid, store)?;
                    effects.extend(conv_effects);
                    // The new nodes will be advertised via heads_dirty in SyncSessions
                }
            }
        }

        // Handle Blob requests
        for sync in self.blob_syncs.values_mut() {
            sync.clear_stalled_fetches(now);
            let reqs = sync.next_requests(4, now);
            for (peer, req) in reqs {
                tracing::debug!("Generated BlobReq for {:?} from {:?}", req.hash, peer);
                effects.push(Effect::SendPacket(peer, ProtocolMessage::BlobReq(req)));
            }
            next_wakeup = next_wakeup.min(sync.next_wakeup(now));
        }

        // Handle SyncSession heads advertisements and background fetching
        for ((peer_pk, cid), session) in self.sessions.iter_mut() {
            if let PeerSession::Active(s) = session {
                if s.common.heads_dirty {
                    effects.push(Effect::SendPacket(
                        *peer_pk,
                        ProtocolMessage::SyncHeads(s.make_sync_heads(0)),
                    ));
                    s.common.heads_dirty = false;
                }

                if s.common.recon_dirty
                    || now.duration_since(s.common.last_recon_time) > Duration::from_secs(60)
                {
                    effects.push(Effect::SendPacket(
                        *peer_pk,
                        ProtocolMessage::SyncShardChecksums {
                            conversation_id: s.conversation_id,
                            shards: s.make_sync_shard_checksums(&EngineStore {
                                store,
                                cache: &self.pending_cache,
                            })?,
                        },
                    ));
                    s.common.recon_dirty = false;
                    s.common.last_recon_time = now;
                }

                // Proactive Blob discovery: Query for blobs marked as missing in this session
                for blob_hash in s.common.missing_blobs.drain() {
                    effects.push(Effect::SendPacket(
                        *peer_pk,
                        ProtocolMessage::BlobQuery(blob_hash),
                    ));
                }

                // Periodic background fetch of missing nodes
                if let Some(req) = s.next_fetch_batch(tox_proto::constants::MAX_BATCH_SIZE) {
                    effects.push(Effect::SendPacket(
                        *peer_pk,
                        ProtocolMessage::FetchBatchReq(req),
                    ));
                }

                let session_wakeup = s.next_wakeup(now);
                next_wakeup = next_wakeup.min(session_wakeup);
                effects.push(Effect::ScheduleWakeup(
                    Task::SessionPoll(*peer_pk, *cid),
                    session_wakeup,
                ));
            }
        }

        effects.push(Effect::ScheduleWakeup(
            Task::SwarmSync(NodeHash::from([0u8; 32])),
            next_wakeup,
        ));

        Ok(effects)
    }

    /// Clears the transient pending state cache.
    pub fn clear_pending(&self) {
        self.pending_cache.lock().clear();
    }

    /// Returns the number of nodes in the pending cache.
    pub fn pending_cache_len(&self) -> usize {
        self.pending_cache.lock().nodes.len()
    }

    pub fn put_pending_node(&self, node: crate::dag::MerkleNode) {
        self.pending_cache.lock().nodes.insert(node.hash(), node);
    }
}

pub(crate) struct EngineStore<'a> {
    pub store: &'a dyn crate::sync::NodeStore,
    pub cache: &'a Mutex<PendingCache>,
}

impl<'a> crate::dag::NodeLookup for EngineStore<'a> {
    fn get_node_type(&self, hash: &NodeHash) -> Option<crate::dag::NodeType> {
        let cache = self.cache.lock();
        cache
            .nodes
            .get(hash)
            .map(|n| n.node_type())
            .or_else(|| self.store.get_node_type(hash))
    }
    fn get_rank(&self, hash: &NodeHash) -> Option<u64> {
        let cache = self.cache.lock();
        cache
            .nodes
            .get(hash)
            .map(|n| n.topological_rank)
            .or_else(|| self.store.get_rank(hash))
    }
    fn contains_node(&self, hash: &NodeHash) -> bool {
        let cache = self.cache.lock();
        cache.nodes.contains_key(hash) || self.store.contains_node(hash)
    }
    fn has_children(&self, hash: &NodeHash) -> bool {
        self.store.has_children(hash)
    }
}

impl<'a> crate::sync::NodeStore for EngineStore<'a> {
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        self.cache
            .lock()
            .heads
            .get(conversation_id)
            .cloned()
            .unwrap_or_else(|| self.store.get_heads(conversation_id))
    }
    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> crate::error::MerkleToxResult<()> {
        self.cache.lock().heads.insert(*conversation_id, heads);
        Ok(())
    }
    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        self.cache
            .lock()
            .admin_heads
            .get(conversation_id)
            .cloned()
            .unwrap_or_else(|| self.store.get_admin_heads(conversation_id))
    }
    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> crate::error::MerkleToxResult<()> {
        self.cache
            .lock()
            .admin_heads
            .insert(*conversation_id, heads);
        Ok(())
    }
    fn has_node(&self, hash: &NodeHash) -> bool {
        self.cache.lock().nodes.contains_key(hash) || self.store.has_node(hash)
    }
    fn is_verified(&self, hash: &NodeHash) -> bool {
        self.cache.lock().verified.contains(hash) || self.store.is_verified(hash)
    }
    fn get_node(&self, hash: &NodeHash) -> Option<crate::dag::MerkleNode> {
        self.cache
            .lock()
            .nodes
            .get(hash)
            .cloned()
            .or_else(|| self.store.get_node(hash))
    }
    fn get_wire_node(&self, hash: &NodeHash) -> Option<crate::dag::WireNode> {
        self.cache
            .lock()
            .wire_nodes
            .get(hash)
            .map(|(_, w)| w.clone())
            .or_else(|| self.store.get_wire_node(hash))
    }
    fn put_node(
        &self,
        conversation_id: &ConversationId,
        node: crate::dag::MerkleNode,
        verified: bool,
    ) -> crate::error::MerkleToxResult<()> {
        let mut cache = self.cache.lock();
        let hash = node.hash();
        if verified {
            cache
                .last_verified_sequences
                .insert((*conversation_id, node.sender_pk), node.sequence_number);
            cache.verified.insert(hash);
        }
        cache.nodes.insert(hash, node);
        Ok(())
    }
    fn put_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        node: crate::dag::WireNode,
    ) -> crate::error::MerkleToxResult<()> {
        self.cache
            .lock()
            .wire_nodes
            .insert(*hash, (*conversation_id, node));
        Ok(())
    }
    fn remove_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> crate::error::MerkleToxResult<()> {
        self.cache.lock().wire_nodes.remove(hash);
        self.store.remove_wire_node(conversation_id, hash)
    }
    fn get_opaque_node_hashes(
        &self,
        conversation_id: &ConversationId,
    ) -> crate::error::MerkleToxResult<Vec<NodeHash>> {
        let mut hashes = self.store.get_opaque_node_hashes(conversation_id)?;
        let cache = self.cache.lock();
        hashes.retain(|h| !cache.nodes.contains_key(h));
        for (hash, (cid, _)) in &cache.wire_nodes {
            if cid == conversation_id && !cache.nodes.contains_key(hash) && !hashes.contains(hash) {
                hashes.push(*hash);
            }
        }
        Ok(hashes)
    }
    fn get_speculative_nodes(
        &self,
        conversation_id: &ConversationId,
    ) -> Vec<crate::dag::MerkleNode> {
        let mut spec = self.store.get_speculative_nodes(conversation_id);
        let cache = self.cache.lock();
        spec.retain(|n| !cache.verified.contains(&n.hash()));
        for (hash, node) in &cache.nodes {
            if !cache.verified.contains(hash) && !spec.iter().any(|n| &n.hash() == hash) {
                spec.push(node.clone());
            }
        }
        spec
    }
    fn mark_verified(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> crate::error::MerkleToxResult<()> {
        let mut cache = self.cache.lock();
        cache.verified.insert(*hash);
        if let Some(node) = cache.nodes.get(hash) {
            let sender_pk = node.sender_pk;
            let seq = node.sequence_number;
            cache
                .last_verified_sequences
                .insert((*conversation_id, sender_pk), seq);
        }
        Ok(())
    }
    fn get_last_sequence_number(
        &self,
        conversation_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64 {
        self.cache
            .lock()
            .last_verified_sequences
            .get(&(*conversation_id, *sender_pk))
            .copied()
            .unwrap_or_else(|| {
                self.store
                    .get_last_sequence_number(conversation_id, sender_pk)
            })
    }
    fn get_node_counts(&self, conversation_id: &ConversationId) -> (usize, usize) {
        let (mut ver, mut spec) = self.store.get_node_counts(conversation_id);
        let cache = self.cache.lock();
        for hash in cache.nodes.keys() {
            // Only count if not already in store to avoid double counting
            if !self.store.has_node(hash) {
                if cache.verified.contains(hash) {
                    ver += 1;
                } else {
                    spec += 1;
                }
            }
        }
        (ver, spec)
    }
    fn get_verified_nodes_by_type(
        &self,
        conversation_id: &ConversationId,
        node_type: crate::dag::NodeType,
    ) -> crate::error::MerkleToxResult<Vec<crate::dag::MerkleNode>> {
        let mut nodes = self
            .store
            .get_verified_nodes_by_type(conversation_id, node_type)?;
        let cache = self.cache.lock();
        for (hash, node) in &cache.nodes {
            if cache.verified.contains(hash)
                && node.node_type() == node_type
                && !nodes.iter().any(|n| &n.hash() == hash)
            {
                nodes.push(node.clone());
            }
        }
        nodes.sort_by_key(|n| n.topological_rank);
        Ok(nodes)
    }
    fn get_node_hashes_in_range(
        &self,
        conversation_id: &ConversationId,
        range: &tox_reconcile::SyncRange,
    ) -> crate::error::MerkleToxResult<Vec<NodeHash>> {
        let mut hashes = self
            .store
            .get_node_hashes_in_range(conversation_id, range)?;
        let cache = self.cache.lock();
        for (hash, node) in &cache.nodes {
            if node.topological_rank >= range.min_rank
                && node.topological_rank <= range.max_rank
                && !hashes.contains(hash)
            {
                hashes.push(*hash);
            }
        }
        Ok(hashes)
    }
    fn size_bytes(&self) -> u64 {
        self.store.size_bytes()
    }
    fn put_conversation_key(
        &self,
        _cid: &ConversationId,
        _epoch: u64,
        _k: KConv,
    ) -> crate::error::MerkleToxResult<()> {
        Ok(())
    }
    fn get_conversation_keys(
        &self,
        cid: &ConversationId,
    ) -> crate::error::MerkleToxResult<Vec<(u64, KConv)>> {
        self.store.get_conversation_keys(cid)
    }
    fn update_epoch_metadata(
        &self,
        _cid: &ConversationId,
        _c: u32,
        _t: i64,
    ) -> crate::error::MerkleToxResult<()> {
        Ok(())
    }
    fn get_epoch_metadata(
        &self,
        cid: &ConversationId,
    ) -> crate::error::MerkleToxResult<Option<(u32, i64)>> {
        self.store.get_epoch_metadata(cid)
    }
    fn put_ratchet_key(
        &self,
        _cid: &ConversationId,
        _h: &NodeHash,
        _k: ChainKey,
    ) -> crate::error::MerkleToxResult<()> {
        Ok(())
    }
    fn get_ratchet_key(
        &self,
        cid: &ConversationId,
        h: &NodeHash,
    ) -> crate::error::MerkleToxResult<Option<ChainKey>> {
        self.store.get_ratchet_key(cid, h)
    }
    fn remove_ratchet_key(
        &self,
        _cid: &ConversationId,
        _h: &NodeHash,
    ) -> crate::error::MerkleToxResult<()> {
        Ok(())
    }
}
