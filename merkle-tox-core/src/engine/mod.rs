use self::session::{Handshake, PeerSession, SyncSession};
use crate::ProtocolMessage;
use crate::cas::SwarmSync;
use crate::clock::{NetworkClock, TimeProvider};
use crate::crypto::ed25519_sk_to_x25519;
use crate::dag::NodeLookup;
use crate::dag::{
    ChainKey, Content, ControlAction, ConversationId, EphemeralSigningPk, EphemeralSigningSk,
    EphemeralX25519Pk, EphemeralX25519Sk, KConv, LogicalIdentityPk, MerkleNode, NodeHash, NodeType,
    PhysicalDeviceDhSk, PhysicalDevicePk, PhysicalDeviceSk,
};
use crate::error::MerkleToxResult;
use crate::identity::IdentityManager;
use crate::sync::{NodeStore, SyncRange, Tier};
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
use tracing::{debug, info};

pub struct MerkleToxEngine {
    pub self_pk: PhysicalDevicePk,
    pub self_logical_pk: LogicalIdentityPk,
    pub self_sk: Option<PhysicalDeviceSk>,
    pub self_dh_sk: Option<PhysicalDeviceDhSk>,
    pub identity_manager: IdentityManager,
    pub clock: NetworkClock,
    /// Maps (Peer PK, Conversation ID) to SyncSession.
    pub sessions: HashMap<(PhysicalDevicePk, ConversationId), PeerSession>,
    pub conversations: HashMap<ConversationId, Conversation>,
    pub blob_syncs: HashMap<NodeHash, SwarmSync>,
    /// Maps generated ephemeral Public Key to Private Key.
    pub ephemeral_keys: HashMap<EphemeralX25519Pk, EphemeralX25519Sk>,
    /// Maps peer_pk to last seen announcement.
    pub peer_announcements: HashMap<PhysicalDevicePk, crate::dag::ControlAction>,
    pub rng: Mutex<StdRng>,
    /// Transient cache for nodes and state written as effects
    /// but not yet committed to store. Used for internal consistency.
    pub(crate) pending_cache: Mutex<PendingCache>,
    /// Tracks highest topological rank of handled HandshakePulses per peer.
    pub highest_handled_pulse: HashMap<(ConversationId, PhysicalDevicePk), u64>,
    /// Latest verified Genesis or Snapshot hash per conversation, used as
    /// `anchor_hash` in KeyWrap nodes.
    pub latest_anchor_hashes: HashMap<ConversationId, NodeHash>,
    /// Ephemeral signing keys per epoch for content node authoring.
    pub self_ephemeral_signing_keys: HashMap<u64, ed25519_dalek::SigningKey>,
    /// Peer ephemeral signing public keys: (sender_pk, epoch) to verifying key bytes.
    pub peer_ephemeral_signing_keys: HashMap<(PhysicalDevicePk, u64), EphemeralSigningPk>,
    /// Disclosed ephemeral signing private keys from past epochs for deniability.
    /// Maps (sender_pk, epoch) to disclosed_signing_sk_bytes.
    pub disclosed_signing_keys: HashMap<(PhysicalDevicePk, u64), EphemeralSigningSk>,
    /// Cache to avoid O(N^2) DAG traversals computing causal history.
    pub(crate) admin_ancestors_cache:
        Mutex<lru::LruCache<NodeHash, std::sync::Arc<std::collections::HashSet<NodeHash>>>>,
    /// Per-conversation opaque wire node store usage tracker.
    /// Tracks (total_bytes, Vec<(hash, size, timestamp, sender_pk)>) for quota enforcement.
    #[allow(clippy::type_complexity)]
    pub opaque_store_usage:
        HashMap<ConversationId, (usize, Vec<(NodeHash, usize, i64, PhysicalDevicePk)>)>,
    /// Counts X3DH handshakes (KeyWrap decryptions consuming ephemeral keys)
    /// per conversation. When >= MAX_HANDSHAKES_PER_ANNOUNCEMENT, fresh
    /// Announcement should be published.
    pub handshake_count_since_announcement: HashMap<ConversationId, u32>,
    /// Devices restored via AnchorSnapshot (heal timestamp in ms).
    /// If not re-keyed within TRUST_RESTORED_EXPIRY_MS, conversation
    /// is downgraded to permanent observer mode.
    pub trust_restored_devices: HashMap<(ConversationId, PhysicalDevicePk), i64>,
    /// Pending KeyWrap ACKs: keywrap_hash to pending state.
    /// When authoring KeyWrap consuming OPK, enters pending state
    /// and buffers content until KEYWRAP_ACK received.
    pub keywrap_pending: HashMap<NodeHash, KeyWrapPending>,
    /// OPK IDs consumed by received KeyWraps.
    /// Maps opk_id to (keywrap_hash, sender_pk, topological_rank) for collision detection.
    pub consumed_opk_ids: HashMap<NodeHash, (NodeHash, PhysicalDevicePk, u64)>,
    /// Anti-Branching: tracks accepted SoftAnchor (device_pk, basis_hash) pairs
    /// per conversation. Spec: Relays MUST accept only one SoftAnchor per
    /// device_pk per basis_hash.
    pub soft_anchor_dedup: HashMap<ConversationId, HashSet<(PhysicalDevicePk, NodeHash)>>,
    /// Tracks (conversation_id, sender_pk, sequence_number) → NodeHash for
    /// equivocation detection.
    pub verified_node_seqs: HashMap<(ConversationId, PhysicalDevicePk, u64), NodeHash>,
    /// Detected equivocations: (conv_id, device_pk, seq, existing_hash, conflicting_hash).
    /// Recorded as engine state so they survive even when the duplicate node is rejected.
    #[allow(clippy::type_complexity)]
    pub equivocations: Vec<(ConversationId, PhysicalDevicePk, u64, NodeHash, NodeHash)>,
    /// Handshake retry state per (conversation, peer) for exponential backoff.
    pub handshake_retry_state: HashMap<(ConversationId, PhysicalDevicePk), HandshakeRetryState>,
    /// Tracks number of KeywrapAck received per conversation for announcement key erasure.
    /// When ack_count / total_recipients >= 50%, old ephemeral keys should be erased.
    pub keywrap_ack_counts: HashMap<ConversationId, (u32, u32)>, // (acks_received, total_recipients)
    /// Blacklist state per peer for 3-tier exponential escalation.
    pub peer_blacklist: HashMap<PhysicalDevicePk, BlacklistState>,
    /// Last time a gossip sketch was broadcast per conversation.
    pub last_gossip_time: HashMap<ConversationId, Instant>,
    /// Our DelegationCertificate per conversation, captured from our
    /// AuthorizeDevice node. Needed for SoftAnchor authoring.
    pub self_certs: HashMap<ConversationId, crate::dag::DelegationCertificate>,
    /// Node hashes currently being promoted from opaque store.
    /// Prevents eviction of entries that are mid-promotion in `reverify_opaque_nodes`.
    pub promotion_locked: HashSet<NodeHash>,
    /// Per-peer CPU budget for sketch decode operations (token bucket).
    pub sketch_cpu_budgets: HashMap<PhysicalDevicePk, CpuBudget>,
    /// Network timestamp (ms) of our last Announcement per conversation.
    /// Used for 30-day rotation trigger in `poll()`.
    pub last_announcement_time_ms: HashMap<ConversationId, i64>,
}

/// State for pending KeyWrap awaiting KEYWRAP_ACK.
#[derive(Debug, Clone)]
pub struct KeyWrapPending {
    pub conversation_id: ConversationId,
    pub recipient_pk: PhysicalDevicePk,
    pub created_at: Instant,
    /// Number of retry attempts (0 = first try). Cap at 3.
    pub attempts: u32,
}

/// State for handshake retry with exponential backoff.
#[derive(Debug, Clone, Default)]
pub struct HandshakeRetryState {
    /// Number of error responses received.
    pub attempts: u32,
    /// Earliest time (network ms) to retry handshake.
    pub next_retry_ms: i64,
    /// Start of the current retry window (network ms).
    pub window_start_ms: i64,
}

/// Per-peer token-bucket CPU budget for IBLT sketch decode operations.
#[derive(Debug, Clone)]
pub struct CpuBudget {
    pub remaining_ms: f64,
    pub last_refill_ms: i64,
}

impl CpuBudget {
    pub fn new(now_ms: i64) -> Self {
        Self {
            remaining_ms: tox_proto::constants::SKETCH_CPU_BUDGET_MS as f64,
            last_refill_ms: now_ms,
        }
    }

    /// Refills tokens based on elapsed time (token bucket at constant rate).
    pub fn refill(&mut self, now_ms: i64) {
        let elapsed = (now_ms - self.last_refill_ms).max(0) as f64;
        let rate = tox_proto::constants::SKETCH_CPU_BUDGET_MS as f64
            / tox_proto::constants::SKETCH_CPU_WINDOW_MS as f64;
        self.remaining_ms = (self.remaining_ms + elapsed * rate)
            .min(tox_proto::constants::SKETCH_CPU_BUDGET_MS as f64);
        self.last_refill_ms = now_ms;
    }

    /// Tries to consume `cost_ms` from the budget. Returns false if insufficient.
    pub fn try_consume(&mut self, cost_ms: f64) -> bool {
        if self.remaining_ms >= cost_ms {
            self.remaining_ms -= cost_ms;
            true
        } else {
            false
        }
    }
}

/// Maximum handshake retries per peer within a 10-minute window.
pub const HANDSHAKE_RETRY_CAP: u32 = 3;
/// Duration of the handshake retry window (10 minutes in ms).
pub const HANDSHAKE_RETRY_WINDOW_MS: i64 = 600_000;
/// Base delay for exponential backoff on handshake retries (2 seconds).
pub const HANDSHAKE_RETRY_BASE_MS: u64 = 2000;
/// Maximum delay for exponential backoff on handshake retries (8 seconds).
pub const HANDSHAKE_RETRY_MAX_MS: u64 = 8000;

/// Blacklist state for a peer with 3-tier exponential escalation.
#[derive(Debug, Clone)]
pub struct BlacklistState {
    /// Current blacklist tier (1-3). 0 means not blacklisted.
    pub tier: u8,
    /// Time (network ms) when the blacklist expires.
    pub expires_at_ms: i64,
}

impl BlacklistState {
    /// Returns the duration for the given tier.
    pub fn tier_duration(tier: u8) -> i64 {
        match tier {
            1 => tox_proto::constants::BLACKLIST_TIER1_MS,
            2 => tox_proto::constants::BLACKLIST_TIER2_MS,
            _ => tox_proto::constants::BLACKLIST_TIER3_MS,
        }
    }

    /// Escalates to the next tier, capping at 3.
    pub fn escalate(&mut self, now_ms: i64) {
        self.tier = (self.tier + 1).min(3);
        self.expires_at_ms = now_ms + Self::tier_duration(self.tier);
    }

    /// Returns true if the peer is currently blacklisted.
    pub fn is_active(&self, now_ms: i64) -> bool {
        self.tier > 0 && now_ms < self.expires_at_ms
    }
}

pub(crate) struct PendingCache {
    pub nodes: HashMap<NodeHash, crate::dag::MerkleNode>,
    pub wire_nodes: HashMap<NodeHash, (ConversationId, crate::dag::WireNode)>,
    pub verified: HashSet<NodeHash>,
    pub heads: HashMap<ConversationId, Vec<NodeHash>>,
    pub admin_heads: HashMap<ConversationId, Vec<NodeHash>>,
    pub last_verified_sequences: HashMap<(ConversationId, PhysicalDevicePk), u64>,
    pub admin_distances: HashMap<NodeHash, u64>,
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
            admin_distances: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.wire_nodes.clear();
        self.verified.clear();
        self.heads.clear();
        self.admin_heads.clear();
        self.last_verified_sequences.clear();
        self.admin_distances.clear();
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
    WriteRatchetKey(ConversationId, NodeHash, ChainKey, u64), // cid, hash, key, epoch_id
    DeleteRatchetKey(ConversationId, NodeHash),
    UpdateHeads(ConversationId, Vec<NodeHash>, bool), // cid, heads, is_admin
    WriteConversationKey(ConversationId, u64, KConv),
    WriteEpochMetadata(ConversationId, u32, i64),
    WriteBlobInfo(crate::cas::BlobInfo),
    WriteChunk(ConversationId, NodeHash, u64, Vec<u8>, Option<Vec<u8>>), // cid, hash, offset, data, proof
    EmitEvent(crate::NodeEvent),
    ScheduleWakeup(Task, Instant),
    NodeEquivocation {
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
        seq: u64,
        existing_hash: NodeHash,
        conflicting_hash: NodeHash,
    },
    /// Signal application layer to create a history snapshot for CAS upload.
    HistorySnapshotNeeded(ConversationId),
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
            highest_handled_pulse: HashMap::new(),
            latest_anchor_hashes: HashMap::new(),
            self_ephemeral_signing_keys: HashMap::new(),
            peer_ephemeral_signing_keys: HashMap::new(),
            disclosed_signing_keys: HashMap::new(),
            rng: Mutex::new(rng),
            pending_cache: Mutex::new(PendingCache::new()),
            admin_ancestors_cache: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(20000).unwrap(),
            )),
            opaque_store_usage: HashMap::new(),
            handshake_count_since_announcement: HashMap::new(),
            trust_restored_devices: HashMap::new(),
            keywrap_pending: HashMap::new(),
            consumed_opk_ids: HashMap::new(),
            soft_anchor_dedup: HashMap::new(),
            self_certs: HashMap::new(),
            verified_node_seqs: HashMap::new(),
            equivocations: Vec::new(),
            handshake_retry_state: HashMap::new(),
            keywrap_ack_counts: HashMap::new(),
            peer_blacklist: HashMap::new(),
            last_gossip_time: HashMap::new(),
            promotion_locked: HashSet::new(),
            sketch_cpu_budgets: HashMap::new(),
            last_announcement_time_ms: HashMap::new(),
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

    /// Loads conversation keys and metadata from store.
    pub fn load_conversation_state(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<()> {
        // 1. Reconstruct Identity state from verified Admin nodes
        let admin_nodes = store.get_verified_nodes_by_type(&conversation_id, NodeType::Admin)?;
        for node in &admin_nodes {
            let mut admin_ancestor_hashes = std::collections::HashSet::new();
            let mut stack = node.parents.clone();
            let mut visited = std::collections::HashSet::new();

            while let Some(parent_hash) = stack.pop() {
                if visited.insert(parent_hash)
                    && let Some(parent_node) = store.get_node(&parent_hash)
                {
                    if parent_node.node_type() == crate::dag::NodeType::Admin {
                        admin_ancestor_hashes.insert(parent_hash);
                    }
                    if let Some(cached) = self.admin_ancestors_cache.lock().get(&parent_hash) {
                        admin_ancestor_hashes.extend(cached.iter().cloned());
                    } else {
                        stack.extend(parent_node.parents.clone());
                    }
                }
            }
            self.admin_ancestors_cache.lock().put(
                node.hash(),
                std::sync::Arc::new(admin_ancestor_hashes.clone()),
            );

            let ctx = crate::identity::CausalContext {
                evaluating_node_hash: node.hash(),
                admin_ancestor_hashes,
            };

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
                            &ctx,
                            conversation_id,
                            node.author_pk,
                            cert,
                            node.network_timestamp,
                            node.topological_rank,
                            node.hash(),
                        );
                    }
                    ControlAction::RevokeDevice {
                        target_device_pk, ..
                    } => {
                        self.identity_manager.revoke_device(
                            conversation_id,
                            node.sender_pk,
                            node.author_pk,
                            *target_device_pk,
                            node.topological_rank,
                            node.network_timestamp,
                            node.hash(),
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
                            node.sender_pk,
                            node.author_pk,
                            *logical_pk,
                            node.topological_rank,
                            node.network_timestamp,
                            node.hash(),
                        );
                    }
                    ControlAction::Announcement {
                        pre_keys,
                        last_resort_key,
                    } => {
                        use ed25519_dalek::{Verifier, VerifyingKey};
                        let valid_pre_keys =
                            if let Ok(vk) = VerifyingKey::from_bytes(node.sender_pk.as_bytes()) {
                                pre_keys
                                    .iter()
                                    .filter(|spk| {
                                        let sig = ed25519_dalek::Signature::from_bytes(
                                            spk.signature.as_ref(),
                                        );
                                        vk.verify(spk.public_key.as_bytes(), &sig).is_ok()
                                    })
                                    .cloned()
                                    .collect()
                            } else {
                                Vec::new()
                            };
                        self.peer_announcements.insert(
                            node.sender_pk,
                            ControlAction::Announcement {
                                pre_keys: valid_pre_keys,
                                last_resort_key: last_resort_key.clone(),
                            },
                        );
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

            // Load ratchet keys for verified nodes
            let all_verified =
                store.get_verified_nodes_by_type(&conversation_id, NodeType::Admin)?;
            let content_nodes =
                store.get_verified_nodes_by_type(&conversation_id, NodeType::Content)?;
            let mut all_nodes = all_verified;
            all_nodes.extend(content_nodes);

            let mut last_nodes: HashMap<PhysicalDevicePk, MerkleNode> = HashMap::new();
            for node in all_nodes {
                let entry = last_nodes.entry(node.sender_pk).or_insert(node.clone());
                if node.sequence_number > entry.sequence_number {
                    *entry = node;
                }
            }

            for (sender_pk, node) in last_nodes {
                if let Some((key, epoch_id)) =
                    store.get_ratchet_key(&conversation_id, &node.hash())?
                {
                    em.commit_node_key(sender_pk, node.sequence_number, key, node.hash(), epoch_id);
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

    /// Registers conversation and optionally initiates sync with peer.
    pub fn start_sync(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: Option<PhysicalDevicePk>,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        self.start_shallow_sync(conversation_id, peer_pk, store, 0, 0)
    }

    /// Initiates shallow sync with depth limits.
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

    /// Starts shallow sync limited to the last N content messages from heads.
    pub fn start_shallow_sync_last_n(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: Option<PhysicalDevicePk>,
        store: &dyn NodeStore,
        last_n: u64,
    ) -> Vec<Effect> {
        let effects = self.start_shallow_sync(conversation_id, peer_pk, store, 0, 0);
        // Set max_backfill_nodes on sessions for this conversation
        for ((_, cid), session) in self.sessions.iter_mut() {
            if *cid == conversation_id {
                let c = session.common_mut();
                c.shallow = true;
                c.max_backfill_nodes = last_n;
                c.backfill_count = 0;
            }
        }
        effects
    }

    /// Sends reinclusion request to admin for trust-restored conversation.
    pub fn request_reinclusion(
        &self,
        conversation_id: ConversationId,
        admin_pk: PhysicalDevicePk,
        snapshot_hash: NodeHash,
    ) -> Vec<Effect> {
        vec![Effect::SendPacket(
            admin_pk,
            ProtocolMessage::ReinclusionRequest {
                conversation_id,
                sender_pk: self.self_pk,
                healing_snapshot_hash: snapshot_hash,
            },
        )]
    }

    // Periodic background tasks (e.g., CAS swarm requests, background reconciliation).
    pub fn poll(&mut self, now: Instant, store: &dyn NodeStore) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        let mut effects = Vec::new();
        let mut next_wakeup = now + Duration::from_secs(3600);

        // 0. Check for automatic rotation
        let now_ms = self.clock.network_time_ms();

        // Proactively evict stale skipped_keys across established conversations.
        for conv in self.conversations.values_mut() {
            if let Conversation::Established(em) = conv {
                em.state
                    .skipped_keys
                    .retain(|_, &mut (_, timestamp)| now_ms - timestamp <= 86_400_000);
            }
        }

        // Evict stale vouchers (VOUCHER_TIMEOUT_MS = 10s).
        for conv in self.conversations.values_mut() {
            for vouch_map in conv.vouchers_mut().values_mut() {
                vouch_map
                    .retain(|_, &mut ts| now_ms - ts <= tox_proto::constants::VOUCHER_TIMEOUT_MS);
            }
            conv.vouchers_mut().retain(|_, v| !v.is_empty());
        }

        // Check trust-restored devices for 30-day expiry.
        // If self expired, downgrade conversation to Pending (permanent observer mode).
        let expired_trust: Vec<(ConversationId, PhysicalDevicePk)> = self
            .trust_restored_devices
            .iter()
            .filter(|&(_, &heal_ts)| {
                now_ms - heal_ts > tox_proto::constants::TRUST_RESTORED_EXPIRY_MS
            })
            .map(|(key, _)| *key)
            .collect();
        for (cid, pk) in expired_trust {
            self.trust_restored_devices.remove(&(cid, pk));
            if pk == self.self_pk {
                // Downgrade to Pending: permanent observer mode
                if let Some(conv) = self.conversations.remove(&cid) {
                    let pending = ConversationData::<conversation::Pending>::new(cid);
                    self.conversations
                        .insert(cid, Conversation::Pending(pending));
                    info!(
                        "Trust-restored expiry for {:?}: downgraded to Pending (observer mode)",
                        cid
                    );
                    let _ = conv; // drop established state
                }
            }
        }

        // Auto-send reinclusion requests when approaching 25-day mark
        // (5-day buffer before 30-day expiry).
        const REINCLUSION_REQUEST_THRESHOLD_MS: i64 = 25 * 24 * 60 * 60 * 1000;
        for (&(cid, pk), &heal_ts) in &self.trust_restored_devices {
            if pk == self.self_pk
                && now_ms - heal_ts > REINCLUSION_REQUEST_THRESHOLD_MS
                && now_ms - heal_ts <= tox_proto::constants::TRUST_RESTORED_EXPIRY_MS
            {
                // Find admin for request
                if let Some(anchor_hash) = self.latest_anchor_hashes.get(&cid) {
                    let ctx = crate::identity::CausalContext::global();
                    let admins = self.identity_manager.list_active_authorized_devices(
                        &ctx,
                        cid,
                        now_ms,
                        u64::MAX,
                    );
                    for admin_pk in admins {
                        if admin_pk != self.self_pk
                            && self.identity_manager.is_admin(
                                &ctx,
                                cid,
                                &admin_pk,
                                &admin_pk.to_logical(),
                                now_ms,
                                u64::MAX,
                            )
                        {
                            effects.extend(self.request_reinclusion(cid, admin_pk, *anchor_hash));
                            break; // One request per poll cycle
                        }
                    }
                }
            }
        }

        let conv_ids: Vec<ConversationId> = self.conversations.keys().cloned().collect();
        for cid in conv_ids {
            if self.check_rotation_triggers(cid) {
                // Only rotate if admin. Use global context: it bypasses
                // per-node causal ancestry check, appropriate for this
                // proactive self-check (no specific node evaluated).
                let ctx = crate::identity::CausalContext::global();
                let is_admin = self.identity_manager.is_admin(
                    &ctx,
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
                    // New nodes advertised via heads_dirty in SyncSessions
                }
            } else if self.check_sender_rekey_triggers(cid) {
                // Per-device Sender Rekey for non-admins (admins get it via K_conv rotation)
                let rekey_effects = self.sender_rekey(cid, store)?;
                effects.extend(rekey_effects);
            }
        }

        // Check if conversation needs announcement rotation after 100 handshakes
        // or after 30 days since last announcement.
        let now_ms = self.clock.network_time_ms();
        let mut announcement_convs: Vec<ConversationId> = self
            .handshake_count_since_announcement
            .iter()
            .filter(|&(_, &count)| count >= tox_proto::constants::MAX_HANDSHAKES_PER_ANNOUNCEMENT)
            .map(|(cid, _)| *cid)
            .collect();
        // Also trigger for conversations whose last announcement is older than 30 days
        for (cid, &last_time) in &self.last_announcement_time_ms {
            if now_ms - last_time >= tox_proto::constants::ANNOUNCEMENT_ROTATION_INTERVAL_MS
                && !announcement_convs.contains(cid)
            {
                announcement_convs.push(*cid);
            }
        }
        for cid in announcement_convs {
            match self.author_announcement(cid, store) {
                Ok(ann_effects) => {
                    effects.extend(ann_effects);
                    self.handshake_count_since_announcement.insert(cid, 0);
                    self.last_announcement_time_ms.insert(cid, now_ms);
                }
                Err(e) => {
                    debug!(
                        "Failed to author announcement rotation for {:?}: {}",
                        cid, e
                    );
                }
            }
        }

        // KEYWRAP_ACK timeout (merkle-tox-handshake-ecies.md §2.A.3):
        // If no ACK within 30s, retry with different OPK (max 3 attempts).
        const KEYWRAP_ACK_TIMEOUT: Duration = Duration::from_secs(30);
        const MAX_KEYWRAP_RETRIES: u32 = 3;
        // Collect expired pending info before retain drops it.
        let mut removed_pending: HashMap<NodeHash, KeyWrapPending> = HashMap::new();
        self.keywrap_pending.retain(|hash, pending| {
            if pending.created_at.elapsed() < KEYWRAP_ACK_TIMEOUT {
                true // keep: still waiting
            } else if pending.attempts < MAX_KEYWRAP_RETRIES {
                debug!(
                    "KEYWRAP_ACK timeout for {:?} (attempt {}), will retry",
                    pending.conversation_id,
                    pending.attempts + 1
                );
                removed_pending.insert(*hash, pending.clone());
                false // remove: will be re-created on retry
            } else {
                debug!(
                    "KEYWRAP_ACK timeout for {:?}, max retries reached, giving up",
                    pending.conversation_id
                );
                false // remove: exhausted retries
            }
        });
        // Retry expired keywrap handshakes with a fresh OPK.
        for (_hash, pending) in removed_pending {
            let conv_id = pending.conversation_id;
            let peer_pk = pending.recipient_pk;
            let attempt = pending.attempts + 1;
            if let Some(spk) = self.get_recipient_spk(&peer_pk) {
                match self.author_x3dh_key_exchange(conv_id, peer_pk, spk, store) {
                    Ok(fx) => {
                        // Update attempt counter on the new pending entry.
                        if let Some(new_pending) = self
                            .keywrap_pending
                            .values_mut()
                            .find(|p| p.conversation_id == conv_id && p.recipient_pk == peer_pk)
                        {
                            new_pending.attempts = attempt;
                        }
                        effects.extend(fx);
                    }
                    Err(e) => debug!("KEYWRAP retry failed for {:?}: {}", conv_id, e),
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
            if !session.common().reachable {
                continue;
            }
            if let PeerSession::Active(s) = session {
                // Clear expired PoW challenges
                s.common
                    .pending_challenges
                    .retain(|_, &mut expiry| expiry > now);
                s.common
                    .pending_sketches
                    .retain(|nonce, _| s.common.pending_challenges.contains_key(nonce));

                // Clear expired rate_limited_until
                if s.common.rate_limited_until.is_some_and(|u| now >= u) {
                    s.common.rate_limited_until = None;
                }

                if s.common.heads_dirty {
                    effects.push(Effect::SendPacket(
                        *peer_pk,
                        ProtocolMessage::SyncHeads(s.make_sync_heads_with_store(0, Some(store))),
                    ));
                    s.common.heads_dirty = false;
                }

                // Guard recon with rate-limited check
                let rate_ok = s.common.rate_limited_until.is_none_or(|until| now >= until);
                if rate_ok
                    && (s.common.recon_dirty
                        || now.duration_since(s.common.last_recon_time)
                            > crate::sync::RECONCILIATION_INTERVAL)
                {
                    match s.make_sync_shard_checksums(&EngineStore {
                        store,
                        cache: &self.pending_cache,
                    }) {
                        Ok(shards) => {
                            effects.push(Effect::SendPacket(
                                *peer_pk,
                                ProtocolMessage::SyncShardChecksums {
                                    conversation_id: s.conversation_id,
                                    shards,
                                },
                            ));
                            s.common.recon_dirty = false;
                            s.common.last_recon_time = now;
                        }
                        Err(e) => {
                            debug!("Failed to compute shard checksums for {:?}: {}", cid, e);
                            // Back off to prevent tight loop; retry after
                            // RECONCILIATION_INTERVAL or when new data arrives.
                            s.common.recon_dirty = false;
                            s.common.last_recon_time = now;
                        }
                    }
                }

                // Proactive Blob discovery: Query blobs marked missing in this session
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
                if session_wakeup <= now {
                    debug!(
                        "Session {:?} requesting immediate wakeup: heads_dirty={}, recon_dirty={}, missing_hot={}, missing_cold={}",
                        cid,
                        s.common.heads_dirty,
                        s.common.recon_dirty,
                        s.common.missing_nodes_hot.len(),
                        s.common.missing_nodes_cold.len()
                    );
                }
                next_wakeup = next_wakeup.min(session_wakeup);
                effects.push(Effect::ScheduleWakeup(
                    Task::SessionPoll(*peer_pk, *cid),
                    session_wakeup,
                ));
            }
        }

        // Multicast Gossip: broadcast Tiny IBLT sketch every 60s per conversation
        let gossip_convs: Vec<ConversationId> = self.conversations.keys().cloned().collect();
        for cid in gossip_convs {
            let last = self
                .last_gossip_time
                .get(&cid)
                .copied()
                .unwrap_or_else(|| now - crate::sync::GOSSIP_INTERVAL);
            if now.duration_since(last) >= crate::sync::GOSSIP_INTERVAL {
                let overlay = EngineStore {
                    store,
                    cache: &self.pending_cache,
                };
                let heads = overlay.get_heads(&cid);
                let max_rank = heads
                    .iter()
                    .filter_map(|h| overlay.get_rank(h))
                    .max()
                    .unwrap_or(0);
                let range = SyncRange {
                    min_rank: 0,
                    max_rank,
                };
                let k_iblt = match self.conversations.get(&cid) {
                    Some(Conversation::Established(em)) => em
                        .get_keys(em.current_epoch())
                        .map(|k| crate::crypto::derive_k_iblt(&k.k_conv, &cid)),
                    _ => None,
                };
                let mut iblt =
                    tox_reconcile::IbltSketch::new_keyed(Tier::Tiny.cell_count(), k_iblt);
                if let Ok(hashes) = overlay.get_node_hashes_in_range(&cid, &range) {
                    for hash in hashes {
                        iblt.insert(hash.as_ref());
                    }
                }
                let sketch = tox_reconcile::SyncSketch {
                    conversation_id: cid,
                    cells: iblt.into_cells(),
                    range,
                };
                // Send to all active peers for this conversation
                for ((peer_pk, peer_cid), session) in &self.sessions {
                    if *peer_cid == cid && matches!(session, PeerSession::Active(_)) {
                        effects.push(Effect::SendPacket(
                            *peer_pk,
                            ProtocolMessage::SyncSketch(sketch.clone()),
                        ));
                    }
                }
                self.last_gossip_time.insert(cid, now);
            }
            let effective_last = self.last_gossip_time.get(&cid).copied().unwrap_or(now);
            let next_gossip = effective_last + crate::sync::GOSSIP_INTERVAL;
            next_wakeup = next_wakeup.min(next_gossip);
        }

        effects.push(Effect::ScheduleWakeup(
            Task::SwarmSync(NodeHash::from([0u8; 32])),
            next_wakeup,
        ));

        Ok(effects)
    }

    /// Clears transient pending state cache.
    pub fn clear_pending(&self) {
        self.pending_cache.lock().clear();
    }

    /// Returns number of nodes in pending cache.
    pub fn pending_cache_len(&self) -> usize {
        self.pending_cache.lock().nodes.len()
    }

    pub fn put_pending_node(&self, node: crate::dag::MerkleNode) {
        self.pending_cache.lock().nodes.insert(node.hash(), node);
    }

    /// Looks up recipient's Signed Pre-Key (SPK) from Announcement.
    /// Prefers first non-expired pre-key, falls back to last_resort_key.
    pub fn get_recipient_spk(
        &mut self,
        recipient_pk: &PhysicalDevicePk,
    ) -> Option<EphemeralX25519Pk> {
        let now_ms = self.clock.network_time_ms();
        match self.peer_announcements.get(recipient_pk)? {
            ControlAction::Announcement {
                pre_keys,
                last_resort_key,
            } => pre_keys
                .iter()
                .find(|pk| pk.expires_at > now_ms)
                .map(|pk| pk.public_key)
                .or(Some(last_resort_key.public_key)),
            _ => None,
        }
    }

    /// Resolves X25519 public key for ECIES wrapping to recipient.
    ///
    /// 1. If recipient has Announcement with pre-keys, use SPK.
    /// 2. Otherwise, convert device public key to X25519 via
    ///    [`crate::crypto::device_pk_to_x25519`] (handles Ed25519 and
    ///    native X25519 device keys).
    pub fn resolve_recipient_spk(&mut self, recipient_pk: &PhysicalDevicePk) -> EphemeralX25519Pk {
        self.get_recipient_spk(recipient_pk).unwrap_or_else(|| {
            EphemeralX25519Pk::from(
                crate::crypto::device_pk_to_x25519(recipient_pk.as_bytes()).to_bytes(),
            )
        })
    }

    /// Consumes One-Time Pre-Key from recipient's Announcement.
    ///
    /// Returns `(OPK public key, opk_id)` where `opk_id = Blake3(OPK_pk)`.
    /// Consumed OPK removed from `peer_announcements` to prevent
    /// reuse. First pre-key (`pre_keys[0]`) treated as SPK and
    /// never consumed; only `pre_keys[1..]` are OPKs.
    pub fn consume_recipient_opk(
        &mut self,
        recipient_pk: &PhysicalDevicePk,
    ) -> Option<(EphemeralX25519Pk, NodeHash)> {
        let now_ms = self.clock.network_time_ms();
        let ann = self.peer_announcements.get_mut(recipient_pk)?;
        if let ControlAction::Announcement { pre_keys, .. } = ann {
            // pre_keys[0] is SPK; pre_keys[1..] are OPKs. Find first non-expired OPK.
            if let Some(idx) = pre_keys
                .iter()
                .skip(1)
                .position(|pk| pk.expires_at > now_ms)
            {
                let opk = pre_keys.remove(idx + 1); // +1 because position was relative to skip(1)
                let opk_id = NodeHash::from(*blake3::hash(opk.public_key.as_bytes()).as_bytes());
                return Some((opk.public_key, opk_id));
            }
        }
        None
    }

    /// Finds our OPK private key matching `opk_id` (Blake3 hash
    /// of OPK public key). Returns `None` if no match found or if
    /// `opk_id` is all-zeros (no OPK consumed).
    pub fn find_opk_sk(&self, opk_id: &NodeHash) -> Option<&EphemeralX25519Sk> {
        if *opk_id == NodeHash::from([0u8; 32]) {
            return None;
        }
        self.ephemeral_keys.iter().find_map(|(pk, sk)| {
            let hash = blake3::hash(pk.as_bytes());
            if *hash.as_bytes() == *opk_id.as_bytes() {
                Some(sk)
            } else {
                None
            }
        })
    }

    /// Consumes (removes) our OPK private key matching `opk_id`.
    /// Returns removed secret key for forward secrecy: caller should
    /// drop immediately after use.
    pub fn consume_opk_sk(&mut self, opk_id: &NodeHash) -> Option<EphemeralX25519Sk> {
        if *opk_id == NodeHash::from([0u8; 32]) {
            return None;
        }
        let pk_to_remove = self.ephemeral_keys.iter().find_map(|(pk, _)| {
            let hash = blake3::hash(pk.as_bytes());
            if *hash.as_bytes() == *opk_id.as_bytes() {
                Some(*pk)
            } else {
                None
            }
        })?;
        self.ephemeral_keys.remove(&pk_to_remove)
    }

    /// Updates reachability status for all sessions associated with peer.
    pub fn set_peer_reachable(&mut self, peer_pk: PhysicalDevicePk, reachable: bool) {
        for ((p, _), session) in self.sessions.iter_mut() {
            if p == &peer_pk {
                session.common_mut().reachable = reachable;
            }
        }
    }

    /// Escalates blacklist tier for a peer (called on IBLT decode failure,
    /// Bao root mismatch, or other protocol violations).
    pub fn blacklist_escalate(&mut self, peer_pk: PhysicalDevicePk) {
        let now = self.clock.network_time_ms();
        let state = self
            .peer_blacklist
            .entry(peer_pk)
            .or_insert(BlacklistState {
                tier: 0,
                expires_at_ms: 0,
            });
        state.escalate(now);
    }

    /// Returns true if a peer is currently blacklisted.
    pub fn is_blacklisted(&self, peer_pk: &PhysicalDevicePk, now_ms: i64) -> bool {
        self.peer_blacklist
            .get(peer_pk)
            .is_some_and(|bl| bl.is_active(now_ms))
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
    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64> {
        if let Some(&dist) = self.cache.lock().admin_distances.get(hash) {
            return Some(dist);
        }
        // Look up cached node first. If admin node, distance is 0.
        // If content node, compute by checking parents recursively.
        let cached_node = self.cache.lock().nodes.get(hash).cloned();
        if let Some(node) = cached_node {
            if node.node_type() == crate::dag::NodeType::Admin {
                self.cache.lock().admin_distances.insert(*hash, 0);
                return Some(0);
            }
            let mut min_dist = u64::MAX;
            for parent in &node.parents {
                if let Some(dist) = self.get_admin_distance(parent) {
                    min_dist = min_dist.min(dist);
                }
            }
            let result = if min_dist == u64::MAX {
                Some(10)
            } else {
                Some(min_dist + 1)
            };
            if let Some(d) = result {
                self.cache.lock().admin_distances.insert(*hash, d);
            }
            return result;
        }
        self.store.get_admin_distance(hash)
    }
    fn contains_node(&self, hash: &NodeHash) -> bool {
        let cache = self.cache.lock();
        cache.nodes.contains_key(hash) || self.store.contains_node(hash)
    }
    fn has_children(&self, hash: &NodeHash) -> bool {
        self.store.has_children(hash)
    }
    fn get_soft_anchor_chain_length(&self, hash: &NodeHash) -> Option<u64> {
        // Check pending cache first
        let cached_node = self.cache.lock().nodes.get(hash).cloned();
        if let Some(node) = cached_node {
            if let crate::dag::Content::Control(crate::dag::ControlAction::SoftAnchor {
                basis_hash,
                ..
            }) = &node.content
            {
                let parent_count = self.get_soft_anchor_chain_length(basis_hash).unwrap_or(0);
                return Some(1 + parent_count);
            } else {
                return Some(0);
            }
        }
        self.store.get_soft_anchor_chain_length(hash)
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

        let mut spec_hashes: std::collections::HashSet<_> = spec.iter().map(|n| n.hash()).collect();

        for (hash, node) in &cache.nodes {
            if !cache.verified.contains(hash) && !spec_hashes.contains(hash) {
                spec.push(node.clone());
                spec_hashes.insert(*hash);
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
            // Count only if not already in store to avoid double counting
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
        _epoch: u64,
    ) -> crate::error::MerkleToxResult<()> {
        Ok(())
    }
    fn get_ratchet_key(
        &self,
        cid: &ConversationId,
        h: &NodeHash,
    ) -> crate::error::MerkleToxResult<Option<(ChainKey, u64)>> {
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
