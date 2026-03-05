use crate::crypto::ConversationKeys;
use crate::dag::{
    ChainKey, ConversationId, HeaderKey, KConv, LogicalIdentityPk, MerkleNode, MessageKey,
    NodeAuth, NodeHash, PhysicalDevicePk, SenderKey, WireNode,
};
use ed25519_dalek::Verifier;
use std::collections::{HashMap, HashSet};

/// Genesis flag: only admins may invite.
pub const FLAG_ADMIN_ONLY_INVITE: u64 = 0x01;
/// Genesis flag: any member with MESSAGE permission may invite.
pub const FLAG_MEMBER_INVITE: u64 = 0x02;

#[derive(Clone)]
pub struct Pending {
    pub speculative_nodes: HashSet<NodeHash>,
    pub vouchers: HashMap<NodeHash, HashMap<PhysicalDevicePk, i64>>,
    /// Genesis flags from the conversation's Genesis node.
    pub genesis_flags: u64,
}

#[derive(Clone)]
pub struct Established {
    pub epochs: HashMap<u64, ConversationKeys>,
    pub sender_ratchets: HashMap<PhysicalDevicePk, (u64, ChainKey, Option<NodeHash>, u64)>, // (last_seq, next_chain_key, last_node_hash, epoch_id)
    pub skipped_keys: HashMap<(PhysicalDevicePk, u64), (MessageKey, i64)>,
    pub current_epoch: u64,
    pub message_count: u32,
    pub last_rotation_time_ms: i64,
    pub vouchers: HashMap<NodeHash, HashMap<PhysicalDevicePk, i64>>,
    /// Per-sender SenderKeys received via SenderKeyDistribution.
    /// (sender_pk, epoch) → random SenderKey used to seed the ratchet.
    pub sender_keys: HashMap<(PhysicalDevicePk, u64), SenderKey>,
    /// Tracks which devices have been sent our SenderKey/ratchet state in the
    /// current epoch (JIT piggybacking). Cleared on epoch rotation.
    pub shared_keys_sent_to: HashSet<PhysicalDevicePk>,
    /// JIT K_header overrides for senders who distributed their ratchet mid-epoch.
    /// (sender_pk, epoch) → K_header bytes.
    pub jit_headers: HashMap<(PhysicalDevicePk, u64), HeaderKey>,
    /// True when the conversation was established via a KeyWrap from an unverified
    /// sender. Content should be surfaced as "identity pending" until the admin chain
    /// is verified.
    pub identity_pending: bool,
    /// Genesis flags from the conversation's Genesis node.
    pub genesis_flags: u64,
    /// Content messages THIS device has authored since last sender rekey.
    pub self_message_count: u32,
    /// Timestamp of THIS device's last SenderKey rotation.
    pub self_last_rekey_time_ms: i64,
}

#[derive(Clone)]
pub struct ConversationData<S> {
    pub id: ConversationId,
    pub state: S,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Conversation {
    Pending(ConversationData<Pending>),
    Established(ConversationData<Established>),
}

impl Conversation {
    pub fn id(&self) -> ConversationId {
        match self {
            Conversation::Pending(c) => c.id,
            Conversation::Established(c) => c.id,
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(self, Conversation::Established(_))
    }

    pub fn genesis_flags(&self) -> u64 {
        match self {
            Conversation::Pending(c) => c.state.genesis_flags,
            Conversation::Established(c) => c.state.genesis_flags,
        }
    }

    pub fn set_genesis_flags(&mut self, flags: u64) {
        match self {
            Conversation::Pending(c) => c.state.genesis_flags = flags,
            Conversation::Established(c) => c.state.genesis_flags = flags,
        }
    }

    pub fn vouchers(&self) -> &HashMap<NodeHash, HashMap<PhysicalDevicePk, i64>> {
        match self {
            Conversation::Pending(c) => &c.state.vouchers,
            Conversation::Established(c) => &c.state.vouchers,
        }
    }

    pub fn vouchers_mut(&mut self) -> &mut HashMap<NodeHash, HashMap<PhysicalDevicePk, i64>> {
        match self {
            Conversation::Pending(c) => &mut c.state.vouchers,
            Conversation::Established(c) => &mut c.state.vouchers,
        }
    }
}

impl ConversationData<Pending> {
    pub fn new(id: ConversationId) -> Self {
        Self {
            id,
            state: Pending {
                speculative_nodes: HashSet::new(),
                vouchers: HashMap::new(),
                genesis_flags: 0,
            },
        }
    }

    pub fn establish(
        self,
        initial_k_conv: KConv,
        now_ms: i64,
        epoch: u64,
    ) -> ConversationData<Established> {
        let mut epochs = HashMap::new();
        epochs.insert(epoch, ConversationKeys::derive(&initial_k_conv));
        ConversationData {
            id: self.id,
            state: Established {
                epochs,
                sender_ratchets: HashMap::new(),
                skipped_keys: HashMap::new(),
                current_epoch: epoch,
                message_count: 0,
                last_rotation_time_ms: now_ms,
                vouchers: self.state.vouchers,
                sender_keys: HashMap::new(),
                shared_keys_sent_to: HashSet::new(),
                jit_headers: HashMap::new(),
                identity_pending: false,
                genesis_flags: self.state.genesis_flags,
                self_message_count: 0,
                self_last_rekey_time_ms: now_ms,
            },
        }
    }

    pub fn record_speculative(&mut self, hash: NodeHash) {
        self.state.speculative_nodes.insert(hash);
    }
}

impl ConversationData<Established> {
    pub fn new(id: ConversationId, initial_k_conv: KConv, now_ms: i64) -> Self {
        let mut epochs = HashMap::new();
        epochs.insert(0, ConversationKeys::derive(&initial_k_conv));
        Self {
            id,
            state: Established {
                epochs,
                sender_ratchets: HashMap::new(),
                skipped_keys: HashMap::new(),
                current_epoch: 0,
                message_count: 0,
                last_rotation_time_ms: now_ms,
                vouchers: HashMap::new(),
                sender_keys: HashMap::new(),
                shared_keys_sent_to: HashSet::new(),
                jit_headers: HashMap::new(),
                identity_pending: false,
                genesis_flags: 0,
                self_message_count: 0,
                self_last_rekey_time_ms: now_ms,
            },
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.state.current_epoch
    }

    pub fn get_keys(&self, epoch: u64) -> Option<&ConversationKeys> {
        self.state.epochs.get(&epoch)
    }

    pub fn rotate(&mut self, new_k_conv: KConv, now_ms: i64) -> u64 {
        self.state.current_epoch += 1;
        self.state.epochs.insert(
            self.state.current_epoch,
            ConversationKeys::derive(&new_k_conv),
        );
        self.state.sender_ratchets.clear(); // Safe because seq resets to 1 in new epoch
        self.state.message_count = 0;
        self.state.last_rotation_time_ms = now_ms;
        self.state.shared_keys_sent_to.clear(); // Epoch change invalidates JIT tracking
        self.state.jit_headers.clear();
        self.state.self_message_count = 0;
        self.state.self_last_rekey_time_ms = now_ms;
        self.state.current_epoch
    }

    pub fn add_epoch(&mut self, epoch: u64, k_conv: KConv) {
        self.state
            .epochs
            .insert(epoch, ConversationKeys::derive(&k_conv));
        if epoch > self.state.current_epoch {
            self.state.current_epoch = epoch;
            self.state.sender_ratchets.clear();
            self.state.message_count = 0;
        }
    }

    pub fn peek_keys(
        &mut self,
        sender_pk: &PhysicalDevicePk,
        seq: u64,
        now_ms: i64,
    ) -> Option<(MessageKey, ChainKey)> {
        let epoch = seq >> 32;
        let counter = seq & 0xFFFFFFFF;

        // Optional TTL cleanup
        self.state
            .skipped_keys
            .retain(|_, &mut (_, timestamp)| now_ms - timestamp <= 86_400_000);

        if let Some(&(last_seq, ref next_key, _, last_epoch)) =
            self.state.sender_ratchets.get(sender_pk)
            && last_epoch == epoch
        {
            if seq == last_seq + 1 {
                let k_msg = crate::crypto::ratchet_message_key(next_key);
                let k_next = crate::crypto::ratchet_step(next_key);
                return Some((k_msg, k_next));
            } else if seq <= last_seq {
                // Past message. Check cache.
                if let Some((k_msg, _)) = self.state.skipped_keys.get(&(*sender_pk, seq)) {
                    // Return a dummy next_chain_key. It won't be used since seq <= last_seq.
                    return Some((k_msg.clone(), ChainKey::from([0u8; 32])));
                }
                return None;
            } else {
                // Forward Skip
                let skip_count = seq - (last_seq + 1);
                if skip_count > 2000 {
                    tracing::debug!("Ratchet skip too large: {}", skip_count);
                    return None;
                }

                let mut chain_key = next_key.clone();
                for s in (last_seq + 1)..seq {
                    let k_msg = crate::crypto::ratchet_message_key(&chain_key);
                    chain_key = crate::crypto::ratchet_step(&chain_key);
                    self.state
                        .skipped_keys
                        .insert((*sender_pk, s), (k_msg, now_ms));
                }

                let k_msg = crate::crypto::ratchet_message_key(&chain_key);
                let k_next = crate::crypto::ratchet_step(&chain_key);
                return Some((k_msg, k_next));
            }
        }

        // Re-initialize from the sender's SenderKey (if received via SKD),
        // falling back to the deterministic derivation from k_conv.
        let keys = self.get_keys(epoch)?;
        let mut chain_key =
            if let Some(sender_key) = self.state.sender_keys.get(&(*sender_pk, epoch)) {
                ChainKey::from(*sender_key.as_bytes())
            } else {
                crate::crypto::ratchet_init_sender(&keys.k_conv, sender_pk)
            };

        if counter > 2000 {
            tracing::debug!("Ratchet initial skip too large: {}", counter);
            return None;
        }

        for s in 1..counter {
            let k_msg = crate::crypto::ratchet_message_key(&chain_key);
            chain_key = crate::crypto::ratchet_step(&chain_key);
            self.state
                .skipped_keys
                .insert((*sender_pk, (epoch << 32) | s), (k_msg, now_ms));
        }

        let k_msg = crate::crypto::ratchet_message_key(&chain_key);
        let k_next = crate::crypto::ratchet_step(&chain_key);

        Some((k_msg, k_next))
    }

    pub fn commit_node_key(
        &mut self,
        sender_pk: PhysicalDevicePk,
        seq: u64,
        next_chain_key: ChainKey,
        node_hash: NodeHash,
        epoch_id: u64,
    ) -> Option<NodeHash> {
        self.state.skipped_keys.remove(&(sender_pk, seq));

        if let Some(&(last_seq, _, _, last_epoch)) = self.state.sender_ratchets.get(&sender_pk) {
            if last_epoch > epoch_id {
                // Don't regress to an older epoch (e.g. when an admin node's
                // side-effects trigger a rotation that advances the ratchet to
                // epoch N+1, and then the admin node's own epoch-N ratchet
                // advance runs afterwards).
                return None;
            }
            if last_epoch == epoch_id && seq <= last_seq {
                // Out-of-order message processed, DO NOT advance the ratchet head.
                return None;
            }
        }

        self.state
            .sender_ratchets
            .insert(sender_pk, (seq, next_chain_key, Some(node_hash), epoch_id))
            .and_then(|(_, _, h, _)| h)
    }

    /// Update the last-seen sequence number for a sender WITHOUT advancing the
    /// ratchet chain key. Used for exception nodes (Admin, SKD, Announcement)
    /// that carry no per-message encryption.
    pub fn track_sender_seq(&mut self, sender_pk: PhysicalDevicePk, seq: u64, epoch_id: u64) {
        if let Some(entry) = self.state.sender_ratchets.get_mut(&sender_pk) {
            let (s, _, _, e) = entry;
            if epoch_id > *e || (epoch_id == *e && seq > *s) {
                *s = seq;
                *e = epoch_id;
            }
        }
        // If no ratchet entry yet, don't create one. The ratchet seed
        // comes from SKD processing, not from sequence tracking.
    }

    pub fn get_sender_last_seq(&self, sender_pk: &PhysicalDevicePk) -> u64 {
        self.state
            .sender_ratchets
            .get(sender_pk)
            .and_then(|&(seq, _, _, epoch)| {
                if epoch == self.state.current_epoch {
                    Some(seq)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Verifies the ephemeral signature on a content node.
    ///
    /// Admin/KeyWrap/SKD nodes use `NodeAuth::Signature` and are verified elsewhere.
    /// Content nodes use `NodeAuth::EphemeralSignature` and are verified against the
    /// per-epoch ephemeral signing key distributed via SenderKeyDistribution.
    ///
    /// The `peer_eph_keys` map contains `(sender_pk, epoch) → verifying_key_bytes`.
    pub fn verify_node_ephemeral_sig(
        &mut self,
        _conversation_id: &ConversationId,
        node: &MerkleNode,
        peer_eph_keys: &std::collections::HashMap<
            (PhysicalDevicePk, u64),
            crate::dag::EphemeralSigningPk,
        >,
        _now_ms: i64,
    ) -> bool {
        let sig_bytes = match &node.authentication {
            NodeAuth::EphemeralSignature(s) => s,
            NodeAuth::Signature(_) => return true, // Admin signatures verified separately
        };

        let epoch = node.sequence_number >> 32;
        if let Some(vk_bytes) = peer_eph_keys.get(&(node.sender_pk, epoch))
            && let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(vk_bytes.as_bytes())
        {
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_ref());
            let auth_data = node.serialize_for_auth();
            if vk.verify(&auth_data, &sig).is_ok() {
                return true;
            }
        }

        tracing::debug!(
            "Ephemeral signature verification failed for node {} (sender={}, seq={}, epoch={})",
            hex::encode(node.hash().as_bytes()),
            hex::encode(node.sender_pk.as_bytes()),
            node.sequence_number,
            epoch,
        );
        false
    }

    /// Identifies the sender and decrypts a content wire node.
    ///
    /// For exception nodes (not ENCRYPTED), calls `unpack_wire_exception` directly.
    /// For encrypted content nodes, uses the sender_hint for O(1) lookup, with an
    /// O(N) AEAD fallback when the hint doesn't match.
    pub fn identify_sender_and_unpack(
        &self,
        wire: &WireNode,
        all_senders: &[(PhysicalDevicePk, LogicalIdentityPk)],
    ) -> Option<MerkleNode> {
        // Exception nodes: cleartext routing/payload
        if !wire.flags.contains(crate::dag::WireFlags::ENCRYPTED) {
            return MerkleNode::unpack_wire_exception(wire).ok();
        }

        let mut epochs: Vec<_> = self.state.epochs.keys().copied().collect();
        epochs.sort_unstable_by(|a, b| b.cmp(a));

        // Phase 1: Try provided candidates first
        for &(sender_pk, logical_pk) in all_senders {
            if let Some(node) = self.try_sender_for_wire(wire, sender_pk, logical_pk, &epochs) {
                return Some(node);
            }
        }

        // Phase 2: Try senders from ratchet state not in the provided list
        for sender_pk in self.state.sender_ratchets.keys() {
            if !all_senders.iter().any(|(d, _)| d == sender_pk) {
                let logical_pk = sender_pk.to_logical();
                if let Some(node) = self.try_sender_for_wire(wire, *sender_pk, logical_pk, &epochs)
                {
                    return Some(node);
                }
            }
        }

        None
    }

    /// Maximum forward-step attempts when searching for the right ratchet position.
    const MAX_RATCHET_SKIP: u32 = 2000;

    /// Tries to decrypt a wire node assuming a specific sender.
    ///
    /// For each epoch, starts from the known ratchet position (or re-init for
    /// seq=1) and steps forward up to MAX_RATCHET_SKIP positions. At each
    /// position, checks the sender_hint first (cheap), then tries AEAD
    /// routing decryption on hint match.
    ///
    /// k_header is derived from the NEXT chain key (after stepping), matching
    /// how authoring packs wire nodes: peek_keys returns (k_msg, k_next) and
    /// k_header = derive_k_header_epoch(k_conv, k_next).
    fn try_sender_for_wire(
        &self,
        wire: &WireNode,
        sender_pk: PhysicalDevicePk,
        logical_pk: LogicalIdentityPk,
        epochs: &[u64],
    ) -> Option<MerkleNode> {
        for &epoch in epochs {
            let keys = self.state.epochs.get(&epoch)?;

            // Determine starting chain key: from sender_ratchets, SenderKey, or deterministic init
            let start_key = if let Some(&(_, ref next_key, _, epoch_id)) =
                self.state.sender_ratchets.get(&sender_pk)
                && epoch_id == epoch
            {
                next_key.clone()
            } else if let Some(sender_key) = self.state.sender_keys.get(&(sender_pk, epoch)) {
                ChainKey::from(*sender_key.as_bytes())
            } else {
                crate::crypto::ratchet_init_sender(&keys.k_conv, &sender_pk)
            };

            // K_header: check JIT override first, then derive from SenderKey
            let k_header = if let Some(h) = self.state.jit_headers.get(&(sender_pk, epoch)) {
                h.clone()
            } else {
                let sender_key = self
                    .state
                    .sender_keys
                    .get(&(sender_pk, epoch))
                    .cloned()
                    .unwrap_or_else(|| {
                        SenderKey::from(
                            *crate::crypto::ratchet_init_sender(&keys.k_conv, &sender_pk)
                                .as_bytes(),
                        )
                    });
                crate::crypto::derive_k_header_epoch(&keys.k_conv, &sender_key)
            };

            // Step forward trying each position
            let mut ck = start_key;
            for _ in 0..Self::MAX_RATCHET_SKIP {
                let k_msg = crate::crypto::ratchet_message_key(&ck);
                let k_next = crate::crypto::ratchet_step(&ck);

                // Fast path: check sender_hint first (4-byte comparison)
                let hint = crate::crypto::compute_sender_hint(&k_msg);
                if hint == wire.sender_hint
                    && let Some(seq) = MerkleNode::try_decrypt_routing(wire, &k_header)
                    && let Ok(node) =
                        MerkleNode::unpack_wire_content(wire, sender_pk, logical_pk, seq, &k_msg)
                {
                    return Some(node);
                }

                ck = k_next;
            }
        }

        None
    }

    /// Tries to unpack an encrypted wire node using room-wide export keys.
    ///
    /// HistoryExport nodes are encrypted with `k_header_export` / `k_payload_export`
    /// derived from `k_conv`. This tries each epoch's export keys and each known
    /// sender to decrypt the node.
    pub fn try_unpack_history_export(
        &self,
        wire: &WireNode,
        all_senders: &[(PhysicalDevicePk, LogicalIdentityPk)],
    ) -> Option<MerkleNode> {
        if !wire.flags.contains(crate::dag::WireFlags::ENCRYPTED) {
            return None;
        }

        for keys in self.state.epochs.values() {
            let k_header_export = crate::crypto::derive_k_header_export(&keys.k_conv);
            let k_payload_export = crate::crypto::derive_k_payload_export(&keys.k_conv);
            let k_msg = MessageKey::from(*k_payload_export.as_bytes());

            // Check sender_hint first
            let hint = crate::crypto::compute_sender_hint(&k_msg);
            if hint != wire.sender_hint {
                continue;
            }

            // Try routing decryption with export k_header
            if let Some(seq) = MerkleNode::try_decrypt_routing(wire, &k_header_export) {
                // Try each known sender
                for &(sender_pk, logical_pk) in all_senders {
                    if let Ok(node) =
                        MerkleNode::unpack_wire_content(wire, sender_pk, logical_pk, seq, &k_msg)
                    {
                        // Verify it's actually a HistoryExport
                        if matches!(node.content, crate::dag::Content::HistoryExport { .. }) {
                            return Some(node);
                        }
                    }
                }
            }
        }
        None
    }
}
