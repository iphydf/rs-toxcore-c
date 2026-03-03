use crate::NodeEvent;
use crate::dag::{
    Content, ControlAction, ConversationId, EphemeralSigningPk, EphemeralSigningSk,
    EphemeralX25519Pk, EphemeralX25519Sk, KConv, MerkleNode, NodeAuth, NodeHash, NodeLookup,
    NodeType, PhysicalDevicePk, SenderKey, ValidationError, WireNode,
};
use crate::engine::{
    Conversation, ConversationData, Effect, EngineStore, KeyWrapPending, MerkleToxEngine,
    conversation,
};
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::NodeStore;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;

const MESSAGES_PER_EPOCH: u32 = 5000;
const EPOCH_DURATION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Re-anchor every N content messages so joining devices have fresh anchor.
const MESSAGES_PER_ANCHOR: u32 = 400;
/// SoftAnchor auto-trigger: minimum admin-distance hops before considering.
const SOFT_ANCHOR_MIN_HOPS: u64 = 400;
/// SoftAnchor auto-trigger: upper bound for randomized threshold.
const SOFT_ANCHOR_MAX_HOPS: u64 = 450;

impl MerkleToxEngine {
    /// Authors KeyWrap node using X3DH for initial key exchange with peer.
    /// Per spec §2.C, K_conv_0 derived internally from SK_shared; caller
    /// does not supply k_conv. Alice's conversation state updated to
    /// Established with K_conv_0 so she can immediately author messages.
    pub fn author_x3dh_key_exchange(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: PhysicalDevicePk,
        peer_spk: EphemeralX25519Pk,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        // Enforce X3DH Last Resort key blocking rule
        if let Some(ControlAction::Announcement {
            last_resort_key, ..
        }) = self.peer_announcements.get(&peer_pk)
            && last_resort_key.public_key == peer_spk
        {
            let content = Content::Control(ControlAction::HandshakePulse);
            return self.author_node(conversation_id, content, Vec::new(), store);
        }

        let mut e_a_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut e_a_sk_bytes);
        let e_a_sk = EphemeralX25519Sk::from(e_a_sk_bytes);
        let e_a_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_a_sk_bytes))
                .to_bytes(),
        );

        // Generate a fresh K_conv_0 and wrap it with ECIES.
        // Consume an OPK from the peer's Announcement if available.
        let mut k_conv_0_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut k_conv_0_bytes);
        let k_conv_0 = KConv::from(k_conv_0_bytes);
        let (opk, opk_id) = self
            .consume_recipient_opk(&peer_pk)
            .map(|(pk, id)| (Some(pk), id))
            .unwrap_or((None, NodeHash::from([0u8; 32])));
        let ciphertext_vec =
            crate::crypto::ecies_wrap(&e_a_sk, &peer_spk, opk.as_ref(), None, k_conv_0.as_bytes());

        let generation = self.get_current_generation(&conversation_id) as u64;

        // Alice is initiator: establish conversation with K_conv_0 BEFORE
        // calling author_node. apply_side_effects (in author_node_internal)
        // advances Alice's ratchet using current epoch key; seeding from K_conv_0
        // ensures Alice's ratchet matches Bob's (who seeds from K_conv_0 when
        // processing KeyWrap).
        let now = self.clock.network_time_ms();
        let em = match self
            .conversations
            .remove(&conversation_id)
            .unwrap_or_else(|| {
                Conversation::Pending(ConversationData::<conversation::Pending>::new(
                    conversation_id,
                ))
            }) {
            Conversation::Pending(p) => p.establish(k_conv_0.clone(), now, generation),
            Conversation::Established(mut e) => {
                e.add_epoch(generation, k_conv_0.clone());
                e
            }
        };
        self.conversations
            .insert(conversation_id, Conversation::Established(em));

        let wrapped = crate::dag::WrappedKey {
            recipient_pk: peer_pk,
            ciphertext: ciphertext_vec,
            opk_id,
        };

        let content = Content::KeyWrap {
            generation,
            anchor_hash: self
                .latest_anchor_hashes
                .get(&conversation_id)
                .copied()
                .unwrap_or_else(|| NodeHash::from(*conversation_id.as_bytes())),
            wrapped_keys: vec![wrapped],
            ephemeral_pk: e_a_pk,
        };

        let mut effects = self.author_node(conversation_id, content, Vec::new(), store)?;

        effects.push(Effect::WriteConversationKey(
            conversation_id,
            generation,
            k_conv_0,
        ));

        // If OPK consumed, enter KeyWrap Pending state (merkle-tox-handshake-ecies.md §2.A.3).
        // Content authoring buffered until KEYWRAP_ACK received.
        if opk_id != NodeHash::from([0u8; 32]) {
            // Find the node hash from effects
            if let Some(kw_hash) = effects.iter().find_map(|e| {
                if let Effect::WriteStore(_, n, _) = e {
                    Some(n.hash())
                } else {
                    None
                }
            }) {
                self.keywrap_pending.insert(
                    kw_hash,
                    KeyWrapPending {
                        conversation_id,
                        recipient_pk: peer_pk,
                        created_at: self.clock.time_provider().now_instant(),
                        attempts: 0,
                    },
                );
            }
        }

        Ok(effects)
    }

    /// Appends a new message to a conversation.
    pub fn author_node(
        &mut self,
        conversation_id: ConversationId,
        content: Content,
        metadata: Vec<u8>,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        // Guard: Spec §5 Observer Mode requires devices in Pending state or
        // Established with identity_pending=true MUST NOT author new nodes.
        // Exceptions: Announcement, HandshakePulse (observer-safe), KeyWrap
        // and SenderKeyDistribution (needed for key exchange in pending mode).
        let is_observer_safe = matches!(
            &content,
            Content::Control(ControlAction::Announcement { .. })
                | Content::Control(ControlAction::HandshakePulse)
                | Content::KeyWrap { .. }
                | Content::SenderKeyDistribution { .. }
        );
        // Guard: KeyWrap Pending state (merkle-tox-handshake-ecies.md §2.A.3).
        // Content authoring blocked while waiting for KEYWRAP_ACK after OPK consumption.
        let is_content = !is_observer_safe
            && !matches!(
                &content,
                Content::Control(ControlAction::Genesis { .. })
                    | Content::Control(ControlAction::AuthorizeDevice { .. })
                    | Content::Control(ControlAction::RevokeDevice { .. })
            );
        if is_content
            && self
                .keywrap_pending
                .values()
                .any(|p| p.conversation_id == conversation_id)
        {
            return Err(crate::error::MerkleToxError::Other(
                "Cannot author content: awaiting KEYWRAP_ACK (OPK consumed)".to_string(),
            ));
        }

        if !is_observer_safe {
            let is_pending = matches!(
                self.conversations.get(&conversation_id),
                Some(Conversation::Pending(_))
            ) && !self
                .identity_manager
                .has_authorization_record(conversation_id, &self.self_pk);
            let is_identity_pending = matches!(
                self.conversations.get(&conversation_id),
                Some(Conversation::Established(e)) if e.state.identity_pending
            );
            if is_pending || is_identity_pending {
                return Err(crate::error::MerkleToxError::Other(
                    "Cannot author nodes: device is in observer mode (pending/identity_pending)"
                        .to_string(),
                ));
            }
        }

        // Block authoring if self is in expired trust-restored state
        if let Some(&heal_ts) = self
            .trust_restored_devices
            .get(&(conversation_id, self.self_pk))
        {
            let now_ms = self.clock.network_time_ms();
            if now_ms - heal_ts > tox_proto::constants::TRUST_RESTORED_EXPIRY_MS {
                return Err(crate::error::MerkleToxError::Other(
                    "Cannot author: trust-restored state has expired (30-day limit)".to_string(),
                ));
            }
        }

        // Check for automatic rotation
        let mut all_effects = Vec::new();
        if self.check_rotation_triggers(conversation_id) {
            let effects = self.rotate_conversation_key(conversation_id, store)?;
            all_effects.extend(effects);
        }

        // JIT Piggybacking: before authoring content node, check for authorized
        // devices lacking SenderKey/ratchet state this epoch.
        // If any exist, author JIT SenderKeyDistribution first.
        if !matches!(&content, Content::Control(_) | Content::KeyWrap { .. })
            && let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id)
        {
            let now = self.clock.network_time_ms();
            let ctx = crate::identity::CausalContext::global();
            let authorized = self.identity_manager.list_active_authorized_devices(
                &ctx,
                conversation_id,
                now,
                u64::MAX,
            );
            let missing: Vec<_> = authorized
                .into_iter()
                .filter(|pk| *pk != self.self_pk)
                .filter(|pk| !em.state.shared_keys_sent_to.contains(pk))
                .collect();
            if !missing.is_empty() {
                // JIT is best-effort: if authoring fails (e.g., no signing key),
                // proceed with content node.
                if let Ok(jit_effects) =
                    self.author_jit_sender_key_distribution(conversation_id, missing, store)
                {
                    all_effects.extend(jit_effects);
                }
            }
        }

        let use_generation = match &content {
            Content::KeyWrap { generation, .. } => Some(*generation),
            _ => None,
        };

        // Capture content node status before `content` is
        // moved into author_node_internal to check re-anchor
        // threshold afterwards.
        let is_content_node = !matches!(&content, Content::Control(_));

        let effects =
            self.author_node_internal(conversation_id, content, metadata, store, use_generation)?;
        all_effects.extend(effects);

        // After content message, check if re-anchoring
        // threshold crossed. If so, auto-author Snapshot so
        // new devices have fresh trust anchor.
        if is_content_node {
            let should_anchor = if let Some(Conversation::Established(em)) =
                self.conversations.get(&conversation_id)
            {
                em.state.message_count > 0 && em.state.message_count % MESSAGES_PER_ANCHOR == 0
            } else {
                false
            };
            if should_anchor && let Ok(snap_effects) = self.create_snapshot(conversation_id, store)
            {
                all_effects.extend(snap_effects);
            }

            // Non-admin SoftAnchor trigger: Level 2 devices author SoftAnchor
            // at 400-450 hops to reset trust cap.
            if !should_anchor {
                let is_admin = self
                    .self_certs
                    .get(&conversation_id)
                    .is_some_and(|c| c.permissions.contains(crate::dag::Permissions::ADMIN));
                if !is_admin && self.self_certs.contains_key(&conversation_id) {
                    let heads = store.get_heads(&conversation_id);
                    let parent_admin_dist = heads
                        .iter()
                        .filter_map(|h| store.get_admin_distance(h))
                        .min()
                        .unwrap_or(0);
                    let hops = parent_admin_dist + 1;
                    if hops >= SOFT_ANCHOR_MIN_HOPS {
                        let threshold = {
                            let mut rng = self.rng.lock();
                            use rand::Rng;
                            rng.gen_range(SOFT_ANCHOR_MIN_HOPS..=SOFT_ANCHOR_MAX_HOPS)
                        };
                        if hops >= threshold
                            && let Ok(anchor_effects) =
                                self.author_soft_anchor(conversation_id, store)
                        {
                            all_effects.extend(anchor_effects);
                        }
                    }
                }
            }
        }

        Ok(all_effects)
    }

    pub fn author_node_with_epoch(
        &mut self,
        conversation_id: ConversationId,
        content: Content,
        metadata: Vec<u8>,
        store: &dyn NodeStore,
        use_epoch: u64,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.author_node_internal(conversation_id, content, metadata, store, Some(use_epoch))
    }

    pub fn author_node_internal(
        &mut self,
        conversation_id: ConversationId,
        content: Content,
        metadata: Vec<u8>,
        store: &dyn NodeStore,
        use_epoch: Option<u64>,
    ) -> MerkleToxResult<Vec<Effect>> {
        let now = self.clock.network_time_ms();
        let author_pk = self.self_logical_pk;

        let (node, node_hash, wire_node) = {
            let overlay = EngineStore {
                store,
                cache: &self.pending_cache,
            };

            let node_type = match &content {
                Content::Control(_) => NodeType::Admin,
                _ => NodeType::Content,
            };

            let _is_bootstrap = matches!(
                content,
                Content::KeyWrap { .. }
                    | Content::HistoryExport { .. }
                    | Content::SenderKeyDistribution { .. }
            );

            // Find or create a session to get the heads.
            let mut parents =
                if let Content::Control(ControlAction::SoftAnchor { basis_hash, .. }) = &content {
                    vec![*basis_hash]
                } else if node_type == NodeType::Admin {
                    overlay.get_admin_heads(&conversation_id)
                } else {
                    // Content nodes (and bootstrap nodes) must merge both tracks
                    // to causally depend on recent AuthorizeDevice/RevokeDevice nodes.
                    let mut p = overlay.get_heads(&conversation_id);
                    for h in overlay.get_admin_heads(&conversation_id) {
                        if !p.contains(&h) {
                            p.push(h);
                        }
                    }
                    p
                };

            // RULE: Use only verified heads as parents for new nodes.
            // Prevents using quarantined/speculative nodes as parents.
            parents.retain(|h| overlay.is_verified(h));

            parents.sort_unstable();

            let topological_rank = if parents.is_empty() {
                0
            } else {
                parents
                    .iter()
                    .filter_map(|h| overlay.get_rank(h))
                    .max()
                    .unwrap_or(0)
                    + 1
            };

            let current_epoch = if let Some(Conversation::Established(em)) =
                self.conversations.get(&conversation_id)
            {
                em.current_epoch()
            } else {
                0
            };

            let last_seq = if let Some(Conversation::Established(em)) =
                self.conversations.get(&conversation_id)
            {
                em.get_sender_last_seq(&self.self_pk)
            } else {
                let cache = self.pending_cache.lock();
                let last_verified = cache
                    .last_verified_sequences
                    .get(&(conversation_id, self.self_pk))
                    .cloned();
                drop(cache);
                last_verified.unwrap_or_else(|| {
                    store.get_last_sequence_number(&conversation_id, &self.self_pk)
                })
            };

            let use_epoch_id = use_epoch.unwrap_or(current_epoch);

            let sequence_number = if (last_seq >> 32) == use_epoch_id {
                last_seq + 1
            } else {
                (use_epoch_id << 32) | 1
            };

            let mut node = MerkleNode {
                parents,
                author_pk,
                sender_pk: self.self_pk,
                sequence_number,
                topological_rank,
                network_timestamp: now,
                content,
                metadata,
                authentication: NodeAuth::EphemeralSignature(crate::dag::Ed25519Signature::from(
                    [0u8; 64],
                )), // Placeholder
                pow_nonce: 0,
            };

            // KeyWrap must be Ed25519-signed (not ephemeral-signed).
            // SKD uses device Signature if no prior epoch ephemeral key
            // (first-ever SKD), otherwise uses EphemeralSignature from
            // previous epoch key (DARE §2).
            let is_key_wrap = matches!(node.content, Content::KeyWrap { .. });
            let is_skd_needs_device_sig =
                matches!(&node.content, Content::SenderKeyDistribution { .. }) && {
                    let eph_epoch = use_epoch.unwrap_or(0);
                    // SKD for epoch N is signed with epoch N-1's key.
                    // If N==0 or epoch N-1 has no key, fall back to device sig.
                    eph_epoch == 0
                        || !self
                            .self_ephemeral_signing_keys
                            .contains_key(&(eph_epoch.saturating_sub(1)))
                };

            // Pre-packed wire for content nodes (encrypt-then-sign):
            // Content nodes packed BEFORE signing so signature covers
            // encrypted wire data, not plaintext.
            let mut content_wire: Option<WireNode> = None;

            // Three signing/packing paths:
            // 1. Device-signed exception nodes (Admin, KeyWrap, first-epoch SKD)
            // 2. Ephemeral-signed exception nodes (subsequent-epoch SKD)
            // 3. Content nodes (encrypt-then-sign)
            //
            // Exception nodes use cleartext wire packing, so
            // node.serialize_for_auth() == wire.serialize_for_auth().
            // Content nodes are encrypted, requiring wire (ciphertext) signature.
            let is_exception = node.is_exception_node();

            if node_type == NodeType::Admin || is_key_wrap || is_skd_needs_device_sig {
                // Path 1: Device signature on exception node.
                if let Some(sk) = &self.self_sk {
                    let signing_key = SigningKey::from_bytes(sk.as_bytes());
                    let sig = signing_key.sign(&node.serialize_for_auth()).to_bytes();
                    node.authentication =
                        NodeAuth::Signature(crate::dag::Ed25519Signature::from(sig));
                } else {
                    return Err(MerkleToxError::Crypto(
                        "Missing signing key for Admin node".to_string(),
                    ));
                }
            } else if is_exception {
                // Path 2: Ephemeral signature on exception node (e.g. SKD epoch > 0).
                // Exception nodes are cleartext, so plaintext auth == wire auth.
                let auth_data = node.serialize_for_auth();

                let current_epoch = if let Some(Conversation::Established(em)) =
                    self.conversations.get(&conversation_id)
                {
                    use_epoch.unwrap_or_else(|| em.current_epoch())
                } else {
                    use_epoch.unwrap_or(0)
                };

                // DARE §2: SKD for epoch n>0 signed with PREVIOUS epoch's
                // ephemeral key (epoch n-1), not current epoch's key.
                let signing_epoch =
                    if matches!(&node.content, Content::SenderKeyDistribution { .. })
                        && current_epoch > 0
                    {
                        current_epoch - 1
                    } else {
                        current_epoch
                    };

                let eph_sk = self
                    .self_ephemeral_signing_keys
                    .entry(signing_epoch)
                    .or_insert_with(|| {
                        let mut bytes = [0u8; 32];
                        self.rng.lock().fill_bytes(&mut bytes);
                        ed25519_dalek::SigningKey::from_bytes(&bytes)
                    });
                let sig = eph_sk.sign(&auth_data).to_bytes();
                node.authentication =
                    NodeAuth::EphemeralSignature(crate::dag::Ed25519Signature::from(sig));
            } else {
                // Path 3: Content nodes (encrypt-then-sign).
                // 1. Increment message count
                if let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                {
                    em.state.message_count += 1;
                }

                // 2. Pack wire with placeholder auth BEFORE signing
                if let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                {
                    let pack_keys = em
                        .peek_keys(&node.sender_pk, node.sequence_number, now)
                        .map(|(k_msg, _k_next)| {
                            let epoch = node.sequence_number >> 32;
                            let keys = em
                                .get_keys(epoch)
                                .or_else(|| em.get_keys(em.current_epoch()));
                            let k_conv = keys
                                .map(|k| &k.k_conv)
                                .cloned()
                                .unwrap_or_else(|| KConv::from([0u8; 32]));
                            let sender_key = em
                                .state
                                .sender_keys
                                .get(&(node.sender_pk, epoch))
                                .cloned()
                                .unwrap_or_else(|| {
                                    SenderKey::from(
                                        *crate::crypto::ratchet_init_sender(
                                            &k_conv,
                                            &node.sender_pk,
                                        )
                                        .as_bytes(),
                                    )
                                });
                            let k_header =
                                crate::crypto::derive_k_header_epoch(&k_conv, &sender_key);
                            let mut routing_nonce = [0u8; 12];
                            let mut payload_nonce = [0u8; 12];
                            self.rng.lock().fill_bytes(&mut routing_nonce);
                            self.rng.lock().fill_bytes(&mut payload_nonce);
                            crate::crypto::PackKeys::Content(crate::crypto::PackContentKeys {
                                k_msg,
                                k_header,
                                routing_nonce,
                                payload_nonce,
                            })
                        });
                    if let Some(keys) = pack_keys
                        && let Ok(wire) = node.pack_wire(&keys, true)
                    {
                        content_wire = Some(wire);
                    }
                }

                // 3. Sign the wire's auth data (encrypt-then-sign).
                // If wire packing failed, fall back to signing the plaintext.
                let auth_data = if let Some(ref wire) = content_wire {
                    wire.serialize_for_auth()
                } else {
                    node.serialize_for_auth()
                };

                let current_epoch = if let Some(Conversation::Established(em)) =
                    self.conversations.get(&conversation_id)
                {
                    use_epoch.unwrap_or_else(|| em.current_epoch())
                } else {
                    use_epoch.unwrap_or(0)
                };

                // DARE §2: SKD for epoch n>0 signed with PREVIOUS epoch's
                // ephemeral key (epoch n-1), not current epoch's key.
                let signing_epoch =
                    if matches!(&node.content, Content::SenderKeyDistribution { .. })
                        && current_epoch > 0
                    {
                        current_epoch - 1
                    } else {
                        current_epoch
                    };

                // Look up (or generate) the ephemeral signing key for this epoch
                let eph_sk = self
                    .self_ephemeral_signing_keys
                    .entry(signing_epoch)
                    .or_insert_with(|| {
                        let mut bytes = [0u8; 32];
                        self.rng.lock().fill_bytes(&mut bytes);
                        ed25519_dalek::SigningKey::from_bytes(&bytes)
                    });
                let sig = eph_sk.sign(&auth_data).to_bytes();
                node.authentication =
                    NodeAuth::EphemeralSignature(crate::dag::Ed25519Signature::from(sig));

                // 4. Copy auth to pre-packed wire node
                if let Some(ref mut wire) = content_wire {
                    wire.authentication = node.authentication.clone();
                }
            }

            let hash = node.hash();
            overlay.put_node(&conversation_id, node.clone(), true)?;

            // Store the wire representation for future sync
            let mut wire_node = None;
            if let Some(wire) = content_wire {
                // Content node was already packed during encrypt-then-sign
                overlay.put_wire_node(&conversation_id, &hash, wire.clone())?;
                wire_node = Some(wire);
            } else if let Some(Conversation::Established(em)) =
                self.conversations.get_mut(&conversation_id)
            {
                // Exception nodes: pack after signing (wire copies auth from node)
                let pack_keys = if node.is_exception_node() {
                    Some(crate::crypto::PackKeys::Exception)
                } else {
                    em.peek_keys(&node.sender_pk, node.sequence_number, now)
                        .map(|(k_msg, _k_next)| {
                            let epoch = node.sequence_number >> 32;
                            let keys = em
                                .get_keys(epoch)
                                .or_else(|| em.get_keys(em.current_epoch()));
                            let k_conv = keys
                                .map(|k| &k.k_conv)
                                .cloned()
                                .unwrap_or_else(|| KConv::from([0u8; 32]));
                            let sender_key = em
                                .state
                                .sender_keys
                                .get(&(node.sender_pk, epoch))
                                .cloned()
                                .unwrap_or_else(|| {
                                    SenderKey::from(
                                        *crate::crypto::ratchet_init_sender(
                                            &k_conv,
                                            &node.sender_pk,
                                        )
                                        .as_bytes(),
                                    )
                                });
                            let k_header =
                                crate::crypto::derive_k_header_epoch(&k_conv, &sender_key);
                            let mut routing_nonce = [0u8; 12];
                            let mut payload_nonce = [0u8; 12];
                            self.rng.lock().fill_bytes(&mut routing_nonce);
                            self.rng.lock().fill_bytes(&mut payload_nonce);
                            crate::crypto::PackKeys::Content(crate::crypto::PackContentKeys {
                                k_msg,
                                k_header,
                                routing_nonce,
                                payload_nonce,
                            })
                        })
                };

                if let Some(keys) = pack_keys
                    && let Ok(wire) = node.pack_wire(&keys, true)
                {
                    overlay.put_wire_node(&conversation_id, &hash, wire.clone())?;
                    wire_node = Some(wire);
                }
            }

            (node, hash, wire_node)
        };

        let mut effects = Vec::new();

        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id)
            && node.node_type() != NodeType::Admin
        {
            effects.push(Effect::WriteEpochMetadata(
                conversation_id,
                em.state.message_count,
                em.state.last_rotation_time_ms,
            ));
        }

        // Persist locally via effect
        effects.push(Effect::WriteStore(conversation_id, node.clone(), true));

        // Also persist wire node via effect if we have it
        if let Some(wire) = wire_node {
            effects.push(Effect::WriteWireNode(conversation_id, node_hash, wire));
        }

        // Update active sessions so they advertise the new head
        for ((_, cid), session) in self.sessions.iter_mut() {
            if cid == &conversation_id {
                let common = session.common_mut();
                common.local_heads.clear();
                common.local_heads.insert(node_hash);
                common.heads_dirty = true;
            }
        }

        let verified_node =
            crate::engine::processor::VerifiedNode::new(node.clone(), node.content.clone());
        let side_effects = self.apply_side_effects(conversation_id, &verified_node, store)?;
        effects.extend(side_effects);

        // If it was an identity-affecting action, re-validate all nodes
        match verified_node.content() {
            Content::Control(ControlAction::AuthorizeDevice { .. })
            | Content::Control(ControlAction::RevokeDevice { .. })
            | Content::Control(ControlAction::Leave(_)) => {
                let inv_effects = self.revalidate_all_verified_nodes(conversation_id, store);
                effects.extend(inv_effects);
            }
            _ => {}
        }

        effects.push(Effect::EmitEvent(NodeEvent::NodeVerified {
            conversation_id,
            hash: node_hash,
            node: node.clone(),
        }));

        Ok(effects)
    }

    /// Authors an Announcement node with fresh ephemeral keys.
    pub fn author_announcement(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        let mut pre_keys = Vec::new();
        // Generate 5 fresh ephemeral pre-keys
        for _ in 0..5 {
            let mut sk_bytes = [0u8; 32];
            self.rng.lock().fill_bytes(&mut sk_bytes);
            let sk = EphemeralX25519Sk::from(sk_bytes);
            let pk = EphemeralX25519Pk::from(
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk_bytes))
                    .to_bytes(),
            );

            // Store the private key
            self.ephemeral_keys.insert(pk, sk);

            // Sign the public key with our identity key
            let signature = if let Some(sk) = &self.self_sk {
                let signing_key = SigningKey::from_bytes(sk.as_bytes());
                crate::dag::Ed25519Signature::from(signing_key.sign(pk.as_bytes()).to_bytes())
            } else {
                return Err(MerkleToxError::Crypto("Missing identity key".to_string()));
            };

            pre_keys.push(crate::dag::SignedPreKey {
                public_key: pk,
                signature,
                expires_at: self.clock.network_time_ms() + 30 * 24 * 60 * 60 * 1000, // 30 days
            });
        }

        // Last resort key
        let mut lr_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut lr_sk_bytes);
        let lr_sk = EphemeralX25519Sk::from(lr_sk_bytes);
        let lr_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(lr_sk_bytes))
                .to_bytes(),
        );
        self.ephemeral_keys.insert(lr_pk, lr_sk);

        let lr_sig = if let Some(sk) = &self.self_sk {
            let signing_key = SigningKey::from_bytes(sk.as_bytes());
            crate::dag::Ed25519Signature::from(signing_key.sign(lr_pk.as_bytes()).to_bytes())
        } else {
            crate::dag::Ed25519Signature::from([0u8; 64])
        };

        let last_resort_key = crate::dag::SignedPreKey {
            public_key: lr_pk,
            signature: lr_sig,
            expires_at: i64::MAX,
        };

        let content = Content::Control(ControlAction::Announcement {
            pre_keys,
            last_resort_key,
        });

        self.author_node(conversation_id, content, Vec::new(), store)
    }

    /// Checks if a conversation key rotation is triggered by message count or time.
    pub fn check_rotation_triggers(&mut self, conversation_id: ConversationId) -> bool {
        let now = self.clock.network_time_ms();
        if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id) {
            if em.state.message_count >= MESSAGES_PER_EPOCH {
                return true;
            }
            if now - em.state.last_rotation_time_ms >= EPOCH_DURATION_MS {
                return true;
            }
        }
        false
    }

    /// Rotates the conversation key, creating Rekey and KeyWrap nodes.
    pub fn rotate_conversation_key(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();
        let now = self.clock.network_time_ms();
        let mut new_k_conv_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut new_k_conv_bytes);
        let new_k_conv = KConv::from(new_k_conv_bytes);

        let mut effects = Vec::new();

        let (old_generation, new_generation) =
            if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id) {
                (Some(em.current_epoch()), em.current_epoch() + 1)
            } else {
                (None, 0)
            };

        // 2. Update Conversation state (Perform the actual rotation)
        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id) {
            em.rotate(new_k_conv.clone(), now);
        } else {
            let em = ConversationData::<conversation::Established>::new(
                conversation_id,
                new_k_conv.clone(),
                now,
            );
            self.conversations
                .insert(conversation_id, Conversation::Established(em));
        };

        // Persist new key
        effects.push(Effect::WriteConversationKey(
            conversation_id,
            new_generation,
            new_k_conv,
        ));

        // 3. Create KeyWrap nodes for all authorized devices (bootstraps the NEW generation)
        let mut wrapped_keys = Vec::new();
        let k_conv_bytes = {
            let em = match self.conversations.get(&conversation_id).unwrap() {
                Conversation::Established(em) => em,
                _ => unreachable!(),
            };
            *em.get_keys(new_generation).unwrap().k_conv.as_bytes()
        };

        // Generate an ephemeral key for this rotation to avoid two-time pad
        let mut e_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut e_sk_bytes);
        let e_sk = EphemeralX25519Sk::from(e_sk_bytes);
        let e_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_sk_bytes)).to_bytes(),
        );

        let dummy_ctx = crate::identity::CausalContext {
            evaluating_node_hash: crate::dag::NodeHash::from([0u8; 32]),
            admin_ancestor_hashes: std::collections::HashSet::new(),
        };

        let recipients = self.identity_manager.list_active_authorized_devices(
            &dummy_ctx,
            conversation_id,
            now,
            u64::MAX,
        );
        tracing::debug!(
            "Rotation: Found {} active recipients at max rank",
            recipients.len()
        );
        for recipient_pk in recipients {
            if recipient_pk == self.self_pk {
                continue;
            }
            // Skip members publishing Announcement with
            // only last-resort key (empty pre_keys list).
            // If no announcement received, fall through and wrap normally.
            let only_last_resort = self
                .peer_announcements
                .get(&recipient_pk)
                .is_some_and(|ann| {
                    matches!(
                        ann,
                        crate::dag::ControlAction::Announcement { pre_keys, .. }
                        if pre_keys.is_empty()
                    )
                });
            if only_last_resort {
                tracing::debug!(
                    "Skipping KeyWrap for {:?}: only last-resort key available",
                    recipient_pk
                );
                continue;
            }
            let spk = self.resolve_recipient_spk(&recipient_pk);
            let (opk, opk_id) = self
                .consume_recipient_opk(&recipient_pk)
                .map(|(pk, id)| (Some(pk), id))
                .unwrap_or((None, NodeHash::from([0u8; 32])));
            let ciphertext =
                crate::crypto::ecies_wrap(&e_sk, &spk, opk.as_ref(), None, &k_conv_bytes);
            wrapped_keys.push(crate::dag::WrappedKey {
                recipient_pk,
                ciphertext,
                opk_id,
            });
        }

        if !wrapped_keys.is_empty() || new_generation == 0 {
            let anchor_hash = self
                .latest_anchor_hashes
                .get(&conversation_id)
                .copied()
                .unwrap_or_else(|| NodeHash::from(*conversation_id.as_bytes()));
            let wrap_effects = self.author_node_internal(
                conversation_id,
                Content::KeyWrap {
                    generation: new_generation,
                    anchor_hash,
                    wrapped_keys,
                    ephemeral_pk: e_pk,
                },
                Vec::new(),
                store,
                Some(new_generation),
            )?;
            effects.extend(wrap_effects);
        }

        // DARE §2: Author SenderKeyDistribution for the new epoch.
        let skd_effects = self.author_sender_key_distribution(
            conversation_id,
            new_generation,
            old_generation,
            store,
        )?;
        effects.extend(skd_effects);

        // Clean up old ephemeral signing key (now disclosed).
        if let Some(old_gen) = old_generation {
            self.self_ephemeral_signing_keys.remove(&old_gen);
        }

        Ok(effects)
    }

    /// Authors a SenderKeyDistribution node for a new epoch (DARE §2).
    ///
    /// Distributes:
    /// - `ephemeral_signing_pk`: the verifying key for the NEW epoch's ephemeral signing key
    /// - `disclosed_keys`: the OLD epoch's ephemeral signing secret key (if it exists)
    /// - `wrapped_keys`: the new SenderKey wrapped via ECIES for each authorized recipient
    fn author_sender_key_distribution(
        &mut self,
        conversation_id: ConversationId,
        new_generation: u64,
        old_generation: Option<u64>,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        // Ensure we have an ephemeral signing key for the new epoch.
        let new_eph_sk = self
            .self_ephemeral_signing_keys
            .entry(new_generation)
            .or_insert_with(|| {
                let mut bytes = [0u8; 32];
                self.rng.lock().fill_bytes(&mut bytes);
                ed25519_dalek::SigningKey::from_bytes(&bytes)
            });
        let ephemeral_signing_pk = EphemeralSigningPk::from(new_eph_sk.verifying_key().to_bytes());

        // Collect disclosed keys: the old epoch's ephemeral signing secret key.
        let disclosed_keys: Vec<EphemeralSigningSk> = if let Some(old_gen) = old_generation
            && let Some(old_sk) = self.self_ephemeral_signing_keys.get(&old_gen)
        {
            vec![EphemeralSigningSk::from(old_sk.to_bytes())]
        } else {
            vec![]
        };

        // Generate a fresh ephemeral DH key for ECIES wrapping.
        let mut skd_e_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut skd_e_sk_bytes);
        let skd_e_sk = EphemeralX25519Sk::from(skd_e_sk_bytes);
        let skd_e_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(skd_e_sk_bytes))
                .to_bytes(),
        );

        // Generate a fresh random SenderKey for this epoch.
        let mut sender_key_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut sender_key_bytes);
        let sender_key = SenderKey::from(sender_key_bytes);

        // Store our own SenderKey so our ratchet uses it.
        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id) {
            em.state
                .sender_keys
                .insert((self.self_pk, new_generation), sender_key.clone());
        }

        // Wrap the SenderKey (not k_conv) for each authorized recipient.
        let now = self.clock.network_time_ms();
        if !matches!(
            self.conversations.get(&conversation_id),
            Some(Conversation::Established(_))
        ) {
            return Err(MerkleToxError::Other(
                "Cannot author SKD: conversation not established".to_string(),
            ));
        }

        let dummy_ctx = crate::identity::CausalContext {
            evaluating_node_hash: crate::dag::NodeHash::from([0u8; 32]),
            admin_ancestor_hashes: std::collections::HashSet::new(),
        };
        let recipients = self.identity_manager.list_active_authorized_devices(
            &dummy_ctx,
            conversation_id,
            now,
            u64::MAX,
        );

        // Compute our own X25519 secret for auth_secret computation.
        let self_dh_sk_bytes = self.self_dh_sk.as_ref().map(|sk| *sk.as_bytes());

        let mut wrapped_keys = Vec::new();
        for recipient_pk in recipients {
            if recipient_pk == self.self_pk {
                continue;
            }
            let spk = self.resolve_recipient_spk(&recipient_pk);
            let (opk, opk_id) = self
                .consume_recipient_opk(&recipient_pk)
                .map(|(pk, id)| (Some(pk), id))
                .unwrap_or((None, NodeHash::from([0u8; 32])));
            // auth_secret = ECDH(sender_x25519_sk, recipient_spk) for deniable auth
            let auth_secret = self_dh_sk_bytes.map(|sk| {
                let ss = x25519_dalek::StaticSecret::from(sk);
                let rpk = x25519_dalek::PublicKey::from(*spk.as_bytes());
                *ss.diffie_hellman(&rpk).as_bytes()
            });
            let ciphertext = crate::crypto::ecies_wrap(
                &skd_e_sk,
                &spk,
                opk.as_ref(),
                auth_secret.as_ref(),
                sender_key.as_bytes(),
            );
            wrapped_keys.push(crate::dag::WrappedKey {
                recipient_pk,
                ciphertext,
                opk_id,
            });
        }

        // Track which devices received our SenderKey in this epoch
        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id) {
            for wrapped in &wrapped_keys {
                em.state.shared_keys_sent_to.insert(wrapped.recipient_pk);
            }
        }

        let content = Content::SenderKeyDistribution {
            ephemeral_pk: skd_e_pk,
            wrapped_keys,
            ephemeral_signing_pk,
            disclosed_keys,
        };

        self.author_node_internal(
            conversation_id,
            content,
            Vec::new(),
            store,
            Some(new_generation),
        )
    }

    /// Authors a JIT SenderKeyDistribution containing the current ratchet state
    /// (K_chain, last_seq, K_header) for newly-authorized devices that haven't
    /// received our SenderKey yet. This enables immediate decryption without
    /// waiting for the next epoch rotation.
    fn author_jit_sender_key_distribution(
        &mut self,
        conversation_id: ConversationId,
        target_devices: Vec<PhysicalDevicePk>,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        // Bail out early if we don't have a signing key: avoids computing
        // ECIES wraps only to fail at the signing step.
        if self.self_sk.is_none() {
            return Ok(Vec::new());
        }

        let epoch =
            if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id) {
                em.current_epoch()
            } else {
                return Ok(Vec::new());
            };

        // Get our current ratchet state
        let (last_seq, next_key) = if let Some(Conversation::Established(em)) =
            self.conversations.get(&conversation_id)
        {
            if let Some(&(seq, ref key, _, epoch_id)) = em.state.sender_ratchets.get(&self.self_pk)
                && epoch_id == epoch
            {
                (seq, key.clone())
            } else {
                let keys = em.get_keys(epoch).ok_or_else(|| {
                    MerkleToxError::Other("No keys for current epoch".to_string())
                })?;
                let init = crate::crypto::ratchet_init_sender(&keys.k_conv, &self.self_pk);
                (epoch << 32, init)
            }
        } else {
            return Ok(Vec::new());
        };

        // Derive K_header for this sender/epoch
        let k_header =
            if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id) {
                if let Some(h) = em.state.jit_headers.get(&(self.self_pk, epoch)) {
                    h.clone()
                } else {
                    let keys = em.get_keys(epoch).ok_or_else(|| {
                        MerkleToxError::Other("No keys for current epoch".to_string())
                    })?;
                    let sender_key = em
                        .state
                        .sender_keys
                        .get(&(self.self_pk, epoch))
                        .cloned()
                        .unwrap_or_else(|| {
                            SenderKey::from(
                                *crate::crypto::ratchet_init_sender(&keys.k_conv, &self.self_pk)
                                    .as_bytes(),
                            )
                        });
                    crate::crypto::derive_k_header_epoch(&keys.k_conv, &sender_key)
                }
            } else {
                return Ok(Vec::new());
            };

        // Build 72-byte JIT payload: [next_key(32) || last_seq(8 BE) || k_header(32)]
        let mut payload = Vec::with_capacity(72);
        payload.extend_from_slice(next_key.as_bytes());
        payload.extend_from_slice(&last_seq.to_be_bytes());
        payload.extend_from_slice(k_header.as_bytes());

        // Generate ephemeral DH key for ECIES
        let mut jit_e_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut jit_e_sk_bytes);
        let jit_e_sk = EphemeralX25519Sk::from(jit_e_sk_bytes);
        let jit_e_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(jit_e_sk_bytes))
                .to_bytes(),
        );

        // Compute our own X25519 secret for auth_secret computation
        let self_dh_sk_bytes = self.self_dh_sk.as_ref().map(|sk| *sk.as_bytes());

        // Wrap JIT payload for each target device
        let mut wrapped_keys = Vec::new();
        for recipient_pk in &target_devices {
            let spk = self.resolve_recipient_spk(recipient_pk);
            let (opk, opk_id) = self
                .consume_recipient_opk(recipient_pk)
                .map(|(pk, id)| (Some(pk), id))
                .unwrap_or((None, NodeHash::from([0u8; 32])));
            let auth_secret = self_dh_sk_bytes.map(|sk| {
                let ss = x25519_dalek::StaticSecret::from(sk);
                let rpk = x25519_dalek::PublicKey::from(*spk.as_bytes());
                *ss.diffie_hellman(&rpk).as_bytes()
            });
            let ciphertext = crate::crypto::ecies_wrap(
                &jit_e_sk,
                &spk,
                opk.as_ref(),
                auth_secret.as_ref(),
                &payload,
            );
            wrapped_keys.push(crate::dag::WrappedKey {
                recipient_pk: *recipient_pk,
                ciphertext,
                opk_id,
            });
        }

        // Record targets as sent
        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id) {
            for pk in &target_devices {
                em.state.shared_keys_sent_to.insert(*pk);
            }
        }

        // Get/create ephemeral signing key for current epoch
        let new_eph_sk = self
            .self_ephemeral_signing_keys
            .entry(epoch)
            .or_insert_with(|| {
                let mut bytes = [0u8; 32];
                self.rng.lock().fill_bytes(&mut bytes);
                ed25519_dalek::SigningKey::from_bytes(&bytes)
            });
        let ephemeral_signing_pk = EphemeralSigningPk::from(new_eph_sk.verifying_key().to_bytes());

        let content = Content::SenderKeyDistribution {
            ephemeral_pk: jit_e_pk,
            wrapped_keys,
            ephemeral_signing_pk,
            disclosed_keys: vec![], // JIT has no disclosed keys
        };

        self.author_node_internal(conversation_id, content, Vec::new(), store, Some(epoch))
    }

    pub fn get_authorized_devices(
        &self,
        conversation_id: &ConversationId,
    ) -> Vec<PhysicalDevicePk> {
        self.identity_manager
            .list_authorized_devices(*conversation_id)
    }

    pub fn get_current_generation(&self, conversation_id: &ConversationId) -> u32 {
        self.conversations
            .get(conversation_id)
            .and_then(|c| match c {
                Conversation::Established(em) => Some(em.current_epoch() as u32),
                Conversation::Pending(_) => None,
            })
            .unwrap_or(0)
    }

    /// Authors a HistoryExport node to distribute historical keys.
    pub fn author_history_key_export(
        &mut self,
        conversation_id: ConversationId,
        blob_hash: NodeHash,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        match self.conversations.get(&conversation_id) {
            Some(Conversation::Established(_)) => {}
            _ => return Err(MerkleToxError::KeyNotFound(conversation_id, 0)),
        };

        let heads = store.get_heads(&conversation_id);
        if heads.is_empty() {
            return Err(MerkleToxError::Validation(ValidationError::EmptyDag));
        }

        // Generate a fresh random K_export for blob encryption.
        let mut k_export = [0u8; 32];
        self.rng.lock().fill_bytes(&mut k_export);

        // Generate an ephemeral key for the history export ECIES wrapping.
        let mut he_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut he_sk_bytes);
        let he_sk = EphemeralX25519Sk::from(he_sk_bytes);
        let he_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(he_sk_bytes))
                .to_bytes(),
        );

        // Encrypt K_export for our other authorized devices using ECIES.
        let mut wrapped_keys = Vec::new();
        {
            let dummy_ctx = crate::identity::CausalContext {
                evaluating_node_hash: crate::dag::NodeHash::from([0u8; 32]),
                admin_ancestor_hashes: std::collections::HashSet::new(),
            };
            let recipients = self.identity_manager.list_active_authorized_devices(
                &dummy_ctx,
                conversation_id,
                self.clock.network_time_ms(),
                u64::MAX,
            );
            for recipient_pk in recipients {
                if recipient_pk != self.self_pk {
                    let spk = self.resolve_recipient_spk(&recipient_pk);
                    let (opk, opk_id) = self
                        .consume_recipient_opk(&recipient_pk)
                        .map(|(pk, id)| (Some(pk), id))
                        .unwrap_or((None, NodeHash::from([0u8; 32])));
                    let ciphertext =
                        crate::crypto::ecies_wrap(&he_sk, &spk, opk.as_ref(), None, &k_export);
                    wrapped_keys.push(crate::dag::WrappedKey {
                        recipient_pk,
                        ciphertext,
                        opk_id,
                    });
                }
            }
        }

        let content = Content::HistoryExport {
            blob_hash,
            ephemeral_pk: he_pk,
            wrapped_keys,
        };

        self.author_node(conversation_id, content, Vec::new(), store)
    }

    /// Authors a snapshot node for the current conversation state.
    pub fn create_snapshot(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        let heads = store.get_heads(&conversation_id);
        if heads.is_empty() {
            return Err(MerkleToxError::Validation(ValidationError::EmptyDag));
        }
        let basis_hash = heads[0]; // Simplified

        let members = self
            .identity_manager
            .list_members(conversation_id)
            .into_iter()
            .map(|(pk, role, joined)| crate::dag::MemberInfo {
                public_key: pk,
                role,
                joined_at: joined,
            })
            .collect();

        let mut last_seq_numbers = Vec::new();
        for dev_pk in self
            .identity_manager
            .list_authorized_devices(conversation_id)
        {
            let seq = store.get_last_sequence_number(&conversation_id, &dev_pk);
            last_seq_numbers.push((dev_pk, seq));
        }

        let content = Content::Control(ControlAction::Snapshot(crate::dag::SnapshotData {
            basis_hash,
            members,
            last_seq_numbers,
        }));

        self.author_node(conversation_id, content, Vec::new(), store)
    }

    /// Authors SoftAnchor node for conversation.
    /// Allows Level 2 (non-admin) participants to reset 500-hop ancestry
    /// trust cap when admins are offline.
    pub fn author_soft_anchor(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        let admin_heads = store.get_admin_heads(&conversation_id);
        if admin_heads.is_empty() {
            return Err(MerkleToxError::Validation(ValidationError::EmptyDag));
        }
        let basis_hash = admin_heads[0];

        let cert = self
            .self_certs
            .get(&conversation_id)
            .ok_or(MerkleToxError::NotAuthorized)?
            .clone();

        let content = Content::Control(ControlAction::SoftAnchor { basis_hash, cert });
        self.author_node(conversation_id, content, Vec::new(), store)
    }
}
