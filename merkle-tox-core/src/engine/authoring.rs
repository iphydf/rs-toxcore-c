use crate::NodeEvent;
use crate::dag::{
    Content, ControlAction, ConversationId, EphemeralX25519Pk, EphemeralX25519Sk, KConv,
    MerkleNode, NodeAuth, NodeLookup, NodeType, PhysicalDevicePk, ValidationError,
};
use crate::engine::{
    Conversation, ConversationData, Effect, EngineStore, MerkleToxEngine, conversation,
};
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::NodeStore;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;

const MESSAGES_PER_EPOCH: u32 = 5000;
const EPOCH_DURATION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

impl MerkleToxEngine {
    /// Authors a KeyWrap node using X3DH for initial key exchange with a peer.
    pub fn author_x3dh_key_exchange(
        &mut self,
        conversation_id: ConversationId,
        peer_pk: PhysicalDevicePk,
        peer_spk: EphemeralX25519Pk,
        k_conv: KConv,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        // Enforce X3DH Last Resort key blocking rule
        let _logical_pk = self
            .identity_manager
            .resolve_logical_pk(conversation_id, &peer_pk)
            .unwrap_or(peer_pk.to_logical());
        if let Some(ControlAction::Announcement {
            last_resort_key, ..
        }) = self.peer_announcements.get(&peer_pk)
            && last_resort_key.public_key == peer_spk
        {
            return Err(MerkleToxError::Crypto(
                "Handshake with last resort key blocked. Send HandshakePulse instead.".to_string(),
            ));
        }

        let mut e_a_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut e_a_sk_bytes);
        let e_a_sk = EphemeralX25519Sk::from(e_a_sk_bytes);
        let e_a_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_a_sk_bytes))
                .to_bytes(),
        );

        let sk = self
            .self_sk
            .as_ref()
            .ok_or_else(|| MerkleToxError::Crypto("Missing identity key".to_string()))?;

        let sk_shared =
            crate::crypto::x3dh_derive_secret_initiator(sk, &e_a_sk, &peer_pk, &peer_spk, None)
                .ok_or_else(|| {
                    MerkleToxError::Crypto("Failed to derive X3DH shared secret".to_string())
                })?;

        // Wrap the k_conv using SK_shared
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let mut ciphertext = *k_conv.as_bytes();
        let mut cipher = chacha20::ChaCha20::new(sk_shared.as_bytes().into(), &[0u8; 12].into());
        cipher.apply_keystream(&mut ciphertext);

        let wrapped = crate::dag::WrappedKey {
            recipient_pk: peer_pk,
            ciphertext: ciphertext.to_vec(),
        };

        let content = Content::KeyWrap {
            epoch: self.get_current_epoch(&conversation_id) as u64,
            wrapped_keys: vec![wrapped],
            ephemeral_pk: Some(e_a_pk),
            pre_key_pk: Some(peer_spk),
        };

        self.author_node(conversation_id, content, Vec::new(), store)
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

        // Check for automatic rotation
        let mut all_effects = Vec::new();
        if self.check_rotation_triggers(conversation_id) {
            let effects = self.rotate_conversation_key(conversation_id, store)?;
            all_effects.extend(effects);
        }

        let use_epoch = match &content {
            Content::KeyWrap { epoch, .. } => Some(*epoch),
            Content::RatchetSnapshot { epoch, .. } => Some(*epoch),
            _ => None,
        };

        let effects =
            self.author_node_internal(conversation_id, content, metadata, store, use_epoch)?;
        all_effects.extend(effects);
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
        _use_epoch: Option<u64>,
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

            let is_bootstrap = matches!(
                content,
                Content::KeyWrap { .. } | Content::RatchetSnapshot { .. }
            );

            // Find or create a session to get the heads.
            let mut parents = if node_type == NodeType::Admin {
                overlay.get_admin_heads(&conversation_id)
            } else if is_bootstrap {
                // Bootstrap nodes (KeyWrap, RatchetSnapshot) merge both tracks
                let mut p = overlay.get_heads(&conversation_id);
                for h in overlay.get_admin_heads(&conversation_id) {
                    if !p.contains(&h) {
                        p.push(h);
                    }
                }
                p
            } else {
                overlay.get_heads(&conversation_id)
            };

            // RULE: Only use verified heads as parents for new nodes.
            // This prevents quarantined/speculative nodes from being used as parents.
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

            let last_seq = overlay.get_last_sequence_number(&conversation_id, &self.self_pk);
            let sequence_number = last_seq + 1;

            let mut node = MerkleNode {
                parents,
                author_pk,
                sender_pk: self.self_pk,
                sequence_number,
                topological_rank,
                network_timestamp: now,
                content,
                metadata,
                authentication: NodeAuth::Mac(crate::dag::NodeMac::from([0u8; 32])), // Placeholder
            };

            if node_type == NodeType::Admin {
                if let Some(sk) = &self.self_sk {
                    let signing_key = SigningKey::from_bytes(sk.as_bytes());
                    let sig = signing_key
                        .sign(&node.serialize_for_auth(&conversation_id))
                        .to_bytes();
                    node.authentication =
                        NodeAuth::Signature(crate::dag::Ed25519Signature::from(sig));
                } else {
                    return Err(MerkleToxError::Crypto(
                        "Missing signing key for Admin node".to_string(),
                    ));
                }

                // Admin nodes also advance the ratchet if keys are available
            } else {
                // Calculate MAC if we have keys
                if let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                {
                    em.state.message_count += 1;

                    let keys = if let Some(epoch) = _use_epoch {
                        // Use epoch root key if requested (for bootstrapping)
                        em.get_keys(epoch).cloned()
                    } else {
                        // Try to use per-message ratchet
                        em.peek_keys(&node.parents).map(|(k_msg, _)| {
                            crate::crypto::ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()))
                        })
                    };

                    if let Some(keys) = keys {
                        let auth_data = node.serialize_for_auth(&conversation_id);
                        node.authentication = NodeAuth::Mac(keys.calculate_mac(&auth_data));
                    }
                }
            }

            let hash = node.hash();
            overlay.put_node(&conversation_id, node.clone(), true)?;

            // Also store the wire representation for future sync
            let mut wire_node = None;
            if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id)
                && let Some(keys) = if let Some(epoch) = _use_epoch {
                    em.get_keys(epoch).cloned()
                } else {
                    em.peek_keys(&node.parents).map(|(k_msg, _)| {
                        crate::crypto::ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()))
                    })
                }
                && let Ok(wire) = node.pack_wire(&keys, true)
            {
                overlay.put_wire_node(&conversation_id, &hash, wire.clone())?;
                wire_node = Some(wire);
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

        let (old_epoch, new_epoch) =
            if let Some(Conversation::Established(em)) = self.conversations.get(&conversation_id) {
                (Some(em.current_epoch()), em.current_epoch() + 1)
            } else {
                (None, 0)
            };

        // 1. Create Rekey node (belongs to the OLD epoch's ratchet)
        let rekey_effects = self.author_node_internal(
            conversation_id,
            Content::Control(ControlAction::Rekey { new_epoch }),
            Vec::new(),
            store,
            old_epoch,
        )?;
        let rekey_node = rekey_effects
            .iter()
            .find_map(|e| {
                if let Effect::WriteStore(_, node, _) = e
                    && matches!(node.content, Content::Control(ControlAction::Rekey { .. }))
                {
                    return Some(node.clone());
                }
                None
            })
            .unwrap();
        tracing::debug!(
            "Rotation: Rekey node created at rank {}",
            rekey_node.topological_rank
        );
        effects.extend(rekey_effects);

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
            new_epoch,
            new_k_conv,
        ));

        // 3. Create KeyWrap nodes for all authorized devices (bootstraps the NEW epoch)
        let mut wrapped_keys = Vec::new();
        let em = match self.conversations.get(&conversation_id).unwrap() {
            Conversation::Established(em) => em,
            _ => unreachable!(),
        };
        let keys = em.get_keys(new_epoch).unwrap();

        // Generate an ephemeral key for this rotation to avoid two-time pad
        let mut e_sk_bytes = [0u8; 32];
        self.rng.lock().fill_bytes(&mut e_sk_bytes);
        let e_sk = e_sk_bytes;
        let e_pk = EphemeralX25519Pk::from(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_sk_bytes)).to_bytes(),
        );

        let recipients = self.identity_manager.list_active_authorized_devices(
            conversation_id,
            now,
            rekey_node.topological_rank,
        );
        tracing::debug!(
            "Rotation: Found {} active recipients at rank {}",
            recipients.len(),
            rekey_node.topological_rank
        );
        for recipient_pk in recipients {
            if recipient_pk != self.self_pk
                && let Some(ciphertext) = keys.wrap_for(&e_sk, &recipient_pk)
            {
                wrapped_keys.push(crate::dag::WrappedKey {
                    recipient_pk,
                    ciphertext,
                });
            }
        }

        if !wrapped_keys.is_empty() || new_epoch == 0 {
            let wrap_effects = self.author_node_internal(
                conversation_id,
                Content::KeyWrap {
                    epoch: new_epoch,
                    wrapped_keys,
                    ephemeral_pk: Some(e_pk),
                    pre_key_pk: None,
                },
                Vec::new(),
                store,
                Some(new_epoch),
            )?;
            effects.extend(wrap_effects);
        }

        Ok(effects)
    }

    pub fn get_authorized_devices(
        &self,
        conversation_id: &ConversationId,
    ) -> Vec<PhysicalDevicePk> {
        self.identity_manager
            .list_authorized_devices(*conversation_id)
    }

    pub fn get_current_epoch(&self, conversation_id: &ConversationId) -> u32 {
        self.conversations
            .get(conversation_id)
            .and_then(|c| match c {
                Conversation::Established(em) => Some(em.current_epoch() as u32),
                Conversation::Pending(_) => None,
            })
            .unwrap_or(0)
    }

    /// Authors a RatchetSnapshot node for self-recovery.
    pub fn author_ratchet_snapshot(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        let em = match self.conversations.get(&conversation_id) {
            Some(Conversation::Established(em)) => em,
            _ => return Err(MerkleToxError::KeyNotFound(conversation_id, 0)),
        };

        let heads = store.get_heads(&conversation_id);
        if heads.is_empty() {
            return Err(MerkleToxError::Validation(ValidationError::EmptyDag));
        }

        // We take the chain key derived from current heads
        let (_k_msg, k_next) = em.peek_keys(&heads).ok_or_else(|| {
            MerkleToxError::Ratchet("Missing parent chain keys for snapshot".to_string())
        })?;

        // Encrypt for our other authorized devices
        let mut wrapped_keys = Vec::new();
        if let Some(sk) = &self.self_dh_sk {
            let recipients = self.identity_manager.list_active_authorized_devices(
                conversation_id,
                self.clock.network_time_ms(),
                u64::MAX,
            );
            for recipient_pk in recipients {
                if recipient_pk != self.self_pk
                    && let Some(temp_keys) = Some(crate::crypto::ConversationKeys::derive(
                        &k_next.to_conversation_key(),
                    ))
                    && let Some(ciphertext) = temp_keys.wrap_for(sk.as_bytes(), &recipient_pk)
                {
                    wrapped_keys.push(crate::dag::WrappedKey {
                        recipient_pk,
                        ciphertext,
                    });
                }
            }
        }

        let content = Content::RatchetSnapshot {
            epoch: em.current_epoch(),
            ciphertext: tox_proto::serialize(&wrapped_keys)?,
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

        let content = Content::Control(ControlAction::Snapshot {
            basis_hash,
            members,
            last_seq_numbers,
        });

        self.author_node(conversation_id, content, Vec::new(), store)
    }
}
