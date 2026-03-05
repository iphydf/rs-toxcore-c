use crate::dag::{Content, ControlAction, ConversationId};
use crate::engine::processor::VerifiedNode;
use crate::engine::{Conversation, Effect, MerkleToxEngine};
use crate::error::MerkleToxResult;
use crate::sync::NodeStore;

impl MerkleToxEngine {
    /// Applies administrative and cryptographic side-effects of verified node.
    pub fn apply_side_effects(
        &mut self,
        conversation_id: ConversationId,
        node: &VerifiedNode,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        let (node_ref, content) = (node.node(), node.content());
        let mut effects = Vec::new();

        let mut admin_ancestor_hashes = std::collections::HashSet::new();
        let mut stack = node_ref.parents.clone();
        let mut visited = std::collections::HashSet::new();

        let overlay = crate::engine::EngineStore {
            store,
            cache: &self.pending_cache,
        };

        while let Some(parent_hash) = stack.pop() {
            if visited.insert(parent_hash)
                && let Some(parent_node) = overlay.get_node(&parent_hash)
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

        // Apply Administrative Actions
        match content {
            Content::Control(ControlAction::Genesis {
                creator_pk,
                created_at,
                flags,
                ..
            }) => {
                self.identity_manager.add_member(
                    conversation_id,
                    *creator_pk,
                    0, // Role: Owner/Admin
                    *created_at,
                );
                // Record genesis node as initial anchor for KeyWrap nodes.
                self.latest_anchor_hashes
                    .insert(conversation_id, node.hash());
                // Store genesis flags for invite permission checks.
                if let Some(conv) = self.conversations.get_mut(&conversation_id) {
                    conv.set_genesis_flags(*flags);
                }
                // Promote identity_pending to false: Genesis confirms admin chain root.
                if let Some(Conversation::Established(e)) =
                    self.conversations.get_mut(&conversation_id)
                {
                    e.state.identity_pending = false;
                }
            }
            Content::Control(ControlAction::AuthorizeDevice { cert }) => {
                self.identity_manager.authorize_device(
                    &ctx,
                    conversation_id,
                    node_ref.author_pk,
                    cert,
                    node_ref.network_timestamp,
                    node_ref.topological_rank,
                    node.hash(),
                )?;
                // Store our cert for SoftAnchor authoring
                if cert.device_pk == self.self_pk {
                    self.self_certs.insert(conversation_id, cert.clone());
                }
            }
            Content::Control(ControlAction::RevokeDevice {
                target_device_pk, ..
            }) => {
                self.identity_manager.revoke_device(
                    conversation_id,
                    node_ref.sender_pk,
                    node_ref.author_pk,
                    *target_device_pk,
                    node_ref.topological_rank,
                    node_ref.network_timestamp,
                    node.hash(),
                );
                // Purge vouches from revoked device (§5: immediate purge)
                if let Some(conv) = self.conversations.get_mut(&conversation_id) {
                    for vouch_set in conv.vouchers_mut().values_mut() {
                        vouch_set.remove(target_device_pk);
                    }
                }
                // Membership change triggers immediate K_conv rotation, but only
                // on admin who authored revocation. Other devices processing
                // this node should not auto-rotate (prevents
                // conflicting parallel rotations).
                if node_ref.sender_pk == self.self_pk {
                    let now_revoke = self.clock.network_time_ms();
                    let is_admin_revoke = self
                        .identity_manager
                        .get_permissions(
                            &ctx,
                            conversation_id,
                            &self.self_pk,
                            &self.self_logical_pk,
                            now_revoke,
                            node_ref.topological_rank,
                        )
                        .unwrap_or(crate::dag::Permissions::NONE)
                        .contains(crate::dag::Permissions::ADMIN);
                    if is_admin_revoke
                        && let Ok(mut r_effects) =
                            self.rotate_conversation_key_post_revocation(conversation_id, store)
                    {
                        effects.append(&mut r_effects);
                    }
                }
            }
            Content::Control(ControlAction::Invite(invite)) => {
                self.identity_manager.add_member(
                    conversation_id,
                    invite.invitee_pk,
                    invite.role,
                    node_ref.network_timestamp,
                );
            }
            Content::Control(ControlAction::Leave(logical_pk)) => {
                self.identity_manager.remove_member(
                    conversation_id,
                    node_ref.sender_pk,
                    node_ref.author_pk,
                    *logical_pk,
                    node_ref.topological_rank,
                    node_ref.network_timestamp,
                    node.hash(),
                );
            }
            Content::Control(ControlAction::Announcement {
                pre_keys,
                last_resort_key,
            }) => {
                // Verify each pre-key's Ed25519 signature before accepting.
                // Signature covers only raw X25519 public key bytes and
                // must be made by announcing device's key (node_ref.sender_pk).
                use ed25519_dalek::{Verifier, VerifyingKey};
                let valid_pre_keys = if let Ok(vk) =
                    VerifyingKey::from_bytes(node_ref.sender_pk.as_bytes())
                {
                    pre_keys
                        .iter()
                        .filter(|spk| {
                            let sig = ed25519_dalek::Signature::from_bytes(spk.signature.as_ref());
                            vk.verify(spk.public_key.as_bytes(), &sig).is_ok()
                        })
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                self.peer_announcements.insert(
                    node_ref.sender_pk,
                    ControlAction::Announcement {
                        pre_keys: valid_pre_keys,
                        last_resort_key: last_resort_key.clone(),
                    },
                );
            }
            Content::Control(ControlAction::Snapshot(_)) => {
                // Update latest anchor hash so future KeyWraps reference it.
                self.latest_anchor_hashes
                    .insert(conversation_id, node.hash());
            }
            Content::Control(ControlAction::AnchorSnapshot { data, .. }) => {
                // Update latest anchor hash so future KeyWraps reference it.
                self.latest_anchor_hashes
                    .insert(conversation_id, node.hash());
                // Apply member list from snapshot to
                // identity_manager so nodes authored by members can
                // be re-verified after snapshot is accepted.
                for member in &data.members {
                    self.identity_manager.add_member(
                        conversation_id,
                        member.public_key,
                        member.role,
                        member.joined_at,
                    );
                }
                // Track trust-restored devices. If logical identity
                // appears in snapshot's member list, record heal timestamp
                // for 30-day expiry enforcement.
                let self_logical = self.self_logical_pk;
                if data.members.iter().any(|m| m.public_key == self_logical) {
                    let now_ms = self.clock.network_time_ms();
                    self.trust_restored_devices
                        .insert((conversation_id, self.self_pk), now_ms);
                }
            }
            Content::Control(ControlAction::SoftAnchor { .. }) => {
                // SoftAnchor resets 500-hop ancestry trust cap.
                // Update latest anchor hash so future KeyWraps reference it.
                self.latest_anchor_hashes
                    .insert(conversation_id, node.hash());
            }
            Content::Control(ControlAction::HandshakePulse) => {
                let max_rank = self
                    .highest_handled_pulse
                    .entry((conversation_id, node_ref.sender_pk))
                    .or_insert(0);
                if node_ref.topological_rank <= *max_rank {
                    tracing::debug!("HandshakePulse ignored due to topological debounce.");
                } else {
                    *max_rank = node_ref.topological_rank;

                    let now = self.clock.network_time_ms();
                    let is_admin = self
                        .identity_manager
                        .get_permissions(
                            &ctx,
                            conversation_id,
                            &self.self_pk,
                            &self.self_logical_pk,
                            now,
                            node_ref.topological_rank,
                        )
                        .unwrap_or(crate::dag::Permissions::NONE)
                        .contains(crate::dag::Permissions::ADMIN);

                    if is_admin {
                        let should_rotate = if let Some(Conversation::Established(em)) =
                            self.conversations.get(&conversation_id)
                        {
                            now - em.state.last_rotation_time_ms >= 300_000 // 5 minutes
                        } else {
                            true
                        };

                        if should_rotate {
                            tracing::debug!(
                                "HandshakePulse received, executing debounced key rotation."
                            );
                            if let Ok(mut r_effects) =
                                self.rotate_conversation_key(conversation_id, store)
                            {
                                effects.append(&mut r_effects);
                            }
                        } else {
                            tracing::debug!("HandshakePulse ignored due to 5-minute debounce.");
                        }
                    }
                }
            }
            Content::SenderKeyDistribution {
                ephemeral_signing_pk,
                disclosed_keys,
                ..
            } => {
                // Store sender's ephemeral signing public key only if we
                // have epoch key (k_conv) for this epoch. Preserves
                // PCS: revoked device that cannot decrypt SKD's wrapped
                // keys must not verify subsequent content messages.
                //
                // Exception: device-signed SKDs (first epoch or signing key
                // reset) bypass PCS gate because device Ed25519
                // signature already authenticates sender. Allows
                // new devices joining mid-conversation to learn signing
                // key chain even for epochs whose k_conv they never received.
                let epoch = node_ref.sequence_number >> 32;
                let has_epoch_key = matches!(
                    self.conversations.get(&conversation_id),
                    Some(Conversation::Established(em)) if em.get_keys(epoch).is_some()
                );
                let is_device_signed =
                    matches!(&node_ref.authentication, crate::dag::NodeAuth::Signature(_));
                if has_epoch_key || is_device_signed {
                    self.peer_ephemeral_signing_keys
                        .insert((node_ref.sender_pk, epoch), *ephemeral_signing_pk);

                    // Store disclosed keys from previous epochs for deniability.
                    // Each disclosed key is ephemeral_signing_sk for epoch
                    // immediately preceding this SKD's epoch.
                    if epoch > 0 {
                        for (i, key) in disclosed_keys.iter().enumerate() {
                            let disclosed_epoch = epoch - 1 - i as u64;
                            self.disclosed_signing_keys
                                .insert((node_ref.sender_pk, disclosed_epoch), key.clone());
                        }
                    }
                }

                // Same-epoch SKD = sender rekey. Reset ratchet for this sender
                // so peek_keys re-initializes from the new SenderKey.
                if let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                    && epoch == em.current_epoch()
                {
                    em.state.sender_ratchets.remove(&node_ref.sender_pk);
                }
            }
            _ => {}
        }

        // Advance ratchet if keys are available (exception nodes skip ratchet advancement
        // but still track sequence numbers for ordering).
        let now = self.clock.network_time_ms();
        if node.node().skips_ratchet() {
            if let Some(Conversation::Established(em)) =
                self.conversations.get_mut(&conversation_id)
            {
                let epoch = node_ref.sequence_number >> 32;
                em.track_sender_seq(node_ref.sender_pk, node_ref.sequence_number, epoch);
            }
        } else if let Some(Conversation::Established(em)) =
            self.conversations.get_mut(&conversation_id)
        {
            if let Some((_, k_next)) =
                em.peek_keys(&node_ref.sender_pk, node_ref.sequence_number, now)
            {
                tracing::debug!(
                    "Advancing ratchet for node {} (sender={}, seq={})",
                    hex::encode(node.hash().as_bytes()),
                    hex::encode(node_ref.sender_pk.as_bytes()),
                    node_ref.sequence_number
                );
                let node_epoch = node_ref.sequence_number >> 32;
                let prev_hash = em.commit_node_key(
                    node_ref.sender_pk,
                    node_ref.sequence_number,
                    k_next.clone(),
                    node.hash(),
                    node_epoch,
                );
                effects.push(Effect::WriteRatchetKey(
                    conversation_id,
                    node.hash(),
                    k_next,
                    node_epoch,
                ));

                // Purge previous ratchet key from persistent storage.
                if let Some(prev) = prev_hash {
                    tracing::debug!(
                        "Purging old ratchet key for previous node {}",
                        hex::encode(prev.as_bytes())
                    );
                    effects.push(Effect::DeleteRatchetKey(conversation_id, prev));
                }
            } else {
                tracing::debug!(
                    "Ratchet NOT advanced for node {}: peek_keys returned None",
                    hex::encode(node.hash().as_bytes())
                );
            }
        }

        let overlay = crate::engine::EngineStore {
            store,
            cache: &self.pending_cache,
        };

        effects.extend(update_heads(conversation_id, node, &overlay)?);
        Ok(effects)
    }
}

fn update_heads(
    conversation_id: ConversationId,
    node: &VerifiedNode,
    overlay: &crate::engine::EngineStore,
) -> MerkleToxResult<Vec<Effect>> {
    let node_ref = node.node();
    let hash = node.hash();
    let mut effects = Vec::new();

    if node_ref.node_type() == crate::dag::NodeType::Admin {
        let mut heads = overlay.get_admin_heads(&conversation_id);
        heads.retain(|h| !node_ref.parents.contains(h));
        if !heads.contains(&hash) {
            heads.push(hash);
        }
        overlay.set_admin_heads(&conversation_id, heads.clone())?;
        effects.push(Effect::UpdateHeads(conversation_id, heads, true));
    } else {
        let mut heads = overlay.get_heads(&conversation_id);
        heads.retain(|h| !node_ref.parents.contains(h));
        if !heads.contains(&hash) {
            heads.push(hash);
        }
        overlay.set_heads(&conversation_id, heads.clone())?;
        effects.push(Effect::UpdateHeads(conversation_id, heads, false));
    }

    Ok(effects)
}
