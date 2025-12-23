use crate::dag::{Content, ControlAction, ConversationId};
use crate::engine::processor::VerifiedNode;
use crate::engine::{Conversation, Effect, MerkleToxEngine};
use crate::error::MerkleToxResult;
use crate::sync::NodeStore;
use tracing::info;

impl MerkleToxEngine {
    /// Applies the administrative and cryptographic side-effects of a verified node.
    pub fn apply_side_effects(
        &mut self,
        conversation_id: ConversationId,
        node: &VerifiedNode,
        store: &dyn NodeStore,
    ) -> MerkleToxResult<Vec<Effect>> {
        let (node_ref, content) = (node.node(), node.content());
        let mut effects = Vec::new();

        let overlay = crate::engine::EngineStore {
            store,
            cache: &self.pending_cache,
        };

        // Special case: RatchetSnapshot for self-recovery
        if let Content::RatchetSnapshot { epoch, ciphertext } = content
            && let Some(sk) = &self.self_dh_sk
            && let Ok(wrapped_keys) =
                tox_proto::deserialize::<Vec<crate::dag::WrappedKey>>(ciphertext)
        {
            for wrapped in wrapped_keys {
                if wrapped.recipient_pk == self.self_pk {
                    // Unwrap ratchet chain key
                    if let Some(k_conv) = crate::crypto::ConversationKeys::unwrap_from(
                        sk.as_bytes(),
                        &node_ref.sender_pk,
                        &wrapped.ciphertext,
                    ) {
                        let chain_key = k_conv.to_chain_key();
                        if let Some(Conversation::Established(em)) =
                            self.conversations.get_mut(&conversation_id)
                            && em.get_keys(*epoch).is_some()
                        {
                            info!("Resuming ratchet from snapshot in epoch {}", epoch);
                            em.commit_node_key(node.hash(), &node_ref.parents, chain_key.clone());
                            effects.push(Effect::WriteRatchetKey(
                                conversation_id,
                                node.hash(),
                                chain_key,
                            ));
                        }
                    }
                    break;
                }
            }
        }

        // Apply Administrative Actions
        match content {
            Content::Control(ControlAction::Genesis {
                creator_pk,
                created_at,
                ..
            }) => {
                self.identity_manager.add_member(
                    conversation_id,
                    *creator_pk,
                    0, // Role: Owner/Admin
                    *created_at,
                );
            }
            Content::Control(ControlAction::AuthorizeDevice { cert }) => {
                self.identity_manager.authorize_device(
                    conversation_id,
                    node_ref.author_pk,
                    cert,
                    node_ref.network_timestamp,
                    node_ref.topological_rank,
                )?;
            }
            Content::Control(ControlAction::RevokeDevice {
                target_device_pk, ..
            }) => {
                self.identity_manager.revoke_device(
                    conversation_id,
                    *target_device_pk,
                    node_ref.topological_rank,
                );
                // Membership change should trigger rotation if we are admin
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
                    *logical_pk,
                    node_ref.topological_rank,
                );
            }
            Content::Control(ControlAction::Rekey { new_epoch }) => {
                info!(
                    "Conversation {:?} rotated to epoch {}",
                    conversation_id, new_epoch
                );
            }
            Content::Control(action @ ControlAction::Announcement { .. }) => {
                self.peer_announcements
                    .insert(node_ref.sender_pk, action.clone());
            }
            _ => {}
        }

        // Advance ratchet if keys are available
        if let Some(Conversation::Established(em)) = self.conversations.get_mut(&conversation_id) {
            let is_bootstrap = matches!(
                content,
                Content::KeyWrap { .. }
                    | Content::RatchetSnapshot { .. }
                    | Content::Control(ControlAction::Genesis { .. })
            );

            let ratchet_info = if let Some((k_msg, k_next)) = em.peek_keys(&node_ref.parents) {
                Some((k_msg, k_next))
            } else if is_bootstrap {
                // For bootstrap nodes, if we can't find parent keys, use the epoch root
                let k_conv = em
                    .get_keys(em.current_epoch())
                    .ok_or_else(|| {
                        crate::error::MerkleToxError::KeyNotFound(
                            conversation_id,
                            em.current_epoch(),
                        )
                    })?
                    .k_conv
                    .clone();
                let k_msg = crate::crypto::ratchet_message_key(&k_conv.to_chain_key());
                let k_next = crate::crypto::ratchet_step(&k_conv.to_chain_key());
                Some((k_msg, k_next))
            } else {
                None
            };

            if let Some((_, k_next)) = ratchet_info {
                tracing::debug!(
                    "Advancing ratchet for node {} with parents {:?}",
                    hex::encode(node.hash().as_bytes()),
                    node_ref
                        .parents
                        .iter()
                        .map(|p| hex::encode(p.as_bytes()))
                        .collect::<Vec<_>>()
                );
                em.commit_node_key(node.hash(), &node_ref.parents, k_next.clone());
                effects.push(Effect::WriteRatchetKey(
                    conversation_id,
                    node.hash(),
                    k_next,
                ));

                // Purge parent ratchet keys from persistent storage after they are used.
                // Memory-level retention for concurrent branches is handled by em.commit_node_key.
                for parent_hash in &node_ref.parents {
                    tracing::debug!(
                        "Purging old ratchet key for parent {}",
                        hex::encode(parent_hash.as_bytes())
                    );
                    effects.push(Effect::DeleteRatchetKey(conversation_id, *parent_hash));
                }
            } else {
                tracing::debug!(
                    "Ratchet NOT advanced for node {}: peek_keys returned None",
                    hex::encode(node.hash().as_bytes())
                );
            }
        }

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
