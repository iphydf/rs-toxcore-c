use crate::NodeEvent;
use crate::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeAuth,
    NodeType, Permissions,
};
use crate::engine::processor::VerifiedNode;
use crate::engine::{Conversation, ConversationData, Effect, MerkleToxEngine, conversation};
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::{BlobStore, NodeStore};
use tox_proto::constants::{MAX_SPECULATIVE_NODES_PER_CONVERSATION, MAX_VERIFIED_NODES_PER_DEVICE};
use tracing::{debug, error, info, warn};

const VOUCH_THRESHOLD: usize = 1;

impl MerkleToxEngine {
    /// Handles a received Merkle node.
    pub fn handle_node(
        &mut self,
        conversation_id: ConversationId,
        node: MerkleNode,
        store: &dyn NodeStore,
        blob_store: Option<&dyn BlobStore>,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.handle_node_internal_ext(conversation_id, node, store, blob_store, true)
    }

    pub(crate) fn handle_node_internal_ext(
        &mut self,
        conversation_id: ConversationId,
        node: MerkleNode,
        store: &dyn NodeStore,
        blob_store: Option<&dyn BlobStore>,
        reverify: bool,
    ) -> MerkleToxResult<Vec<Effect>> {
        let node_hash = node.hash();
        let mut effects = Vec::new();
        let now = self.clock.network_time_ms();

        let (verified, authentic) = {
            let overlay = crate::engine::EngineStore {
                store,
                cache: &self.pending_cache,
            };

            if overlay.is_verified(&node_hash) {
                return Ok(effects);
            }

            // 1. Validate DAG rules
            let structurally_valid = match node.validate(&conversation_id, &overlay) {
                Ok(_) => true,
                Err(crate::dag::ValidationError::MissingParents(_))
                | Err(crate::dag::ValidationError::TopologicalRankViolation { .. }) => false,
                Err(e) => {
                    info!("Node validation failed: {}", e);
                    return Err(MerkleToxError::Validation(e));
                }
            };

            let mut authentic = false;
            let mut quarantined = false;

            // Hard Monotonicity Check
            let mut max_parent_ts = 0;
            let is_bootstrap = matches!(
                node.content,
                Content::KeyWrap { .. }
                    | Content::RatchetSnapshot { .. }
                    | Content::Control(ControlAction::Genesis { .. })
                    | Content::Control(ControlAction::AuthorizeDevice { .. })
            );

            let is_authorized = self.identity_manager.is_authorized(
                conversation_id,
                &node.sender_pk,
                &node.author_pk,
                node.network_timestamp,
                node.topological_rank,
            );

            for p in &node.parents {
                if let Some(parent_node) = overlay.get_node(p) {
                    max_parent_ts = max_parent_ts.max(parent_node.network_timestamp);
                }

                if !overlay.is_verified(p) && !is_bootstrap {
                    debug!(
                        "Node {} quarantined: parent {} is not verified",
                        hex::encode(node_hash.as_bytes()),
                        hex::encode(p.as_bytes())
                    );
                    quarantined = true;
                }
            }

            if !is_authorized && !is_bootstrap && !quarantined {
                let vouches = self
                    .conversations
                    .get(&conversation_id)
                    .map(|c| c.vouchers().get(&node_hash).map_or(0, |v| v.len()))
                    .unwrap_or(0);

                if vouches < VOUCH_THRESHOLD {
                    debug!(
                        "Node {} quarantined: not authorized and insufficient vouches ({}/{})",
                        hex::encode(node_hash.as_bytes()),
                        vouches,
                        VOUCH_THRESHOLD
                    );
                    quarantined = true;
                }
            }

            if node.network_timestamp < max_parent_ts {
                debug!(
                    "Node {} quarantined: timestamp {} < max parent timestamp {}",
                    hex::encode(node_hash.as_bytes()),
                    node.network_timestamp,
                    max_parent_ts
                );
                quarantined = true;
            }

            if node.network_timestamp > now + 10 * 60 * 1000 {
                debug!(
                    "Node {} quarantined: timestamp {} is too far in the future (now={} + 10min)",
                    hex::encode(node_hash.as_bytes()),
                    node.network_timestamp,
                    now
                );
                quarantined = true;
            }

            debug!(
                "Node {} is_authorized={}, quarantined={}",
                hex::encode(node_hash.as_bytes()),
                is_authorized,
                quarantined
            );

            if is_authorized
                || self
                    .identity_manager
                    .has_authorization_record(conversation_id, &node.sender_pk)
            {
                self.check_permissions(conversation_id, &node, node.network_timestamp)?;
            }

            if is_authorized {
                let last_verified_seq =
                    overlay.get_last_sequence_number(&conversation_id, &node.sender_pk);

                debug!(
                    "Node {} last_verified_seq={}",
                    hex::encode(node_hash.as_bytes()),
                    last_verified_seq
                );

                if node.sequence_number <= last_verified_seq {
                    warn!(
                        "Node {} has invalid sequence number {} (last verified was {})",
                        hex::encode(node_hash.as_bytes()),
                        node.sequence_number,
                        last_verified_seq
                    );
                    return Err(MerkleToxError::Validation(
                        crate::dag::ValidationError::InvalidSequenceNumber {
                            actual: node.sequence_number,
                            last: last_verified_seq,
                        },
                    ));
                }

                if node.sequence_number > last_verified_seq + 1 {
                    debug!(
                        "Node {} is future sequence number {} (last verified was {})",
                        hex::encode(node_hash.as_bytes()),
                        node.sequence_number,
                        last_verified_seq
                    );
                    // We don't mark as quarantined here anymore, because we want to allow
                    // skipping unverifiable nodes (like old KeyWraps).
                    // The parent-is-verified check will handle topological ordering.
                }

                if last_verified_seq >= MAX_VERIFIED_NODES_PER_DEVICE {
                    warn!(
                        "Device {:?} has exceeded its verified node quota ({}) in conversation {:?}",
                        node.sender_pk, MAX_VERIFIED_NODES_PER_DEVICE, conversation_id
                    );
                    return Err(MerkleToxError::Validation(
                        crate::dag::ValidationError::TooManyVerifiedNodes,
                    ));
                }
            }

            let mut verified = false;
            if is_authorized {
                if let Content::KeyWrap {
                    epoch,
                    wrapped_keys,
                    ephemeral_pk,
                    pre_key_pk,
                } = &node.content
                {
                    let mut k_conv_received = None;
                    if let (Some(e_a), Some(spk_b_pk)) = (ephemeral_pk, pre_key_pk)
                        && let Some(spk_b_sk) = self.ephemeral_keys.get(spk_b_pk)
                        && let Some(sk) = &self.self_sk
                        && let Some(sk_shared) = crate::crypto::x3dh_derive_secret_recipient(
                            sk,
                            spk_b_sk,
                            &node.sender_pk,
                            e_a,
                            None,
                        )
                    {
                        for wrapped in wrapped_keys {
                            if wrapped.recipient_pk == self.self_pk
                                && wrapped.ciphertext.len() == 32
                            {
                                use chacha20::cipher::{KeyIvInit, StreamCipher};
                                let mut k = [0u8; 32];
                                k.copy_from_slice(&wrapped.ciphertext);
                                let mut cipher = chacha20::ChaCha20::new(
                                    sk_shared.as_bytes().into(),
                                    &[0u8; 12].into(),
                                );
                                cipher.apply_keystream(&mut k);
                                k_conv_received = Some(KConv::from(k));
                                break;
                            }
                        }
                    }
                    if k_conv_received.is_none()
                        && let Some(sk) = &self.self_dh_sk
                    {
                        for wrapped in wrapped_keys {
                            if wrapped.recipient_pk == self.self_pk {
                                if let Some(e_a) = ephemeral_pk {
                                    // Alice used an ephemeral key for this rotation
                                    k_conv_received =
                                        crate::crypto::ConversationKeys::unwrap_from_x25519(
                                            sk.as_bytes(),
                                            e_a.as_bytes(),
                                            &wrapped.ciphertext,
                                        );
                                } else {
                                    // Alice used her static key (backward compatibility)
                                    k_conv_received = crate::crypto::ConversationKeys::unwrap_from(
                                        sk.as_bytes(),
                                        &node.sender_pk,
                                        &wrapped.ciphertext,
                                    );
                                }
                                if k_conv_received.is_some() {
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(k_conv) = k_conv_received {
                        let em =
                            match self
                                .conversations
                                .remove(&conversation_id)
                                .unwrap_or_else(|| {
                                    Conversation::Pending(
                                        ConversationData::<conversation::Pending>::new(
                                            conversation_id,
                                        ),
                                    )
                                }) {
                                Conversation::Pending(p) => {
                                    p.establish(k_conv.clone(), node.network_timestamp, *epoch)
                                }
                                Conversation::Established(mut e) => {
                                    e.add_epoch(*epoch, k_conv.clone());
                                    e
                                }
                            };
                        effects.push(Effect::WriteConversationKey(
                            conversation_id,
                            *epoch,
                            k_conv,
                        ));
                        self.conversations
                            .insert(conversation_id, Conversation::Established(em));
                    }
                } else if let Content::RatchetSnapshot { epoch, ciphertext } = &node.content
                    && let Some(sk) = &self.self_dh_sk
                    && let Ok(wrapped_keys) =
                        tox_proto::deserialize::<Vec<crate::dag::WrappedKey>>(ciphertext)
                {
                    for wrapped in wrapped_keys {
                        if wrapped.recipient_pk == self.self_pk {
                            if let Some(k_conv) = crate::crypto::ConversationKeys::unwrap_from(
                                sk.as_bytes(),
                                &node.sender_pk,
                                &wrapped.ciphertext,
                            ) {
                                let chain_key = k_conv.to_chain_key();
                                if let Some(Conversation::Established(em)) =
                                    self.conversations.get_mut(&conversation_id)
                                    && em.current_epoch() == *epoch
                                {
                                    em.commit_node_key(node_hash, &node.parents, chain_key);
                                }
                            }
                            break;
                        }
                    }
                }
            }

            if let NodeAuth::Mac(_) = &node.authentication {
                if let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                {
                    if em.verify_node_mac(&conversation_id, &node) {
                        authentic = true;
                    }

                    if !authentic {
                        debug!(
                            "Node {} MAC verification failed after trying all epochs",
                            hex::encode(node_hash.as_bytes())
                        );
                    }
                }
            } else if let NodeAuth::Signature(_) = &node.authentication {
                authentic = true;
            }

            if authentic && structurally_valid && !quarantined {
                verified = true;
            } else if !is_authorized
                && !quarantined
                && let Content::Control(ControlAction::AuthorizeDevice { cert }) = &node.content
                && self
                    .identity_manager
                    .authorize_device(
                        conversation_id,
                        node.author_pk,
                        cert,
                        node.network_timestamp,
                        node.topological_rank,
                    )
                    .is_ok()
                && structurally_valid
            {
                verified = true;
            }

            if verified {
                overlay.put_node(&conversation_id, node.clone(), true)?;
                debug!(
                    "Node {} verified and added to overlay",
                    hex::encode(node_hash.as_bytes())
                );
            } else {
                debug!(
                    "Node {} NOT verified. structurally_valid={}, authentic={}, is_authorized={}, quarantined={}",
                    hex::encode(node_hash.as_bytes()),
                    structurally_valid,
                    authentic,
                    is_authorized,
                    quarantined
                );
                let (_, spec_count) = overlay.get_node_counts(&conversation_id);
                if spec_count >= MAX_SPECULATIVE_NODES_PER_CONVERSATION {
                    warn!(
                        "Too many speculative nodes for conversation {:?}, rejecting node {}",
                        conversation_id,
                        hex::encode(node_hash.as_bytes())
                    );
                    return Err(MerkleToxError::Validation(
                        crate::dag::ValidationError::TooManySpeculativeNodes,
                    ));
                }
                overlay.put_node(&conversation_id, node.clone(), false)?;
            }

            (verified, authentic)
        };

        // Ensure conversation entry exists
        self.conversations
            .entry(conversation_id)
            .or_insert_with(|| {
                Conversation::Pending(ConversationData::<conversation::Pending>::new(
                    conversation_id,
                ))
            });

        // 3. Update Sync Sessions
        for ((_, cid), session) in self.sessions.iter_mut() {
            if cid == &conversation_id {
                session.on_node_received(&node, store, blob_store);
                if authentic {
                    for parent_hash in &node.parents {
                        session.record_vouch(*parent_hash, node.sender_pk);
                    }
                }
            }
        }

        if authentic && let Some(conv) = self.conversations.get_mut(&conversation_id) {
            for parent_hash in &node.parents {
                conv.vouchers_mut()
                    .entry(*parent_hash)
                    .or_default()
                    .insert(node.sender_pk);
            }
        }

        info!(
            "Engine persisting node {} (verified={})",
            hex::encode(node_hash.as_bytes()),
            verified
        );
        effects.push(Effect::WriteStore(conversation_id, node.clone(), verified));

        if authentic || verified {
            let is_bootstrap = matches!(
                node.content,
                Content::KeyWrap { .. }
                    | Content::RatchetSnapshot { .. }
                    | Content::Control(ControlAction::Genesis { .. })
                    | Content::Control(ControlAction::AuthorizeDevice { .. })
            );

            if verified || is_bootstrap {
                let verified_node = VerifiedNode::new(node.clone(), node.content.clone());
                let side_effects =
                    self.apply_side_effects(conversation_id, &verified_node, store)?;
                effects.extend(side_effects);

                if verified {
                    match verified_node.content() {
                        Content::Control(ControlAction::AuthorizeDevice { .. })
                        | Content::Control(ControlAction::RevokeDevice { .. })
                        | Content::Control(ControlAction::Leave(_)) => {
                            effects
                                .extend(self.revalidate_all_verified_nodes(conversation_id, store));
                        }
                        _ => {}
                    }
                }
            }
        }

        if reverify && (authentic || verified) {
            effects.extend(self.reverify_speculative_for_conversation(conversation_id, store));
            effects.extend(self.reverify_opaque_nodes(conversation_id, store));
        }

        if verified {
            effects.push(Effect::EmitEvent(NodeEvent::NodeVerified {
                conversation_id,
                hash: node_hash,
                node,
            }));
        } else {
            effects.push(Effect::EmitEvent(NodeEvent::NodeSpeculative {
                conversation_id,
                hash: node_hash,
                node,
            }));
        }

        Ok(effects)
    }

    /// Re-validates all verified nodes for a conversation.
    /// Used when a revocation node is received that might invalidate previously verified nodes.
    pub fn revalidate_all_verified_nodes(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        let verified_content = store
            .get_verified_nodes_by_type(&conversation_id, NodeType::Content)
            .unwrap_or_default();
        let verified_admin = store
            .get_verified_nodes_by_type(&conversation_id, NodeType::Admin)
            .unwrap_or_default();

        let mut all_verified = verified_content;
        all_verified.extend(verified_admin);
        all_verified.sort_by_key(|n| n.topological_rank);

        debug!("Re-validating {} verified nodes", all_verified.len());

        for node in all_verified {
            if !self.verify_node_internal(conversation_id, &node, store) {
                debug!(
                    "  Invalidating node {} (rank {})",
                    hex::encode(node.hash().as_bytes()),
                    node.topological_rank
                );
                info!(
                    "Node {} retroactively invalidated due to identity changes",
                    hex::encode(node.hash().as_bytes())
                );
                effects.push(Effect::WriteStore(conversation_id, node.clone(), false));
                effects.push(Effect::EmitEvent(NodeEvent::NodeInvalidated {
                    conversation_id,
                    hash: node.hash(),
                }));
            }
        }
        effects
    }

    /// Checks if the sender has required permissions for the node's content.
    fn check_permissions(
        &self,
        conversation_id: ConversationId,
        node: &MerkleNode,
        now: i64,
    ) -> MerkleToxResult<()> {
        let actual = self
            .identity_manager
            .get_permissions(
                conversation_id,
                &node.sender_pk,
                &node.author_pk,
                now,
                node.topological_rank,
            )
            .unwrap_or(Permissions::NONE);

        let required = match &node.content {
            Content::Text(_)
            | Content::Blob { .. }
            | Content::Reaction { .. }
            | Content::Location { .. }
            | Content::Redaction { .. }
            | Content::Other { .. }
            | Content::RatchetSnapshot { .. } => Permissions::MESSAGE,
            Content::Control(action) => match action {
                ControlAction::AuthorizeDevice { .. }
                | ControlAction::RevokeDevice { .. }
                | ControlAction::SetTitle(_)
                | ControlAction::SetTopic(_)
                | ControlAction::Invite(_)
                | ControlAction::Snapshot { .. }
                | ControlAction::Rekey { .. }
                | ControlAction::Genesis { .. } => Permissions::ADMIN,
                ControlAction::Leave(target_pk) => {
                    if node.author_pk == *target_pk {
                        Permissions::NONE // Self-leave is always allowed
                    } else {
                        Permissions::ADMIN // Kicking others requires admin
                    }
                }
                ControlAction::Announcement { .. } | ControlAction::HandshakePulse => {
                    Permissions::NONE
                } // No permissions required
            },
            Content::KeyWrap { .. } => Permissions::ADMIN,
        };

        if !actual.contains(required) {
            return Err(MerkleToxError::PermissionDenied {
                pk: node.sender_pk,
                required: required.bits(),
                actual: actual.bits(),
            });
        }
        Ok(())
    }

    /// Re-scans speculative nodes for a specific author and verifies them if possible.
    pub fn reverify_speculative_for_author(
        &mut self,
        conversation_id: ConversationId,
        author_pk: LogicalIdentityPk,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        let speculative = store.get_speculative_nodes(&conversation_id);
        for node in speculative {
            if node.author_pk == author_pk {
                let (verified, v_effects) = self.verify_node(conversation_id, &node, store);
                if verified {
                    if let Err(e) = store.mark_verified(&conversation_id, &node.hash()) {
                        error!("Failed to mark node verified: {}", e);
                    } else {
                        effects.extend(v_effects);
                        effects.push(Effect::WriteStore(conversation_id, node.clone(), true));
                        effects.push(Effect::EmitEvent(NodeEvent::NodeVerified {
                            conversation_id,
                            hash: node.hash(),
                            node: node.clone(),
                        }));
                        // Vouch for parents of newly verified node
                        for ((_, cid), session) in self.sessions.iter_mut() {
                            if cid == &conversation_id {
                                for parent_hash in &node.parents {
                                    session.record_vouch(*parent_hash, node.sender_pk);
                                }
                            }
                        }
                    }
                }
            }
        }
        effects
    }

    /// Re-scans all speculative nodes for a conversation and verifies them if possible.
    pub fn reverify_speculative_for_conversation(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        let mut all_effects = Vec::new();
        loop {
            let mut verified_any = false;
            let speculative = {
                let overlay = crate::engine::EngineStore {
                    store,
                    cache: &self.pending_cache,
                };
                overlay.get_speculative_nodes(&conversation_id)
            };

            if speculative.is_empty() {
                break;
            }

            debug!(
                "reverify_speculative_for_conversation: found {} speculative nodes",
                speculative.len()
            );

            for node in speculative {
                let node_hash = node.hash();
                // Only attempt to verify if the node is already known to be authentic
                // OR if it's an Admin node (which are always "authentic" for this purpose as they use signatures)
                let is_authentic = match &node.authentication {
                    NodeAuth::Signature(_) => true,
                    NodeAuth::Mac(_) => {
                        if let Some(Conversation::Established(em)) =
                            self.conversations.get(&conversation_id)
                        {
                            em.verify_node_mac(&conversation_id, &node)
                        } else {
                            false
                        }
                    }
                };

                debug!(
                    "Node {} is_authentic={}",
                    hex::encode(node_hash.as_bytes()),
                    is_authentic
                );

                if !is_authentic {
                    continue;
                }

                if let Ok(v_effects) =
                    self.handle_node_internal_ext(conversation_id, node, store, None, false)
                {
                    // Check if the node actually became verified
                    let became_verified = v_effects.iter().any(|e| {
                        if let Effect::WriteStore(_, _, verified) = e {
                            *verified
                        } else {
                            false
                        }
                    });

                    if became_verified {
                        verified_any = true;
                        all_effects.extend(v_effects);
                    }
                }
            }

            if !verified_any {
                break;
            }
        }
        all_effects
    }

    /// Attempts to verify a speculative node.
    pub fn verify_node(
        &mut self,
        conversation_id: ConversationId,
        node: &MerkleNode,
        store: &dyn NodeStore,
    ) -> (bool, Vec<Effect>) {
        let mut effects = Vec::new();
        let now = self.clock.network_time_ms();

        let (verified, _authentic, _structurally_valid, _quarantined, _is_authorized) = {
            let overlay = crate::engine::EngineStore {
                store,
                cache: &self.pending_cache,
            };

            // 1. Structural check (including parents)
            let structurally_valid = match node.validate(&conversation_id, &overlay) {
                Ok(_) => true,
                Err(crate::dag::ValidationError::MissingParents(_))
                | Err(crate::dag::ValidationError::TopologicalRankViolation { .. }) => false,
                Err(e) => {
                    debug!(
                        "Node {} failed validation: {:?}",
                        hex::encode(node.hash().as_bytes()),
                        e
                    );
                    return (false, effects);
                }
            };

            // Hard Monotonicity Check
            let mut max_parent_ts = 0;
            for p in &node.parents {
                if let Some(parent_node) = overlay.get_node(p) {
                    max_parent_ts = max_parent_ts.max(parent_node.network_timestamp);
                }
            }

            let mut quarantined = false;
            if node.network_timestamp < max_parent_ts {
                debug!(
                    "Node {} failed verification: network_timestamp {} < max_parent_ts {}",
                    hex::encode(node.hash().as_bytes()),
                    node.network_timestamp,
                    max_parent_ts
                );
                quarantined = true;
            }

            if node.network_timestamp > now + 10 * 60 * 1000 {
                debug!(
                    "Node {} failed verification: network_timestamp {} > now + 10min",
                    hex::encode(node.hash().as_bytes()),
                    node.network_timestamp
                );
                quarantined = true;
            }

            let is_authorized = self.identity_manager.is_authorized(
                conversation_id,
                &node.sender_pk,
                &node.author_pk,
                node.network_timestamp,
                node.topological_rank,
            );

            let mut authentic = false;
            let mut verified = false;

            if is_authorized && !quarantined {
                if let NodeAuth::Signature(_) = &node.authentication {
                    authentic = true;
                } else if let NodeAuth::Mac(mac) = &node.authentication {
                    if overlay.is_verified(&node.hash()) {
                        // If already verified once, trust its authenticity.
                        // We are just re-checking authorization (e.g. for revocation).
                        authentic = true;
                    } else if let Some(Conversation::Established(em)) =
                        self.conversations.get_mut(&conversation_id)
                    {
                        if let Some((k_msg, _k_next)) = em.peek_keys(&node.parents) {
                            let keys = crate::crypto::ConversationKeys::derive(&KConv::from(
                                *k_msg.as_bytes(),
                            ));
                            if keys.verify_mac(&node.serialize_for_auth(&conversation_id), mac) {
                                authentic = true;
                            }
                        }

                        if !authentic {
                            let auth_data = node.serialize_for_auth(&conversation_id);
                            if let Some(keys) = em.get_keys(em.current_epoch())
                                && keys.verify_mac(&auth_data, mac)
                            {
                                authentic = true;
                            }
                        }
                    }
                }

                if authentic && structurally_valid {
                    verified = true;
                    overlay
                        .mark_verified(&conversation_id, &node.hash())
                        .unwrap();
                }
            }

            (
                verified,
                authentic,
                structurally_valid,
                quarantined,
                is_authorized,
            )
        };

        if verified {
            if let NodeAuth::Signature(_) = &node.authentication
                && let Some(Conversation::Established(em)) =
                    self.conversations.get_mut(&conversation_id)
                && let Some((_, k_next)) = em.peek_keys(&node.parents)
            {
                em.commit_node_key(node.hash(), &node.parents, k_next.clone());
                effects.push(Effect::WriteRatchetKey(
                    conversation_id,
                    node.hash(),
                    k_next,
                ));
            }
            return (true, effects);
        }

        (false, effects)
    }

    /// Internal version of verify_node used for re-validation.
    fn verify_node_internal(
        &mut self,
        conversation_id: ConversationId,
        node: &MerkleNode,
        store: &dyn NodeStore,
    ) -> bool {
        self.verify_node(conversation_id, node, store).0
    }

    /// Attempts to unpack and verify nodes from the Opaque Store.
    pub fn reverify_opaque_nodes(
        &mut self,
        conversation_id: ConversationId,
        store: &dyn NodeStore,
    ) -> Vec<Effect> {
        let mut all_effects = Vec::new();
        loop {
            let mut progress = false;
            let (opaque_hashes, em_opt) = {
                let overlay = crate::engine::EngineStore {
                    store,
                    cache: &self.pending_cache,
                };
                (
                    overlay
                        .get_opaque_node_hashes(&conversation_id)
                        .unwrap_or_default(),
                    if let Some(Conversation::Established(em)) =
                        self.conversations.get(&conversation_id)
                    {
                        Some(em.clone())
                    } else {
                        None
                    },
                )
            };

            let em = match em_opt {
                Some(e) => e,
                None => break,
            };

            for hash in opaque_hashes {
                let wire = {
                    let overlay = crate::engine::EngineStore {
                        store,
                        cache: &self.pending_cache,
                    };
                    match overlay.get_wire_node(&hash) {
                        Some(w) => w,
                        None => continue,
                    }
                };

                let unpacked = em.unpack_node(&conversation_id, &wire);

                if let Some(node) = unpacked {
                    debug!(
                        "Successfully unpacked opaque node {} from Opaque Store",
                        hex::encode(hash.as_bytes())
                    );

                    all_effects.push(Effect::DeleteWireNode(conversation_id, hash));
                    {
                        let overlay = crate::engine::EngineStore {
                            store,
                            cache: &self.pending_cache,
                        };
                        let _ = overlay.remove_wire_node(&conversation_id, &hash);
                    }

                    if let Ok(node_effects) =
                        self.handle_node_internal_ext(conversation_id, node, store, None, false)
                    {
                        all_effects.extend(node_effects);
                        progress = true;
                    }
                }
            }

            if !progress {
                break;
            }
        }
        all_effects
    }
}
