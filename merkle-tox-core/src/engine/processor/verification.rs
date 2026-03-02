use crate::NodeEvent;
use crate::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeAuth,
    NodeHash, NodeType, Permissions,
};
use crate::engine::processor::VerifiedNode;
use crate::engine::{Conversation, ConversationData, Effect, MerkleToxEngine, conversation};
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::{BlobStore, NodeStore};
use tox_proto::constants::{MAX_SPECULATIVE_NODES_PER_CONVERSATION, MAX_VERIFIED_NODES_PER_DEVICE};
use tracing::{debug, error, info, warn};

const VOUCH_THRESHOLD: usize = 1;

impl MerkleToxEngine {
    /// Handles received Merkle node.
    pub fn handle_node(
        &mut self,
        conversation_id: ConversationId,
        node: MerkleNode,
        store: &dyn NodeStore,
        blob_store: Option<&dyn BlobStore>,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();
        self.handle_node_internal_ext(conversation_id, node, store, blob_store, true)
    }

    pub fn handle_node_internal_ext(
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

        let is_bootstrap = matches!(
            node.content,
            Content::KeyWrap { .. }
                | Content::HistoryExport { .. }
                | Content::SenderKeyDistribution { .. }
                | Content::Control(ControlAction::Genesis { .. })
                | Content::Control(ControlAction::AuthorizeDevice { .. })
                | Content::Control(ControlAction::AnchorSnapshot { .. })
        );

        // Collect OPK IDs consumed during verification for deferred deletion
        // (cannot mutate self.ephemeral_keys while overlay holds &self.pending_cache).
        let mut opk_ids_to_consume: Vec<NodeHash> = Vec::new();

        let (verified, authentic) = {
            let overlay = crate::engine::EngineStore {
                store,
                cache: &self.pending_cache,
            };

            if overlay.is_verified(&node_hash) {
                return Ok(effects);
            }

            // Deduplicate speculative nodes for external submissions.
            // If node already stored (even as unverified/speculative),
            // skip re-processing avoiding duplicate WriteStore effects.
            // Internal re-verification calls (reverify=false) must be
            // allowed through so speculative nodes can be promoted to
            // verified when new identity state becomes available.
            if reverify && overlay.has_node(&node_hash) {
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

            // Timestamp lower-bound check: spec §3 says ts >= oldest_parent_ts - 10min.
            let mut min_parent_ts = i64::MAX;

            let mut admin_ancestor_hashes = std::collections::HashSet::new();
            let mut stack = node.parents.clone();
            let mut visited = std::collections::HashSet::new();

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

            let is_authorized = self.identity_manager.is_authorized(
                &ctx,
                conversation_id,
                &node.sender_pk,
                &node.author_pk,
                node.network_timestamp,
                node.topological_rank,
            );

            for p in &node.parents {
                if let Some(parent_node) = overlay.get_node(p) {
                    min_parent_ts = min_parent_ts.min(parent_node.network_timestamp);
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

            if min_parent_ts != i64::MAX && node.network_timestamp < min_parent_ts - 600_000 {
                debug!(
                    "Node {} quarantined: timestamp {} < oldest parent timestamp {} - 10min",
                    hex::encode(node_hash.as_bytes()),
                    node.network_timestamp,
                    min_parent_ts
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
                self.check_permissions(&ctx, conversation_id, &node, node.network_timestamp)?;
            }

            // Edit validation: target must be Text, author must match
            if let Content::Edit { target_hash, .. } = &node.content
                && let Some(target_node) = overlay.get_node(target_hash)
            {
                if !matches!(target_node.content, Content::Text(_)) {
                    return Err(MerkleToxError::Validation(
                        crate::dag::ValidationError::InvalidEditTarget,
                    ));
                }
                if target_node.author_pk != node.author_pk {
                    return Err(MerkleToxError::Validation(
                        crate::dag::ValidationError::EditAuthorMismatch,
                    ));
                }
                // If target not found, allow speculatively (parents may arrive later)
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
                    // Check ratchet state to distinguish legitimate
                    // out-of-order delivery from sequence number replay.
                    // If ratchet consumed this seq and no skipped key
                    // remains, key was already used: reject as replay.
                    let is_replay = if let Some(Conversation::Established(em)) =
                        self.conversations.get(&conversation_id)
                    {
                        let epoch = node.sequence_number >> 32;
                        if let Some(&(last_seq, _, _, last_epoch)) =
                            em.state.sender_ratchets.get(&node.sender_pk)
                        {
                            last_epoch == epoch
                                && node.sequence_number <= last_seq
                                && !em
                                    .state
                                    .skipped_keys
                                    .contains_key(&(node.sender_pk, node.sequence_number))
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if is_replay {
                        return Err(MerkleToxError::Validation(
                            crate::dag::ValidationError::InvalidSequenceNumber {
                                actual: node.sequence_number,
                                last: last_verified_seq,
                            },
                        ));
                    }

                    debug!(
                        "Node {} has out-of-order sequence number {} (last verified was {})",
                        hex::encode(node_hash.as_bytes()),
                        node.sequence_number,
                        last_verified_seq
                    );
                }

                if node.sequence_number > last_verified_seq + 1 {
                    debug!(
                        "Node {} is future sequence number {} (last verified was {})",
                        hex::encode(node_hash.as_bytes()),
                        node.sequence_number,
                        last_verified_seq
                    );
                    // We don't mark quarantined here anymore, to allow
                    // skipping unverifiable nodes (like old KeyWraps).
                    // Parent-is-verified check handles topological ordering.
                }

                if (last_verified_seq & 0xFFFFFFFF) >= MAX_VERIFIED_NODES_PER_DEVICE {
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
                    generation,
                    anchor_hash: _,
                    wrapped_keys,
                    ephemeral_pk,
                } = &node.content
                {
                    let mut k_conv_received = None;
                    // Try ECIES unwrap using SPK secrets.
                    // If opk_id is non-zero, find and use OPK private key.
                    for wrapped in wrapped_keys {
                        if wrapped.recipient_pk == self.self_pk {
                            // OPK collision detection (merkle-tox-handshake-ecies.md §5)
                            if wrapped.opk_id != NodeHash::from([0u8; 32]) {
                                if let Some((_prev_hash, prev_sender, prev_rank)) =
                                    self.consumed_opk_ids.get(&wrapped.opk_id)
                                {
                                    // Collision detected: same OPK consumed by two KeyWraps.
                                    // Deterministic tie-breaker: lower topological_rank wins,
                                    // then lexicographic sender_pk.
                                    let this_wins = (node.topological_rank, &node.sender_pk)
                                        < (*prev_rank, prev_sender);
                                    if !this_wins {
                                        debug!(
                                            "OPK collision: discarding entry from {:?} (rank {}), winner at rank {}",
                                            node.sender_pk, node.topological_rank, prev_rank
                                        );
                                        continue; // skip this entry
                                    }
                                    debug!(
                                        "OPK collision: new entry from {:?} (rank {}) wins over {:?} (rank {})",
                                        node.sender_pk,
                                        node.topological_rank,
                                        prev_sender,
                                        prev_rank
                                    );
                                    // New entry wins: overwrite below
                                }
                                // Record OPK consumption
                                self.consumed_opk_ids.insert(
                                    wrapped.opk_id,
                                    (node_hash, node.sender_pk, node.topological_rank),
                                );
                            }
                            let opk_sk = self.find_opk_sk(&wrapped.opk_id);
                            for spk_sk in self.ephemeral_keys.values() {
                                if let Some(pt) = crate::crypto::ecies_unwrap_32(
                                    spk_sk,
                                    ephemeral_pk,
                                    opk_sk,
                                    None,
                                    &wrapped.ciphertext,
                                ) {
                                    k_conv_received = Some(KConv::from(pt));
                                    break;
                                }
                            }
                            // Also try device DH key as SPK fallback
                            if k_conv_received.is_none()
                                && let Some(sk) = &self.self_dh_sk
                            {
                                let dh_as_eph = crate::dag::EphemeralX25519Sk::from(*sk.as_bytes());
                                if let Some(pt) = crate::crypto::ecies_unwrap_32(
                                    &dh_as_eph,
                                    ephemeral_pk,
                                    opk_sk,
                                    None,
                                    &wrapped.ciphertext,
                                ) {
                                    k_conv_received = Some(KConv::from(pt));
                                }
                            }
                            // Consume OPK private key for forward secrecy
                            if k_conv_received.is_some() {
                                opk_ids_to_consume.push(wrapped.opk_id);
                                break;
                            }
                        }
                    }
                    if let Some(k_conv) = k_conv_received {
                        // Send KEYWRAP_ACK to sender (off-DAG, §5)
                        effects.push(Effect::SendPacket(
                            node.sender_pk,
                            crate::ProtocolMessage::KeywrapAck {
                                keywrap_hash: node_hash,
                                recipient_pk: self.self_pk,
                            },
                        ));
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
                                    let mut est = p.establish(
                                        k_conv.clone(),
                                        node.network_timestamp,
                                        *generation,
                                    );
                                    // Mark identity_pending when establishing from KeyWrap
                                    // whose sender lacks verified Genesis chain.
                                    let has_genesis = self
                                        .identity_manager
                                        .get_founder(&conversation_id)
                                        .is_some();
                                    est.state.identity_pending = !has_genesis;
                                    est
                                }
                                Conversation::Established(mut e) => {
                                    e.add_epoch(*generation, k_conv.clone());
                                    e
                                }
                            };
                        effects.push(Effect::WriteConversationKey(
                            conversation_id,
                            *generation,
                            k_conv,
                        ));
                        self.conversations
                            .insert(conversation_id, Conversation::Established(em));
                        // Track handshake for announcement rotation
                        *self
                            .handshake_count_since_announcement
                            .entry(conversation_id)
                            .or_insert(0) += 1;
                        // Clear trust-restored state: device fully re-included
                        self.trust_restored_devices
                            .remove(&(conversation_id, self.self_pk));
                    }
                } else if let Content::SenderKeyDistribution {
                    ephemeral_pk: skd_ephemeral_pk,
                    wrapped_keys,
                    ..
                } = &node.content
                {
                    // Unwrap SenderKey distributed via ECIES.
                    // SKD wraps per-sender random SenderKey (not k_conv).
                    // auth_secret = ECDH(sender_x25519, recipient_spk).
                    // Payload is 32 bytes for rotation SKD or 72 bytes for JIT SKD.
                    let sender_x25519_pk =
                        crate::crypto::device_pk_to_x25519(node.sender_pk.as_bytes());
                    let mut skd_payload: Option<Vec<u8>> = None;
                    for wrapped in wrapped_keys {
                        if wrapped.recipient_pk == self.self_pk {
                            let opk_sk = self.find_opk_sk(&wrapped.opk_id);
                            // Try each SPK secret
                            for spk_sk in self.ephemeral_keys.values() {
                                let spk = x25519_dalek::StaticSecret::from(*spk_sk.as_bytes());
                                let auth_secret = *spk.diffie_hellman(&sender_x25519_pk).as_bytes();
                                if let Some(pt) = crate::crypto::ecies_unwrap(
                                    spk_sk,
                                    skd_ephemeral_pk,
                                    opk_sk,
                                    Some(&auth_secret),
                                    &wrapped.ciphertext,
                                ) {
                                    skd_payload = Some(pt);
                                    break;
                                }
                            }
                            // Also try device DH key as SPK for backward compat
                            if skd_payload.is_none()
                                && let Some(sk) = &self.self_dh_sk
                            {
                                let dh_as_eph = crate::dag::EphemeralX25519Sk::from(*sk.as_bytes());
                                let spk = x25519_dalek::StaticSecret::from(*sk.as_bytes());
                                let auth_secret = *spk.diffie_hellman(&sender_x25519_pk).as_bytes();
                                if let Some(pt) = crate::crypto::ecies_unwrap(
                                    &dh_as_eph,
                                    skd_ephemeral_pk,
                                    opk_sk,
                                    Some(&auth_secret),
                                    &wrapped.ciphertext,
                                ) {
                                    skd_payload = Some(pt);
                                }
                            }
                            // Consume OPK private key for forward secrecy
                            if skd_payload.is_some() {
                                opk_ids_to_consume.push(wrapped.opk_id);
                                break;
                            }
                        }
                    }
                    // Dispatch on payload length: 32-byte = rotation SKD (root SenderKey),
                    // 72-byte = JIT SKD (K_chain || last_seq || K_header).
                    if let Some(payload) = skd_payload {
                        let epoch = node.sequence_number >> 32;
                        if let Some(Conversation::Established(em)) =
                            self.conversations.get_mut(&conversation_id)
                        {
                            if payload.len() == 32 {
                                // Rotation SKD: store root SenderKey
                                let mut sk = [0u8; 32];
                                sk.copy_from_slice(&payload);
                                em.state.sender_keys.insert(
                                    (node.sender_pk, epoch),
                                    crate::dag::SenderKey::from(sk),
                                );
                            } else if payload.len() == 72 {
                                // JIT SKD: extract (K_chain, last_seq, K_header)
                                let mut chain_key = [0u8; 32];
                                chain_key.copy_from_slice(&payload[0..32]);
                                let last_seq =
                                    u64::from_be_bytes(payload[32..40].try_into().unwrap());
                                let mut k_header = [0u8; 32];
                                k_header.copy_from_slice(&payload[40..72]);
                                // Seed ratchet at provided position
                                em.state.sender_ratchets.insert(
                                    node.sender_pk,
                                    (last_seq, crate::dag::ChainKey::from(chain_key), None, epoch),
                                );
                                // Store K_header for routing decryption
                                em.state.jit_headers.insert(
                                    (node.sender_pk, epoch),
                                    crate::dag::HeaderKey::from(k_header),
                                );
                            }
                        }
                    }
                } else if let Content::HistoryExport {
                    blob_hash,
                    ephemeral_pk: he_ephemeral_pk,
                    wrapped_keys,
                } = &node.content
                {
                    // Register blob_hash for CAS fetching when we are recipient.
                    // Unwrapped bytes are K_export: fresh key used to encrypt blob.
                    for wrapped in wrapped_keys {
                        if wrapped.recipient_pk == self.self_pk {
                            let mut k_export: Option<[u8; 32]> = None;
                            let opk_sk = self.find_opk_sk(&wrapped.opk_id);
                            for spk_sk in self.ephemeral_keys.values() {
                                if let Some(pt) = crate::crypto::ecies_unwrap_32(
                                    spk_sk,
                                    he_ephemeral_pk,
                                    opk_sk,
                                    None,
                                    &wrapped.ciphertext,
                                ) {
                                    k_export = Some(pt);
                                    break;
                                }
                            }
                            // Also try device DH key as SPK
                            if k_export.is_none()
                                && let Some(sk) = &self.self_dh_sk
                            {
                                let dh_as_eph = crate::dag::EphemeralX25519Sk::from(*sk.as_bytes());
                                k_export = crate::crypto::ecies_unwrap_32(
                                    &dh_as_eph,
                                    he_ephemeral_pk,
                                    opk_sk,
                                    None,
                                    &wrapped.ciphertext,
                                );
                            }
                            // Consume OPK private key for forward secrecy
                            if k_export.is_some() {
                                opk_ids_to_consume.push(wrapped.opk_id);
                                let info = crate::cas::BlobInfo {
                                    hash: *blob_hash,
                                    size: 0,
                                    bao_root: None,
                                    status: crate::cas::BlobStatus::Pending,
                                    received_mask: None,
                                    decryption_key: k_export,
                                };
                                self.blob_syncs
                                    .insert(*blob_hash, crate::cas::SwarmSync::new(info));
                            }
                            break;
                        }
                    }
                }
            }

            if let NodeAuth::EphemeralSignature(sig) = &node.authentication {
                if matches!(
                    &node.content,
                    Content::Control(ControlAction::Genesis { .. })
                ) {
                    // Genesis: verify MAC embedded in first 32 bytes of signature
                    if let Some(Conversation::Established(em)) =
                        self.conversations.get(&conversation_id)
                        && let Some(keys) = em.get_keys(0)
                    {
                        let auth_data = node.serialize_for_auth();
                        let mac = keys.calculate_mac(&auth_data);
                        if sig.as_bytes()[..32] == *mac.as_bytes() {
                            authentic = true;
                        }
                    }
                } else {
                    // Content nodes: verify ephemeral signature against stored
                    // peer ephemeral signing public key for sender's epoch.
                    let epoch = node.sequence_number >> 32;
                    // DARE §2: SKD for epoch n is signed with epoch n-1's key.
                    let lookup_epoch =
                        if matches!(&node.content, Content::SenderKeyDistribution { .. }) {
                            epoch.saturating_sub(1)
                        } else {
                            epoch
                        };
                    if let Some(epk) = self
                        .peer_ephemeral_signing_keys
                        .get(&(node.sender_pk, lookup_epoch))
                    {
                        let vk = ed25519_dalek::VerifyingKey::from_bytes(epk.as_bytes());
                        if let Ok(vk) = vk {
                            let ed_sig = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
                            // Encrypt-then-sign: for content nodes, try
                            // verifying against wire node's auth data
                            // (ciphertext) first. Fall back to plaintext
                            // auth data for direct API / legacy compat.
                            if !node.is_exception_node() {
                                if let Some(wire) = overlay.get_wire_node(&node_hash) {
                                    let wire_auth = wire.serialize_for_auth();
                                    if vk.verify_strict(&wire_auth, &ed_sig).is_ok() {
                                        authentic = true;
                                    }
                                }
                                if !authentic {
                                    let plain_auth = node.serialize_for_auth();
                                    if vk.verify_strict(&plain_auth, &ed_sig).is_ok() {
                                        authentic = true;
                                    }
                                }
                            } else {
                                let auth_data = node.serialize_for_auth();
                                if vk.verify_strict(&auth_data, &ed_sig).is_ok() {
                                    authentic = true;
                                }
                            }
                        }
                    }
                }
            } else if let NodeAuth::Signature(_) = &node.authentication {
                authentic = true;
            }

            // For unauthorized AnchorSnapshot nodes the generic path must be
            // skipped: speculative trust requires a founder-signed ADMIN cert,
            // checked in the dedicated branch below.
            let skip_generic_path = !is_authorized
                && matches!(
                    &node.content,
                    Content::Control(ControlAction::AnchorSnapshot { .. })
                        | Content::Control(ControlAction::SoftAnchor { .. })
                );

            if authentic && structurally_valid && !quarantined && !skip_generic_path {
                verified = true;
            } else if !is_authorized && !quarantined && structurally_valid && !skip_generic_path {
                // Vouched: unauthorized node passed vouch threshold (line ~146),
                // so enough authorized members referenced it as a parent.
                verified = true;
            } else if !is_authorized
                && !quarantined
                && let Content::Control(ControlAction::AuthorizeDevice { cert }) = &node.content
                && self
                    .identity_manager
                    .authorize_device(
                        &ctx,
                        conversation_id,
                        node.author_pk,
                        cert,
                        node.network_timestamp,
                        node.topological_rank,
                        node.hash(),
                    )
                    .is_ok()
                && structurally_valid
            {
                verified = true;
            } else if !is_authorized
                && !quarantined
                && structurally_valid
                && let Content::Control(ControlAction::AnchorSnapshot { cert, data: _ }) =
                    &node.content
            {
                if let Some(founder_pk) = self.identity_manager.get_founder(&conversation_id) {
                    let sig_ok = crate::identity::verify_delegation(
                        cert,
                        founder_pk,
                        node.network_timestamp,
                    )
                    .is_ok();
                    let has_admin = cert.permissions.contains(crate::dag::Permissions::ADMIN);
                    let device_bound = cert.device_pk == node.sender_pk;
                    if sig_ok && has_admin && device_bound {
                        verified = true;
                        tracing::debug!(
                            "AnchorSnapshot verified against Genesis founder's key. Speculative 'Identity Pending' mode active."
                        );
                    } else if sig_ok && !has_admin {
                        tracing::warn!(
                            "AnchorSnapshot certificate valid but lacks ADMIN permission: rejecting speculative trust."
                        );
                    } else {
                        tracing::warn!(
                            "AnchorSnapshot certificate failed verification against Founder's key."
                        );
                    }
                } else {
                    tracing::warn!("Could not find Founder PK for AnchorSnapshot verification.");
                }
            } else if !is_authorized
                && !quarantined
                && structurally_valid
                && let Content::Control(ControlAction::SoftAnchor { cert, .. }) = &node.content
                && let Some(founder_pk) = self.identity_manager.get_founder(&conversation_id)
            {
                let sig_ok =
                    crate::identity::verify_delegation(cert, founder_pk, node.network_timestamp)
                        .is_ok();
                let has_admin = cert.permissions.contains(crate::dag::Permissions::ADMIN);
                let device_bound = cert.device_pk == node.sender_pk;
                if sig_ok && has_admin && device_bound {
                    verified = true;
                    tracing::debug!("SoftAnchor verified against Genesis founder's key.");
                }
            }

            // Anti-branching post-check: applies to all SoftAnchors. Speculative
            // path performs this check, but authorized SoftAnchors bypass it via
            // generic path, requiring this post-check.
            if verified
                && let Content::Control(ControlAction::SoftAnchor { basis_hash, .. }) =
                    &node.content
            {
                let dedup_key = (node.sender_pk, *basis_hash);
                let dedup_set = self.soft_anchor_dedup.entry(conversation_id).or_default();
                if !dedup_set.insert(dedup_key) {
                    tracing::debug!(
                        "SoftAnchor rejected (authorized path): duplicate (device_pk, basis_hash)"
                    );
                    verified = false;
                }
            }

            if verified {
                overlay.put_node(&conversation_id, node.clone(), true)?;
            } else {
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

        // Consume OPK private keys for forward secrecy (deferred from inside overlay scope)
        for opk_id in opk_ids_to_consume {
            self.consume_opk_sk(&opk_id);
        }

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

        if verified || (authentic && is_bootstrap) {
            let verified_node = VerifiedNode::new(node.clone(), node.content.clone());
            let side_effects = self.apply_side_effects(conversation_id, &verified_node, store)?;
            effects.extend(side_effects);

            if verified {
                match verified_node.content() {
                    Content::Control(ControlAction::AuthorizeDevice { .. })
                    | Content::Control(ControlAction::RevokeDevice { .. })
                    | Content::Control(ControlAction::Leave(_)) => {
                        effects.extend(self.revalidate_all_verified_nodes(conversation_id, store));
                    }
                    _ => {}
                }
            }
        }

        if reverify && (authentic || verified) {
            // Process opaque nodes first: they may unpack into MerkleNodes
            // that are parents of speculative nodes.  Processing them first
            // ensures those parents are verified before we re-check
            // quarantined speculative nodes.
            effects.extend(self.reverify_opaque_nodes(conversation_id, store));
            effects.extend(self.reverify_speculative_for_conversation(conversation_id, store));
        }

        if verified {
            let is_identity_pending = self.conversations.get(&conversation_id).is_some_and(
                |c| matches!(c, Conversation::Established(e) if e.state.identity_pending),
            );
            if is_identity_pending {
                effects.push(Effect::EmitEvent(NodeEvent::NodeIdentityPending {
                    conversation_id,
                    hash: node_hash,
                    node,
                }));
            } else {
                effects.push(Effect::EmitEvent(NodeEvent::NodeVerified {
                    conversation_id,
                    hash: node_hash,
                    node,
                }));
            }
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
        ctx: &crate::identity::CausalContext,
        conversation_id: ConversationId,
        node: &MerkleNode,
        now: i64,
    ) -> MerkleToxResult<()> {
        let actual = self
            .identity_manager
            .get_permissions(
                ctx,
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
            | Content::Edit { .. }
            | Content::Redaction { .. }
            | Content::Custom { .. }
            | Content::HistoryExport { .. }
            | Content::LegacyBridge { .. }
            | Content::SenderKeyDistribution { .. } => Permissions::MESSAGE,
            Content::Control(action) => match action {
                ControlAction::AuthorizeDevice { .. }
                | ControlAction::RevokeDevice { .. }
                | ControlAction::SetTitle(_)
                | ControlAction::SetTopic(_)
                | ControlAction::Invite(_)
                | ControlAction::Snapshot(_)
                | ControlAction::AnchorSnapshot { .. }
                | ControlAction::SoftAnchor { .. }
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
                        let is_identity_pending = self
                            .conversations
                            .get(&conversation_id)
                            .is_some_and(|c| {
                                matches!(c, Conversation::Established(e) if e.state.identity_pending)
                            });
                        if is_identity_pending {
                            effects.push(Effect::EmitEvent(NodeEvent::NodeIdentityPending {
                                conversation_id,
                                hash: node.hash(),
                                node: node.clone(),
                            }));
                        } else {
                            effects.push(Effect::EmitEvent(NodeEvent::NodeVerified {
                                conversation_id,
                                hash: node.hash(),
                                node: node.clone(),
                            }));
                        }
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
                    NodeAuth::EphemeralSignature(sig) => {
                        if matches!(
                            &node.content,
                            Content::Control(ControlAction::Genesis { .. })
                        ) {
                            // Genesis: verify MAC embedded in first 32 bytes
                            if let Some(Conversation::Established(em)) =
                                self.conversations.get(&conversation_id)
                                && let Some(keys) = em.get_keys(0)
                            {
                                let auth_data = node.serialize_for_auth();
                                let mac = keys.calculate_mac(&auth_data);
                                sig.as_bytes()[..32] == *mac.as_bytes()
                            } else {
                                false
                            }
                        } else {
                            let epoch = node.sequence_number >> 32;
                            // DARE §2: SKD for epoch n is signed with epoch n-1's key.
                            let lookup_epoch =
                                if matches!(&node.content, Content::SenderKeyDistribution { .. }) {
                                    epoch.saturating_sub(1)
                                } else {
                                    epoch
                                };
                            if let Some(epk) = self
                                .peer_ephemeral_signing_keys
                                .get(&(node.sender_pk, lookup_epoch))
                            {
                                let vk = ed25519_dalek::VerifyingKey::from_bytes(epk.as_bytes());
                                if let Ok(vk) = vk {
                                    let ed_sig =
                                        ed25519_dalek::Signature::from_bytes(sig.as_bytes());
                                    // Encrypt-then-sign: try wire auth
                                    // first, plaintext fallback.
                                    let mut sig_ok = false;
                                    if !node.is_exception_node() {
                                        let overlay = crate::engine::EngineStore {
                                            store,
                                            cache: &self.pending_cache,
                                        };
                                        if let Some(wire) = overlay.get_wire_node(&node_hash) {
                                            let wire_auth = wire.serialize_for_auth();
                                            if vk.verify_strict(&wire_auth, &ed_sig).is_ok() {
                                                sig_ok = true;
                                            }
                                        }
                                        if !sig_ok {
                                            let plain_auth = node.serialize_for_auth();
                                            if vk.verify_strict(&plain_auth, &ed_sig).is_ok() {
                                                sig_ok = true;
                                            }
                                        }
                                    } else {
                                        let auth_data = node.serialize_for_auth();
                                        if vk.verify_strict(&auth_data, &ed_sig).is_ok() {
                                            sig_ok = true;
                                        }
                                    }
                                    sig_ok
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                    }
                };

                debug!(
                    "Node {} is_authentic={}",
                    hex::encode(node_hash.as_bytes()),
                    is_authentic
                );

                if !is_authentic {
                    // Allow vouched nodes through for re-verification
                    let vouches = self
                        .conversations
                        .get(&conversation_id)
                        .map(|c| c.vouchers().get(&node_hash).map_or(0, |v| v.len()))
                        .unwrap_or(0);
                    if vouches < VOUCH_THRESHOLD {
                        continue;
                    }
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
                        // Update the pending cache so subsequent nodes in this
                        // loop iteration can see their parent as verified.
                        for e in &v_effects {
                            if let Effect::WriteStore(cid, n, true) = e {
                                let h = n.hash();
                                let mut cache = self.pending_cache.lock();
                                cache.nodes.insert(h, n.clone());
                                cache.verified.insert(h);
                                let sender_pk = n.sender_pk;
                                let seq = n.sequence_number;
                                let entry = cache
                                    .last_verified_sequences
                                    .entry((*cid, sender_pk))
                                    .or_insert(0);
                                if seq > *entry {
                                    *entry = seq;
                                }
                            }
                        }
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
        let effects = Vec::new();
        let now = self.clock.network_time_ms();

        let (verified, ..) = {
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

            // Timestamp lower-bound check: spec says ts >= min_parent_ts - 10min.
            // There is deliberately no requirement that ts >= max parent ts.
            let mut min_parent_ts_vn = i64::MAX;
            for p in &node.parents {
                if let Some(parent_node) = overlay.get_node(p) {
                    min_parent_ts_vn = min_parent_ts_vn.min(parent_node.network_timestamp);
                }
            }

            let mut quarantined = false;
            if min_parent_ts_vn != i64::MAX && node.network_timestamp < min_parent_ts_vn - 600_000 {
                debug!(
                    "Node {} failed verification: network_timestamp {} < min_parent_ts {} - 10min",
                    hex::encode(node.hash().as_bytes()),
                    node.network_timestamp,
                    min_parent_ts_vn
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

            let mut admin_ancestor_hashes = std::collections::HashSet::new();
            let mut stack = node.parents.clone();
            let mut visited = std::collections::HashSet::new();

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

            let is_authorized = self.identity_manager.is_authorized(
                &ctx,
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
                } else if let NodeAuth::EphemeralSignature(sig) = &node.authentication {
                    if overlay.is_verified(&node.hash()) {
                        // If already verified once, trust its authenticity.
                        // We are just re-checking authorization (e.g. for revocation).
                        authentic = true;
                    } else {
                        let epoch = node.sequence_number >> 32;
                        // DARE §2: SKD for epoch n is signed with epoch n-1's key.
                        let lookup_epoch =
                            if matches!(&node.content, Content::SenderKeyDistribution { .. }) {
                                epoch.saturating_sub(1)
                            } else {
                                epoch
                            };
                        if let Some(epk) = self
                            .peer_ephemeral_signing_keys
                            .get(&(node.sender_pk, lookup_epoch))
                        {
                            let vk = ed25519_dalek::VerifyingKey::from_bytes(epk.as_bytes());
                            if let Ok(vk) = vk {
                                let ed_sig = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
                                // Encrypt-then-sign: try wire auth first,
                                // plaintext fallback.
                                if !node.is_exception_node() {
                                    if let Some(wire) = overlay.get_wire_node(&node.hash()) {
                                        let wire_auth = wire.serialize_for_auth();
                                        if vk.verify_strict(&wire_auth, &ed_sig).is_ok() {
                                            authentic = true;
                                        }
                                    }
                                    if !authentic {
                                        let plain_auth = node.serialize_for_auth();
                                        if vk.verify_strict(&plain_auth, &ed_sig).is_ok() {
                                            authentic = true;
                                        }
                                    }
                                } else {
                                    let auth_data = node.serialize_for_auth();
                                    if vk.verify_strict(&auth_data, &ed_sig).is_ok() {
                                        authentic = true;
                                    }
                                }
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

                let all_senders = self
                    .identity_manager
                    .list_all_authorized_sender_pairs(conversation_id);
                let unpacked = em.identify_sender_and_unpack(&wire, &all_senders);

                if let Some(node) = unpacked {
                    debug!(
                        "Successfully unpacked opaque node {} from Opaque Store",
                        hex::encode(hash.as_bytes())
                    );

                    // Remove from opaque store usage tracker when promoted
                    if let Some((total, entries)) =
                        self.opaque_store_usage.get_mut(&conversation_id)
                        && let Some(pos) = entries.iter().position(|(h, _, _)| *h == hash)
                    {
                        *total -= entries[pos].1;
                        entries.swap_remove(pos);
                    }
                    all_effects.push(Effect::DeleteWireNode(conversation_id, hash));

                    // Keep the wire node in the pending cache so that
                    // handle_node_internal_ext can verify encrypt-then-sign
                    // signatures against the wire data. Remove from the
                    // backing store but preserve in cache.
                    {
                        let _ = store.remove_wire_node(&conversation_id, &hash);
                        self.pending_cache
                            .lock()
                            .wire_nodes
                            .insert(hash, (conversation_id, wire.clone()));
                    }

                    if let Ok(node_effects) =
                        self.handle_node_internal_ext(conversation_id, node, store, None, false)
                    {
                        all_effects.extend(node_effects);
                        progress = true;
                    }
                    // Clean up wire node from cache after verification
                    self.pending_cache.lock().wire_nodes.remove(&hash);
                }
            }

            if !progress {
                break;
            }
        }
        all_effects
    }
}
