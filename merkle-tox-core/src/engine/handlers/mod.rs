use crate::cas::{BlobData, SwarmSync};
use crate::dag::{ConversationId, PhysicalDevicePk};
use crate::engine::session::{Active, Handshake, PeerSession, SyncSession};
use crate::engine::{CpuBudget, Effect, EngineStore, MerkleToxEngine};
use crate::error::MerkleToxResult;
use crate::sync::{BlobStore, DecodingResult, NodeStore, Tier};
use crate::{NodeEvent, ProtocolMessage};
use tracing::{debug, info};

impl MerkleToxEngine {
    /// Handles an incoming protocol message from a peer.
    pub fn handle_message(
        &mut self,
        sender_pk: PhysicalDevicePk,
        message: ProtocolMessage,
        store: &dyn NodeStore,
        blob_store: Option<&dyn BlobStore>,
    ) -> MerkleToxResult<Vec<Effect>> {
        self.clear_pending();

        self.stats
            .messages_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Blacklist check: reject messages from blacklisted peers
        let now_bl = self.clock.network_time_ms();
        if let Some(bl) = self.peer_blacklist.get(&sender_pk)
            && bl.is_active(now_bl)
        {
            debug!(
                "Dropping message from blacklisted peer {:?} (tier {}, expires {})",
                sender_pk, bl.tier, bl.expires_at_ms
            );
            return Ok(Vec::new());
        }

        debug!(
            "Engine handling message from {:?}: {:?}",
            sender_pk, message
        );
        let mut effects = Vec::new();

        match message {
            ProtocolMessage::CapsAnnounce {
                version: _,
                features,
            } => {
                let mut sessions_to_activate = Vec::new();
                for ((peer_pk, cid), session) in self.sessions.iter() {
                    if peer_pk == &sender_pk
                        && let PeerSession::Handshake(_) = session
                    {
                        sessions_to_activate.push(*cid);
                    }
                }

                for cid in sessions_to_activate {
                    if let Some(PeerSession::Handshake(s)) = self.sessions.remove(&(sender_pk, cid))
                    {
                        let mut active = s.activate(features);
                        // Send heads immediately on handshake
                        effects.push(Effect::SendPacket(
                            sender_pk,
                            ProtocolMessage::SyncHeads(
                                active.make_sync_heads_with_store(0, Some(store)),
                            ),
                        ));
                        active.common.heads_dirty = false;
                        self.sessions
                            .insert((sender_pk, cid), PeerSession::Active(active));
                    }
                }

                effects.push(Effect::SendPacket(
                    sender_pk,
                    ProtocolMessage::CapsAck {
                        version: 1,
                        features: 0,
                    },
                ));
                effects.push(Effect::EmitEvent(NodeEvent::PeerHandshakeComplete {
                    peer_pk: sender_pk,
                }));
            }
            ProtocolMessage::CapsAck {
                version: _,
                features,
            } => {
                let mut sessions_to_activate = Vec::new();
                for ((peer_pk, cid), session) in self.sessions.iter() {
                    if peer_pk == &sender_pk
                        && let PeerSession::Handshake(_) = session
                    {
                        sessions_to_activate.push(*cid);
                    }
                }

                for cid in sessions_to_activate {
                    if let Some(PeerSession::Handshake(s)) = self.sessions.remove(&(sender_pk, cid))
                    {
                        let mut active = s.activate(features);
                        // Send heads immediately on handshake
                        effects.push(Effect::SendPacket(
                            sender_pk,
                            ProtocolMessage::SyncHeads(
                                active.make_sync_heads_with_store(0, Some(store)),
                            ),
                        ));
                        active.common.heads_dirty = false;
                        self.sessions
                            .insert((sender_pk, cid), PeerSession::Active(active));
                    }
                }
                effects.push(Effect::EmitEvent(NodeEvent::PeerHandshakeComplete {
                    peer_pk: sender_pk,
                }));
            }
            ProtocolMessage::SyncHeads(heads) => {
                let conv_id = heads.conversation_id;
                // Drop messages naming a conversation we have not
                // joined locally. Without this gate the
                // `entry((sender, conv_id)).or_insert_with(...)` below
                // allocates session state per peer-supplied 32-byte
                // conv_id — unbounded memory growth from a single
                // friend at line rate. See
                // `tests/adversarial_unknown_conversation_test.rs`.
                if !self.conversations.contains_key(&conv_id) {
                    return Ok(effects);
                }
                {
                    let now = self.clock.time_provider().now_instant();
                    let entry = self.sessions.entry((sender_pk, conv_id));
                    let session = entry.or_insert_with(|| {
                        PeerSession::Handshake(SyncSession::<Handshake>::new(
                            conv_id,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            false,
                            now,
                        ))
                    });

                    if let PeerSession::Handshake(_) = session
                        && let Some(PeerSession::Handshake(s)) =
                            self.sessions.remove(&(sender_pk, conv_id))
                    {
                        self.sessions
                            .insert((sender_pk, conv_id), PeerSession::Active(s.activate(0)));
                    }

                    if let Some(PeerSession::Active(s)) =
                        self.sessions.get_mut(&(sender_pk, conv_id))
                    {
                        s.handle_sync_heads(
                            heads,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                        );

                        if let Some(req) = s.next_fetch_batch(tox_proto::constants::MAX_BATCH_SIZE)
                        {
                            effects.push(Effect::SendPacket(
                                sender_pk,
                                ProtocolMessage::FetchBatchReq(req),
                            ));
                        }
                    }
                }
            }
            ProtocolMessage::SyncSketch(sketch) => {
                let conv_id = sketch.conversation_id;
                // See SyncHeads for the rationale — same per-conv_id
                // session allocation, same gate.
                if !self.conversations.contains_key(&conv_id) {
                    return Ok(effects);
                }
                {
                    let now = self.clock.time_provider().now_instant();
                    let entry = self.sessions.entry((sender_pk, conv_id));
                    let session = entry.or_insert_with(|| {
                        PeerSession::Handshake(SyncSession::<Handshake>::new(
                            conv_id,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            false,
                            now,
                        ))
                    });

                    if let PeerSession::Handshake(_) = session
                        && let Some(PeerSession::Handshake(s)) =
                            self.sessions.remove(&(sender_pk, conv_id))
                    {
                        self.sessions
                            .insert((sender_pk, conv_id), PeerSession::Active(s.activate(0)));
                    }

                    if let Some(PeerSession::Active(s)) =
                        self.sessions.get_mut(&(sender_pk, conv_id))
                    {
                        // Protection: Medium and Large sketches require PoW
                        let tier = Tier::from_cell_count(sketch.cells.len());
                        if tier == Tier::Medium || tier == Tier::Large {
                            let nonce =
                                s.generate_challenge(sketch.clone(), now, &mut self.rng.lock());
                            effects.push(Effect::SendPacket(
                                sender_pk,
                                ProtocolMessage::ReconPowChallenge {
                                    conversation_id: sketch.conversation_id,
                                    nonce,
                                    difficulty: s.common.effective_difficulty,
                                },
                            ));
                            return Ok(effects);
                        }

                        // CPU budget check: refill and estimate cost
                        let budget_now = self.clock.network_time_ms();
                        let budget = self
                            .sketch_cpu_budgets
                            .entry(sender_pk)
                            .or_insert_with(|| CpuBudget::new(budget_now));
                        budget.refill(budget_now);
                        // Estimate decode cost: ~0.01ms per cell is a reasonable estimate
                        let estimated_cost = sketch.cells.len() as f64 * 0.01;
                        if !budget.try_consume(estimated_cost) {
                            debug!(
                                "Sketch CPU budget exhausted for {:?}, sending backoff",
                                sender_pk
                            );
                            effects.push(Effect::SendPacket(
                                sender_pk,
                                ProtocolMessage::SyncRateLimited {
                                    conversation_id: conv_id,
                                    retry_after_ms: tox_proto::Untrusted::new(1000),
                                },
                            ));
                            return Ok(effects);
                        }

                        let keys = match self.conversations.get(&conv_id) {
                            Some(crate::engine::Conversation::Established(em)) => {
                                em.get_keys(em.current_epoch())
                            }
                            _ => None,
                        };
                        let k_iblt =
                            keys.map(|k| crate::crypto::derive_k_iblt(&k.k_conv, &conv_id));

                        let sketch_ok = process_sketch(
                            s,
                            sender_pk,
                            sketch,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            keys,
                            k_iblt,
                            &mut effects,
                        )?;
                        if !sketch_ok {
                            // Drain budget unconditionally: one decode miss is
                            // cheap to pay for, but a busy attacker shouldn't
                            // burn more CPU on retries until the window refills.
                            if let Some(budget) = self.sketch_cpu_budgets.get_mut(&sender_pk) {
                                budget.remaining_ms = 0.0;
                            }
                            // Blacklist only after SKETCH_DECODE_THRESHOLD
                            // consecutive failures — a single failure under
                            // packet loss is indistinguishable from a stale
                            // sketch and must not trigger tier-1 silencing.
                            self.record_sketch_decode_failure(sender_pk);
                        } else {
                            self.record_sketch_decode_success(sender_pk);
                        }
                    }
                }
            }
            ProtocolMessage::SyncReconFail {
                conversation_id,
                range,
            } => {
                if let Some(PeerSession::Active(session)) =
                    self.sessions.get_mut(&(sender_pk, conversation_id))
                {
                    session.handle_sync_recon_fail(range);
                    // The next poll will trigger a larger sketch if needed
                }
            }
            ProtocolMessage::SyncShardChecksums {
                conversation_id,
                shards,
            } => {
                // Drop the whole packet on amplification flags. The
                // legitimate count is `max_rank / SHARD_SIZE`; legitimate
                // per-shard ranges are exactly `SHARD_SIZE` wide. Either
                // bound exceeded means the packet is hostile or buggy —
                // partial acceptance lets an attacker piggyback a
                // u64::MAX-span range on legitimate-looking entries.
                if shards.len() > tox_proto::constants::MAX_SYNC_SHARDS
                    || shards.iter().any(|(r, _)| {
                        r.max_rank.saturating_sub(r.min_rank).saturating_add(1)
                            > crate::sync::SHARD_SIZE
                    })
                {
                    return Ok(effects);
                }
                let conv_id = conversation_id;
                // See SyncHeads for the rationale — same per-conv_id
                // session allocation, same gate.
                if !self.conversations.contains_key(&conv_id) {
                    return Ok(effects);
                }
                {
                    let now = self.clock.time_provider().now_instant();
                    let entry = self.sessions.entry((sender_pk, conv_id));
                    let session = entry.or_insert_with(|| {
                        PeerSession::Handshake(SyncSession::<Handshake>::new(
                            conv_id,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            false,
                            now,
                        ))
                    });

                    if let PeerSession::Handshake(_) = session
                        && let Some(PeerSession::Handshake(s)) =
                            self.sessions.remove(&(sender_pk, conv_id))
                    {
                        self.sessions
                            .insert((sender_pk, conv_id), PeerSession::Active(s.activate(0)));
                    }

                    if let Some(PeerSession::Active(s)) =
                        self.sessions.get_mut(&(sender_pk, conv_id))
                    {
                        let overlay = EngineStore {
                            store,
                            cache: &self.pending_cache,
                        };
                        let k_iblt = match self.conversations.get(&conv_id) {
                            Some(crate::engine::Conversation::Established(em)) => em
                                .get_keys(em.current_epoch())
                                .map(|k| crate::crypto::derive_k_iblt(&k.k_conv, &conv_id)),
                            _ => None,
                        };
                        let different = s.handle_sync_shard_checksums(shards, &overlay)?;
                        for range in different {
                            if let Some(tier) = s.get_iblt_tier(&range) {
                                effects.push(Effect::SendPacket(
                                    sender_pk,
                                    ProtocolMessage::SyncSketch(
                                        s.make_sync_sketch_keyed(range, tier, &overlay, k_iblt)?,
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
            ProtocolMessage::SyncRateLimited {
                conversation_id,
                retry_after_ms,
            } => {
                if let Some(session) = self.sessions.get_mut(&(sender_pk, conversation_id)) {
                    let retry_after_ms = retry_after_ms.clamp_max(super::SYNC_RATE_LIMITED_MAX_MS);
                    let until = self.clock.time_provider().now_instant()
                        + std::time::Duration::from_millis(retry_after_ms as u64);
                    session.common_mut().rate_limited_until = Some(until);
                }
            }
            ProtocolMessage::KeywrapAck {
                keywrap_hash,
                recipient_pk,
            } => {
                // `KeywrapAck` has no cryptographic payload: its fields
                // (`keywrap_hash`, `recipient_pk`) are both publicly
                // observable. Authentication relies on the Tox transport
                // layer, which binds `sender_pk` to the connection's
                // session key. `recipient_pk` is tagged
                // `Claimed<PhysicalDevicePk>`, so the only way to
                // unwrap it is to verify it matches the transport
                // sender. A forged ACK from any other peer cannot
                // clear the claim and the handler returns early.
                let Some(recipient_pk) = recipient_pk.verify(&sender_pk) else {
                    return Ok(effects);
                };
                // Release KeyWrap Pending state for the conversation whose
                // KeyWrap matches this ACK.
                if let Some(pending) = self.keywrap_pending.remove(&keywrap_hash) {
                    if pending.recipient_pk == recipient_pk {
                        debug!(
                            "KeywrapAck received from {:?} for {:?}",
                            sender_pk,
                            hex::encode(keywrap_hash.as_bytes()),
                        );
                        // Track ack for announcement key erasure (§50% threshold)
                        let (acks, total) = self
                            .keywrap_ack_counts
                            .entry(pending.conversation_id)
                            .or_insert((0, 0));
                        *acks += 1;
                        // Erase old ephemeral keys when 50% of recipients have acked
                        if *total > 0 && *acks * 2 >= *total {
                            debug!(
                                "50% ack threshold reached for {:?}, erasing old ephemeral keys",
                                pending.conversation_id
                            );
                            // Determine current epoch to preserve its keys
                            let current_epoch = self
                                .conversations
                                .get(&pending.conversation_id)
                                .and_then(|c| match c {
                                    crate::engine::Conversation::Established(e) => {
                                        Some(e.state.current_epoch)
                                    }
                                    _ => None,
                                });
                            if let Some(epoch) = current_epoch {
                                // Erase old ephemeral X25519 keys (SPK/OPK):
                                // keep only keys from current rotation
                                // Note: ephemeral_keys is a flat map without epoch association,
                                // but the consumed OPKs should be cleaned up. We keep the
                                // most recently generated keys and remove consumed ones.
                                // Erase old ephemeral signing keys (keep only current epoch)
                                self.self_ephemeral_signing_keys.retain(|&e, _| e >= epoch);
                            }
                            // Reset counter for next rotation
                            *acks = 0;
                            *total = 0;
                        }
                    } else {
                        // Mismatch: put it back
                        self.keywrap_pending.insert(keywrap_hash, pending);
                    }
                }
            }
            ProtocolMessage::ReconPowChallenge {
                conversation_id,
                nonce,
                difficulty,
            } => {
                let solution = crate::engine::session::active::solve_challenge(nonce, difficulty);
                effects.push(Effect::SendPacket(
                    sender_pk,
                    ProtocolMessage::ReconPowSolution {
                        conversation_id,
                        nonce,
                        solution,
                    },
                ));
            }
            ProtocolMessage::ReconPowSolution {
                conversation_id,
                nonce,
                solution,
            } => {
                if let Some(PeerSession::Active(session)) =
                    self.sessions.get_mut(&(sender_pk, conversation_id))
                {
                    let now = self.clock.time_provider().now_instant();
                    if session.verify_solution(nonce, solution, now)
                        && let Some(sketch) = session.take_pending_sketch(nonce)
                    {
                        let keys = match self.conversations.get(&conversation_id) {
                            Some(crate::engine::Conversation::Established(em)) => {
                                em.get_keys(em.current_epoch())
                            }
                            _ => None,
                        };
                        let k_iblt =
                            keys.map(|k| crate::crypto::derive_k_iblt(&k.k_conv, &conversation_id));

                        let sketch_ok = process_sketch(
                            session,
                            sender_pk,
                            sketch,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            keys,
                            k_iblt,
                            &mut effects,
                        )?;
                        if !sketch_ok {
                            if let Some(budget) = self.sketch_cpu_budgets.get_mut(&sender_pk) {
                                budget.remaining_ms = 0.0;
                            }
                            self.record_sketch_decode_failure(sender_pk);
                        } else {
                            self.record_sketch_decode_success(sender_pk);
                        }
                    }
                }
            }
            ProtocolMessage::FetchBatchReq(req) => {
                let conv_id = req.conversation_id;
                if self.sessions.contains_key(&(sender_pk, conv_id)) {
                    let overlay = EngineStore {
                        store,
                        cache: &self.pending_cache,
                    };

                    // Clamp incoming batches at MAX_BATCH_SIZE. The local
                    // authoring path (see `SyncSession::next_fetch_batch`) also
                    // caps here; a peer sending more is either buggy or hostile,
                    // and we refuse to burn O(n) store lookups + wire-packs for
                    // them.
                    for hash in req
                        .hashes
                        .into_iter()
                        .take(tox_proto::constants::MAX_BATCH_SIZE)
                    {
                        // 1. Try to find an existing wire node (already encrypted)
                        if let Some(wire_node) = overlay.get_wire_node(&hash) {
                            effects.push(Effect::SendPacket(
                                sender_pk,
                                ProtocolMessage::MerkleNode {
                                    conversation_id: conv_id,
                                    hash,
                                    node: wire_node,
                                },
                            ));
                            continue;
                        }

                        // 2. Fallback: pack the node on the fly
                        if let Some(node) = overlay.get_node(&hash) {
                            let pack_keys = crate::crypto::PackKeys::Exception;
                            if let Ok(wire_node) = node.pack_wire(&pack_keys, true) {
                                effects.push(Effect::SendPacket(
                                    sender_pk,
                                    ProtocolMessage::MerkleNode {
                                        conversation_id: conv_id,
                                        hash,
                                        node: wire_node,
                                    },
                                ));
                            }
                        }
                    }
                }
            }
            ProtocolMessage::MerkleNode {
                conversation_id,
                hash,
                node: wire_node,
            } => {
                let conv_id = conversation_id;
                // Drop messages naming a conversation we have not
                // joined locally. Without this gate the unconditional
                // `Effect::WriteWireNode(conv_id, ...)` below lands in
                // the fs-backed store, where `ensure_conversation`
                // creates a fresh on-disk conversation tree (3 mkdirs
                // + 5 file opens + a permanent `inner.conversations`
                // HashMap entry) per peer-supplied 32-byte hash — a
                // friend at line rate exhausts inodes. See
                // `tests/adversarial_unknown_conversation_test.rs`.
                if !self.conversations.contains_key(&conv_id) {
                    return Ok(effects);
                }
                // Peer served a node — reset §3.11 withholding counter.
                // A peer who delivers any `MerkleNode` is not withholding,
                // so prior speculative misses should not stack toward a
                // blacklist. Also graduates this peer out of the sketch-
                // decode "grace period" — they've demonstrated they can
                // deliver content, so later sketch-decode failures are
                // the spec's "consistent failure" case. Scenario 10
                // relies on this (sketches may never fire during the
                // pre-phase; MerkleNode receipt is the reliable signal).
                self.reset_withholding_count(sender_pk);
                self.record_sketch_decode_success(sender_pk);
                {
                    let mut unpacked = None;

                    // Always store the wire node so we can re-distribute it and try to unpack later
                    effects.push(Effect::WriteWireNode(conv_id, hash, wire_node.clone()));
                    if let Some(PeerSession::Active(_session)) =
                        self.sessions.get_mut(&(sender_pk, conv_id))
                    {
                        let overlay = EngineStore {
                            store,
                            cache: &self.pending_cache,
                        };
                        overlay.put_wire_node(&conv_id, &hash, wire_node.clone())?;
                    }

                    // Try exception (cleartext) unpack first: covers Admin, KeyWrap, etc.
                    if !wire_node.flags.contains(crate::dag::WireFlags::ENCRYPTED)
                        && let Ok(mut node) =
                            crate::dag::MerkleNode::unpack_wire_exception(&wire_node)
                    {
                        // unpack_wire_exception sets author_pk = sender_pk.to_logical(),
                        // which is only correct for admin nodes. For SKD/KeyWrap/HistoryExport
                        // nodes, sender_pk is a device key and author_pk should be the
                        // corresponding master (logical) key. Resolve via identity_manager.
                        let all_senders = self
                            .identity_manager
                            .list_all_authorized_sender_pairs(conv_id);
                        if let Some((_, logical_pk)) =
                            all_senders.iter().find(|(d, _)| *d == node.sender_pk)
                        {
                            node.author_pk = *logical_pk;
                        }
                        unpacked = Some(node);
                    }

                    // For encrypted content nodes, use sender identification
                    if unpacked.is_none()
                        && let Some(crate::engine::Conversation::Established(em)) =
                            self.conversations.get(&conv_id)
                    {
                        let mut all_senders = self
                            .identity_manager
                            .list_all_authorized_sender_pairs(conv_id);
                        // Also try the network-level sender as a candidate
                        if !all_senders.iter().any(|(d, _)| *d == sender_pk) {
                            all_senders.push((sender_pk, sender_pk.to_logical()));
                        }
                        unpacked = em.identify_sender_and_unpack(&wire_node, &all_senders);

                        // Fallback: try HistoryExport room-wide export keys
                        if unpacked.is_none() {
                            unpacked = em.try_unpack_history_export(&wire_node, &all_senders);
                        }
                    }

                    if let Some(node) = unpacked {
                        // Use handle_node_internal_ext directly (not handle_node)
                        // to avoid clearing the pending cache. The wire node was
                        // stored in the cache above and must remain accessible
                        // for encrypt-then-sign verification.
                        let node_effects =
                            self.handle_node_internal_ext(conv_id, node, store, blob_store, true)?;
                        effects.extend(node_effects);
                        // Remove from opaque tracking if it was previously stored
                        if let Some((total, entries)) = self.opaque_store_usage.get_mut(&conv_id)
                            && let Some(pos) = entries.iter().position(|(h, _, _, _)| *h == hash)
                        {
                            *total -= entries[pos].1;
                            entries.swap_remove(pos);
                        }
                    } else {
                        debug!(
                            "Failed to unpack wire node: {}",
                            hex::encode(hash.as_bytes())
                        );
                        // Track opaque store usage for quota enforcement
                        let wire_size = wire_node.payload_data.len()
                            + wire_node.encrypted_routing.len()
                            + wire_node.parents.len() * 32;
                        let now_ms = self.clock.network_time_ms();
                        let (total, entries) = self
                            .opaque_store_usage
                            .entry(conv_id)
                            .or_insert_with(|| (0, Vec::new()));
                        // Per-sender opaque quota
                        let sender_count = entries
                            .iter()
                            .filter(|(_, _, _, spk)| *spk == sender_pk)
                            .count();
                        if sender_count >= tox_proto::constants::MAX_OPAQUE_REQUESTS_PER_VOUCHER {
                            debug!(
                                "Per-sender opaque quota exceeded for {:?} in {:?}",
                                sender_pk, conv_id
                            );
                        } else {
                            *total += wire_size;
                            entries.push((hash, wire_size, now_ms, sender_pk));
                        }
                        // Evict cold-first, then by lowest rank within tier
                        // Filter out promotion-locked entries before eviction
                        while *total > tox_proto::constants::OPAQUE_STORE_QUOTA
                            && entries
                                .iter()
                                .any(|(h, _, _, _)| !self.promotion_locked.contains(h))
                        {
                            let max_rank = store
                                .get_heads(&conv_id)
                                .iter()
                                .filter_map(|h| store.get_rank(h))
                                .max()
                                .unwrap_or(0);
                            let hot_cutoff =
                                max_rank.saturating_sub(tox_proto::constants::HOT_WINDOW_RANKS);
                            entries.sort_by(|a, b| {
                                let a_locked = self.promotion_locked.contains(&a.0);
                                let b_locked = self.promotion_locked.contains(&b.0);
                                // Locked entries sort LAST (never evicted)
                                match (a_locked, b_locked) {
                                    (true, false) => return std::cmp::Ordering::Greater,
                                    (false, true) => return std::cmp::Ordering::Less,
                                    _ => {}
                                }
                                let a_rank = store.get_rank(&a.0).unwrap_or(0);
                                let b_rank = store.get_rank(&b.0).unwrap_or(0);
                                let a_cold = a_rank < hot_cutoff;
                                let b_cold = b_rank < hot_cutoff;
                                // Cold before hot; within same tier, lowest rank first
                                match (a_cold, b_cold) {
                                    (true, false) => std::cmp::Ordering::Less,
                                    (false, true) => std::cmp::Ordering::Greater,
                                    _ => a_rank.cmp(&b_rank),
                                }
                            });
                            let (evicted_hash, evicted_size, _, _) = entries.remove(0);
                            *total -= evicted_size;
                            effects.push(Effect::DeleteWireNode(conv_id, evicted_hash));
                        }
                        if let Some(PeerSession::Active(session)) =
                            self.sessions.get_mut(&(sender_pk, conv_id))
                        {
                            session.on_wire_node_received(hash, &wire_node, store);
                        }
                    }
                }
            }
            ProtocolMessage::BlobQuery(hash) => {
                if let Some(bs) = blob_store
                    && let Some(info) = bs.get_blob_info(&hash)
                    && (info.status == crate::cas::BlobStatus::Available
                        || info.status == crate::cas::BlobStatus::Downloading)
                {
                    effects.push(Effect::SendPacket(
                        sender_pk,
                        ProtocolMessage::BlobAvail(info),
                    ));
                }
            }
            ProtocolMessage::BlobAvail(info) => {
                let blob_hash = info.hash;
                // Clamp the peer-supplied `info.size` against the
                // protocol cap *before* committing any state. Mirrors
                // the HistoryExport ingestion clamp at
                // `processor/verification.rs:629`. Without this gate
                // a friend can advertise `info.size = 1<<40`, which
                // seeds `sync.info.size` with the attacker's value
                // and lets subsequent `BlobData` pieces drive
                // unbounded `partial_chunks` allocation in the
                // BlobData handler (one ~1.3 KB packet per ~64 KiB
                // of receiver RAM, ~50× wire-to-RAM amplification,
                // sustained because `remove_seeder` doesn't clear
                // `partial_chunks`). See
                // `tests/adversarial_blob_avail_oom_test.rs`.
                if info.size > tox_proto::constants::MAX_BLOB_SIZE {
                    return Ok(effects);
                }
                // Mirror the `BlobFetch` gate at handlers/mod.rs:962-978.
                // Without this check any friend-connected peer could
                // ship a `BlobAvail` for an arbitrary 32-byte hash and
                // force us to either (a) allocate a fresh `SwarmSync`
                // plus a synchronous `WriteBlobInfo` disk write per
                // unseen hash — unbounded local memory + disk
                // amplification — or (b) register themselves as a
                // seeder for any in-progress download, polluting the
                // seeder set of blobs they are not authorised to
                // participate in. Both branches close on the same gate:
                // require the hash to map to a known conversation and
                // the sender to share a session in it.
                let authorised = self
                    .blob_conversations
                    .get(&blob_hash)
                    .is_some_and(|conv_id| self.sessions.contains_key(&(sender_pk, *conv_id)));
                if !authorised {
                    return Ok(effects);
                }
                if let Some(sync) = self.blob_syncs.get_mut(&blob_hash) {
                    // No separate root check: `blob_hash` IS the chunk-Merkle
                    // root (see doc/merkle-tox-cas.md §3). A peer claiming
                    // to serve this hash is either telling the truth (each
                    // chunk they send gets verified against the root by
                    // the BlobData handler) or will be caught by chunk
                    // verification and removed from the seeder set there.
                    tracing::debug!(
                        "Adding seeder {:?} for blob {:?} (partial={})",
                        sender_pk,
                        blob_hash,
                        info.received_mask.is_some(),
                    );
                    sync.add_seeder(sender_pk);
                } else if let Some(bs) = blob_store
                    && !bs.has_blob(&blob_hash)
                {
                    tracing::debug!(
                        "Starting swarm sync for blob {:?} with seeder {:?}",
                        blob_hash,
                        sender_pk
                    );
                    let mut local_info = info.clone();
                    local_info.status = crate::cas::BlobStatus::Pending;
                    local_info.received_mask = None;
                    let mut sync = SwarmSync::new_with_offset(local_info.clone(), &self.self_pk);
                    sync.add_seeder(sender_pk);
                    self.blob_syncs.insert(blob_hash, sync);
                    effects.push(Effect::WriteBlobInfo(local_info));
                }
            }
            ProtocolMessage::BlobReq(req) => {
                // Legacy pull fallback. Normally suppressed while a push
                // stream is active (see `SwarmSync::next_requests` gating);
                // this path only runs for peers that don't support push.
                // No per-piece Merkle proof — the primary streaming path is
                // what carries chunk-boundary proofs. Legacy callers
                // fall back to full-blob verification at finalize time.
                //
                // Clamp peer-supplied `offset` / `length` at the handler
                // before any storage call. The legacy pull-fallback
                // protocol serves at most one *piece* per `BlobReq`
                // because `BlobData.data` is structurally capped at
                // `MAX_PIECE_DATA` (the modern per-piece envelope).
                // Reject any `offset` past the blob's known size: the
                // storage layer has a defensive bounds check, but it's
                // defense-in-depth, not the primary gate.
                let blob_hash = req.hash;
                // Mirror the `BlobFetch` authorization gate. Without
                // this, any friend who learns a blob hash (former
                // member, leaked log, public hash) can drain upload
                // bandwidth at line rate by piping legacy BlobReqs.
                // Same attack shape as the BlobFetch leak closed in
                // the prior commit; this is the legacy pull-fallback
                // sibling.
                let authorised = self
                    .blob_conversations
                    .get(&blob_hash)
                    .is_some_and(|conv_id| self.sessions.contains_key(&(sender_pk, *conv_id)));
                if !authorised {
                    return Ok(effects);
                }
                let Some(length) = req.length.checked_le(crate::cas::MAX_PIECE_DATA as u32) else {
                    return Ok(effects);
                };
                if let Some(bs) = blob_store
                    && let Some(info) = bs.get_blob_info(&blob_hash)
                    && let Some(offset) = req.offset.checked_lt(info.size)
                    && let Ok(data_vec) = bs.get_chunk(&blob_hash, offset, length)
                    && let Ok(data) = tox_proto::BoundedBytes::try_from_vec(data_vec)
                {
                    effects.push(Effect::SendPacket(
                        sender_pk,
                        ProtocolMessage::BlobData(BlobData {
                            hash: req.hash,
                            offset: tox_proto::Untrusted::new(offset),
                            data,
                            proof: tox_proto::BoundedBytes::new(),
                        }),
                    ));
                }
            }
            ProtocolMessage::BlobData(data) => {
                let blob_hash = data.hash;
                self.stats
                    .blob_data_received
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(sync) = self.blob_syncs.get_mut(&blob_hash)
                    && blob_store.is_some()
                {
                    // Sender authorisation. Mirrors the BlobAvail /
                    // BlobReq / BlobFetch arms — only registered
                    // seeders (peers who shipped a BlobAvail through
                    // the blob_conversations gate and were added via
                    // `sync.add_seeder`) may push pieces. Without
                    // this check, any friend who learns the blob
                    // hash can pin one ~64 KiB `partial_chunks`
                    // buffer per unique chunk_idx — sustained wire-
                    // to-RAM amplification limited only by `info.size
                    // / CHUNK_SIZE`. The cleanup path
                    // (`SwarmSync::remove_seeder` clearing
                    // `partial_chunks` when seeders empty) never
                    // fires for an attacker who was never *in*
                    // `seeders`. See
                    // `tests/adversarial_blob_data_test.rs §BD-4`.
                    if !sync.has_seeder(&sender_pk) {
                        return Ok(effects);
                    }
                    // Spec: doc/merkle-tox-cas.md §3. Buffer pieces in
                    // memory until a full 64KB chunk is assembled, then
                    // verify it against the trusted `sync.info.hash`
                    // (which IS the chunk Merkle root — see commit adding
                    // ChunkMerkleTree + Option A decision). On success,
                    // emit one WriteChunk. On failure (tampered bytes,
                    // bad proof, wrong root, or missing proof) drop the
                    // chunk, emit no WriteChunk, and remove the seeder.
                    let chunk_len = data.data.len();
                    // Clamp the peer-supplied offset against the
                    // (also peer-supplied, but already committed)
                    // `sync.info.size` *before* any arithmetic touches
                    // it. Without this gate `chunk_start + CHUNK_SIZE`
                    // and `chunk_end - chunk_start` both wrap on huge
                    // offsets — the wrapped `usize` then drives
                    // `vec![0u8; …]` into an OOM/abort. Single-packet
                    // kill from any authenticated peer reachable
                    // through the unauthenticated `BlobAvail` join.
                    let Some(offset) = data.offset.checked_lt(sync.info.size) else {
                        return Ok(effects);
                    };
                    let chunk_idx = offset / crate::cas::CHUNK_SIZE;
                    let chunk_start = chunk_idx * crate::cas::CHUNK_SIZE;
                    let chunk_end = chunk_start
                        .saturating_add(crate::cas::CHUNK_SIZE)
                        .min(sync.info.size);
                    let full_chunk_size = (chunk_end - chunk_start) as usize;
                    let piece_offset_in_chunk = (offset - chunk_start) as usize;

                    // Drop duplicate piece arrivals for already-verified
                    // chunks on the floor. Without this guard, a late
                    // retransmission arriving after the chunk completed
                    // would: (1) call `partial_chunks.entry().or_insert`,
                    // creating a FRESH zero-filled buffer with only this
                    // one piece populated, (2) let the chunk_now_complete
                    // check pass (the chunk is still in completed_ranges),
                    // (3) trigger verification against the zero buffer,
                    // which fails spuriously, (4) cause the cascade that
                    // produced 5-16x retransmission amplification in
                    // scenario 5 (task #22).
                    if sync
                        .tracker
                        .completed_ranges
                        .iter()
                        .any(|&(s, e)| chunk_idx >= s && chunk_idx <= e)
                    {
                        return Ok(effects);
                    }

                    // Buffer the piece bytes into the partial chunk.
                    let buf = sync
                        .partial_chunks
                        .entry(chunk_idx)
                        .or_insert_with(|| vec![0u8; full_chunk_size]);
                    if piece_offset_in_chunk + chunk_len <= buf.len() {
                        buf[piece_offset_in_chunk..piece_offset_in_chunk + chunk_len]
                            .copy_from_slice(&data.data);
                    }

                    // Stash the proof if this piece carries one. Pieces
                    // can arrive out of order, so we buffer the proof
                    // now and use it when the chunk finishes.
                    if !data.proof.is_empty() {
                        // pending_proofs is in-memory state — `Vec<u8>`
                        // is fine. Convert from BoundedBytes via
                        // `to_vec`.
                        sync.pending_proofs
                            .insert(chunk_idx, data.proof.as_slice().to_vec());
                    }

                    sync.tracker.mark_piece_received(offset, chunk_len);
                    self.stats
                        .blob_data_stored
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // If the chunk just completed, verify and emit.
                    let chunk_now_complete = sync
                        .tracker
                        .completed_ranges
                        .iter()
                        .any(|&(s, e)| chunk_idx >= s && chunk_idx <= e);
                    if chunk_now_complete
                        && let Some(chunk_bytes) = sync.partial_chunks.remove(&chunk_idx)
                    {
                        let num_chunks = sync.info.size.div_ceil(crate::cas::CHUNK_SIZE) as usize;
                        let root_bytes = *sync.info.hash.as_bytes();
                        let proof = sync.pending_proofs.remove(&chunk_idx);
                        // Single-chunk blobs have a 1-leaf Merkle tree,
                        // so the proof is empty by construction — the
                        // chunk's leaf hash IS the root. In that case we
                        // verify with an empty proof and skip the
                        // "must have buffered a proof" check.
                        let verified = if num_chunks == 1 {
                            crate::cas::ChunkMerkleTree::verify_chunk(
                                &chunk_bytes,
                                chunk_idx as usize,
                                num_chunks,
                                &[],
                                &root_bytes,
                            )
                        } else {
                            match &proof {
                                Some(p) if !p.is_empty() => {
                                    crate::cas::ChunkMerkleTree::verify_chunk(
                                        &chunk_bytes,
                                        chunk_idx as usize,
                                        num_chunks,
                                        p,
                                        &root_bytes,
                                    )
                                }
                                // Multi-chunk blob must present a
                                // non-empty proof for every chunk.
                                _ => false,
                            }
                        };

                        if verified {
                            let conv_id = self
                                .sessions
                                .keys()
                                .filter(|(p, _)| p == &sender_pk)
                                .map(|(_, c)| *c)
                                .next()
                                .unwrap_or(ConversationId::from([0u8; 32]));
                            effects.push(Effect::WriteChunk(
                                conv_id,
                                blob_hash,
                                chunk_start,
                                chunk_bytes,
                                None,
                            ));
                        } else {
                            // Chunk failed verification. Drop the buffer
                            // (already done by remove above), unmark the
                            // chunk from the tracker so subsequent
                            // retransmit requests can re-fetch it, and
                            // remove the seeder — they sent us bad data.
                            tracing::warn!(
                                "Chunk verification FAILED for blob {:?} chunk {} from seeder {:?} \
                                 (proof_present={}). Removing seeder.",
                                blob_hash,
                                chunk_idx,
                                sender_pk,
                                proof.is_some(),
                            );
                            sync.tracker
                                .completed_ranges
                                .retain(|&(s, e)| !(chunk_idx >= s && chunk_idx <= e));
                            sync.remove_seeder(&sender_pk);
                        }
                    }

                    if sync.tracker.is_complete() {
                        let mut info = sync.info.clone();
                        info.status = crate::cas::BlobStatus::Available;
                        info.received_mask = None;
                        effects.push(Effect::WriteBlobInfo(info.clone()));

                        for (pk, _) in self.sessions.keys() {
                            if *pk != self.self_pk {
                                effects.push(Effect::SendPacket(
                                    *pk,
                                    ProtocolMessage::BlobAvail(info.clone()),
                                ));
                            }
                        }

                        self.blob_syncs.remove(&blob_hash);
                        effects.push(Effect::EmitEvent(NodeEvent::BlobAvailable {
                            hash: blob_hash,
                        }));
                    }
                }
            }
            ProtocolMessage::BlobFetch(fetch) => {
                let blob_hash = fetch.hash;
                // Only serve peers who are current participants of the
                // conversation the blob was exported from. Without this
                // gate, any friend-connected peer (including revoked
                // former members) can drain upload bandwidth by
                // knowing a blob hash. If we don't know which
                // conversation the blob belongs to, decline to serve.
                let authorised = self
                    .blob_conversations
                    .get(&blob_hash)
                    .is_some_and(|conv_id| self.sessions.contains_key(&(sender_pk, *conv_id)));
                if !authorised {
                    return Ok(effects);
                }
                if let Some(bs) = blob_store
                    && let Some(info) = bs.get_blob_info(&blob_hash)
                    && info.status == crate::cas::BlobStatus::Available
                {
                    // Clamp peer-supplied `completed_ranges` against
                    // our own `num_chunks` before handing them to the
                    // push stream, which expects trusted bounds.
                    let num_chunks = info.size.div_ceil(crate::cas::CHUNK_SIZE);
                    let receiver_completed = fetch.completed_ranges.map(|ranges| {
                        ranges
                            .into_iter()
                            .filter_map(|(s, e)| {
                                let s = s.checked_in(0, num_chunks)?;
                                let e = e.clamp_max(num_chunks.saturating_sub(1));
                                (e >= s).then_some((s, e))
                            })
                            .collect()
                    });
                    // Start a push stream for this peer. Build the
                    // chunk-Merkle tree up front so the flush hot path
                    // never hits synchronous disk I/O to produce a
                    // proof.
                    let tree = crate::cas::ChunkMerkleTree::from_store(bs, blob_hash, info.size);
                    let stream =
                        crate::cas::PushStream::new(blob_hash, info.size, receiver_completed, tree);
                    self.push_streams.insert((blob_hash, sender_pk), stream);
                    tracing::debug!(
                        "Started push stream for blob {:?} to {:?}",
                        blob_hash,
                        sender_pk
                    );
                }
            }
            ProtocolMessage::BlobProgress(progress) => {
                let blob_hash = progress.hash;
                if let Some(stream) = self.push_streams.get_mut(&(blob_hash, sender_pk)) {
                    stream.on_progress(&progress);
                }
            }
            ProtocolMessage::BlobCancel(blob_hash) => {
                self.push_streams.remove(&(blob_hash, sender_pk));
                tracing::debug!(
                    "Cancelled push stream for blob {:?} to {:?}",
                    blob_hash,
                    sender_pk
                );
            }
            ProtocolMessage::ReinclusionRequest {
                conversation_id,
                sender_pk: requester_pk,
                healing_snapshot_hash,
            } => {
                // `requester_pk` is tagged `Claimed<PhysicalDevicePk>`;
                // the only way to unwrap it is to verify against the
                // transport-authenticated `sender_pk`. A peer forging
                // a claim naming a snapshot member cannot pass this
                // gate, so the admin is not a membership oracle and
                // no spoofed k_conv rotation is triggered.
                let Some(requester_pk) = requester_pk.verify(&sender_pk) else {
                    return Ok(effects);
                };
                // Verify: snapshot exists and is verified, self is admin, requester
                // was in the snapshot's member list.
                let is_admin = self.is_self_admin(conversation_id);
                if is_admin {
                    if let Some(snapshot_node) = store.get_node(&healing_snapshot_hash)
                        && store.is_verified(&healing_snapshot_hash)
                    {
                        // Validate that the requester appears in the snapshot's member list.
                        let requester_in_snapshot = if let crate::dag::Content::Control(
                            crate::dag::ControlAction::AnchorSnapshot { data, .. },
                        ) = &snapshot_node.content
                        {
                            data.members
                                .iter()
                                .any(|m| m.public_key == requester_pk.to_logical())
                        } else {
                            false
                        };

                        if !requester_in_snapshot {
                            debug!("Reinclusion rejected: requester not in snapshot member list");
                            effects.push(Effect::SendPacket(
                                sender_pk,
                                ProtocolMessage::ReinclusionResponse {
                                    conversation_id,
                                    accepted: false,
                                },
                            ));
                        } else {
                            // Issue a fresh KeyWrap via rotate_conversation_key
                            match self.rotate_conversation_key(conversation_id, store) {
                                Ok(rotation_effects) => {
                                    effects.extend(rotation_effects);
                                    effects.push(Effect::SendPacket(
                                        sender_pk,
                                        ProtocolMessage::ReinclusionResponse {
                                            conversation_id,
                                            accepted: true,
                                        },
                                    ));
                                }
                                Err(e) => {
                                    debug!("Reinclusion rotation failed: {}", e);
                                    effects.push(Effect::SendPacket(
                                        sender_pk,
                                        ProtocolMessage::ReinclusionResponse {
                                            conversation_id,
                                            accepted: false,
                                        },
                                    ));
                                }
                            }
                        }
                    } else {
                        effects.push(Effect::SendPacket(
                            sender_pk,
                            ProtocolMessage::ReinclusionResponse {
                                conversation_id,
                                accepted: false,
                            },
                        ));
                    }
                }
            }
            ProtocolMessage::ReinclusionResponse {
                conversation_id,
                accepted,
            } => {
                if accepted {
                    info!(
                        "Reinclusion accepted for conversation {:?}",
                        conversation_id
                    );
                } else {
                    debug!(
                        "Reinclusion rejected for conversation {:?}",
                        conversation_id
                    );
                }
            }
            ProtocolMessage::AdminGossip {
                conversation_id,
                hash,
            } => {
                // Priority-fetch admin node if not already known.
                let overlay = EngineStore {
                    store,
                    cache: &self.pending_cache,
                };
                if !overlay.has_node(&hash)
                    && let Some(PeerSession::Active(session)) =
                        self.sessions.get_mut(&(sender_pk, conversation_id))
                    && !session.common.in_flight_fetches.contains(&hash)
                    && !session.common.missing_admin_nodes.contains(&hash)
                    && session.common.missing_admin_nodes.len() < super::MAX_MISSING_ADMIN_NODES
                {
                    session.common.missing_admin_nodes.push_back(hash);
                    session.common.heads_dirty = true;
                }
            }
            ProtocolMessage::HandshakeError {
                conversation_id,
                reason,
            } => {
                debug!(
                    "Handshake error from {:?} for {:?}: {}",
                    sender_pk, conversation_id, reason
                );
                // See SyncHeads for the rationale — `handshake_retry_state`
                // grows per peer-supplied conv_id without the gate.
                if !self.conversations.contains_key(&conversation_id) {
                    return Ok(effects);
                }
                // Track retry state with exponential backoff (2s base, 8s ceiling, 3 per 10min)
                let now = self.clock.network_time_ms();
                let state = self
                    .handshake_retry_state
                    .entry((conversation_id, sender_pk))
                    .or_default();
                // If the prior window expired, start a fresh one. Mirrors
                // `author_x3dh_key_exchange`; without this slide, stale
                // `window_start_ms` would freeze `attempts` at whatever
                // value the peer has driven it to.
                if state.window_start_ms == 0
                    || now >= state.window_start_ms + super::HANDSHAKE_RETRY_WINDOW_MS
                {
                    state.window_start_ms = now;
                    state.attempts = 0;
                }
                state.attempts += 1;
                let backoff_ms = (super::HANDSHAKE_RETRY_BASE_MS << state.attempts.min(2))
                    .min(super::HANDSHAKE_RETRY_MAX_MS);
                state.next_retry_ms = now + backoff_ms as i64;
            }
            ProtocolMessage::Unknown { discriminant, data } => {
                // Forward-compat catch-all: a newer peer sent us a
                // protocol-message variant our build doesn't
                // recognise. Log and drop. The wire bytes are
                // preserved in `data` so a metric/observability hook
                // could surface them, but we deliberately don't do
                // anything else — acting on an unknown message would
                // be guessing at semantics we don't have.
                debug!(
                    sender_pk = ?sender_pk,
                    discriminant,
                    data_len = data.len(),
                    "received ProtocolMessage::Unknown — newer peer protocol variant; dropping"
                );
            }
        }

        Ok(effects)
    }
}

/// Returns true on success, false on decode failure.
fn process_sketch(
    session: &mut SyncSession<Active>,
    sender_pk: PhysicalDevicePk,
    sketch: tox_reconcile::SyncSketch,
    store: &dyn NodeStore,
    _keys: Option<&crate::crypto::ConversationKeys>,
    k_iblt: Option<[u8; 32]>,
    effects: &mut Vec<Effect>,
) -> MerkleToxResult<bool> {
    let decode_ok;
    match session.handle_sync_sketch_keyed(sketch.clone(), store, k_iblt)? {
        DecodingResult::Success {
            missing_locally: _,
            missing_remotely,
        } => {
            decode_ok = true;
            // Clamp reply count: a peer-controlled empty sketch decodes
            // to `local_hashes` (up to `d_max(tier)` ≈ 680 for Large),
            // which without this cap turns one inbound packet into up
            // to ~680 outbound `MerkleNode` packets. The remainder is
            // re-fetched naturally by the peer's next sketch round-trip
            // — convergence is unaffected.
            for hash in missing_remotely
                .into_iter()
                .take(tox_proto::constants::MAX_SKETCH_REPLY_BATCH)
            {
                // Prefer cached wire nodes; fall back to exception packing
                if let Some(wire_node) = store.get_wire_node(&hash) {
                    effects.push(Effect::SendPacket(
                        sender_pk,
                        ProtocolMessage::MerkleNode {
                            conversation_id: sketch.conversation_id,
                            hash,
                            node: wire_node,
                        },
                    ));
                } else if let Some(node) = store.get_node(&hash) {
                    // Re-pack as exception (cleartext): content nodes should have
                    // been stored as wire nodes when first authored/received.
                    let pack_keys = crate::crypto::PackKeys::Exception;
                    if let Ok(wire_node) = node.pack_wire(&pack_keys, true) {
                        debug!(
                            "Sending node {} as result of sketch",
                            hex::encode(hash.as_bytes())
                        );
                        effects.push(Effect::SendPacket(
                            sender_pk,
                            ProtocolMessage::MerkleNode {
                                conversation_id: sketch.conversation_id,
                                hash,
                                node: wire_node,
                            },
                        ));
                    } else {
                        debug!(
                            "Failed to pack node {} for sending",
                            hex::encode(hash.as_bytes())
                        );
                    }
                } else {
                    debug!(
                        "Node {} not found in store for sending",
                        hex::encode(hash.as_bytes())
                    );
                }
            }
        }
        DecodingResult::Failed => {
            effects.push(Effect::SendPacket(
                sender_pk,
                ProtocolMessage::SyncReconFail {
                    conversation_id: sketch.conversation_id,
                    range: sketch.range,
                },
            ));
            decode_ok = false;
        }
    }

    if let Some(req) = session.next_fetch_batch(tox_proto::constants::MAX_BATCH_SIZE) {
        effects.push(Effect::SendPacket(
            sender_pk,
            ProtocolMessage::FetchBatchReq(req),
        ));
    }
    Ok(decode_ok)
}
