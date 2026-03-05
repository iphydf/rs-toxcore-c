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
                                    retry_after_ms: 1000,
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
                            // Drain remaining budget and escalate blacklist
                            if let Some(budget) = self.sketch_cpu_budgets.get_mut(&sender_pk) {
                                budget.remaining_ms = 0.0;
                            }
                            self.blacklist_escalate(sender_pk);
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
                let conv_id = conversation_id;
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
                    let until = self.clock.time_provider().now_instant()
                        + std::time::Duration::from_millis(retry_after_ms as u64);
                    session.common_mut().rate_limited_until = Some(until);
                }
            }
            ProtocolMessage::KeywrapAck {
                keywrap_hash,
                recipient_pk,
            } => {
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
                            self.blacklist_escalate(sender_pk);
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

                    for hash in req.hashes {
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
                {
                    effects.push(Effect::SendPacket(
                        sender_pk,
                        ProtocolMessage::BlobAvail(info),
                    ));
                }
            }
            ProtocolMessage::BlobAvail(info) => {
                let blob_hash = info.hash;
                if let Some(sync) = self.blob_syncs.get_mut(&blob_hash) {
                    // Validate bao_root matches our stored info
                    if sync.info.bao_root.is_some() && info.bao_root != sync.info.bao_root {
                        tracing::warn!(
                            "Peer {:?} sent mismatching bao_root for blob {:?}, blacklisting",
                            sender_pk,
                            blob_hash
                        );
                        sync.remove_seeder(&sender_pk);
                    } else {
                        tracing::debug!("Adding seeder {:?} for blob {:?}", sender_pk, blob_hash);
                        sync.add_seeder(sender_pk);
                    }
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
                    let mut sync = SwarmSync::new(local_info.clone());
                    sync.add_seeder(sender_pk);
                    self.blob_syncs.insert(blob_hash, sync);
                    effects.push(Effect::WriteBlobInfo(local_info));
                }
            }
            ProtocolMessage::BlobReq(req) => {
                let blob_hash = req.hash;
                if let Some(bs) = blob_store
                    && let Ok((data, proof)) =
                        bs.get_chunk_with_proof(&blob_hash, req.offset, req.length)
                {
                    effects.push(Effect::SendPacket(
                        sender_pk,
                        ProtocolMessage::BlobData(BlobData {
                            hash: req.hash,
                            offset: req.offset,
                            data,
                            proof,
                        }),
                    ));
                }
            }
            ProtocolMessage::BlobData(data) => {
                let blob_hash = data.hash;
                if let Some(sync) = self.blob_syncs.get_mut(&blob_hash) {
                    if sync.on_chunk_received(&data) && blob_store.is_some() {
                        // Find conversation_id for this blob.
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
                            data.offset,
                            data.data.clone(),
                            Some(data.proof.clone()),
                        ));

                        if sync.tracker.is_complete() {
                            let mut info = sync.info.clone();
                            info.status = crate::cas::BlobStatus::Available;
                            effects.push(Effect::WriteBlobInfo(info));
                            self.blob_syncs.remove(&blob_hash);
                            effects.push(Effect::EmitEvent(NodeEvent::BlobAvailable {
                                hash: blob_hash,
                            }));
                        }
                    } else {
                        // Verification failed, remove seeder
                        sync.remove_seeder(&sender_pk);
                    }
                }
            }
            ProtocolMessage::ReinclusionRequest {
                conversation_id,
                sender_pk: requester_pk,
                healing_snapshot_hash,
            } => {
                // Verify: snapshot exists and is verified, self is admin, requester
                // was in the snapshot's member list.
                let now_ms = self.clock.network_time_ms();
                let ctx = crate::identity::CausalContext::global();
                let is_admin = self.identity_manager.is_admin(
                    &ctx,
                    conversation_id,
                    &self.self_pk,
                    &self.self_pk.to_logical(),
                    now_ms,
                    u64::MAX,
                );
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
                // Track retry state with exponential backoff (2s base, 8s ceiling, 3 per 10min)
                let now = self.clock.network_time_ms();
                let state = self
                    .handshake_retry_state
                    .entry((conversation_id, sender_pk))
                    .or_default();
                if state.window_start_ms == 0 {
                    state.window_start_ms = now;
                }
                state.attempts += 1;
                let backoff_ms = (super::HANDSHAKE_RETRY_BASE_MS << state.attempts.min(2))
                    .min(super::HANDSHAKE_RETRY_MAX_MS);
                state.next_retry_ms = now + backoff_ms as i64;
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
            for hash in missing_remotely {
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
