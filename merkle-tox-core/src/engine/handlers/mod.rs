use crate::cas::{BlobData, SwarmSync};
use crate::dag::{ConversationId, PhysicalDevicePk};
use crate::engine::session::{Active, Handshake, PeerSession, SyncSession};
use crate::engine::{Effect, EngineStore, MerkleToxEngine};
use crate::error::MerkleToxResult;
use crate::sync::{BlobStore, DecodingResult, NodeStore, Tier};
use crate::{NodeEvent, ProtocolMessage};
use tracing::debug;

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
                            ProtocolMessage::SyncHeads(active.make_sync_heads(0)),
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
                            ProtocolMessage::SyncHeads(active.make_sync_heads(0)),
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

                        let keys = match self.conversations.get(&conv_id) {
                            Some(crate::engine::Conversation::Established(em)) => {
                                em.get_keys(em.current_epoch())
                            }
                            _ => None,
                        };

                        process_sketch(
                            s,
                            sender_pk,
                            sketch,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            keys,
                            &mut effects,
                        )?;
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
                        let different = s.handle_sync_shard_checksums(shards, &overlay)?;
                        for range in different {
                            if let Some(tier) = s.get_iblt_tier(&range) {
                                effects.push(Effect::SendPacket(
                                    sender_pk,
                                    ProtocolMessage::SyncSketch(
                                        s.make_sync_sketch(range, tier, &overlay)?,
                                    ),
                                ));
                            }
                        }
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

                        process_sketch(
                            session,
                            sender_pk,
                            sketch,
                            &EngineStore {
                                store,
                                cache: &self.pending_cache,
                            },
                            keys,
                            &mut effects,
                        )?;
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
                        if let Some(node) = overlay.get_node(&hash)
                            && let Some(crate::engine::Conversation::Established(em)) =
                                self.conversations.get(&conv_id)
                        {
                            let pack_keys = em.peek_keys(&node.parents).map(|(k_msg, _)| {
                                crate::crypto::ConversationKeys::derive(&crate::dag::KConv::from(
                                    *k_msg.as_bytes(),
                                ))
                            });

                            let pack_keys =
                                pack_keys.or_else(|| em.get_keys(em.current_epoch()).cloned());

                            if let Some(keys) = pack_keys
                                && let Ok(wire_node) = node.pack_wire(&keys, true)
                            {
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

                    if let Some(crate::engine::Conversation::Established(em)) =
                        self.conversations.get(&conv_id)
                    {
                        unpacked = em.unpack_node(&conv_id, &wire_node);
                    }
                    if let Some(node) = unpacked {
                        let node_effects = self.handle_node(conv_id, node, store, blob_store)?;
                        effects.extend(node_effects);
                    } else {
                        // Admin nodes can be unpacked without keys because they aren't encrypted.
                        if matches!(wire_node.authentication, crate::dag::NodeAuth::Signature(_)) {
                            let dummy_keys = crate::crypto::ConversationKeys::derive(
                                &crate::dag::KConv::from([0u8; 32]),
                            );
                            if let Ok(node) = crate::dag::MerkleNode::unpack_wire(
                                &wire_node,
                                &dummy_keys,
                                &conv_id,
                            ) {
                                let node_effects =
                                    self.handle_node(conv_id, node, store, blob_store)?;
                                effects.extend(node_effects);
                                return Ok(effects);
                            }
                        }

                        debug!(
                            "Failed to unpack wire node: {}",
                            hex::encode(hash.as_bytes())
                        );
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
                    tracing::debug!("Adding seeder {:?} for blob {:?}", sender_pk, blob_hash);
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
        }

        Ok(effects)
    }
}

fn process_sketch(
    session: &mut SyncSession<Active>,
    sender_pk: PhysicalDevicePk,
    sketch: tox_reconcile::SyncSketch,
    store: &dyn NodeStore,
    keys: Option<&crate::crypto::ConversationKeys>,
    effects: &mut Vec<Effect>,
) -> MerkleToxResult<()> {
    match session.handle_sync_sketch(sketch.clone(), store)? {
        DecodingResult::Success {
            missing_locally: _,
            missing_remotely,
        } => {
            for hash in missing_remotely {
                if let Some(node) = store.get_node(&hash) {
                    let wire_node = if let Some(keys) = keys {
                        node.pack_wire(keys, true).ok()
                    } else if node.node_type() == crate::dag::NodeType::Admin
                        || matches!(node.content, crate::dag::Content::KeyWrap { .. })
                    {
                        let dummy_keys = crate::crypto::ConversationKeys::derive(
                            &crate::dag::KConv::from([0u8; 32]),
                        );
                        node.pack_wire(&dummy_keys, true).ok()
                    } else {
                        debug!(
                            "Cannot pack node {} without keys",
                            hex::encode(hash.as_bytes())
                        );
                        None
                    };

                    if let Some(wire_node) = wire_node {
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
        }
    }

    if let Some(req) = session.next_fetch_batch(tox_proto::constants::MAX_BATCH_SIZE) {
        effects.push(Effect::SendPacket(
            sender_pk,
            ProtocolMessage::FetchBatchReq(req),
        ));
    }
    Ok(())
}
