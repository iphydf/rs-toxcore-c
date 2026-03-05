use crate::clock::TimeProvider;
use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use crate::engine::{Effect, MerkleToxEngine};
use crate::sync::{BlobStore, NodeStore};
use crate::{NodeEventHandler, ProtocolMessage, Transport};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_sequenced::{MessageType, Packet, SequenceSession, SessionEvent};
use tracing::{debug, error};

/// Node status snapshot for observability.
pub struct NodeStatus {
    pub pk: PhysicalDevicePk,
    pub heads: Vec<NodeHash>,
    pub verified_count: usize,
    pub speculative_count: usize,
    pub max_rank: u64,
    pub authorized_devices: usize,
    pub current_epoch: u32,
    pub db_size_bytes: u64,
    pub sessions: HashMap<PhysicalDevicePk, SessionStatus>,
}

pub struct SessionStatus {
    pub cwnd: usize,
    pub in_flight_bytes: usize,
    pub rtt: Duration,
}

/// Transport-agnostic Merkle-Tox node orchestrating engine, transport, and storage.
pub struct MerkleToxNode<T: Transport, S: NodeStore + BlobStore> {
    pub engine: MerkleToxEngine,
    pub transport: T,
    pub store: S,
    pub sessions: BTreeMap<PhysicalDevicePk, SequenceSession>,
    pub time_provider: Arc<dyn TimeProvider>,
    pub event_handler: Option<Arc<dyn NodeEventHandler>>,
    /// Cumulative wall-clock time spent in `poll()` sub-phases. Used by
    /// the e2e test harness to localize where bridge poll time goes
    /// (50%+ of alice's iter on the 100 MB transfer at last
    /// measurement). Atomic so the test can read concurrently with
    /// the (single-threaded) writer; values are nanoseconds.
    pub poll_engine_ns: std::sync::atomic::AtomicU64,
    pub poll_push_ns: std::sync::atomic::AtomicU64,
    pub poll_flush_ns: std::sync::atomic::AtomicU64,
}

impl<T: Transport, S: NodeStore + BlobStore> MerkleToxNode<T, S> {
    pub fn status(&self, conversation_id: &ConversationId) -> NodeStatus {
        let (ver_count, spec_count) = self.store.get_node_counts(conversation_id);
        let heads = self.store.get_heads(conversation_id);

        let max_rank = heads
            .iter()
            .filter_map(|h| self.store.get_node(h))
            .map(|n| n.topological_rank)
            .max()
            .unwrap_or(0);

        let sessions = self
            .sessions
            .iter()
            .map(|(pk, s)| {
                (
                    *pk,
                    SessionStatus {
                        cwnd: s.cwnd(),
                        in_flight_bytes: s.in_flight(),
                        rtt: s.current_rto(),
                    },
                )
            })
            .collect();

        NodeStatus {
            pk: self.engine.self_pk,
            heads,
            verified_count: ver_count,
            speculative_count: spec_count,
            max_rank,
            authorized_devices: self.engine.get_authorized_devices(conversation_id).len(),
            current_epoch: self.engine.get_current_generation(conversation_id),
            db_size_bytes: self.store.size_bytes(),
            sessions,
        }
    }

    pub fn new(
        engine: MerkleToxEngine,
        transport: T,
        store: S,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Self {
        Self {
            engine,
            transport,
            store,
            sessions: BTreeMap::new(),
            time_provider,
            event_handler: None,
            poll_engine_ns: std::sync::atomic::AtomicU64::new(0),
            poll_push_ns: std::sync::atomic::AtomicU64::new(0),
            poll_flush_ns: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn set_event_handler(&mut self, handler: Arc<dyn NodeEventHandler>) {
        self.event_handler = Some(handler);
    }

    /// Handles incoming raw packet.
    pub fn handle_packet(&mut self, from: PhysicalDevicePk, data: &[u8]) {
        let now = self.time_provider.now_instant();
        match tox_proto::deserialize::<Packet>(data) {
            Ok(packet) => {
                match &packet {
                    Packet::Data { seq, msg_type, .. } => {
                        tracing::debug!(
                            "Received DATA from {:?}: seq={}, type={:?}",
                            from,
                            seq,
                            msg_type
                        );
                    }
                    Packet::Ack {
                        base_seq,
                        recv_bytes,
                        ..
                    } => {
                        tracing::debug!(
                            "Received ACK from {:?}: base_seq={:?}, recv_bytes={:?}",
                            from,
                            base_seq,
                            recv_bytes
                        );
                    }
                    Packet::Fragment {
                        frag_id,
                        frag_index,
                        frag_total,
                        ..
                    } => {
                        tracing::debug!(
                            "Received FRAGMENT from {:?}: frag_id={}, {}/{}",
                            from,
                            frag_id,
                            frag_index,
                            frag_total
                        );
                    }
                    _ => {}
                }
                if !self.sessions.contains_key(&from) {
                    let s = SequenceSession::new_at(
                        now,
                        self.time_provider.clone(),
                        &mut *self.engine.rng.lock(),
                    );
                    self.sessions.insert(from, s);
                }
                let session = self.sessions.get_mut(&from).unwrap();
                let responses = session.handle_packet(packet, now);
                for resp in responses {
                    if let Ok(resp_data) = tox_proto::serialize(&resp)
                        && let Err(e) = self.transport.send_raw(from, resp_data)
                    {
                        error!("Failed to send transport packet: {:?}", e);
                    }
                }
                self.process_session_events(from, now);
            }
            Err(e) => {
                error!("Failed to deserialize packet from {:?}: {}", from, e);
            }
        }
    }

    fn process_session_events(&mut self, peer_pk: PhysicalDevicePk, now: Instant) {
        loop {
            let event = if let Some(session) = self.sessions.get_mut(&peer_pk) {
                session.poll_event()
            } else {
                None
            };

            let event = match event {
                Some(e) => e,
                None => break,
            };

            match event {
                SessionEvent::DataReceived(_, _mtype, payload)
                | SessionEvent::MessageCompleted(_, _mtype, payload) => {
                    tracing::debug!(
                        "Message from {:?}: type={:?}, len={}",
                        peer_pk,
                        _mtype,
                        payload.len()
                    );
                    match tox_proto::deserialize::<ProtocolMessage>(&payload) {
                        Ok(proto_msg) => {
                            match self.engine.handle_message(
                                peer_pk,
                                proto_msg,
                                &self.store,
                                Some(&self.store),
                            ) {
                                Ok(effects) => {
                                    let mut dummy_wakeup = now;
                                    if let Err(e) =
                                        self.process_effects(effects, now, 0, &mut dummy_wakeup)
                                    {
                                        error!("Failed to process engine effects: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Engine failed to handle message from {:?}: {}",
                                        peer_pk, e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to deserialize protocol message from {:?}: {}",
                                peer_pk, e
                            );
                        }
                    }
                }
                SessionEvent::DatagramDelivered(_seq) => {
                    // Application can track delivery for push streams here
                }
                SessionEvent::DatagramLost(_seq) => {
                    // Application can handle loss for push streams here
                }
                SessionEvent::MessageDropped(frag_id) => {
                    debug!("Fragment message dropped (timeout): frag_id={}", frag_id);
                }
                SessionEvent::ReadyToSend => {
                    // Window opened up, could trigger more sends
                }
            }
        }
    }

    /// Background polling for pacing and maintenance.
    /// Returns next scheduled wakeup time.
    pub fn poll(&mut self) -> Instant {
        use std::sync::atomic::Ordering;
        let now = self.time_provider.now_instant();
        let now_ms = self.time_provider.now_system_ms() as u64;
        let mut next_wakeup = now + Duration::from_secs(3600);

        // 1. Poll Engine for background tasks (e.g., CAS swarm requests)
        let engine_phase_start = std::time::Instant::now();
        let engine_effects = match self.engine.poll(now, &self.store, Some(&self.store)) {
            Ok(res) => res,
            Err(e) => {
                error!("Engine poll failed: {}", e);
                Vec::new()
            }
        };

        if let Err(e) = self.process_effects(engine_effects, now, now_ms, &mut next_wakeup) {
            error!("Failed to process poll effects: {}", e);
        }
        self.poll_engine_ns.fetch_add(
            engine_phase_start.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );
        let push_phase_start = std::time::Instant::now();

        // 2. Drive push streams: send BlobData pieces (~1300B each).
        // Round-robin across all active streams so no single stream
        // monopolises the send budget when CC windows are tight.
        // Each iteration takes ONE piece from each stream, sends it,
        // and removes the stream from the active set if it can't
        // produce or send more. This avoids the old pre-drain pattern
        // where 256 pieces were consumed from the PushStream into a
        // Vec but only a fraction sent — wasting credits.
        {
            let mut active_keys: Vec<_> = self.engine.push_streams.keys().cloned().collect();
            let mut rounds = 0usize;
            while !active_keys.is_empty() && rounds < 256 {
                rounds += 1;
                active_keys.retain(|key| {
                    let (blob_hash, peer_pk) = *key;
                    let outgoing_count = match self.sessions.get(&peer_pk) {
                        Some(s) => s.outgoing_count(),
                        None => return false,
                    };
                    if outgoing_count > 2048 {
                        return false;
                    }

                    let stream = match self.engine.push_streams.get_mut(key) {
                        Some(s) => s,
                        None => return false,
                    };
                    if stream.pass_complete() {
                        if stream.all_done() {
                            return false;
                        }
                        stream.reset_pass();
                    }
                    let offset = match stream.next_piece() {
                        Some(o) => o,
                        None => return false,
                    };

                    let blob_size = stream.blob_size;
                    let chunk_end = ((offset / crate::cas::CHUNK_SIZE + 1)
                        * crate::cas::CHUNK_SIZE)
                        .min(blob_size);
                    let remaining_in_chunk = (chunk_end - offset) as usize;
                    let piece_len = crate::cas::MAX_PIECE_DATA.min(remaining_in_chunk);

                    let data_vec = match self.store.get_chunk(&blob_hash, offset, piece_len as u32)
                    {
                        Ok(r) => r,
                        Err(_) => return false,
                    };
                    let data = match tox_proto::BoundedBytes::try_from_vec(data_vec) {
                        Ok(d) => d,
                        Err(_) => return false,
                    };

                    let piece_end = offset + piece_len as u64;
                    let is_last_piece_of_chunk = piece_end >= chunk_end;
                    let proof = if is_last_piece_of_chunk {
                        let chunk_idx = offset / crate::cas::CHUNK_SIZE;
                        let stream = self.engine.push_streams.get(key).unwrap();
                        let proof_vec = stream
                            .tree
                            .as_ref()
                            .map(|t| t.proof_for(chunk_idx as usize))
                            .unwrap_or_default();
                        match tox_proto::BoundedBytes::try_from_vec(proof_vec) {
                            Ok(p) => p,
                            Err(_) => return false,
                        }
                    } else {
                        tox_proto::BoundedBytes::new()
                    };

                    let msg = ProtocolMessage::BlobData(crate::cas::BlobData {
                        hash: blob_hash,
                        offset: tox_proto::Untrusted::new(offset),
                        data,
                        proof,
                    });
                    let mtype = get_message_type(&msg);
                    let Ok(payload) = tox_proto::serialize(&msg) else {
                        return false;
                    };
                    // Fires in debug builds if a chunk-boundary piece
                    // overflows its one-datagram budget. Release builds
                    // still work — tox-sequenced will fragment — but
                    // fragmentation above 4 GiB blobs wastes a packet
                    // per chunk boundary and is worth a loud signal.
                    debug_assert!(
                        payload.len() <= crate::cas::MAX_BLOBDATA_PAYLOAD,
                        "BlobData payload {} exceeds MAX_BLOBDATA_PAYLOAD {} \
                         (chunk-boundary fragmentation); blob likely > 4 GiB, \
                         see cas.rs MAX_PIECE_DATA docs",
                        payload.len(),
                        crate::cas::MAX_BLOBDATA_PAYLOAD,
                    );
                    let session = self.sessions.get_mut(&peer_pk).unwrap();
                    session.send_auto(mtype, &payload, now).is_ok()
                });
            }
        }
        self.poll_push_ns.fetch_add(
            push_phase_start.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );
        let flush_phase_start = std::time::Instant::now();

        // 3. Flush sessions: paced sending from priority queues.
        for (peer_pk, session) in &mut self.sessions {
            let pk = *peer_pk;
            let transport = &self.transport;
            session.flush(
                now,
                now_ms,
                &mut |packet| match tox_proto::serialize(&packet) {
                    Ok(data) => transport.send_raw(pk, data).is_ok(),
                    Err(e) => {
                        error!("Failed to serialize packet for {:?}: {}", pk, e);
                        false
                    }
                },
            );

            let offset = session.clock_offset();
            if offset != 0 {
                self.engine.clock.update_peer_offset(*peer_pk, offset);
            }

            session.cleanup(now);
            let session_wakeup = session.next_wakeup(now);
            next_wakeup = next_wakeup.min(session_wakeup);
        }
        self.poll_flush_ns.fetch_add(
            flush_phase_start.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );

        next_wakeup
    }

    pub fn process_effects(
        &mut self,
        effects: Vec<Effect>,
        now: Instant,
        now_ms: u64,
        next_wakeup: &mut Instant,
    ) -> crate::error::MerkleToxResult<()> {
        for effect in effects {
            self.process_effect(effect, now, now_ms, next_wakeup)?;
        }
        self.engine.clear_pending();
        Ok(())
    }

    pub fn process_effect(
        &mut self,
        effect: Effect,
        now: Instant,
        _now_ms: u64,
        next_wakeup: &mut Instant,
    ) -> crate::error::MerkleToxResult<()> {
        match effect {
            Effect::SendPacket(peer_pk, msg) => {
                if !self.sessions.contains_key(&peer_pk) {
                    let s = SequenceSession::new_at(
                        now,
                        self.time_provider.clone(),
                        &mut *self.engine.rng.lock(),
                    );
                    self.sessions.insert(peer_pk, s);
                }
                let session = self.sessions.get_mut(&peer_pk).unwrap();
                let mtype = get_message_type(&msg);
                if let Ok(payload) = tox_proto::serialize(&msg)
                    && let Err(e) = session.send_auto(mtype, &payload, now)
                {
                    error!("Failed to queue engine message: {:?}", e);
                }
            }
            Effect::WriteStore(cid, node, verified) => {
                self.store.put_node(&cid, node, verified)?;
            }
            Effect::WriteWireNode(cid, hash, node) => {
                self.store.put_wire_node(&cid, &hash, node)?;
            }
            Effect::DeleteWireNode(cid, hash) => {
                self.store.remove_wire_node(&cid, &hash)?;
            }
            Effect::WriteRatchetKey(cid, hash, key, epoch_id) => {
                self.store.put_ratchet_key(&cid, &hash, key, epoch_id)?;
            }
            Effect::DeleteRatchetKey(cid, hash) => {
                self.store.remove_ratchet_key(&cid, &hash)?;
            }
            Effect::UpdateHeads(cid, heads, is_admin) => {
                if is_admin {
                    self.store.set_admin_heads(&cid, heads)?;
                } else {
                    self.store.set_heads(&cid, heads)?;
                }
            }
            Effect::WriteConversationKey(cid, epoch, key) => {
                self.store.put_conversation_key(&cid, epoch, key)?;
            }
            Effect::WriteEpochMetadata(cid, count, time) => {
                self.store.update_epoch_metadata(&cid, count, time)?;
            }
            Effect::WriteBlobInfo(info) => {
                self.store.put_blob_info(info)?;
            }
            Effect::WriteChunk(cid, hash, offset, data, proof) => {
                self.store
                    .put_chunk(&cid, &hash, offset, &data, proof.as_deref())?;
            }
            Effect::EmitEvent(ne) => {
                if let Some(handler) = &self.event_handler {
                    handler.handle_event(ne);
                }
            }
            Effect::ScheduleWakeup(_task, time) => {
                *next_wakeup = (*next_wakeup).min(time);
            }
            Effect::NodeEquivocation {
                conversation_id,
                device_pk,
                seq,
                existing_hash,
                conflicting_hash,
            } => {
                if let Some(handler) = &self.event_handler {
                    handler.handle_event(crate::NodeEvent::EquivocationDetected {
                        conversation_id,
                        device_pk,
                        seq,
                        existing_hash,
                        conflicting_hash,
                    });
                }
            }
            Effect::HistorySnapshotNeeded(cid) => {
                if let Some(handler) = &self.event_handler {
                    handler.handle_event(crate::NodeEvent::HistorySnapshotNeeded {
                        conversation_id: cid,
                    });
                }
            }
        }
        Ok(())
    }

    /// Explicitly sends message to peer.
    pub fn send_message(&mut self, to: PhysicalDevicePk, msg: ProtocolMessage) {
        let now = self.time_provider.now_instant();
        if !self.sessions.contains_key(&to) {
            let s = SequenceSession::new_at(
                now,
                self.time_provider.clone(),
                &mut *self.engine.rng.lock(),
            );
            self.sessions.insert(to, s);
        }
        let session = self.sessions.get_mut(&to).unwrap();
        if let Ok(payload) = tox_proto::serialize(&msg)
            && let Err(e) = session.send_auto(get_message_type(&msg), &payload, now)
        {
            error!("Failed to queue explicit message: {:?}", e);
        }
    }

    /// Updates peer availability.
    pub fn set_peer_available(&mut self, peer: PhysicalDevicePk, available: bool) {
        if !available {
            self.sessions.remove(&peer);
        }
        self.engine.set_peer_reachable(peer, available);
    }
}

fn get_message_type(msg: &ProtocolMessage) -> MessageType {
    match msg {
        ProtocolMessage::CapsAnnounce { .. } => MessageType::CapsAnnounce,
        ProtocolMessage::CapsAck { .. } => MessageType::CapsAck,
        ProtocolMessage::SyncHeads(_) => MessageType::SyncHeads,
        ProtocolMessage::FetchBatchReq(_) => MessageType::FetchBatchReq,
        ProtocolMessage::MerkleNode { .. } => MessageType::MerkleNode,
        ProtocolMessage::BlobQuery(_) => MessageType::BlobQuery,
        ProtocolMessage::BlobAvail(_) => MessageType::BlobAvail,
        ProtocolMessage::BlobReq(_) => MessageType::BlobReq,
        ProtocolMessage::BlobData(_) => MessageType::BlobData,
        ProtocolMessage::BlobFetch(_) => MessageType::BlobFetch,
        ProtocolMessage::BlobProgress(_) => MessageType::BlobProgress,
        ProtocolMessage::BlobCancel(_) => MessageType::BlobCancel,
        ProtocolMessage::SyncSketch(_) => MessageType::SyncSketch,
        ProtocolMessage::SyncReconFail { .. } => MessageType::SyncReconFail,
        ProtocolMessage::SyncShardChecksums { .. } => MessageType::SyncShardChecksums,
        ProtocolMessage::SyncRateLimited { .. } => MessageType::SyncRateLimited,
        ProtocolMessage::KeywrapAck { .. } => MessageType::KeywrapAck,
        ProtocolMessage::ReconPowChallenge { .. } => MessageType::ReconPowChallenge,
        ProtocolMessage::ReconPowSolution { .. } => MessageType::ReconPowSolution,
        ProtocolMessage::ReinclusionRequest { .. } => MessageType::ReinclusionRequest,
        ProtocolMessage::ReinclusionResponse { .. } => MessageType::ReinclusionResponse,
        ProtocolMessage::HandshakeError { .. } => MessageType::HandshakeError,
        ProtocolMessage::AdminGossip { .. } => MessageType::AdminGossip,
        // `Unknown` is purely a receive-side catch-all; we never
        // construct one to send. If this fires, a caller
        // round-tripped an unknown variant through our send path
        // (which would re-emit the original wire bytes correctly,
        // but we still want to flag the unusual flow rather than
        // silently classify it as a known tier).
        ProtocolMessage::Unknown { discriminant, .. } => unreachable!(
            "ProtocolMessage::Unknown(discriminant={discriminant}) reached the send \
             classifier — Unknown is a receive-only catch-all and must not be \
             round-tripped through the local send path."
        ),
    }
}
