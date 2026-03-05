use crate::clock::TimeProvider;
use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use crate::engine::{Effect, MerkleToxEngine};
use crate::sync::{BlobStore, NodeStore};
use crate::{NodeEventHandler, ProtocolMessage, Transport};
use std::collections::HashMap;
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
    pub retransmit_count: u64,
}

/// Transport-agnostic Merkle-Tox node orchestrating engine, reliability, and storage.
pub struct MerkleToxNode<T: Transport, S: NodeStore + BlobStore> {
    pub engine: MerkleToxEngine,
    pub transport: T,
    pub store: S,
    pub sessions: HashMap<PhysicalDevicePk, SequenceSession>,
    pub time_provider: Arc<dyn TimeProvider>,
    pub event_handler: Option<Arc<dyn NodeEventHandler>>,
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
                        rtt: s.current_rto(), // UI approximation
                        retransmit_count: s.retransmit_count(),
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
            sessions: HashMap::new(),
            time_provider,
            event_handler: None,
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
                    Packet::Data { message_id, .. } => {
                        tracing::debug!(
                            "Received DATA packet from {:?}: msg_id={}",
                            from,
                            message_id
                        );
                    }
                    Packet::Ack(ack) => {
                        tracing::debug!(
                            "Received ACK packet from {:?}: msg_id={}",
                            from,
                            ack.message_id
                        );
                    }
                    Packet::Nack(nack) => {
                        tracing::debug!(
                            "Received NACK packet from {:?}: msg_id={}",
                            from,
                            nack.message_id
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
                if !responses.is_empty() {
                    tracing::debug!("Generated {} responses to {:?}", responses.len(), from);
                }
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

            if let SessionEvent::MessageCompleted(_id, _mtype, payload) = event {
                tracing::debug!(
                    "Message completed from {:?}: type={:?}, len={}",
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
                                tracing::debug!("Engine generated {} effects", effects.len());
                                let mut dummy_wakeup = now;
                                if let Err(e) =
                                    self.process_effects(effects, now, 0, &mut dummy_wakeup)
                                {
                                    error!("Failed to process engine effects: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Engine failed to handle message from {:?}: {}", peer_pk, e);
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
        }
    }

    /// Background polling for retransmissions and pacing.
    /// Returns next scheduled wakeup time.
    pub fn poll(&mut self) -> Instant {
        let now = self.time_provider.now_instant();
        let now_ms = self.time_provider.now_system_ms() as u64;
        let mut next_wakeup = now + Duration::from_secs(3600);

        // 1. Poll Engine for background tasks (e.g., CAS swarm requests)
        let engine_effects = match self.engine.poll(now, &self.store) {
            Ok(res) => res,
            Err(e) => {
                error!("Engine poll failed: {}", e);
                Vec::new()
            }
        };

        if let Err(e) = self.process_effects(engine_effects, now, now_ms, &mut next_wakeup) {
            error!("Failed to process poll effects: {}", e);
        }

        // 2. Poll Sessions for outgoing packets
        for (peer_pk, session) in &mut self.sessions {
            let pk = *peer_pk;
            let transport = &self.transport;
            session.flush_packets(
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

            // Update consensus clock offset from transport PING/PONG.
            let offset = session.clock_offset();
            if offset != 0 {
                self.engine.clock.update_peer_offset(*peer_pk, offset);
            }

            session.cleanup(now);
            let session_wakeup = session.next_wakeup(now);
            if session_wakeup <= now {
                debug!(
                    "Transport session for {:?} requesting immediate wakeup",
                    peer_pk
                );
            }
            next_wakeup = next_wakeup.min(session_wakeup);
        }

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
                    && let Err(e) = session.send_message(mtype, &payload, now)
                {
                    error!("Failed to queue engine message: {:?}", e);
                    // Transport queuing failure is usually non-fatal for DAG state.
                    // Execution continues after logging.
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
            Effect::NodeEquivocation { .. } => {
                // Equivocation events are informational; no store action needed.
            }
            Effect::HistorySnapshotNeeded(_cid) => {
                // Application-layer trigger: caller should compile history snapshot,
                // encrypt, upload to CAS, and call author_history_key_export().
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
            && let Err(e) = session.send_message(get_message_type(&msg), &payload, now)
        {
            error!("Failed to queue explicit message: {:?}", e);
        }
    }

    /// Updates peer availability.
    /// Removes transient reliability session when peer goes offline.
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
    }
}
