use crate::SessionEvent;
use crate::bitset::BitSet;
use crate::congestion::{Algorithm, AlgorithmType, CongestionControl};
use crate::error::SequencedError;
use crate::flat_map::FlatMap;
use crate::outgoing::OutgoingMessage;
use crate::protocol::{
    self, ESTIMATED_PAYLOAD_SIZE, FragmentCount, FragmentIndex, MAX_CONCURRENT_INCOMING,
    MAX_CONCURRENT_OUTGOING, MAX_TOX_PACKET_SIZE, MessageId, MessageType, Packet, Priority,
    REASSEMBLY_TIMEOUT_SECS, SelectiveAck, TimestampMs,
};
use crate::quota::ReassemblyQuota;
use crate::reassembly::MessageReassembler;
use crate::rtt::RttEstimator;
use crate::scheduler::PriorityScheduler;
use crate::time::TimeProvider;
use std::cmp;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;
use tracing::{debug, warn};

pub const PING_INTERVAL_IDLE: Duration = Duration::from_secs(60);
pub const PING_INTERVAL_ACTIVE: Duration = Duration::from_secs(10);
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const FAIR_SHARE_GUARANTEE: usize = 16 * 1024; // 16KB per peer guaranteed

/// A reliable synchronization session with a specific peer.
#[derive(ToxProto)]
pub struct SequenceSession<C: CongestionControl = Algorithm> {
    next_message_id: MessageId,
    outgoing: FlatMap<MessageId, OutgoingMessage>,
    incoming: FlatMap<MessageId, MessageReassembler>,
    /// Shared memory quota for reassembly across all sessions.
    pub quota: ReassemblyQuota,
    /// Maximum memory allowed for this specific session.
    pub max_per_session: usize,
    /// Total bytes currently buffered in all incoming reassemblers for this session.
    incoming_buffer_size: usize,
    /// Stores the final state of recently completed messages to send final ACKs.
    completed_incoming: FlatMap<MessageId, (SelectiveAck, Instant)>,
    /// Pending ACKs: message_id -> (count_since_last_ack, first_pending_at)
    pending_acks: FlatMap<MessageId, (usize, Instant)>,
    /// Pending NACKs: message_id -> first_observed_at
    pending_nacks: FlatMap<MessageId, Instant>,
    /// Queue for outbound unreliable datagrams.
    datagram_queue: VecDeque<Packet>,
    /// Scheduler for fair sharing between concurrent messages.
    scheduler: PriorityScheduler,
    events: VecDeque<SessionEvent>,
    rtt: RttEstimator,
    congestion_control: C,
    in_flight: usize,
    /// Receiver's advertised window (in bytes).
    peer_rwnd: usize,
    delivered_bytes: usize,
    last_delivery_time: Instant,
    last_ping: Instant,
    last_ping_sent: Option<Instant>,
    last_activity: Instant,
    next_pacing_time: Instant,
    last_rwnd_probe: Instant,
    zero_window_probes_sent: u32,
    last_emitted_cwnd: usize,
    app_limited: bool,
    highest_received_id: Option<MessageId>,
    time_provider: Arc<dyn TimeProvider>,
    retransmit_count: u64,
    /// Estimated clock offset to the peer (ms).
    clock_offset: i64,
    rng: rand::rngs::StdRng,
}

impl SequenceSession<Algorithm> {
    pub fn new(time_provider: Arc<dyn TimeProvider>, rng: &mut dyn rand::RngCore) -> Self {
        Self::new_at(time_provider.now_instant(), time_provider, rng)
    }

    pub fn new_at(
        now: Instant,
        time_provider: Arc<dyn TimeProvider>,
        rng: &mut dyn rand::RngCore,
    ) -> Self {
        Self::with_quota_at(
            ReassemblyQuota::new(crate::protocol::MAX_TOTAL_REASSEMBLY_BUFFER),
            now,
            time_provider,
            rng,
        )
    }

    pub fn with_quota_at(
        quota: ReassemblyQuota,
        now: Instant,
        time_provider: Arc<dyn TimeProvider>,
        rng: &mut dyn rand::RngCore,
    ) -> Self {
        use rand::SeedableRng;
        let cc_rng = rand::rngs::StdRng::seed_from_u64(rng.next_u64());
        let session_rng = rand::rngs::StdRng::seed_from_u64(rng.next_u64());
        Self::with_congestion_control_and_quota_at(
            Algorithm::new(AlgorithmType::Aimd, cc_rng),
            quota,
            now,
            time_provider,
            session_rng,
        )
    }
}

impl<C: CongestionControl> SequenceSession<C> {
    fn calculate_priority(
        message_type: Option<MessageType>,
        total_fragments: FragmentCount,
        size_est: usize,
    ) -> Priority {
        if let Some(mtype) = message_type {
            let prio = mtype.priority();
            if prio == Priority::Critical {
                return Priority::Critical;
            }
        }

        if total_fragments.0 == 1 {
            return Priority::Standard;
        }

        match message_type {
            Some(mtype) => mtype.priority(),
            None => {
                if size_est < 32 * 1024 {
                    Priority::Standard
                } else {
                    Priority::Bulk
                }
            }
        }
    }

    pub fn with_congestion_control_at(
        congestion_control: C,
        now: Instant,
        time_provider: Arc<dyn TimeProvider>,
        rng: &mut dyn rand::RngCore,
    ) -> Self {
        use rand::SeedableRng;
        let session_rng = rand::rngs::StdRng::seed_from_u64(rng.next_u64());
        Self::with_congestion_control_and_quota_at(
            congestion_control,
            ReassemblyQuota::new(crate::protocol::MAX_TOTAL_REASSEMBLY_BUFFER),
            now,
            time_provider,
            session_rng,
        )
    }

    pub fn with_congestion_control_and_quota_at(
        congestion_control: C,
        quota: ReassemblyQuota,
        now: Instant,
        time_provider: Arc<dyn TimeProvider>,
        mut rng: rand::rngs::StdRng,
    ) -> Self {
        use rand::RngCore;
        let next_message_id = MessageId(rng.next_u32());
        Self {
            next_message_id,
            outgoing: FlatMap::new(),
            incoming: FlatMap::new(),
            quota: quota.clone(),
            max_per_session: crate::protocol::MAX_TOTAL_REASSEMBLY_BUFFER,
            incoming_buffer_size: 0,
            completed_incoming: FlatMap::new(),
            pending_acks: FlatMap::new(),
            pending_nacks: FlatMap::new(),
            datagram_queue: VecDeque::new(),
            scheduler: PriorityScheduler::new(),
            events: VecDeque::new(),
            rtt: RttEstimator::new(),
            congestion_control,
            in_flight: 0,
            peer_rwnd: crate::protocol::MAX_TOTAL_REASSEMBLY_BUFFER,
            delivered_bytes: 0,
            last_delivery_time: now,
            last_ping: now - CONNECTION_TIMEOUT,
            last_ping_sent: None,
            last_activity: now,
            next_pacing_time: now,
            last_rwnd_probe: now,
            zero_window_probes_sent: 0,
            last_emitted_cwnd: 0,
            app_limited: true,
            highest_received_id: None,
            time_provider: time_provider.clone(),
            retransmit_count: 0,
            clock_offset: 0,
            rng,
        }
    }

    pub fn next_message_id(&self) -> MessageId {
        self.next_message_id
    }

    pub fn set_quota(&mut self, quota: ReassemblyQuota) {
        self.quota = quota;
        if self.incoming_buffer_size > 0 {
            self.quota.reserve_guaranteed(self.incoming_buffer_size);
        }
    }

    pub fn set_time_provider(&mut self, time_provider: Arc<dyn TimeProvider>) {
        self.time_provider = time_provider;
    }

    pub fn send_message(
        &mut self,
        message_type: MessageType,
        data: &[u8],
        now: Instant,
    ) -> Result<MessageId, SequencedError> {
        self.send_message_at(message_type, data, now)
    }

    pub fn send_message_at(
        &mut self,
        message_type: MessageType,
        data: &[u8],
        now: Instant,
    ) -> Result<MessageId, SequencedError> {
        if self.outgoing.len() >= MAX_CONCURRENT_OUTGOING {
            return Err(SequencedError::QueueFull);
        }

        let mut id = self.next_message_id;
        for _ in 0..MAX_CONCURRENT_OUTGOING {
            if !self.outgoing.contains_key(&id) {
                break;
            }
            id = id.wrapping_add(1);
        }

        if self.outgoing.contains_key(&id) {
            return Err(SequencedError::QueueFull);
        }

        self.next_message_id = id.wrapping_add(1);

        let envelope = protocol::OutboundEnvelope {
            message_type,
            payload: data,
        };

        let full_payload = protocol::serialize(&envelope)
            .map_err(|e| SequencedError::SerializationError(e.to_string()))?;

        if full_payload.len() > protocol::MAX_MESSAGE_SIZE {
            return Err(SequencedError::MessageTooLarge);
        }

        let payload_mtu = MAX_TOX_PACKET_SIZE.saturating_sub(crate::protocol::PACKET_OVERHEAD);
        if payload_mtu == 0 {
            return Err(SequencedError::MessageTooLarge);
        }

        let msg = OutgoingMessage::new(message_type, full_payload, payload_mtu, now)?;

        self.scheduler
            .update_message(id.0, message_type.priority() as u8);
        self.outgoing.insert(id, msg);
        Ok(id)
    }

    pub fn set_message_timeout(&mut self, message_id: MessageId, timeout: Duration) {
        if let Some(msg) = self.outgoing.get_mut(&message_id) {
            msg.timeout = timeout;
        }
    }

    pub fn send_datagram(
        &mut self,
        message_type: MessageType,
        data: &[u8],
    ) -> Result<(), SequencedError> {
        if self.datagram_queue.len() >= protocol::MAX_DATAGRAM_QUEUE {
            return Err(SequencedError::QueueFull);
        }

        let overhead = 10;
        if data.len() + overhead > MAX_TOX_PACKET_SIZE {
            return Err(SequencedError::MessageTooLarge);
        }

        self.datagram_queue.push_back(Packet::Datagram {
            message_type,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn check_cwnd_change(&mut self) {
        let cwnd = self.congestion_control.cwnd();
        let threshold = (self.last_emitted_cwnd as f32 * 0.1).max(1.0) as usize;
        let abs_diff = cwnd.abs_diff(self.last_emitted_cwnd);

        if abs_diff >= threshold || self.last_emitted_cwnd == 0 {
            self.events
                .push_back(SessionEvent::CongestionWindowChanged(cwnd));
            self.last_emitted_cwnd = cwnd;
        }
    }

    pub fn handle_packet(&mut self, packet: Packet, now: Instant) -> Vec<Packet> {
        self.last_activity = now;
        let replies = self.handle_packet_internal(packet, now);
        self.check_cwnd_change();
        replies
    }

    fn handle_packet_internal(&mut self, packet: Packet, now: Instant) -> Vec<Packet> {
        let mut responses = Vec::new();

        match packet {
            Packet::Data {
                message_id,
                fragment_index,
                total_fragments,
                data,
            } => {
                self.handle_data_packet(
                    message_id,
                    fragment_index,
                    total_fragments,
                    data,
                    now,
                    &mut responses,
                );
            }
            Packet::Ack(ack) => self.handle_ack_packet(ack, now),
            Packet::Nack(nack) => self.handle_nack_packet(nack, now),
            Packet::Ping { t1 } => {
                use rand::Rng;
                let jitter = self.rng.r#gen_range(-5..=5);
                let now_ms = self.time_provider.now_system_ms();
                let t2 = TimestampMs(now_ms + jitter);
                let t3 = TimestampMs(now_ms + jitter);
                responses.push(Packet::Pong { t1, t2, t3 });
            }
            Packet::Pong { t1, t2, t3 } => {
                let t4 = self.time_provider.now_system_ms();
                if let Some(sent_time) = self.last_ping_sent.take() {
                    let rtt_sample = now.saturating_duration_since(sent_time);
                    self.rtt.update(rtt_sample);
                    self.clock_offset = ((t2.0 - t1.0) + (t3.0 - t4)) / 2;
                    self.congestion_control
                        .on_ack(rtt_sample, None, 0, self.in_flight, now);
                }
            }
            Packet::Datagram { message_type, data } => {
                self.events.push_back(SessionEvent::MessageCompleted(
                    MessageId(0),
                    message_type,
                    data,
                ));
            }
        }

        responses
    }

    fn handle_data_packet(
        &mut self,
        message_id: MessageId,
        fragment_index: FragmentIndex,
        total_fragments: FragmentCount,
        data: Vec<u8>,
        now: Instant,
        responses: &mut Vec<Packet>,
    ) {
        if self.check_completed_message(message_id, responses) {
            return;
        }

        if self.is_ancient_message(message_id) {
            return;
        }

        let mut peeked_type = None;
        if fragment_index.0 == 0 {
            peeked_type = peek_message_type(&data);
        }

        if !self.ensure_reassembler(
            message_id,
            peeked_type,
            total_fragments,
            data.len(),
            now,
            responses,
        ) {
            return;
        }

        self.process_fragment(message_id, fragment_index, data, now, responses);
    }

    fn check_completed_message(&self, message_id: MessageId, responses: &mut Vec<Packet>) -> bool {
        if let Some((ack, _)) = self.completed_incoming.get(&message_id) {
            let mut ack = ack.clone();
            ack.rwnd = self.current_rwnd();
            responses.push(Packet::Ack(ack));
            true
        } else {
            false
        }
    }

    fn is_ancient_message(&self, message_id: MessageId) -> bool {
        if let Some(highest) = self.highest_received_id {
            let diff = message_id.wrapping_sub(highest);
            if diff > 0x80000000 {
                let offset = highest.wrapping_sub(message_id);
                if offset >= crate::protocol::MAX_COMPLETED_INCOMING as u32 {
                    return true;
                }
                if !self.incoming.contains_key(&message_id)
                    && !self.completed_incoming.contains_key(&message_id)
                    && offset > 32
                {
                    return true;
                }
            } else if diff == 0
                && !self.incoming.contains_key(&message_id)
                && !self.completed_incoming.contains_key(&message_id)
            {
                return true;
            }
        }
        false
    }

    fn ensure_reassembler(
        &mut self,
        message_id: MessageId,
        message_type: Option<MessageType>,
        total_fragments: FragmentCount,
        data_len: usize,
        now: Instant,
        responses: &mut Vec<Packet>,
    ) -> bool {
        if let Some(entry) = self.incoming.get_mut(&message_id) {
            if let Some(mtype) = message_type {
                entry.priority =
                    Self::calculate_priority(Some(mtype), total_fragments, entry.reserved_bytes);
            }
            return entry.total_fragments == total_fragments;
        }

        if self.incoming.len() >= MAX_CONCURRENT_INCOMING {
            responses.push(self.create_rejection_ack(message_id));
            return false;
        }

        let initial_reservation = if total_fragments.0 > 1 {
            (data_len.max(ESTIMATED_PAYLOAD_SIZE)) * (total_fragments.0 as usize)
        } else {
            data_len
        };

        let priority = Self::calculate_priority(message_type, total_fragments, initial_reservation);
        let is_fair_share = self.incoming_buffer_size + initial_reservation <= FAIR_SHARE_GUARANTEE;

        let reserved = if is_fair_share {
            self.quota.reserve_guaranteed(initial_reservation)
        } else {
            self.quota.reserve(initial_reservation, priority)
        };

        if !reserved || self.incoming_buffer_size + initial_reservation > self.max_per_session {
            if reserved {
                self.quota.release(initial_reservation);
            }
            responses.push(self.create_rejection_ack(message_id));
            return false;
        }

        match MessageReassembler::new(
            message_id,
            total_fragments,
            priority,
            initial_reservation,
            now,
        ) {
            Ok(re) => {
                self.incoming_buffer_size += initial_reservation;
                self.incoming.insert(message_id, re);
                if self
                    .highest_received_id
                    .is_none_or(|h| message_id.wrapping_sub(h) < 0x80000000)
                {
                    self.highest_received_id = Some(message_id);
                }
                true
            }
            Err(_) => {
                self.quota.release(initial_reservation);
                responses.push(self.create_rejection_ack(message_id));
                false
            }
        }
    }

    fn process_fragment(
        &mut self,
        message_id: MessageId,
        fragment_index: FragmentIndex,
        data: Vec<u8>,
        now: Instant,
        responses: &mut Vec<Packet>,
    ) {
        let entry = self.incoming.get_mut(&message_id).unwrap();
        let priority = entry.priority;

        match entry.add_fragment(fragment_index, data, now) {
            Ok(complete) => {
                let base_idx = entry.buffer.base_index();
                if fragment_index.0 > base_idx.0 + 30 {
                    self.pending_nacks
                        .insert(message_id, now - Duration::from_secs(1));
                } else if fragment_index.0 > base_idx.0 {
                    self.pending_nacks.entry(message_id).or_insert(now);
                }

                let new_planned = entry.planned_total_size();
                if new_planned != entry.reserved_bytes {
                    if new_planned > entry.reserved_bytes {
                        let addition = new_planned - entry.reserved_bytes;
                        let is_fair_share =
                            self.incoming_buffer_size + addition <= FAIR_SHARE_GUARANTEE;

                        let reserved = if is_fair_share {
                            self.quota.reserve_guaranteed(addition)
                        } else {
                            self.quota.reserve(addition, priority)
                        };

                        if !reserved || self.incoming_buffer_size + addition > self.max_per_session
                        {
                            if reserved {
                                self.quota.release(addition);
                            }
                            if let Some(reassembler) = self.incoming.remove(&message_id) {
                                self.incoming_buffer_size -= reassembler.reserved_bytes;
                                self.quota.release(reassembler.reserved_bytes);
                                responses.push(self.create_rejection_ack(message_id));
                            }
                            return;
                        }
                        self.incoming_buffer_size += addition;
                        entry.reserved_bytes = new_planned;
                    } else {
                        let reduction = entry.reserved_bytes - new_planned;
                        self.quota.release(reduction);
                        self.incoming_buffer_size -= reduction;
                        entry.reserved_bytes = new_planned;
                    }
                }

                if complete {
                    self.pending_nacks.remove(&message_id);
                    if let Some(reassembler) = self.incoming.remove(&message_id) {
                        self.incoming_buffer_size -= reassembler.reserved_bytes;
                        self.quota.release(reassembler.reserved_bytes);

                        let current_rwnd = self.current_rwnd();
                        let ack = reassembler.create_ack(current_rwnd);

                        if let Some(assembled) = reassembler.assemble() {
                            match protocol::deserialize::<protocol::InboundEnvelope>(&assembled) {
                                Ok(envelope) => {
                                    self.events.push_back(SessionEvent::MessageCompleted(
                                        message_id,
                                        envelope.message_type,
                                        envelope.payload,
                                    ));
                                    self.completed_incoming.insert(message_id, (ack, now));

                                    if self.completed_incoming.len()
                                        > protocol::MAX_COMPLETED_INCOMING
                                    {
                                        let oldest_id =
                                            *self.completed_incoming.keys().next().unwrap();
                                        self.completed_incoming.remove(&oldest_id);
                                    }
                                    self.pending_acks.insert(message_id, (2, now));
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize message {}: {}", message_id, e);
                                    self.completed_incoming.insert(message_id, (ack, now));
                                    if self.completed_incoming.len()
                                        > protocol::MAX_COMPLETED_INCOMING
                                    {
                                        let oldest_id =
                                            *self.completed_incoming.keys().next().unwrap();
                                        self.completed_incoming.remove(&oldest_id);
                                    }
                                    self.pending_acks.insert(message_id, (2, now));
                                }
                            }
                        }
                    }
                } else {
                    let entry = self.pending_acks.entry(message_id).or_insert((0, now));
                    entry.0 += 1;
                }
            }
            Err(_) => {
                if let Some(r) = self.incoming.remove(&message_id) {
                    self.incoming_buffer_size -= r.reserved_bytes;
                    self.quota.release(r.reserved_bytes);
                }
            }
        }
    }

    fn create_rejection_ack(&self, message_id: MessageId) -> Packet {
        let rwnd = self.current_rwnd();
        Packet::Ack(protocol::SelectiveAck {
            message_id,
            base_index: FragmentIndex(0),
            bitmask: 0,
            rwnd,
        })
    }

    fn handle_ack_packet(&mut self, ack: SelectiveAck, now: Instant) {
        let SelectiveAck {
            message_id,
            base_index,
            bitmask,
            rwnd,
        } = ack;

        let rwnd_bytes = rwnd.0 as usize * ESTIMATED_PAYLOAD_SIZE;
        if rwnd_bytes >= ESTIMATED_PAYLOAD_SIZE {
            self.zero_window_probes_sent = 0;
        }
        self.peer_rwnd = rwnd_bytes;

        let mut newly_delivered_bytes = 0;
        let mut message_fully_acked = false;
        let mut ack_res = None;

        if let Some(msg) = self.outgoing.get_mut(&message_id) {
            let res = msg.on_ack(base_index, bitmask, now, self.delivered_bytes);
            newly_delivered_bytes = res.newly_delivered_bytes;
            self.delivered_bytes += res.newly_delivered_bytes;
            if res.newly_delivered_bytes > 0 {
                self.last_delivery_time = now;
            }
            self.in_flight = self
                .in_flight
                .saturating_sub(res.newly_completed_in_flight_bytes);

            if res.loss_detected {
                self.congestion_control.on_nack(now);
            }
            if msg.all_acked() {
                message_fully_acked = true;
            }
            ack_res = Some(res);
        }

        if let Some(res) = ack_res {
            let final_delivery_sample = res.delivery_sample.map(
                |(delivered_at_send, delivery_time_at_send, _, app_limited)| {
                    crate::congestion::DeliverySample {
                        bytes_delivered: self.delivered_bytes - delivered_at_send,
                        duration: now.saturating_duration_since(delivery_time_at_send),
                        now,
                        app_limited,
                    }
                },
            );

            if let Some(min_rtt) = res.min_rtt {
                self.rtt.update(min_rtt);
            }

            let rtt_to_report = res.first_rtt.unwrap_or_else(|| self.rtt.srtt());
            self.congestion_control.on_ack(
                rtt_to_report,
                final_delivery_sample,
                newly_delivered_bytes,
                self.in_flight,
                now,
            );
        } else {
            self.congestion_control
                .on_ack(self.rtt.srtt(), None, 0, self.in_flight, now);
        }

        if message_fully_acked {
            self.events
                .push_back(SessionEvent::MessageAcked(message_id));
            self.scheduler.remove_message(message_id.0);
            self.outgoing.remove(&message_id);
            self.events.push_back(SessionEvent::ReadyToSend);
        }
    }

    fn handle_nack_packet(&mut self, nack: crate::protocol::Nack, now: Instant) {
        if let Some(msg) = self.outgoing.get_mut(&nack.message_id) {
            let mut nack_triggered = false;
            let mut to_remove_nack = BitSet::<{ crate::protocol::BITSET_WORDS }>::new();
            let mut nack_needs_cleanup = false;

            for &idx in &nack.missing_indices {
                if !msg.is_acked(idx) {
                    let state = &mut msg.fragment_states[idx.0 as usize];
                    if state.last_sent.take().is_some() {
                        self.in_flight = self.in_flight.saturating_sub(msg.fragment_len(idx));
                        if to_remove_nack.set(idx.0 as usize) {
                            nack_needs_cleanup = true;
                        }
                    }
                    if !msg.retransmit_bitset.get(idx.0 as usize) {
                        msg.retransmit_queue.push_back(idx);
                        msg.retransmit_bitset.set(idx.0 as usize);
                    }
                    nack_triggered = true;
                }
            }

            if nack_needs_cleanup {
                msg.in_flight_queue
                    .retain(|(idx, _)| !to_remove_nack.get(idx.0 as usize));
            }

            if nack_triggered {
                self.congestion_control.on_nack(now);
            }
        }
    }

    pub fn next_check_time(&self) -> Instant {
        let mut min_time = self
            .next_pacing_time
            .min(self.last_ping + PING_INTERVAL_ACTIVE);

        if self.peer_rwnd < ESTIMATED_PAYLOAD_SIZE {
            let probe_delay = self.rtt.rto_with_backoff(self.zero_window_probes_sent);
            min_time = min_time.min(self.last_rwnd_probe + probe_delay);
        }

        for (count, first_pending_at) in self.pending_acks.values() {
            if *count < 2 {
                min_time = min_time.min(*first_pending_at + crate::protocol::DELAYED_ACK_TIMEOUT);
            } else {
                return self.last_activity;
            }
        }

        for msg in self.outgoing.values() {
            if let Some((idx, last_sent)) = msg.in_flight_queue.front() {
                let state = &msg.fragment_states[idx.0 as usize];
                let retries = state.rto_backoff;
                let current_rto = self.rtt.rto_with_backoff(retries);
                min_time = min_time.min(*last_sent + current_rto);
            }
            if !msg.retransmit_queue.is_empty() || msg.next_fragment.0 < msg.num_fragments.0 {
                min_time = min_time.min(self.next_pacing_time);
            }
        }

        min_time
    }

    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut next = now + Duration::from_secs(3600);

        if self.next_pacing_time > now {
            next = next.min(self.next_pacing_time);
        } else {
            if !self.datagram_queue.is_empty() {
                return now;
            }

            let cwnd = self.congestion_control.cwnd();
            if self.in_flight < cwnd * ESTIMATED_PAYLOAD_SIZE {
                let has_retransmit = self
                    .outgoing
                    .values()
                    .any(|m| !m.retransmit_queue.is_empty());

                if has_retransmit {
                    // Oldest hole bypasses peer_rwnd in poll() if it's the first in burst,
                    // so we return now.
                    return now;
                }

                for msg in self.outgoing.values() {
                    if msg.next_fragment.0 < msg.num_fragments.0 {
                        let fragment_len = msg.fragment_len(msg.next_fragment);
                        if self.in_flight + fragment_len <= self.peer_rwnd {
                            return now;
                        }
                    }
                }
            }
        }

        let rto_est = self.rtt.rto();
        for msg in self.outgoing.values() {
            if let Some(&(idx, last_sent)) = msg.in_flight_queue.front() {
                let state = &msg.fragment_states[idx.0 as usize];
                if state.last_sent.is_none_or(|s| s <= last_sent) {
                    let retries = state.rto_backoff;
                    let current_rto = rto_est * (1 << 6.min(retries));
                    next = next.min(last_sent + current_rto);
                }
            }
        }

        if self.in_flight > 0 {
            let srtt = self.rtt.srtt();
            let tlp_threshold = srtt.mul_f32(1.5).max(Duration::from_millis(10));
            for msg in self.outgoing.values() {
                if let Some(&(idx, last_sent)) = msg.in_flight_queue.back() {
                    let state = &msg.fragment_states[idx.0 as usize];
                    if state.last_sent.is_none_or(|s| s <= last_sent) {
                        next = next.min(last_sent + tlp_threshold);
                    }
                }
            }
        }

        if self.peer_rwnd < ESTIMATED_PAYLOAD_SIZE && !self.outgoing.is_empty() {
            let probe_delay = self.rtt.rto_with_backoff(self.zero_window_probes_sent);
            let probe_at = self.last_rwnd_probe + probe_delay;
            next = next.min(probe_at.max(self.next_pacing_time));
        }

        for (_, (count, pending_at)) in self.pending_acks.iter() {
            let timeout = *pending_at + crate::protocol::DELAYED_ACK_TIMEOUT;
            if *count >= 2 || timeout <= now {
                return now;
            }
            next = next.min(timeout);
        }
        for (_, pending_at) in self.pending_nacks.iter() {
            let nack_delay = (self.rtt.srtt() / 4).max(Duration::from_millis(10));
            let timeout = *pending_at + nack_delay;
            if timeout <= now {
                return now;
            }
            next = next.min(timeout);
        }

        let is_active = !self.outgoing.is_empty() || !self.incoming.is_empty();
        let ping_interval = if is_active {
            PING_INTERVAL_ACTIVE
        } else {
            PING_INTERVAL_IDLE
        };

        next = next.min(self.last_ping + ping_interval);
        next = next.min(self.last_activity + CONNECTION_TIMEOUT);

        next.max(now)
    }

    pub fn get_packets_to_send(&mut self, now: Instant, now_ms: u64) -> Vec<Packet> {
        let mut packets = Vec::new();
        self.flush_packets(now, now_ms, &mut |p| {
            packets.push(p);
            true
        });
        packets
    }

    /// Push-model packet sending with inline failure handling.
    ///
    /// For each packet that needs to be sent, calls `sender(packet)`. If the sender
    /// returns `true`, the session state is updated to reflect successful delivery.
    /// If the sender returns `false` (e.g., transport SENDQ full), the session stops
    /// producing packets and leaves internal state consistent: `in_flight` only
    /// increments for packets that were actually accepted by the transport.
    pub fn flush_packets<F>(&mut self, now: Instant, now_ms: u64, sender: &mut F)
    where
        F: FnMut(Packet) -> bool,
    {
        let is_active = !self.outgoing.is_empty() || !self.incoming.is_empty();
        let ping_interval = if is_active {
            PING_INTERVAL_ACTIVE
        } else {
            PING_INTERVAL_IDLE
        };

        // Ping
        if now.saturating_duration_since(self.last_ping) >= ping_interval {
            let packet = Packet::Ping {
                t1: TimestampMs(now_ms as i64),
            };
            if sender(packet) {
                self.last_ping = now;
                self.last_ping_sent = Some(now);
                self.last_activity = now;
            }
        }

        // Datagrams
        while self.datagram_queue.front().is_some() {
            if now < self.next_pacing_time {
                break;
            }
            let dg_len = if let Some(Packet::Datagram { data, .. }) = self.datagram_queue.front() {
                data.len() + 10
            } else {
                0
            };
            let dg = self.datagram_queue.pop_front().unwrap();
            if !sender(dg) {
                break;
            }
            self.last_activity = now;
            let pacing_rate = self.congestion_control.pacing_rate();
            let gap_secs = if pacing_rate > 0.0 && pacing_rate.is_finite() {
                (dg_len as f32 / pacing_rate).min(1.0)
            } else {
                0.0
            };
            self.next_pacing_time =
                self.next_pacing_time.max(now) + Duration::from_secs_f32(gap_secs);
        }

        // Zero-window probe
        if self.peer_rwnd < ESTIMATED_PAYLOAD_SIZE && !self.outgoing.is_empty() {
            let probe_delay = self.rtt.rto_with_backoff(self.zero_window_probes_sent);
            if now >= self.next_pacing_time
                && now.saturating_duration_since(self.last_rwnd_probe) >= probe_delay
            {
                let mut probe_target = None;
                for (id, msg) in self.outgoing.iter() {
                    if let Some(&idx) = msg.retransmit_queue.front() {
                        probe_target = Some((*id, idx, false));
                        break;
                    } else if msg.next_fragment.0 < msg.num_fragments.0 {
                        probe_target = Some((*id, msg.next_fragment, true));
                        break;
                    } else if let Some(&(idx, _)) = msg.in_flight_queue.front() {
                        probe_target = Some((*id, idx, false));
                        break;
                    }
                }
                if let Some((id, idx, is_new)) = probe_target
                    && self.try_send_fragment(id, idx, now, sender)
                {
                    if is_new && let Some(msg) = self.find_outgoing_mut(id) {
                        msg.next_fragment.0 += 1;
                    }
                    self.last_rwnd_probe = now;
                    self.zero_window_probes_sent += 1;
                }
            }
        }

        // Main data loop
        let mut any_data_sent = false;
        loop {
            let next_pacing_time = self.next_pacing_time;
            let peer_rwnd = self.peer_rwnd;
            let in_flight = self.in_flight;
            let cwnd = self.congestion_control.cwnd();
            let rto_est = self.rtt.rto();

            let outgoing = &self.outgoing;

            let next_id = self.scheduler.next_message(|id| {
                let msg = outgoing.get(&MessageId(id))?;

                if now < next_pacing_time {
                    return None;
                }

                // A. Check retransmissions
                if let Some(&idx) = msg.retransmit_queue.front()
                    && !msg.is_acked(idx)
                {
                    let fragment_len = msg.fragment_len(idx);
                    let is_oldest_hole = idx == msg.highest_cumulative_ack;

                    if is_oldest_hole {
                        if in_flight / ESTIMATED_PAYLOAD_SIZE < cwnd || !any_data_sent {
                            return Some(fragment_len);
                        }
                    } else if in_flight / ESTIMATED_PAYLOAD_SIZE < cwnd
                        && in_flight + fragment_len <= peer_rwnd
                    {
                        return Some(fragment_len);
                    }
                }

                // B. Check timeouts (RTO)
                if let Some(&(idx, last_sent)) = msg.in_flight_queue.front() {
                    let retries = msg.fragment_states[idx.0 as usize].rto_backoff;
                    let current_rto = rto_est * (1 << 6.min(retries));
                    let elapsed = now.saturating_duration_since(last_sent);
                    if elapsed >= current_rto
                        && !msg.is_acked(idx)
                        && msg.fragment_states[idx.0 as usize]
                            .last_sent
                            .is_none_or(|s| s <= last_sent)
                    {
                        let fragment_len = msg.fragment_len(idx);

                        if (in_flight / ESTIMATED_PAYLOAD_SIZE < cwnd
                            && in_flight + fragment_len <= peer_rwnd)
                            || !any_data_sent
                        {
                            return Some(fragment_len);
                        }
                    }
                }

                // C. Check new data
                if msg.next_fragment.0 < msg.num_fragments.0 {
                    let idx = msg.next_fragment;
                    let state = &msg.fragment_states[idx.0 as usize];
                    if !msg.is_acked(idx)
                        && state.last_sent.is_none()
                        && state.delivery_info.is_none()
                    {
                        let fragment_len = msg.fragment_len(idx);
                        if in_flight / ESTIMATED_PAYLOAD_SIZE < cwnd
                            && in_flight + fragment_len <= peer_rwnd
                        {
                            return Some(fragment_len);
                        }
                    }
                }
                None
            });

            if let Some(id) = next_id {
                let m_id = MessageId(id);
                if self.send_next_fragment_for_message(m_id, now, sender) {
                    any_data_sent = true;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Tail Loss Probe
        if !any_data_sent && self.in_flight > 0 {
            let srtt = self.rtt.srtt();
            let tlp_threshold = srtt.mul_f32(1.5).max(Duration::from_millis(10));
            let mut tlp_target = None;
            for (id, msg) in self.outgoing.iter() {
                if let Some(&(idx, last_sent)) = msg.in_flight_queue.back()
                    && now.saturating_duration_since(last_sent) >= tlp_threshold
                {
                    tlp_target = Some((*id, idx));
                    break;
                }
            }
            if let Some((id, idx)) = tlp_target {
                self.try_send_fragment(id, idx, now, sender);
            }
        }

        // ACKs and NACKs
        self.flush_pending_acks(now, sender);
        self.flush_pending_nacks(now, sender);

        // App-limited detection
        let cwnd = self.congestion_control.cwnd();
        if self.in_flight < cwnd * ESTIMATED_PAYLOAD_SIZE {
            let mut has_more_data = false;
            for m in self.outgoing.values() {
                if !m.retransmit_queue.is_empty() || m.next_fragment.0 < m.num_fragments.0 {
                    has_more_data = true;
                    break;
                }
            }
            if !has_more_data {
                self.app_limited = true;
            }
        }
    }

    fn send_next_fragment_for_message<F>(
        &mut self,
        id: MessageId,
        now: Instant,
        sender: &mut F,
    ) -> bool
    where
        F: FnMut(Packet) -> bool,
    {
        // A. Retransmission (peek, don't pop yet)
        let retransmit_idx = self
            .outgoing
            .get(&id)
            .and_then(|m| m.retransmit_queue.front().copied());
        if let Some(idx) = retransmit_idx {
            if self.try_send_fragment(id, idx, now, sender) {
                // Pop on success
                if let Some(msg) = self.outgoing.get_mut(&id) {
                    let popped = msg.retransmit_queue.pop_front();
                    if let Some(p_idx) = popped {
                        msg.retransmit_bitset.unset(p_idx.0 as usize);
                    }
                }
                return true;
            }
            return false;
        }

        // B. RTO timeout (peek, don't pop yet)
        let timeout_info = self
            .outgoing
            .get(&id)
            .and_then(|m| m.in_flight_queue.front().copied());
        if let Some((idx, last_sent)) = timeout_info {
            let msg = self.outgoing.get(&id).unwrap();
            let retries = msg.fragment_states[idx.0 as usize].rto_backoff;
            let current_rto = self.rtt.rto_with_backoff(retries);
            if now.saturating_duration_since(last_sent) >= current_rto {
                if self.try_send_fragment(id, idx, now, sender) {
                    // Apply mutations on success
                    if let Some(msg) = self.outgoing.get_mut(&id) {
                        msg.fragment_states[idx.0 as usize].rto_backoff += 1;
                        msg.in_flight_queue.pop_front();
                        self.congestion_control.on_timeout(now);
                    }
                    return true;
                }
                return false;
            }
        }

        // C. New data (peek, don't advance yet)
        let next_idx = self.outgoing.get(&id).and_then(|m| {
            if m.next_fragment.0 < m.num_fragments.0 {
                Some(m.next_fragment)
            } else {
                None
            }
        });
        if let Some(idx) = next_idx {
            if self.try_send_fragment(id, idx, now, sender) {
                // Advance on success
                if let Some(msg) = self.outgoing.get_mut(&id) {
                    msg.next_fragment.0 += 1;
                }
                return true;
            }
            return false;
        }

        false
    }

    pub fn cleanup(&mut self, now: Instant) {
        let quota = &self.quota;
        let incoming_buffer_size = &mut self.incoming_buffer_size;
        self.incoming.retain(|_id, r| {
            let elapsed = now.saturating_duration_since(r.last_activity);
            if elapsed >= Duration::from_secs(REASSEMBLY_TIMEOUT_SECS) {
                let allocated = r.reserved_bytes;
                *incoming_buffer_size -= allocated;
                quota.release(allocated);
                false
            } else {
                true
            }
        });

        let in_flight = &mut self.in_flight;
        let events = &mut self.events;
        let scheduler = &mut self.scheduler;
        self.outgoing.retain(|id, m| {
            let timed_out = now.saturating_duration_since(m.last_ack_at) >= m.timeout;
            let session_lost = now.saturating_duration_since(m.last_ack_at) >= CONNECTION_TIMEOUT;
            if timed_out || session_lost {
                let reason = "Timed out".to_string();
                events.push_back(SessionEvent::MessageFailed(*id, reason));
                scheduler.remove_message(id.0);
                for (idx, state) in m.fragment_states.iter().enumerate() {
                    if state.last_sent.is_some() {
                        *in_flight =
                            in_flight.saturating_sub(m.fragment_len(FragmentIndex(idx as u16)));
                    }
                }
                m.in_flight_queue.clear();
                events.push_back(SessionEvent::ReadyToSend);
                false
            } else {
                true
            }
        });
        self.completed_incoming
            .retain(|_, (_, time)| now.saturating_duration_since(*time) < Duration::from_secs(30));
    }

    pub fn is_dead(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) > CONNECTION_TIMEOUT
    }

    pub fn clock_offset(&self) -> i64 {
        self.clock_offset
    }
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn current_rwnd(&self) -> FragmentCount {
        let mut planned_size = 0;
        for r in self.incoming.values() {
            planned_size += r.planned_total_size();
        }
        let local_avail = self.max_per_session.saturating_sub(planned_size);
        let global_avail = self.quota.available();
        FragmentCount(
            (cmp::min(local_avail, global_avail) / ESTIMATED_PAYLOAD_SIZE).min(u16::MAX as usize)
                as u16,
        )
    }

    pub fn cwnd(&self) -> usize {
        self.congestion_control.cwnd()
    }
    pub fn pacing_rate(&self) -> f32 {
        self.congestion_control.pacing_rate()
    }
    pub fn current_rto(&self) -> Duration {
        self.rtt.rto()
    }
    pub fn retransmit_count(&self) -> u64 {
        self.retransmit_count
    }
    pub fn retransmit_queue_len(&self) -> usize {
        self.outgoing
            .values()
            .map(|m| m.retransmit_queue.len())
            .sum()
    }

    pub fn poll_event(&mut self) -> Option<SessionEvent> {
        self.events.pop_front()
    }
    pub fn find_outgoing(&self, id: MessageId) -> Option<&OutgoingMessage> {
        self.outgoing.get(&id)
    }
    pub fn find_incoming(&self, id: MessageId) -> Option<&MessageReassembler> {
        self.incoming.get(&id)
    }
    fn find_outgoing_mut(&mut self, id: MessageId) -> Option<&mut OutgoingMessage> {
        self.outgoing.get_mut(&id)
    }

    /// Build a fragment packet, call sender, and only apply state mutations on success.
    /// Returns true if the sender accepted the packet.
    fn try_send_fragment<F>(
        &mut self,
        id: MessageId,
        idx: FragmentIndex,
        now: Instant,
        sender: &mut F,
    ) -> bool
    where
        F: FnMut(Packet) -> bool,
    {
        // 1. Read fragment data and metadata (immutable)
        let (fragment, total, fragment_len) = if let Some(msg) = self.find_outgoing(id) {
            (
                msg.get_fragment(idx),
                msg.num_fragments,
                msg.fragment_len(idx),
            )
        } else {
            return false;
        };

        // 2. Build packet
        let packet = Packet::Data {
            message_id: id,
            fragment_index: idx,
            total_fragments: total,
            data: fragment,
        };

        // 3. Try to send
        if !sender(packet) {
            return false;
        }

        // 4. Apply mutations (only on success)
        let pacing_rate = self.congestion_control.pacing_rate();
        let cwnd = self.congestion_control.cwnd();
        if self.in_flight + fragment_len >= cwnd * ESTIMATED_PAYLOAD_SIZE {
            self.app_limited = false;
        }
        let delivered_bytes = self.delivered_bytes;
        let last_delivery_time = self.last_delivery_time;
        let app_limited = self.app_limited;
        if let Some(msg) = self.find_outgoing_mut(id) {
            let (_is_retransmission, was_in_flight) = msg.mark_fragment_sent(
                idx,
                now,
                delivered_bytes,
                last_delivery_time,
                app_limited,
                fragment_len,
            );
            if was_in_flight {
                self.in_flight = self.in_flight.saturating_sub(fragment_len);
                self.retransmit_count += 1;
            }
        }
        self.congestion_control.on_fragment_sent(fragment_len, now);
        debug!(
            "Sending fragment {} of message {} (len {})",
            idx, id, fragment_len
        );
        self.in_flight += fragment_len;
        self.last_activity = now;
        let gap_secs = if pacing_rate > 0.0 && pacing_rate.is_finite() {
            (fragment_len as f32 / pacing_rate).min(1.0)
        } else {
            0.0
        };
        self.next_pacing_time = self.next_pacing_time.max(now) + Duration::from_secs_f32(gap_secs);
        true
    }

    fn flush_pending_acks<F>(&mut self, now: Instant, sender: &mut F)
    where
        F: FnMut(Packet) -> bool,
    {
        let current_rwnd = self.current_rwnd();
        let mut ids_to_ack = Vec::new();
        for (id, (count, first_pending_at)) in self.pending_acks.iter() {
            if *count >= 2
                || now.saturating_duration_since(*first_pending_at)
                    >= crate::protocol::DELAYED_ACK_TIMEOUT
            {
                ids_to_ack.push(*id);
            }
        }
        for id in ids_to_ack {
            let packet = if let Some(reassembler) = self.incoming.get(&id) {
                Some(Packet::Ack(reassembler.create_ack(current_rwnd)))
            } else if let Some((mut ack, _)) = self.completed_incoming.get(&id).cloned() {
                ack.rwnd = current_rwnd;
                Some(Packet::Ack(ack))
            } else {
                None
            };
            if let Some(packet) = packet {
                if sender(packet) {
                    self.pending_acks.remove(&id);
                    self.pending_nacks.remove(&id);
                } else {
                    break;
                }
            } else {
                self.pending_acks.remove(&id);
                self.pending_nacks.remove(&id);
            }
        }
    }

    fn flush_pending_nacks<F>(&mut self, now: Instant, sender: &mut F)
    where
        F: FnMut(Packet) -> bool,
    {
        let mut ids_to_nack = Vec::new();
        for (id, first_pending_at) in self.pending_nacks.iter() {
            if now.saturating_duration_since(*first_pending_at)
                >= (self.rtt.srtt() / 4).max(Duration::from_millis(10))
            {
                ids_to_nack.push(*id);
            }
        }
        for id in ids_to_nack {
            if let Some(nack) = self
                .incoming
                .get(&id)
                .and_then(|reassembler| reassembler.create_nack(reassembler.buffer.base_index()))
            {
                if sender(Packet::Nack(nack)) {
                    self.pending_nacks.remove(&id);
                } else {
                    break;
                }
            } else {
                self.pending_nacks.remove(&id);
            }
        }
    }
}

impl<C: CongestionControl> Drop for SequenceSession<C> {
    fn drop(&mut self) {
        self.quota.release(self.incoming_buffer_size);
    }
}

fn peek_message_type(data: &[u8]) -> Option<MessageType> {
    if data.len() < 2 {
        return None;
    }
    if data[0] != 0x92 {
        return None;
    }
    match data[1] {
        0x01 => Some(MessageType::CapsAnnounce),
        0x02 => Some(MessageType::CapsAck),
        0x03 => Some(MessageType::SyncHeads),
        0x04 => Some(MessageType::FetchBatchReq),
        0x05 => Some(MessageType::MerkleNode),
        0x06 => Some(MessageType::BlobQuery),
        0x07 => Some(MessageType::BlobAvail),
        0x08 => Some(MessageType::BlobReq),
        0x09 => Some(MessageType::BlobData),
        0x0A => Some(MessageType::SyncSketch),
        0x0B => Some(MessageType::SyncReconFail),
        0x0C => Some(MessageType::SyncShardChecksums),
        0x0D => Some(MessageType::HandshakeError),
        0x0E => Some(MessageType::SyncRateLimited),
        0x0F => Some(MessageType::KeywrapAck),
        0x10 => Some(MessageType::ReinclusionRequest),
        0x11 => Some(MessageType::ReinclusionResponse),
        0x12 => Some(MessageType::ReconPowChallenge),
        0x13 => Some(MessageType::ReconPowSolution),
        0x14 => Some(MessageType::AdminGossip),
        _ => None,
    }
}
