use crate::SessionEvent;
use crate::congestion::{Algorithm, AlgorithmType, CongestionControl, DeliverySample};
use crate::error::SequencedError;
use crate::flat_map::FlatMap;
use crate::protocol::{
    self, ESTIMATED_PAYLOAD_SIZE, MAX_CONCURRENT_REASSEMBLY, MAX_FRAGMENT_MESSAGE,
    MAX_SENT_TRACKING, MAX_TOX_PACKET_SIZE, MessageType, Packet, REASSEMBLY_TIMEOUT, TimestampMs,
};
use crate::quota::ReassemblyQuota;
use crate::reassembly::FragmentReassembly;
use crate::rtt::RttEstimator;
use crate::scheduler::PriorityScheduler;
use crate::time::TimeProvider;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;
use tracing::{debug, warn};

pub const PING_INTERVAL_IDLE: Duration = Duration::from_secs(60);
pub const PING_INTERVAL_ACTIVE: Duration = Duration::from_secs(10);
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
const ACK_INTERVAL: Duration = Duration::from_millis(10);
/// Anti-fingerprint jitter applied to the ACK emission gate. Each
/// flush call generates a fresh value in `[-ACK_JITTER_MS, +ACK_JITTER_MS]`
/// added to `ACK_INTERVAL` before comparing against `last_ack_sent`.
/// This smooths observable ACK arrival patterns at the peer without
/// affecting protocol semantics (the ACK content is unchanged; only
/// the moment of transmission varies).
///
/// ±5 ms matches the existing PONG timestamp jitter (see
/// `merkle-tox-clock.md` §3.3) and is small enough to be invisible at
/// the throughput scale. Effective inter-ACK interval is uniform on
/// [ACK_INTERVAL - ACK_JITTER_MS, ACK_INTERVAL + ACK_JITTER_MS].
const ACK_JITTER_MS: i64 = 5;

/// A sent datagram tracked for loss detection.
#[derive(Debug, Clone, ToxProto)]
struct SentDatagram {
    seq: u32,
    sent_time: Instant,
    size: usize,
    resolved: bool,
}

/// Bounded sliding-window receiver for cumulative ACK semantics.
///
/// Tracks "next contiguous seq expected" (the value reported in ACKs as
/// `base_seq`) plus a fixed-size bitmap of out-of-order seqs in the
/// window `[base, base + WINDOW_BITS)`. The bitmap is *never serialized*
/// — only `base` is sent on the wire. The bitmap exists only to enable
/// reordering tolerance: if seq B+5 arrives before B, we remember B+5
/// so that when B finally arrives `base` can jump past both.
///
/// On window overflow (seq lands at or beyond `base + WINDOW_BITS`),
/// the window slides forward, implicitly declaring oldest unfilled gaps
/// as "no longer tracked." The data has already been delivered to the
/// application on receipt; the sender's RTO timer is the authority for
/// declaring those seqs lost.
const WINDOW_BITS: usize = 1024;
const WINDOW_WORDS: usize = WINDOW_BITS / 64;

#[derive(Debug, Clone, ToxProto)]
struct RecvTracker {
    /// Next contiguous seq expected. All seqs `< base` are implicitly
    /// delivered from the sender's perspective.
    base: u32,
    /// Fixed-size bitmap covering seqs in `[base, base + WINDOW_BITS)`.
    bitmap: [u64; WINDOW_WORDS],
    initialized: bool,
}

impl RecvTracker {
    fn new() -> Self {
        Self {
            base: 0,
            bitmap: [0u64; WINDOW_WORDS],
            initialized: false,
        }
    }

    fn mark_received(&mut self, seq: u32) {
        if !self.initialized {
            self.base = seq;
            self.initialized = true;
        }

        let offset = seq.wrapping_sub(self.base);
        // Old (already-acknowledged or forgotten) seq — ignore.
        if offset > 0x7FFF_FFFF {
            return;
        }
        let mut offset = offset as usize;

        // Out of window: slide forward enough to admit `seq`. This
        // forgets the oldest gaps.
        if offset >= WINDOW_BITS {
            let slide = offset - WINDOW_BITS + 1;
            self.slide_forward(slide);
            offset = (seq.wrapping_sub(self.base)) as usize;
            // After sliding, offset must fit.
            debug_assert!(offset < WINDOW_BITS);
        }

        let word_idx = offset / 64;
        let bit_idx = offset % 64;
        self.bitmap[word_idx] |= 1u64 << bit_idx;

        self.advance_contiguous();
    }

    /// Returns the next-expected seq (sent on the wire as ACK `base_seq`).
    fn next_expected(&self) -> u32 {
        self.base
    }

    /// Build SACK ranges reporting non-contiguous receipts above `base`.
    ///
    /// Walks the internal bitmap to find runs of consecutive set bits
    /// (received seqs above `base`) and emits each run as a `(start, length)`
    /// pair. Capped at `protocol::MAX_SACK_RANGES`; if the bitmap contains
    /// more distinct runs than the cap, the longest runs are kept (they
    /// describe the most data and are most valuable as feedback).
    ///
    /// Bit 0 of the bitmap corresponds to seq `base`; since `base` is
    /// "next-expected" (i.e., not yet received), bit 0 is always zero —
    /// any 1-bits represent above-base receipts that the cumulative ack
    /// alone cannot describe.
    fn build_sack_ranges(
        &self,
    ) -> tox_proto::BoundedVec<(u32, u32), { protocol::MAX_SACK_RANGES }> {
        if !self.initialized {
            return tox_proto::BoundedVec::new();
        }
        // First pass: enumerate all runs of set bits.
        let mut runs: smallvec::SmallVec<(u32, u32), 16> = smallvec::SmallVec::new();
        let mut i = 0usize;
        while i < WINDOW_BITS {
            // skip zeros
            while i < WINDOW_BITS && !self.bit(i) {
                i += 1;
            }
            if i >= WINDOW_BITS {
                break;
            }
            // collect ones
            let start = i;
            while i < WINDOW_BITS && self.bit(i) {
                i += 1;
            }
            let length = (i - start) as u32;
            runs.push((self.base.wrapping_add(start as u32), length));
        }
        // Cap at MAX_SACK_RANGES; keep longest if over-capacity.
        if runs.len() > protocol::MAX_SACK_RANGES {
            runs.sort_by_key(|&(_, len)| std::cmp::Reverse(len));
            runs.truncate(protocol::MAX_SACK_RANGES);
            // Sort back by start_seq so receivers see ranges in order.
            runs.sort_by_key(|&(start, _)| start);
        }
        // The truncate above guarantees `runs.len() <= MAX_SACK_RANGES`;
        // `try_from_iter` will only fail if a future change weakens the
        // invariant, in which case panicking here surfaces the bug at
        // its source rather than letting an oversize SACK list reach
        // the wire.
        tox_proto::BoundedVec::try_from_iter(runs)
            .expect("build_sack_ranges produced more entries than MAX_SACK_RANGES")
    }

    fn bit(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        (self.bitmap[word] & (1u64 << bit)) != 0
    }

    /// Walk leading contiguous received bits and advance `base` past them.
    fn advance_contiguous(&mut self) {
        let mut advance = 0usize;
        for word_idx in 0..WINDOW_WORDS {
            let word = self.bitmap[word_idx];
            if word == u64::MAX {
                advance = (word_idx + 1) * 64;
            } else {
                advance = word_idx * 64 + word.trailing_ones() as usize;
                break;
            }
        }
        if advance > 0 {
            self.slide_forward(advance);
        }
    }

    /// Slide the window forward by `bits`, advancing `base` and shifting
    /// the bitmap right (oldest bits drop, newer bits shift down).
    fn slide_forward(&mut self, bits: usize) {
        self.base = self.base.wrapping_add(bits as u32);
        if bits >= WINDOW_BITS {
            self.bitmap = [0u64; WINDOW_WORDS];
            return;
        }
        let word_shift = bits / 64;
        let bit_shift = bits % 64;
        // Shift words down by `word_shift`.
        if word_shift > 0 {
            for i in 0..WINDOW_WORDS {
                self.bitmap[i] = if i + word_shift < WINDOW_WORDS {
                    self.bitmap[i + word_shift]
                } else {
                    0
                };
            }
        }
        // Shift remaining bits.
        if bit_shift > 0 {
            for i in 0..WINDOW_WORDS {
                let lo = self.bitmap[i] >> bit_shift;
                let hi = if i + 1 < WINDOW_WORDS {
                    self.bitmap[i + 1] << (64 - bit_shift)
                } else {
                    0
                };
                self.bitmap[i] = lo | hi;
            }
        }
    }
}

/// A congestion-controlled datagram session with a specific peer.
#[derive(ToxProto)]
pub struct SequenceSession<C: CongestionControl = Algorithm> {
    // === Sequence counters ===
    next_seq: u32,
    next_frag_id: u32,

    // === Send queue ===
    /// Pending packets by queue_id. For DATA: queue_id = seq. For FRAGMENT group: queue_id = frag_id.
    pending_packets: FlatMap<u32, VecDeque<Packet>>,
    /// DRR scheduler for fair priority-based sending.
    scheduler: PriorityScheduler,

    // === ACK tracking (receiver side) ===
    recv_bitmap: RecvTracker,
    recv_bytes: u64,
    ack_pending: bool,
    last_ack_sent: Instant,

    // === Loss detection (sender side) ===
    sent_datagrams: VecDeque<SentDatagram>,
    bytes_sent: u64,
    bytes_acked: u64,
    /// Sum of `size` fields across all *unresolved* entries in
    /// `sent_datagrams`. Maintained incrementally; never recomputed.
    /// Drives the cwnd gate via `outstanding_bytes()`. Distinct from
    /// `bytes_sent − bytes_acked` (peer-driven) because it falls when
    /// the sender locally resolves an entry as lost — letting cwnd
    /// reopen even if the peer's recv counter is temporarily stuck
    /// (e.g. after a real-loss event collapses the connection).
    sum_unresolved_bytes: u64,

    // === Delivery rate estimation ===
    last_peer_recv_bytes: u64,
    last_ack_time: Instant,

    // === Fragment reassembly (receiver side) ===
    incoming_fragments: FlatMap<u32, FragmentReassembly>,
    pub quota: ReassemblyQuota,
    pub max_per_session: usize,
    incoming_buffer_size: usize,

    // === Congestion control ===
    congestion_control: C,
    rtt: RttEstimator,

    // === Session lifecycle ===
    events: VecDeque<SessionEvent>,
    last_ping: Instant,
    last_ping_sent: Option<Instant>,
    last_activity: Instant,
    next_pacing_time: Instant,
    app_limited: bool,
    /// Flush diagnostic counters: how many times each loop-exit reason
    /// fired across all `flush()` calls. Cumulative; read via
    /// `flush_diag()`. Used to figure out which gate is binding under load.
    flush_calls: u64,
    flush_pkts_sent: u64,
    flush_break_cwnd: u64,
    flush_break_app_limited: u64,
    flush_break_sender_rejected: u64,
    /// Cumulative ACK packets processed via `handle_ack`. Counts arrivals,
    /// not progress — useful to distinguish "peer stopped acking" from
    /// "acks arrive but bytes_acked doesn't advance".
    acks_received: u64,
    /// Cumulative `DatagramLost` events emitted, from either the bitmap
    /// loss-threshold path or the 30s hard-expiry path.
    losses_emitted: u64,
    time_provider: Arc<dyn TimeProvider>,
    clock_offset: i64,
    rng: rand::rngs::StdRng,
}

/// Snapshot of flush-loop diagnostic counters. Returned by
/// `SequenceSession::flush_diag()`. All fields are cumulative since
/// session creation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlushDiag {
    /// Total number of `flush()` invocations.
    pub calls: u64,
    /// Total DATA/FRAGMENT packets sent across all flushes.
    pub pkts_sent: u64,
    /// Times the flush loop exited because `outstanding >= cwnd_bytes`.
    pub break_cwnd: u64,
    /// Times the flush loop exited because the scheduler returned None
    /// (no message ready to send — either queues empty or DRR rotation
    /// stalled because no level had enough deficit for the next packet).
    pub break_app_limited: u64,
    /// Times the flush loop exited because the transport sender returned
    /// false (e.g. underlying socket queue full).
    pub break_sender_rejected: u64,
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
            ReassemblyQuota::new(protocol::MAX_TOTAL_REASSEMBLY_BUFFER),
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
            Algorithm::new(AlgorithmType::Bbrv1, cc_rng),
            quota,
            now,
            time_provider,
            session_rng,
        )
    }
}

impl<C: CongestionControl> SequenceSession<C> {
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
            ReassemblyQuota::new(protocol::MAX_TOTAL_REASSEMBLY_BUFFER),
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
        Self {
            next_seq: rng.next_u32(),
            next_frag_id: rng.next_u32(),
            pending_packets: FlatMap::new(),
            scheduler: PriorityScheduler::new(),
            recv_bitmap: RecvTracker::new(),
            recv_bytes: 0,
            ack_pending: false,
            last_ack_sent: now,
            sent_datagrams: VecDeque::new(),
            bytes_sent: 0,
            bytes_acked: 0,
            sum_unresolved_bytes: 0,
            last_peer_recv_bytes: 0,
            last_ack_time: now,
            incoming_fragments: FlatMap::new(),
            quota: quota.clone(),
            max_per_session: protocol::MAX_TOTAL_REASSEMBLY_BUFFER,
            incoming_buffer_size: 0,
            congestion_control,
            rtt: RttEstimator::new(),
            events: VecDeque::new(),
            last_ping: now - PING_INTERVAL_IDLE, // trigger immediate first PING
            last_ping_sent: None,
            last_activity: now,
            next_pacing_time: now,
            app_limited: true,
            flush_calls: 0,
            flush_pkts_sent: 0,
            flush_break_cwnd: 0,
            flush_break_app_limited: 0,
            flush_break_sender_rejected: 0,
            acks_received: 0,
            losses_emitted: 0,
            time_provider,
            clock_offset: 0,
            rng,
        }
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

    // === Sending ===

    /// Queue a single-packet DATA datagram. Returns seq number.
    pub fn send(
        &mut self,
        msg_type: MessageType,
        data: &[u8],
        _now: Instant,
    ) -> Result<u32, SequencedError> {
        let max_payload = MAX_TOX_PACKET_SIZE.saturating_sub(protocol::PACKET_OVERHEAD);
        if data.len() > max_payload {
            return Err(SequencedError::DatagramTooLarge);
        }

        // Check send queue size (prevent unbounded queueing)
        const MAX_QUEUED_ENTRIES: usize = 4096;
        if self.pending_packets.len() >= MAX_QUEUED_ENTRIES {
            return Err(SequencedError::WindowFull);
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let packet = Packet::Data {
            seq,
            msg_type,
            data: data.to_vec(),
        };

        let mut queue = VecDeque::with_capacity(1);
        queue.push_back(packet);
        self.pending_packets.insert(seq, queue);
        self.scheduler
            .update_message(seq, msg_type.priority() as u8);

        Ok(seq)
    }

    /// Queue a fragmented message. Returns frag_id.
    pub fn send_fragmented(
        &mut self,
        msg_type: MessageType,
        data: &[u8],
        _now: Instant,
    ) -> Result<u32, SequencedError> {
        if data.len() > MAX_FRAGMENT_MESSAGE {
            return Err(SequencedError::MessageTooLarge);
        }

        let payload_mtu = MAX_TOX_PACKET_SIZE.saturating_sub(protocol::PACKET_OVERHEAD + 10);
        if payload_mtu == 0 {
            return Err(SequencedError::MessageTooLarge);
        }

        let frag_total = data.len().div_ceil(payload_mtu) as u16;
        let frag_id = self.next_frag_id;
        self.next_frag_id = self.next_frag_id.wrapping_add(1);

        let mut queue = VecDeque::with_capacity(frag_total as usize);
        for i in 0..frag_total {
            let start = i as usize * payload_mtu;
            let end = (start + payload_mtu).min(data.len());
            queue.push_back(Packet::Fragment {
                frag_id,
                frag_index: i,
                frag_total,
                msg_type,
                data: data[start..end].to_vec(),
            });
        }

        self.pending_packets.insert(frag_id, queue);
        self.scheduler
            .update_message(frag_id, msg_type.priority() as u8);

        Ok(frag_id)
    }

    /// Convenience: send as DATA if it fits, otherwise fragment.
    pub fn send_auto(
        &mut self,
        msg_type: MessageType,
        data: &[u8],
        _now: Instant,
    ) -> Result<u32, SequencedError> {
        let max_payload = MAX_TOX_PACKET_SIZE.saturating_sub(protocol::PACKET_OVERHEAD);
        if data.len() <= max_payload {
            self.send(msg_type, data, _now)
        } else {
            self.send_fragmented(msg_type, data, _now)
        }
    }

    // === Receiving ===

    pub fn handle_packet(&mut self, packet: Packet, now: Instant) -> Vec<Packet> {
        self.last_activity = now;
        self.handle_packet_internal(packet, now)
    }

    fn handle_packet_internal(&mut self, packet: Packet, now: Instant) -> Vec<Packet> {
        match packet {
            Packet::Data {
                seq,
                msg_type,
                data,
            } => {
                self.recv_bytes += data.len() as u64;
                self.recv_bitmap.mark_received(seq);
                self.ack_pending = true;
                self.events
                    .push_back(SessionEvent::DataReceived(seq, msg_type, data));
                vec![]
            }
            Packet::Ack {
                base_seq,
                recv_bytes,
                sack_ranges,
            } => {
                self.handle_ack(base_seq, recv_bytes, sack_ranges, now);
                vec![]
            }
            Packet::Ping { t1 } => {
                use rand::Rng;
                let jitter = self.rng.r#gen_range(-5..=5);
                let now_ms = self.time_provider.now_system_ms();
                let t2 = TimestampMs(now_ms + jitter);
                let t3 = TimestampMs(now_ms + jitter);
                vec![Packet::Pong { t1, t2, t3 }]
            }
            Packet::Pong { t1, t2, t3 } => {
                let t4 = self.time_provider.now_system_ms();
                if let Some(sent_time) = self.last_ping_sent.take() {
                    let rtt_sample = now.saturating_duration_since(sent_time);
                    self.rtt.update(rtt_sample);
                    self.clock_offset = ((t2.0 - t1.0) + (t3.0 - t4)) / 2;
                    // Feed RTT to CC even without delivery sample
                    self.congestion_control.on_ack(
                        rtt_sample,
                        None,
                        0,
                        self.outstanding_bytes(),
                        now,
                    );
                }
                vec![]
            }
            Packet::Fragment {
                frag_id,
                frag_index,
                frag_total,
                msg_type,
                data,
            } => {
                self.recv_bytes += data.len() as u64;
                self.ack_pending = true;
                self.handle_fragment(frag_id, frag_index, frag_total, msg_type, data, now);
                vec![]
            }
        }
    }

    fn handle_ack(
        &mut self,
        base_seq: tox_proto::Untrusted<u32>,
        recv_bytes: tox_proto::Untrusted<u64>,
        sack_ranges: tox_proto::Untrusted<
            tox_proto::BoundedVec<(u32, u32), { protocol::MAX_SACK_RANGES }>,
        >,
        now: Instant,
    ) {
        // Selective ACK ranges (above-base receipts). Unwrapped here;
        // clamping is applied below before any iteration.
        let raw_sack = sack_ranges.expose_unchecked().clone();
        // Peer-supplied ACK fields are tagged `Untrusted<T>` at the
        // type level, so they cannot be used in arithmetic without
        // an explicit clamp/check against self-state.
        //
        //   * `recv_bytes` is clamped to `bytes_sent` — the peer
        //     cannot have received more than we transmitted, and an
        //     inflated value would otherwise feed BBR's delivery rate
        //     estimator with fabricated throughput.
        //
        //   * `base_seq` must not be strictly ahead of `next_seq`. A
        //     forged future value would otherwise blind the cumulative
        //     resolver below — every in-flight datagram would be
        //     marked delivered.
        self.acks_received += 1;
        let recv_bytes = recv_bytes.clamp_max(self.bytes_sent);
        let base_seq = *base_seq.expose_unchecked();
        let base_ahead = base_seq.wrapping_sub(self.next_seq);
        if base_ahead != 0 && base_ahead <= 0x7FFF_FFFF {
            return;
        }

        // Compute delivery rate sample from recv_bytes delta
        let delta_recv = recv_bytes.saturating_sub(self.last_peer_recv_bytes);
        let delta_time = now.saturating_duration_since(self.last_ack_time);

        let sample = if delta_recv > 0 && delta_time > Duration::from_millis(1) {
            Some(DeliverySample {
                bytes_delivered: delta_recv as usize,
                duration: delta_time,
                now,
                app_limited: self.app_limited,
            })
        } else {
            None
        };

        // Update bytes_acked from peer's cumulative recv counter
        if recv_bytes > self.bytes_acked {
            self.bytes_acked = recv_bytes;
        }

        // Track the freshest (most-recently-sent) datagram resolved by
        // this ACK so we can sample RTT from `now - sent_time`. Pinning
        // to the freshest sample minimises the contribution of receiver
        // ack-batching delay (ACK_INTERVAL) to the measurement: older
        // entries in the same ACK have necessarily sat in the pipeline
        // longer.
        //
        // Every entry in `sent_datagrams` corresponds to exactly one
        // transmission — loss is signalled to the upper layer via
        // `DatagramLost`, and any retransmit re-enters at a *new* seq —
        // so Karn's ambiguity around retransmitted samples does not
        // apply here.
        let mut newest_acked_send_time: Option<Instant> = None;

        // Resolve sent_datagrams against the cumulative `base_seq`. Any
        // entry with `seq < base_seq` is implicitly delivered.
        for entry in self.sent_datagrams.iter_mut() {
            if entry.resolved {
                continue;
            }
            let offset = entry.seq.wrapping_sub(base_seq);
            if offset > 0x7FFF_FFFF {
                entry.resolved = true;
                self.sum_unresolved_bytes =
                    self.sum_unresolved_bytes.saturating_sub(entry.size as u64);
                self.events
                    .push_back(SessionEvent::DatagramDelivered(entry.seq));
                if newest_acked_send_time.is_none_or(|t| entry.sent_time > t) {
                    newest_acked_send_time = Some(entry.sent_time);
                }
            }
        }

        // Selective resolution from SACK ranges. Each range covers seqs
        // `[start, start + length)` that the peer reports having received
        // above `base_seq`. Clamp aggressively against self-state:
        //   - start must be at-or-after `base_seq` (below-base is already
        //     covered by cumulative resolution above).
        //   - start + length must not exceed `next_seq` (the peer cannot
        //     have received seqs we never sent).
        //   - length must be ≤ MAX_SACK_RANGE_LENGTH (bound per-range work).
        //   - Ranges must be sorted ascending and non-overlapping; we
        //     enforce this by tracking `last_end` and skipping any range
        //     that starts before it.
        // The `entry.resolved` guard means overlap with already-resolved
        // entries is harmless — `sum_unresolved_bytes` is only decremented
        // on the first transition.
        if !raw_sack.is_empty() {
            let mut last_end: u32 = base_seq;
            for (start, length) in raw_sack.iter().copied() {
                if length == 0 || length > protocol::MAX_SACK_RANGE_LENGTH {
                    continue;
                }
                // start must be ≥ base_seq (use wrapping for seq math)
                if start.wrapping_sub(base_seq) > 0x7FFF_FFFF {
                    continue;
                }
                // ranges must be sorted & non-overlapping
                if start.wrapping_sub(last_end) > 0x7FFF_FFFF {
                    continue;
                }
                let end = start.wrapping_add(length);
                // end must be ≤ next_seq
                if end.wrapping_sub(self.next_seq) <= 0x7FFF_FFFF && end != self.next_seq {
                    continue;
                }
                last_end = end;
                // Resolve any unresolved entries whose seq falls in [start, end).
                for entry in self.sent_datagrams.iter_mut() {
                    if entry.resolved {
                        continue;
                    }
                    let off_from_start = entry.seq.wrapping_sub(start);
                    if off_from_start < length {
                        entry.resolved = true;
                        self.sum_unresolved_bytes =
                            self.sum_unresolved_bytes.saturating_sub(entry.size as u64);
                        self.events
                            .push_back(SessionEvent::DatagramDelivered(entry.seq));
                        if newest_acked_send_time.is_none_or(|t| entry.sent_time > t) {
                            newest_acked_send_time = Some(entry.sent_time);
                        }
                    }
                }
            }
        }

        // Trim resolved entries from front
        while self.sent_datagrams.front().is_some_and(|e| e.resolved) {
            self.sent_datagrams.pop_front();
        }

        // If this ACK resolved at least one datagram, derive a fresh
        // RTT sample from the freshest resolution and feed both the
        // RFC 6298 estimator (drives RTO) and the congestion controller
        // (BBRv2 drives `min_rtt` from this; AIMD/Cubic ignore it).
        // Without this, SRTT is updated *only* from explicit Ping/Pong
        // exchanges (`PING_INTERVAL_ACTIVE = 10 s`), which is far too
        // sparse for short flows: BBRv2 ends up flooring `min_rtt` at
        // the initial estimate (~200 ms after one stale Pong sample)
        // and inflates BDP/cwnd/pacing accordingly.
        let rtt_for_cc = if let Some(sent_at) = newest_acked_send_time {
            let rtt_sample = now.saturating_duration_since(sent_at);
            self.rtt.update(rtt_sample);
            rtt_sample
        } else {
            self.rtt.srtt()
        };

        // Feed CC
        self.congestion_control.on_ack(
            rtt_for_cc,
            sample,
            delta_recv as usize,
            self.outstanding_bytes(),
            now,
        );

        self.last_peer_recv_bytes = recv_bytes;
        self.last_ack_time = now;

        // Emit ReadyToSend if window opened up
        if self.outstanding_bytes() < self.congestion_control.cwnd() * ESTIMATED_PAYLOAD_SIZE {
            self.events.push_back(SessionEvent::ReadyToSend);
        }
    }

    /// Timer-based loss detection. Scans `sent_datagrams` and emits
    /// `DatagramLost` for entries whose age exceeds the current RTO
    /// (RFC 6298: `srtt + 4*rttvar`, clamped to [MIN_RTO, MAX_RTO]).
    /// Calls `on_loss` on the congestion controller once per scan if
    /// any losses fired (matches the pre-Plan-C cadence). Independent
    /// of ack arrival, so the connection self-heals even if the ack
    /// channel temporarily stalls.
    fn check_losses(&mut self, now: Instant) {
        let rto = self.rtt.rto();
        let mut bytes_lost: usize = 0;
        for entry in self.sent_datagrams.iter_mut() {
            if entry.resolved {
                continue;
            }
            if now.saturating_duration_since(entry.sent_time) >= rto {
                entry.resolved = true;
                self.sum_unresolved_bytes =
                    self.sum_unresolved_bytes.saturating_sub(entry.size as u64);
                self.events.push_back(SessionEvent::DatagramLost(entry.seq));
                self.losses_emitted += 1;
                bytes_lost = bytes_lost.saturating_add(entry.size);
            }
        }
        while self.sent_datagrams.front().is_some_and(|e| e.resolved) {
            self.sent_datagrams.pop_front();
        }
        if bytes_lost > 0 {
            // Pass actual byte total to CC. BBRv2 uses this for its
            // loss-rate divisor; AIMD/Cubic/BBRv1 ignore it (they
            // react to events rather than byte volume).
            self.congestion_control.on_loss(bytes_lost, now);
        }
    }

    fn handle_fragment(
        &mut self,
        frag_id: u32,
        frag_index: u16,
        frag_total: u16,
        msg_type: MessageType,
        data: Vec<u8>,
        now: Instant,
    ) {
        if frag_total == 0 || frag_index >= frag_total {
            return;
        }

        // Create new reassembly if needed
        if !self.incoming_fragments.contains_key(&frag_id) {
            if self.incoming_fragments.len() >= MAX_CONCURRENT_REASSEMBLY {
                debug!(
                    "fragment reassembly limit reached, dropping frag_id={}",
                    frag_id
                );
                return;
            }

            let estimated_size = frag_total as usize * ESTIMATED_PAYLOAD_SIZE;
            if !self.quota.reserve(estimated_size, msg_type.priority()) {
                debug!("quota exhausted for frag_id={}", frag_id);
                return;
            }

            let entry = FragmentReassembly::new(frag_id, frag_total, msg_type, estimated_size, now);
            self.incoming_fragments.insert(frag_id, entry);
        }

        let Some(entry) = self.incoming_fragments.get_mut(&frag_id) else {
            return;
        };

        // Verify consistency
        if entry.frag_total != frag_total {
            warn!("frag_total mismatch for frag_id={}", frag_id);
            return;
        }

        let complete = entry.add_fragment(frag_index, data, now);

        if complete {
            let entry = self.incoming_fragments.remove(&frag_id).unwrap();
            let reserved = entry.reserved_bytes;
            self.quota.release(reserved);

            if let Some(assembled) = entry.assemble() {
                self.events
                    .push_back(SessionEvent::MessageCompleted(frag_id, msg_type, assembled));
            }
        }
    }

    // === Flushing ===

    /// Paced sending from priority queues. Calls sender for each packet to transmit.
    /// Returns false from sender to stop sending (transport queue full).
    pub fn flush<F>(&mut self, now: Instant, now_ms: u64, sender: &mut F)
    where
        F: FnMut(Packet) -> bool,
    {
        // 0. Timer-based loss detection. With cumulative-only acks the
        // sender is the sole authority on declaring loss; this scan
        // ages out unresolved sent_datagrams that have outlived `rto()`.
        // Independent of ack arrival, so the connection self-heals even
        // if the ack channel temporarily stalls.
        self.check_losses(now);

        // 1. Send PING if needed
        let ping_interval = if self.pending_packets.is_empty() {
            PING_INTERVAL_IDLE
        } else {
            PING_INTERVAL_ACTIVE
        };
        if now.saturating_duration_since(self.last_ping) >= ping_interval {
            let t1 = TimestampMs(now_ms as i64);
            if sender(Packet::Ping { t1 }) {
                self.last_ping = now;
                self.last_ping_sent = Some(now);
            }
        }

        // 2. Send ACK if pending. Cumulative + bounded SACK ranges;
        // fixed-bounded size, never approaches MAX_DATAGRAM_SIZE.
        //
        // The emission gate adds ±ACK_JITTER_MS to ACK_INTERVAL on
        // each call. This is anti-fingerprint hygiene: a passive
        // observer of inter-ACK arrivals can no longer infer
        // millisecond-scale receiver-side timing patterns from
        // regular ACK pacing. The averaged inter-ACK interval is
        // unchanged at ACK_INTERVAL.
        let ack_interval = {
            use rand::Rng;
            let jitter_ms: i64 = self.rng.r#gen_range(-ACK_JITTER_MS..=ACK_JITTER_MS);
            let base_ms = ACK_INTERVAL.as_millis() as i64;
            Duration::from_millis((base_ms + jitter_ms).max(1) as u64)
        };
        if self.ack_pending && now.saturating_duration_since(self.last_ack_sent) >= ack_interval {
            let base_seq = self.recv_bitmap.next_expected();
            let sack_ranges = self.recv_bitmap.build_sack_ranges();
            let ack = Packet::Ack {
                base_seq: tox_proto::Untrusted::new(base_seq),
                recv_bytes: tox_proto::Untrusted::new(self.recv_bytes),
                sack_ranges: tox_proto::Untrusted::new(sack_ranges),
            };
            if sender(ack) {
                self.ack_pending = false;
                self.last_ack_sent = now;
            }
        }

        // 3. DRR loop: send paced packets from priority queues
        let cwnd_bytes =
            (self.congestion_control.cwnd() * ESTIMATED_PAYLOAD_SIZE).max(protocol::INITIAL_WINDOW);
        let pacing_rate = self.congestion_control.pacing_rate();

        self.flush_calls += 1;

        loop {
            // Check send window. cwnd is the only intra-flush gate: bursting
            // up to cwnd per host iteration is exactly what BBR's cwnd is
            // sized for. The historical `outstanding > cwnd_bytes / 2`
            // pacing gate effectively clamped in_flight at half cwnd because
            // `now` is constant within a flush call — once `next_pacing_time`
            // was advanced after the first send, the gate fired for every
            // subsequent send. Pacing across flush calls is preserved by
            // `next_pacing_time` being honored in `next_wakeup()` so the
            // host re-iterates promptly when paced.
            if self.outstanding_bytes() >= cwnd_bytes {
                self.flush_break_cwnd += 1;
                break;
            }

            // Ask scheduler for next queue_id to service
            let pending = &self.pending_packets;
            let queue_id = self.scheduler.next_message(|id| {
                pending
                    .get(&id)
                    .and_then(|q| q.front().map(estimate_packet_size))
            });

            let Some(queue_id) = queue_id else {
                self.app_limited = true;
                self.flush_break_app_limited += 1;
                break;
            };

            // Pop packet from queue
            let Some(queue) = self.pending_packets.get_mut(&queue_id) else {
                self.scheduler.remove_message(queue_id);
                continue;
            };

            let Some(packet) = queue.pop_front() else {
                self.scheduler.remove_message(queue_id);
                self.pending_packets.remove(&queue_id);
                continue;
            };

            let packet_size = estimate_packet_size(&packet);

            // Compute payload bytes before sending (matching recv_bytes on receiver)
            let payload_bytes = match &packet {
                Packet::Data { data, .. } | Packet::Fragment { data, .. } => data.len(),
                _ => 0,
            };

            // Snapshot fields needed AFTER the move into sender(packet)
            let data_seq = if let Packet::Data { seq, .. } = &packet {
                Some(*seq)
            } else {
                None
            };

            // Send it. If the transport rejects (e.g. underlying socket queue
            // full), put the packet back at the front of its queue so we'll
            // retry on the next flush rather than silently dropping it.
            if !sender(packet.clone()) {
                if let Some(queue) = self.pending_packets.get_mut(&queue_id) {
                    queue.push_front(packet);
                }
                self.flush_break_sender_rejected += 1;
                break;
            }
            self.flush_pkts_sent += 1;

            // Now that the packet is on the wire, track it for loss detection
            if let Some(seq) = data_seq
                && self.sent_datagrams.len() < MAX_SENT_TRACKING
            {
                self.sent_datagrams.push_back(SentDatagram {
                    seq,
                    sent_time: now,
                    size: packet_size,
                    resolved: false,
                });
                self.sum_unresolved_bytes += packet_size as u64;
            }

            self.bytes_sent += payload_bytes as u64;
            self.congestion_control.on_packet_sent(packet_size, now);
            self.app_limited = false;

            // Update pacing time
            if pacing_rate > 0.0 {
                let interval = Duration::from_secs_f32(packet_size as f32 / pacing_rate);
                let interval = interval.max(protocol::MIN_PACING_INTERVAL);
                self.next_pacing_time = now + interval;
            }

            // Clean up empty queue
            if self
                .pending_packets
                .get(&queue_id)
                .is_some_and(|q| q.is_empty())
            {
                self.scheduler.remove_message(queue_id);
                self.pending_packets.remove(&queue_id);
            }
        }
    }

    // === Maintenance ===

    pub fn cleanup(&mut self, now: Instant) {
        // Timeout fragment reassemblies
        let mut timed_out = Vec::new();
        for (frag_id, entry) in self.incoming_fragments.iter() {
            if now.saturating_duration_since(entry.created_at) >= REASSEMBLY_TIMEOUT {
                timed_out.push(*frag_id);
            }
        }
        for frag_id in timed_out {
            if let Some(entry) = self.incoming_fragments.remove(&frag_id) {
                self.quota.release(entry.reserved_bytes);
                self.events.push_back(SessionEvent::MessageDropped(frag_id));
            }
        }

        // Expire very old sent datagram entries
        let expiry = self.rtt.srtt() * 4;
        while self
            .sent_datagrams
            .front()
            .is_some_and(|e| e.resolved && now.saturating_duration_since(e.sent_time) > expiry)
        {
            self.sent_datagrams.pop_front();
        }

        // Also expire unresolved entries that are way too old (prevent unbounded growth)
        let hard_expiry = Duration::from_secs(30);
        while self
            .sent_datagrams
            .front()
            .is_some_and(|e| now.saturating_duration_since(e.sent_time) > hard_expiry)
        {
            let entry = self.sent_datagrams.pop_front().unwrap();
            if !entry.resolved {
                self.sum_unresolved_bytes =
                    self.sum_unresolved_bytes.saturating_sub(entry.size as u64);
                self.events.push_back(SessionEvent::DatagramLost(entry.seq));
                self.losses_emitted += 1;
            }
        }
    }

    pub fn is_dead(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= CONNECTION_TIMEOUT
    }

    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut next = now + PING_INTERVAL_IDLE;

        // Pacing time
        if self.next_pacing_time > now && !self.pending_packets.is_empty() {
            next = next.min(self.next_pacing_time);
        }

        // ACK interval
        if self.ack_pending {
            next = next.min(self.last_ack_sent + ACK_INTERVAL);
        }

        // Fragment reassembly timeouts
        for (_, entry) in self.incoming_fragments.iter() {
            next = next.min(entry.created_at + REASSEMBLY_TIMEOUT);
        }

        // Ping interval
        let ping_interval = if self.pending_packets.is_empty() {
            PING_INTERVAL_IDLE
        } else {
            PING_INTERVAL_ACTIVE
        };
        next = next.min(self.last_ping + ping_interval);

        next
    }

    // === Event polling ===

    pub fn poll_event(&mut self) -> Option<SessionEvent> {
        self.events.pop_front()
    }

    // === Observability ===

    pub fn cwnd(&self) -> usize {
        self.congestion_control.cwnd()
    }

    pub fn in_flight(&self) -> usize {
        self.outstanding_bytes()
    }

    pub fn pacing_rate(&self) -> f32 {
        self.congestion_control.pacing_rate()
    }

    /// Returns cumulative flush-loop diagnostic counters: total flush calls,
    /// total packets sent, and which loop-exit reason fired how many times.
    /// Used to figure out which gate is binding under load.
    pub fn flush_diag(&self) -> FlushDiag {
        FlushDiag {
            calls: self.flush_calls,
            pkts_sent: self.flush_pkts_sent,
            break_cwnd: self.flush_break_cwnd,
            break_app_limited: self.flush_break_app_limited,
            break_sender_rejected: self.flush_break_sender_rejected,
        }
    }

    pub fn current_rto(&self) -> Duration {
        self.rtt.rto()
    }

    pub fn current_srtt(&self) -> Duration {
        self.rtt.srtt()
    }

    pub fn acks_received(&self) -> u64 {
        self.acks_received
    }

    pub fn losses_emitted(&self) -> u64 {
        self.losses_emitted
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_acked(&self) -> u64 {
        self.bytes_acked
    }

    /// Number of `sent_datagrams` entries still awaiting resolution
    /// (not yet acked or marked lost). Distinct from `in_flight()` which
    /// is computed from byte counters.
    pub fn unresolved_sent(&self) -> usize {
        self.sent_datagrams.iter().filter(|e| !e.resolved).count()
    }

    /// Time elapsed since the last ACK arrived. Saturates if no ACK has
    /// ever arrived.
    pub fn last_ack_age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_ack_time)
    }

    /// Time elapsed since this side last emitted an ACK to the peer.
    /// Receiver-side counterpart to `last_ack_age`.
    pub fn last_ack_sent_age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_ack_sent)
    }

    pub fn ack_pending(&self) -> bool {
        self.ack_pending
    }

    /// Cumulative bytes this side has received and admitted into its
    /// reassembly/bitmap (peer-facing recv counter).
    pub fn recv_bytes(&self) -> u64 {
        self.recv_bytes
    }

    pub fn clock_offset(&self) -> i64 {
        self.clock_offset
    }

    /// Number of pending queue entries (DATA packets + FRAGMENT groups).
    pub fn outgoing_count(&self) -> usize {
        self.pending_packets.len()
    }

    /// Total bytes pending in the send queue.
    pub fn outgoing_bytes(&self) -> usize {
        self.pending_packets
            .iter()
            .map(|(_, q)| q.iter().map(estimate_packet_size).sum::<usize>())
            .sum()
    }

    pub fn incoming_count(&self) -> usize {
        self.incoming_fragments.len()
    }

    /// Bytes the sender locally considers in flight: the sum of
    /// `size` for unresolved entries in `sent_datagrams`. Used by the
    /// cwnd gate. Distinct from `bytes_sent − bytes_acked` (peer-driven)
    /// — local view drops as soon as entries resolve, including via
    /// timer-based loss, which lets cwnd reopen during real-loss events
    /// instead of pinning until the peer's recv counter advances.
    fn outstanding_bytes(&self) -> usize {
        self.sum_unresolved_bytes as usize
    }
}

fn estimate_packet_size(packet: &Packet) -> usize {
    match packet {
        Packet::Data { data, .. } => data.len() + protocol::PACKET_OVERHEAD,
        Packet::Fragment { data, .. } => data.len() + protocol::PACKET_OVERHEAD + 10,
        // Ack is fixed-size: u32 base_seq + u64 recv_bytes + framing.
        Packet::Ack { .. } => 20,
        Packet::Ping { .. } => 12,
        Packet::Pong { .. } => 30,
    }
}
