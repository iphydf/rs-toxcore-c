use crate::bitset::BitSet;
use crate::error::SequencedError;
use crate::protocol::{FragmentCount, FragmentIndex, MessageType};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

/// Result of processing an ACK for a message.
pub struct AckResult {
    pub newly_delivered_bytes: usize,
    pub newly_completed_in_flight_bytes: usize,
    pub min_rtt: Option<Duration>,
    pub first_rtt: Option<Duration>,
    pub loss_detected: bool,
    pub delivery_sample: Option<(usize, Instant, f32, bool)>,
}

/// Delivery information for a fragment to calculate delivery rate.
#[derive(Clone, Copy, Debug, ToxProto)]
pub struct FragmentDeliveryInfo {
    pub delivered_at_send: usize,
    pub delivery_time_at_send: Instant,
    pub first_sent_time: Instant,
    pub size: usize,
    pub app_limited: bool,
}

/// State and delivery info for a single fragment.
#[derive(Clone, Debug, ToxProto)]
pub struct FragmentState {
    pub last_sent: Option<Instant>,
    pub delivery_info: Option<FragmentDeliveryInfo>,
    pub retransmit_count: u32,
    pub rto_backoff: u32,
}

/// A message being sent, tracking which fragments have been acknowledged and
/// managing retransmissions.
///
/// `OutgoingMessage` maintains an `in_flight_queue` of fragments that have been sent
/// but not yet acknowledged, and a `retransmit_queue` for fragments identified
/// as lost (via NACK or duplicate ACKs).
#[derive(ToxProto)]
pub struct OutgoingMessage {
    pub message_type: MessageType,
    pub data: Vec<u8>,
    pub payload_mtu: usize,
    pub num_fragments: FragmentCount,
    pub acked_bitset: BitSet<{ crate::protocol::BITSET_WORDS }>,
    pub acked_count: FragmentCount,
    pub highest_cumulative_ack: FragmentIndex,
    pub next_fragment: FragmentIndex,
    /// Fragments waiting for retransmission (indices).
    pub retransmit_queue: VecDeque<FragmentIndex>,
    pub retransmit_bitset: BitSet<{ crate::protocol::BITSET_WORDS }>,
    /// Fragments currently in flight (indices), ordered by send time.
    pub in_flight_queue: VecDeque<(FragmentIndex, Instant)>,
    pub fragment_states: Vec<FragmentState>,
    pub created_at: Instant,
    pub last_ack_at: Instant,
    pub timeout: Duration,
    /// Fast retransmit: number of duplicate ACKs seen for highest_cumulative_ack.
    pub dup_ack_count: u32,
    pub last_ack_base: FragmentIndex,
    /// The latest `last_sent` time of any fragment that has been acknowledged.
    pub highest_sent_time_acked: Option<Instant>,
}

impl OutgoingMessage {
    pub fn new(
        message_type: MessageType,
        data: Vec<u8>,
        payload_mtu: usize,
        now: Instant,
    ) -> Result<Self, SequencedError> {
        let num_fragments = if data.is_empty() {
            0
        } else {
            data.len().div_ceil(payload_mtu)
        } as u16;

        if num_fragments > crate::protocol::MAX_FRAGMENTS_PER_MESSAGE {
            return Err(SequencedError::MessageTooLarge);
        }

        Ok(Self {
            message_type,
            data,
            payload_mtu,
            num_fragments: FragmentCount(num_fragments),
            acked_bitset: BitSet::new(),
            acked_count: FragmentCount(0),
            highest_cumulative_ack: FragmentIndex(0),
            next_fragment: FragmentIndex(0),
            retransmit_queue: VecDeque::new(),
            retransmit_bitset: BitSet::new(),
            in_flight_queue: VecDeque::new(),
            fragment_states: vec![
                FragmentState {
                    last_sent: None,
                    delivery_info: None,
                    retransmit_count: 0,
                    rto_backoff: 0,
                };
                num_fragments as usize
            ],
            created_at: now,
            last_ack_at: now,
            timeout: Duration::from_secs(30),
            dup_ack_count: 0,
            last_ack_base: FragmentIndex(0),
            highest_sent_time_acked: None,
        })
    }

    pub fn is_acked(&self, index: FragmentIndex) -> bool {
        if index.0 >= self.num_fragments.0 {
            return true;
        }
        self.acked_bitset.get(index.0 as usize)
    }

    pub fn set_acked(&mut self, index: FragmentIndex) -> bool {
        if index.0 >= self.num_fragments.0 {
            return false;
        }
        if self.acked_bitset.set(index.0 as usize) {
            self.acked_count.0 += 1;
            true
        } else {
            false
        }
    }

    pub fn all_acked(&self) -> bool {
        self.acked_count.0 == self.num_fragments.0
    }

    pub fn fragment_len(&self, idx: FragmentIndex) -> usize {
        if idx.0 >= self.num_fragments.0 {
            return 0;
        }
        let start = idx.0 as usize * self.payload_mtu;
        let end = (start + self.payload_mtu).min(self.data.len());
        end - start
    }

    pub fn get_fragment(&self, idx: FragmentIndex) -> Vec<u8> {
        if idx.0 >= self.num_fragments.0 {
            return Vec::new();
        }
        let start = idx.0 as usize * self.payload_mtu;
        let end = (start + self.payload_mtu).min(self.data.len());
        self.data[start..end].to_vec()
    }

    pub fn prepare_fragment_for_send(
        &mut self,
        idx: FragmentIndex,
        now: Instant,
        delivered_bytes: usize,
        last_delivery_time: Instant,
        app_limited: bool,
    ) -> (Vec<u8>, FragmentCount, bool, bool) {
        let start = idx.0 as usize * self.payload_mtu;
        let end = (start + self.payload_mtu).min(self.data.len());
        let fragment = self.data[start..end].to_vec();
        let total = self.num_fragments;
        let state = &mut self.fragment_states[idx.0 as usize];
        let is_retransmission = state.delivery_info.is_some();
        let was_in_flight = state.last_sent.is_some();

        if is_retransmission {
            state.retransmit_count += 1;
        } else {
            state.delivery_info = Some(FragmentDeliveryInfo {
                delivered_at_send: delivered_bytes,
                delivery_time_at_send: last_delivery_time,
                first_sent_time: now,
                size: fragment.len(),
                app_limited,
            });
        }
        state.last_sent = Some(now);
        self.in_flight_queue.push_back((idx, now));
        (fragment, total, is_retransmission, was_in_flight)
    }

    pub fn on_ack(
        &mut self,
        base_index: FragmentIndex,
        bitmask: u64,
        now: Instant,
        total_delivered_bytes: usize,
    ) -> AckResult {
        self.last_ack_at = now;
        let mut res = AckResult {
            newly_delivered_bytes: 0,
            newly_completed_in_flight_bytes: 0,
            min_rtt: None,
            first_rtt: None,
            loss_detected: false,
            delivery_sample: None,
        };

        // Tracks fragments to remove from in_flight_queue (either acked or marked as lost)
        let mut to_remove = BitSet::<{ crate::protocol::BITSET_WORDS }>::new();
        let mut needs_cleanup = false;

        let acked_indices = self.collect_acked_indices(base_index, bitmask);

        let mut any_newly_acked = false;
        for idx in acked_indices {
            if self.process_single_ack(
                idx,
                now,
                total_delivered_bytes,
                &mut to_remove,
                &mut needs_cleanup,
                &mut res,
            ) {
                any_newly_acked = true;
            }
        }

        if base_index > self.last_ack_base {
            self.last_ack_base = base_index;
            self.dup_ack_count = 0;
            self.last_ack_at = now;
        } else if any_newly_acked {
            self.handle_fast_retransmit(base_index, &mut to_remove, &mut needs_cleanup, &mut res);
            self.last_ack_at = now;
        }

        self.detect_losses_from_holes(&mut to_remove, &mut needs_cleanup, &mut res);

        if any_newly_acked {
            let acked = &self.acked_bitset;
            let num = self.num_fragments.0;
            self.retransmit_queue.retain(|&idx| {
                if idx.0 >= num {
                    false
                } else {
                    !acked.get(idx.0 as usize)
                }
            });
            self.retransmit_bitset.clear();
            for &idx in &self.retransmit_queue {
                self.retransmit_bitset.set(idx.0 as usize);
            }
        }

        if needs_cleanup {
            res.newly_completed_in_flight_bytes = self.cleanup_in_flight_queue(&to_remove);
        }

        res
    }

    #[inline]
    fn process_single_ack(
        &mut self,
        idx: FragmentIndex,
        now: Instant,
        total_delivered_bytes: usize,
        to_remove: &mut BitSet<{ crate::protocol::BITSET_WORDS }>,
        needs_cleanup: &mut bool,
        res: &mut AckResult,
    ) -> bool {
        if idx.0 >= self.num_fragments.0 {
            return false;
        }

        // Combined check and set to avoid redundant bit math
        if self.acked_bitset.set(idx.0 as usize) {
            self.acked_count.0 += 1;

            let (info, is_retransmission, last_sent_existed) = {
                let state = &mut self.fragment_states[idx.0 as usize];
                let info = state.delivery_info;
                if let Some(ls) = state.last_sent
                    && self.highest_sent_time_acked.is_none_or(|m| ls > m)
                {
                    self.highest_sent_time_acked = Some(ls);
                }
                let last_sent_existed = state.last_sent.is_some();
                let is_retransmission = state.retransmit_count > 0;
                state.last_sent = None;
                (info, is_retransmission, last_sent_existed)
            };

            if let Some(info) = info {
                res.newly_delivered_bytes += info.size;
                if last_sent_existed {
                    self.mark_for_removal(idx, to_remove, needs_cleanup);
                }

                self.update_delivery_sample(info, res, total_delivered_bytes, now);

                if !is_retransmission {
                    let rtt = now.saturating_duration_since(info.first_sent_time);
                    if res.first_rtt.is_none() {
                        res.first_rtt = Some(rtt);
                    }
                    if res.min_rtt.is_none_or(|m| rtt < m) {
                        res.min_rtt = Some(rtt);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    fn handle_fast_retransmit(
        &mut self,
        base_index: FragmentIndex,
        to_remove: &mut BitSet<{ crate::protocol::BITSET_WORDS }>,
        needs_cleanup: &mut bool,
        res: &mut AckResult,
    ) {
        if base_index == self.last_ack_base && base_index.0 < self.num_fragments.0 {
            self.dup_ack_count += 1;
            if self.dup_ack_count == 3
                && !self.is_acked(base_index)
                && !self.retransmit_bitset.get(base_index.0 as usize)
            {
                let should_trigger =
                    if let Some(ls_this) = self.fragment_states[base_index.0 as usize].last_sent {
                        self.highest_sent_time_acked
                            .is_none_or(|ls_acked| ls_acked >= ls_this)
                    } else {
                        false
                    };
                if should_trigger {
                    self.retransmit_queue.push_back(base_index);
                    self.retransmit_bitset.set(base_index.0 as usize);
                    let state = &mut self.fragment_states[base_index.0 as usize];
                    if state.last_sent.take().is_some() {
                        self.mark_for_removal(base_index, to_remove, needs_cleanup);
                    }
                    res.loss_detected = true;
                }
            }
        }
    }

    pub fn collect_acked_indices(
        &mut self,
        base_index: FragmentIndex,
        bitmask: u64,
    ) -> Vec<FragmentIndex> {
        let mut acked_indices = Vec::new();

        let limit = (base_index.0 as usize).min(self.num_fragments.0 as usize);
        let mut curr = self.highest_cumulative_ack.0 as usize;
        while let Some(idx) = self.acked_bitset.next_zero(curr, limit) {
            acked_indices.push(FragmentIndex(idx as u16));
            curr = idx + 1;
        }
        self.highest_cumulative_ack = self.highest_cumulative_ack.max(base_index);

        let mut temp_mask = bitmask;
        while temp_mask != 0 {
            let i = temp_mask.trailing_zeros();
            temp_mask &= !(1 << i);

            let idx = base_index.0.wrapping_add(1).wrapping_add(i as u16);
            if idx < self.num_fragments.0 && !self.acked_bitset.get(idx as usize) {
                acked_indices.push(FragmentIndex(idx));
            }
        }

        acked_indices
    }

    fn update_delivery_sample(
        &self,
        info: FragmentDeliveryInfo,
        res: &mut AckResult,
        total_delivered_bytes: usize,
        now: Instant,
    ) {
        let duration = now.saturating_duration_since(info.delivery_time_at_send);
        if !duration.is_zero() {
            let delivered_bytes =
                total_delivered_bytes + res.newly_delivered_bytes - info.delivered_at_send;
            let current_rate = delivered_bytes as f32 / duration.as_secs_f32();
            if res
                .delivery_sample
                .is_none_or(|(_, _, rate, _)| current_rate > rate)
            {
                res.delivery_sample = Some((
                    info.delivered_at_send,
                    info.delivery_time_at_send,
                    current_rate,
                    info.app_limited,
                ));
            }
        }
    }

    fn detect_losses_from_holes(
        &mut self,
        to_remove: &mut BitSet<{ crate::protocol::BITSET_WORDS }>,
        needs_cleanup: &mut bool,
        res: &mut AckResult,
    ) {
        let max_ls = self.highest_sent_time_acked;
        let acked_count = self.acked_count.0 as usize;

        // We check for holes from highest_cumulative_ack up to highest_index.
        // Any fragment that has at least 3 fragments acked after it is considered lost.
        let mut acked_so_far = self.highest_cumulative_ack.0 as usize;
        let search_limit = self
            .acked_bitset
            .last_one(self.num_fragments.0 as usize)
            .map(|i| i + 1)
            .unwrap_or(0);

        for idx in (self.highest_cumulative_ack.0 as usize)..search_limit {
            if self.acked_bitset.get(idx) {
                acked_so_far += 1;
            } else if !self.retransmit_bitset.get(idx) {
                // It's a hole.
                let acked_after = acked_count - acked_so_far;
                if acked_after >= 3 {
                    let should_trigger = if let Some(ls_this) = self.fragment_states[idx].last_sent
                    {
                        max_ls.is_some_and(|ls_acked| ls_acked >= ls_this)
                    } else {
                        false
                    };

                    if should_trigger {
                        self.trigger_loss(FragmentIndex(idx as u16), to_remove, needs_cleanup, res);
                    }
                }
            }
        }
    }

    fn trigger_loss(
        &mut self,
        idx: FragmentIndex,
        to_remove: &mut BitSet<{ crate::protocol::BITSET_WORDS }>,
        needs_cleanup: &mut bool,
        res: &mut AckResult,
    ) {
        self.retransmit_queue.push_back(idx);
        self.retransmit_bitset.set(idx.0 as usize);
        let state = &mut self.fragment_states[idx.0 as usize];
        if state.last_sent.take().is_some() {
            self.mark_for_removal(idx, to_remove, needs_cleanup);
        }
        res.loss_detected = true;
    }

    fn mark_for_removal(
        &self,
        idx: FragmentIndex,
        to_remove: &mut BitSet<{ crate::protocol::BITSET_WORDS }>,
        needs_cleanup: &mut bool,
    ) {
        let i = idx.0 as usize;
        if i < crate::protocol::MAX_FRAGMENTS_PER_MESSAGE as usize {
            to_remove.set(i);
            *needs_cleanup = true;
        }
    }

    fn cleanup_in_flight_queue(
        &mut self,
        to_remove: &BitSet<{ crate::protocol::BITSET_WORDS }>,
    ) -> usize {
        let mut removed_bytes = 0;
        let payload_mtu = self.payload_mtu;
        let data_len = self.data.len();
        let num_fragments = self.num_fragments.0;
        let mut already_counted = BitSet::<{ crate::protocol::BITSET_WORDS }>::new();

        self.in_flight_queue.retain(|(idx, _)| {
            if to_remove.get(idx.0 as usize) {
                let f_idx = idx.0;
                if f_idx < num_fragments && already_counted.set(f_idx as usize) {
                    let start = f_idx as usize * payload_mtu;
                    let end = (start + payload_mtu).min(data_len);
                    removed_bytes += end - start;
                }
                false
            } else {
                true
            }
        });
        removed_bytes
    }
}
