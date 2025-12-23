use crate::dag::PhysicalDevicePk;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
pub use tox_sequenced::time::{ManualTimeProvider, SystemTimeProvider, TimeProvider};

/// The maximum rate at which the clock can be slewed (1% drift).
const MAX_SLEW_RATE: f64 = 0.01;
/// The threshold above which we jump the clock instead of slewing (10 minutes).
const SLEW_THRESHOLD_MS: i64 = 10 * 60 * 1000;

/// A median-based consensus clock with slewing and Byzantine resilience.
pub struct NetworkClock {
    /// Mapping of authenticated peer PKs to their measured time offset (local - peer) and weight.
    peer_offsets: BTreeMap<PhysicalDevicePk, (i64, u32)>,
    /// The offset we are aiming for (ms).
    target_offset: i64,
    /// The offset we are currently using (ms).
    current_offset: f64,
    /// The last instant we applied slewing.
    last_slew_instant: Instant,
    /// The monotonic base for time calculations.
    base_instant: Instant,
    /// The system time (UNIX_EPOCH) at base_instant.
    base_system_time: i64,
    /// The last returned network time to ensure monotonicity.
    last_network_time: i64,
    /// The time provider used for all time-related calls.
    time_provider: Arc<dyn TimeProvider>,
}

impl NetworkClock {
    pub fn new(time_provider: Arc<dyn TimeProvider>) -> Self {
        let now_inst = time_provider.now_instant();
        let now_sys = time_provider.now_system_ms();

        Self {
            peer_offsets: BTreeMap::new(),
            target_offset: 0,
            current_offset: 0.0,
            last_slew_instant: now_inst,
            base_instant: now_inst,
            base_system_time: now_sys,
            last_network_time: now_sys,
            time_provider,
        }
    }

    pub fn time_provider(&self) -> &dyn TimeProvider {
        &*self.time_provider
    }

    /// Records a new time offset sample from a trusted peer.
    pub fn update_peer_offset(&mut self, peer: PhysicalDevicePk, offset: i64) {
        self.update_peer_offset_weighted(peer, offset, 1);
    }

    /// Records a new time offset sample with a specific weight.
    pub fn update_peer_offset_weighted(
        &mut self,
        peer: PhysicalDevicePk,
        offset: i64,
        weight: u32,
    ) {
        self.peer_offsets.insert(peer, (offset, weight));
        self.recalculate_consensus();
    }

    fn recalculate_consensus(&mut self) {
        if self.peer_offsets.is_empty() {
            return;
        }

        let mut samples: Vec<(i64, u32)> = self.peer_offsets.values().cloned().collect();
        samples.sort_unstable_by_key(|s| s.0);

        let total_weight: u64 = samples.iter().map(|s| s.1 as u64).sum();
        let target_weight = total_weight / 2;

        let mut current_weight = 0u64;
        let mut target = samples.last().unwrap().0;

        for i in 0..samples.len() {
            let (offset, weight) = samples[i];
            current_weight += weight as u64;
            if current_weight > target_weight {
                target = offset;
                break;
            } else if current_weight == target_weight && total_weight.is_multiple_of(2) {
                // Median falls between two samples, average them.
                if i + 1 < samples.len() {
                    target = (offset + samples[i + 1].0) / 2;
                } else {
                    target = offset;
                }
                break;
            }
        }

        // If this is the first time we set a target (indicated by target_offset
        // being 0 and current_offset being 0.0) and we only have a single peer,
        // we jump to it to facilitate initial synchronization.
        if self.target_offset == 0 && self.current_offset == 0.0 && self.peer_offsets.len() == 1 {
            self.current_offset = target as f64;
        }

        self.target_offset = target;

        // If the drift is massive, we jump instead of slewing.
        let drift = (self.target_offset - self.current_offset as i64).abs();
        if drift > SLEW_THRESHOLD_MS {
            self.current_offset = self.target_offset as f64;
        }
    }

    /// Applies slewing to the current offset based on elapsed time.
    fn apply_slewing(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_slew_instant).as_secs_f64() * 1000.0;
        self.last_slew_instant = now;

        if (self.current_offset - self.target_offset as f64).abs() < 0.1 {
            self.current_offset = self.target_offset as f64;
            return;
        }

        // Calculate max allowed adjustment for this elapsed time.
        let max_adj = elapsed * MAX_SLEW_RATE;
        let remaining = self.target_offset as f64 - self.current_offset;

        if remaining > 0.0 {
            self.current_offset += remaining.min(max_adj);
        } else {
            self.current_offset -= (-remaining).min(max_adj);
        }
    }

    /// Returns the current consensus network time in milliseconds.
    pub fn network_time_ms(&mut self) -> i64 {
        let now = self.time_provider.now_instant();
        self.apply_slewing(now);

        let elapsed = now.duration_since(self.base_instant).as_millis() as i64;
        let net_time = self.base_system_time + elapsed + self.current_offset as i64;

        // Strict monotonicity: never return a time earlier than the previous call.
        if net_time < self.last_network_time {
            self.last_network_time
        } else {
            self.last_network_time = net_time;
            net_time
        }
    }

    pub fn consensus_offset(&self) -> i64 {
        self.current_offset as i64
    }
}
