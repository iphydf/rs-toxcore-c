use super::{CongestionControl, DeliverySample};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

// BBRv2 Constants
const RT_PROP_FILTER_LEN: Duration = Duration::from_secs(10);
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);
const STARTUP_PACING_GAIN: f32 = 2.885;
const DRAIN_PACING_GAIN: f32 = 1.0 / 2.885;
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const IDLE_RESTART_THRESHOLD: Duration = Duration::from_secs(1);
const FULL_BW_THRESH_FACTOR: f32 = 1.25;
const FULL_BW_COUNT_REQ: usize = 3;
const STARTUP_MIN_PACING_RATE: f32 = 100_000.0;
const MIN_PACING_RATE: f32 = 10_000.0;
const MIN_CWND: usize = 4;
const INITIAL_RTT: Duration = Duration::from_secs(10);

const LOSS_THRESH: f32 = 0.02;
const BW_PROBE_UP_GAIN: f32 = 1.25;
const BW_PROBE_DOWN_GAIN: f32 = 0.9;
const PROBE_BW_CWND_GAIN: f32 = 2.0;
const PROBE_RTT_CWND_GAIN: f32 = 0.5;

/// A windowed max filter using a monotonic queue.
#[derive(ToxProto)]
struct MaxFilter {
    samples: VecDeque<(Instant, f32)>,
    window: Duration,
}

impl MaxFilter {
    fn new(window: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            window,
        }
    }

    fn expire_old(&mut self, now: Instant) {
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > self.window)
        {
            self.samples.pop_front();
        }
    }

    fn add(&mut self, now: Instant, sample: f32) {
        self.expire_old(now);
        while self.samples.back().is_some_and(|(_, s)| *s <= sample) {
            self.samples.pop_back();
        }
        self.samples.push_back((now, sample));
    }

    fn get(&self) -> f32 {
        self.samples.front().map(|(_, s)| *s).unwrap_or(0.0)
    }
}

#[derive(PartialEq, Clone, Copy, Debug, ToxProto)]
enum Bbrv2State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

#[derive(ToxProto)]
pub struct Bbrv2 {
    state: Bbrv2State,
    max_bw: MaxFilter,
    min_rtt: Duration,
    min_rtt_stamp: Option<Instant>,

    pacing_gain: f32,
    cwnd_gain: f32,

    filled_pipe: bool,
    full_bw: f32,
    full_bw_count: usize,

    // BBRv2 limits
    inflight_hi: f32,
    bw_hi: f32,
    inflight_lo: f32,
    bw_lo: f32,

    cycle_stamp: Option<Instant>,
    last_ack_time: Option<Instant>,
    last_now: Option<Instant>,

    // Round management
    delivered: usize,
    next_round_delivered: usize,
    round_count: u64,
    round_start_time: Option<Instant>,

    // Loss management
    bytes_lost_in_round: usize,
    bytes_delivered_in_round: usize,
    loss_in_round: bool,

    // ProbeBW state
    cruise_rounds: u32,

    app_limited: bool,

    pub rng: rand::rngs::StdRng,
}

impl Bbrv2 {
    pub fn new(rng: rand::rngs::StdRng) -> Self {
        let mut bbr = Self {
            state: Bbrv2State::Startup,
            max_bw: MaxFilter::new(RT_PROP_FILTER_LEN),
            min_rtt: INITIAL_RTT,
            min_rtt_stamp: None,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: STARTUP_PACING_GAIN,
            filled_pipe: false,
            full_bw: 0.0,
            full_bw_count: 0,
            inflight_hi: f32::INFINITY,
            bw_hi: f32::INFINITY,
            inflight_lo: f32::INFINITY,
            bw_lo: f32::INFINITY,
            cycle_stamp: None,
            last_ack_time: None,
            last_now: None,
            delivered: 0,
            next_round_delivered: 0,
            round_count: 0,
            round_start_time: None,
            bytes_lost_in_round: 0,
            bytes_delivered_in_round: 0,
            loss_in_round: false,
            cruise_rounds: 0,
            app_limited: false,
            rng,
        };
        bbr.enter_startup();
        bbr
    }

    fn update_bandwidth(&mut self, now: Instant, sample: DeliverySample) {
        // Use a minimum duration floor to avoid extreme bandwidth spikes on ultra-fast links
        let duration = sample.duration.max(Duration::from_millis(1));
        let bw = sample.bytes_delivered as f32 / duration.as_secs_f32();
        if bw.is_finite() && bw > 0.0 && (!sample.app_limited || bw > self.max_bw.get()) {
            self.max_bw.add(now, bw);
        }
    }

    fn update_min_rtt(&mut self, now: Instant, rtt: Duration) {
        let expired = self
            .min_rtt_stamp
            .is_some_and(|stamp| now.saturating_duration_since(stamp) > PROBE_RTT_INTERVAL);
        if rtt < self.min_rtt || self.min_rtt_stamp.is_none() || expired {
            self.min_rtt = rtt;
            self.min_rtt_stamp = Some(now);
        }

        if expired && self.state != Bbrv2State::ProbeRtt {
            self.enter_probe_rtt(now);
        }
    }

    fn check_filled_pipe(&mut self) {
        if self.filled_pipe || self.app_limited {
            return;
        }
        let bw = self.max_bw.get();
        if bw > self.full_bw * FULL_BW_THRESH_FACTOR {
            self.full_bw = bw;
            self.full_bw_count = 0;
        } else {
            self.full_bw_count += 1;
            if self.full_bw_count >= FULL_BW_COUNT_REQ {
                self.filled_pipe = true;
            }
        }
    }

    fn enter_startup(&mut self) {
        self.state = Bbrv2State::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = STARTUP_PACING_GAIN;
        self.filled_pipe = false;
        self.full_bw = 0.0;
        self.full_bw_count = 0;
    }

    fn enter_drain(&mut self) {
        self.state = Bbrv2State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = STARTUP_PACING_GAIN;
    }

    fn enter_probe_bw_down(&mut self, now: Instant) {
        self.state = Bbrv2State::ProbeBwDown;
        self.pacing_gain = BW_PROBE_DOWN_GAIN;
        self.cwnd_gain = PROBE_BW_CWND_GAIN;
        self.cycle_stamp = Some(now);
    }

    fn enter_probe_bw_cruise(&mut self, now: Instant) {
        self.state = Bbrv2State::ProbeBwCruise;
        self.pacing_gain = 1.0;
        self.cwnd_gain = PROBE_BW_CWND_GAIN;
        self.cycle_stamp = Some(now);
        use rand::Rng;
        self.cruise_rounds = self.rng.gen_range(4..=8);
    }

    fn enter_probe_bw_refill(&mut self, now: Instant) {
        self.state = Bbrv2State::ProbeBwRefill;
        self.pacing_gain = 1.0;
        self.cwnd_gain = PROBE_BW_CWND_GAIN;
        self.cycle_stamp = Some(now);
    }

    fn enter_probe_bw_up(&mut self, now: Instant) {
        self.state = Bbrv2State::ProbeBwUp;
        self.pacing_gain = BW_PROBE_UP_GAIN;
        self.cwnd_gain = PROBE_BW_CWND_GAIN;
        self.cycle_stamp = Some(now);
    }

    fn enter_probe_rtt(&mut self, now: Instant) {
        self.state = Bbrv2State::ProbeRtt;
        self.pacing_gain = 1.0;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
        self.cycle_stamp = Some(now);
    }

    fn handle_loss_in_round(&mut self, in_flight: usize, now: Instant) {
        if self.bytes_delivered_in_round == 0 {
            return;
        }

        let total_sampled = self.bytes_delivered_in_round + self.bytes_lost_in_round;
        let loss_rate = self.bytes_lost_in_round as f32 / total_sampled as f32;

        if loss_rate > LOSS_THRESH {
            // Excessive loss: cap inflight_hi and bw_hi
            let bdp = self.bdp();
            let limit = (in_flight as f32).max(bdp);
            self.inflight_hi = limit * 0.95;

            let round_duration = now
                .saturating_duration_since(self.round_start_time.unwrap_or(now))
                .as_secs_f32()
                .max(0.001);
            let current_bw = self.bytes_delivered_in_round as f32 / round_duration;
            self.bw_hi = current_bw * 0.95;

            if self.state == Bbrv2State::Startup {
                self.filled_pipe = true;
                self.enter_drain();
            } else if self.state == Bbrv2State::ProbeBwUp {
                self.enter_probe_bw_down(now);
            }
        } else {
            // No excessive loss: grow inflight_hi and bw_hi
            if self.inflight_hi != f32::INFINITY {
                self.inflight_hi += 10.0 * crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;
            }
            if self.bw_hi != f32::INFINITY {
                self.bw_hi *= 1.05;
            }
        }
    }

    fn bdp(&self) -> f32 {
        self.max_bw.get() * self.min_rtt.as_secs_f32()
    }

    fn inflight_with_headroom(&self) -> f32 {
        if self.inflight_hi == f32::INFINITY {
            return f32::INFINITY;
        }
        let headroom = (self.inflight_hi * 0.15).max(1.0);
        (self.inflight_hi - headroom)
            .max(MIN_CWND as f32 * crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32)
    }
}

impl CongestionControl for Bbrv2 {
    fn on_ack(
        &mut self,
        rtt: Duration,
        sample: Option<DeliverySample>,
        bytes_acked: usize,
        in_flight: usize,
        now: Instant,
    ) {
        self.last_now = Some(now);
        self.delivered += bytes_acked;
        self.bytes_delivered_in_round += bytes_acked;

        let mut round_expired = false;
        if self.delivered >= self.next_round_delivered {
            let start_time = self.round_start_time.unwrap_or(now);
            if now.saturating_duration_since(start_time) >= self.min_rtt
                || self.round_start_time.is_none()
            {
                self.next_round_delivered =
                    self.delivered + in_flight.max(crate::protocol::ESTIMATED_PAYLOAD_SIZE);
                self.round_count += 1;
                self.round_start_time = Some(now);
                round_expired = true;
            }
        }

        if round_expired {
            if self.state == Bbrv2State::Startup {
                self.check_filled_pipe();
            }
            self.handle_loss_in_round(in_flight, now);
            self.loss_in_round = false;
            self.bytes_lost_in_round = 0;
            self.bytes_delivered_in_round = 0;
        }

        let idle = self
            .last_ack_time
            .is_some_and(|last| now.saturating_duration_since(last) > IDLE_RESTART_THRESHOLD)
            && in_flight == 0;

        if idle {
            self.enter_startup();
        }
        self.last_ack_time = Some(now);

        self.update_min_rtt(now, rtt);
        if let Some(s) = sample {
            self.update_bandwidth(now, s);
            self.app_limited = s.app_limited;
        }

        match self.state {
            Bbrv2State::Startup => {
                if self.filled_pipe {
                    self.enter_drain();
                }
            }
            Bbrv2State::Drain => {
                if (in_flight as f32) <= self.bdp() {
                    self.enter_probe_bw_down(now);
                }
            }
            Bbrv2State::ProbeBwDown => {
                if (in_flight as f32) <= self.bdp() {
                    self.enter_probe_bw_cruise(now);
                }
            }
            Bbrv2State::ProbeBwCruise => {
                if round_expired {
                    self.cruise_rounds = self.cruise_rounds.saturating_sub(1);
                    if self.cruise_rounds == 0 {
                        self.enter_probe_bw_refill(now);
                    }
                }
            }
            Bbrv2State::ProbeBwRefill => {
                if round_expired {
                    self.enter_probe_bw_up(now);
                }
            }
            Bbrv2State::ProbeBwUp => {
                if (in_flight as f32) >= self.inflight_with_headroom()
                    || round_expired
                    || self.loss_in_round
                {
                    self.enter_probe_bw_down(now);
                }
            }
            Bbrv2State::ProbeRtt => {
                let cycle_expired = self
                    .cycle_stamp
                    .is_none_or(|stamp| now.saturating_duration_since(stamp) > PROBE_RTT_DURATION);
                if cycle_expired {
                    if self.filled_pipe {
                        self.enter_probe_bw_down(now);
                    } else {
                        self.enter_startup();
                    }
                }
            }
        }
    }

    fn on_nack(&mut self, now: Instant) {
        self.last_now = Some(now);
        self.bytes_lost_in_round += crate::protocol::ESTIMATED_PAYLOAD_SIZE;

        if !self.loss_in_round {
            self.loss_in_round = true;
            let bdp = self.bdp();
            let current = if self.inflight_hi == f32::INFINITY {
                bdp * self.cwnd_gain
            } else {
                self.inflight_hi
            };
            // Fast recovery response
            self.inflight_hi = (current * 0.95).max(bdp);
        }
    }

    fn on_timeout(&mut self, now: Instant) {
        self.last_now = Some(now);
        self.bytes_lost_in_round += crate::protocol::ESTIMATED_PAYLOAD_SIZE;
        self.enter_startup();
        self.max_bw = MaxFilter::new(RT_PROP_FILTER_LEN);
        self.max_bw.add(now, 10_000.0);
        self.inflight_hi = f32::INFINITY;
        self.bw_hi = f32::INFINITY;
        self.inflight_lo = f32::INFINITY;
        self.bw_lo = f32::INFINITY;
    }

    fn cwnd(&self) -> usize {
        if self.state == Bbrv2State::ProbeRtt {
            return MIN_CWND;
        }

        let bdp = self.bdp();
        let mtu = crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;

        let mut target = (bdp * self.cwnd_gain / mtu) as usize;

        let limit = (self.inflight_with_headroom() / mtu) as usize;
        target = target.min(limit);

        target.max(MIN_CWND)
    }

    fn pacing_rate(&self) -> f32 {
        if self.state == Bbrv2State::ProbeRtt {
            return (self.max_bw.get() * 0.5).max(MIN_PACING_RATE);
        }

        let mut rate = self.max_bw.get() * self.pacing_gain;

        if self.state == Bbrv2State::Startup {
            rate = rate.max(STARTUP_MIN_PACING_RATE);
        } else {
            rate = rate.max(MIN_PACING_RATE);
        }

        if self.bw_hi != f32::INFINITY {
            rate = rate.min(self.bw_hi * 0.95);
        }

        rate
    }

    fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    fn on_fragment_sent(&mut self, _bytes: usize, now: Instant) {
        self.last_now = Some(now);
    }
}
