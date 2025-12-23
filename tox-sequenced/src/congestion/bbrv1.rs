use super::{CongestionControl, DeliverySample};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

const RT_PROP_FILTER_LEN: Duration = Duration::from_secs(10);
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);
const STARTUP_PACING_GAIN: f32 = 2.885;
const DRAIN_PACING_GAIN: f32 = 1.0 / 2.885;
const PROBE_BW_CWND_GAIN: f32 = 2.0;
const PROBE_RTT_CWND_GAIN: f32 = 1.0;
const PROBE_RTT_PACING_GAIN: f32 = 1.0;
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const IDLE_RESTART_THRESHOLD: Duration = Duration::from_secs(1);
const FULL_BW_THRESH_FACTOR: f32 = 1.25;
const FULL_BW_COUNT_REQ: usize = 3;
const STARTUP_MIN_PACING_RATE: f32 = 200_000.0;
const MIN_PACING_RATE: f32 = 10_000.0;
const MIN_CWND: usize = 4;
const MIN_CWND_GAIN: f32 = 1.1; // Reduced from 1.25
const LOSS_REDUCTION_FACTOR: f32 = 0.9; // Less aggressive (was 0.5)
const LOSS_EVENT_THRESHOLD: usize = 8; // More resilient (was 2)
const INITIAL_RTT: Duration = Duration::from_secs(10);

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

    fn add(&mut self, now: Instant, sample: f32) {
        // Remove samples outside the window
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > self.window)
        {
            self.samples.pop_front();
        }
        // Monotonic queue: remove smaller samples from the back
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
enum Bbrv1State {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(ToxProto)]
pub struct Bbrv1 {
    state: Bbrv1State,
    max_bw: MaxFilter,
    min_rtt: Duration,
    min_rtt_stamp: Option<Instant>,

    pacing_gain: f32,
    cwnd_gain: f32,

    filled_pipe: bool,
    full_bw: f32,
    full_bw_count: usize,

    cycle_index: usize,
    cycle_stamp: Option<Instant>,

    last_ack_time: Option<Instant>,

    // Loss response (BBR v2 inspired)
    loss_count_in_round: usize,
    in_flight_at_round_start: usize,
    round_start: Option<Instant>,

    app_limited: bool,
    has_non_app_limited_sample_in_round: bool,

    pub rng: rand::rngs::StdRng,
}

const PACING_GAINS: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Bbrv1 {
    pub fn new(rng: rand::rngs::StdRng) -> Self {
        let mut bbr = Self {
            state: Bbrv1State::Startup,
            max_bw: MaxFilter::new(RT_PROP_FILTER_LEN),
            min_rtt: INITIAL_RTT,
            min_rtt_stamp: None,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: STARTUP_PACING_GAIN,
            filled_pipe: false,
            full_bw: 0.0,
            full_bw_count: 0,
            cycle_index: 0,
            cycle_stamp: None,
            last_ack_time: None,
            loss_count_in_round: 0,
            in_flight_at_round_start: 0,
            round_start: None,
            app_limited: false,
            has_non_app_limited_sample_in_round: false,
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

        // If we haven't seen a new MinRTT in 10 seconds, enter ProbeRTT
        if expired && self.state != Bbrv1State::ProbeRtt {
            self.enter_probe_rtt(now);
        }
    }

    fn check_filled_pipe(&mut self, round_expired: bool) {
        if self.filled_pipe || !round_expired || self.app_limited {
            return;
        }
        let bw = self.max_bw.get();
        if bw == 0.0 {
            return;
        }
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
        self.state = Bbrv1State::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = STARTUP_PACING_GAIN;
        self.filled_pipe = false;
        self.full_bw = 0.0;
        self.full_bw_count = 0;
    }

    fn enter_drain(&mut self) {
        self.state = Bbrv1State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = STARTUP_PACING_GAIN;
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = Bbrv1State::ProbeBw;
        use rand::Rng;
        self.cycle_index = self.rng.r#gen::<usize>() % PACING_GAINS.len();
        self.pacing_gain = PACING_GAINS[self.cycle_index];
        self.cycle_stamp = Some(now);
    }

    fn enter_probe_rtt(&mut self, now: Instant) {
        self.state = Bbrv1State::ProbeRtt;
        self.pacing_gain = PROBE_RTT_PACING_GAIN;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
        self.cycle_stamp = Some(now);
    }
}

impl CongestionControl for Bbrv1 {
    fn on_ack(
        &mut self,
        rtt: Duration,
        sample: Option<DeliverySample>,
        _bytes_acked: usize,
        in_flight: usize,
        now: Instant,
    ) {
        // Round management
        let round_expired = self
            .round_start
            .is_none_or(|start| now.saturating_duration_since(start) > self.min_rtt);

        if round_expired {
            if self.state == Bbrv1State::Startup && self.has_non_app_limited_sample_in_round {
                self.check_filled_pipe(true);
            }

            self.round_start = Some(now);
            self.loss_count_in_round = 0;
            self.in_flight_at_round_start = in_flight;
            self.app_limited = false;
            self.has_non_app_limited_sample_in_round = false;

            // Reset cwnd_gain to the target for the current state at the start of each round.
            // This ensures we recover from loss-induced reductions.
            match self.state {
                Bbrv1State::Startup | Bbrv1State::Drain => self.cwnd_gain = STARTUP_PACING_GAIN,
                Bbrv1State::ProbeBw => self.cwnd_gain = PROBE_BW_CWND_GAIN,
                Bbrv1State::ProbeRtt => self.cwnd_gain = PROBE_RTT_CWND_GAIN,
            }
        }

        // Idle restart
        let idle = self
            .last_ack_time
            .is_some_and(|last| now.saturating_duration_since(last) > IDLE_RESTART_THRESHOLD);
        if idle {
            self.enter_startup();
        }
        self.last_ack_time = Some(now);

        self.update_min_rtt(now, rtt);
        if let Some(s) = sample {
            self.update_bandwidth(now, s);
            if s.app_limited {
                self.app_limited = true;
            } else {
                self.has_non_app_limited_sample_in_round = true;
            }
        }

        match self.state {
            Bbrv1State::Startup => {
                if self.filled_pipe {
                    self.enter_drain();
                }
            }
            Bbrv1State::Drain => {
                let bdp = self.max_bw.get() * self.min_rtt.as_secs_f32();
                if (in_flight as f32) <= bdp {
                    self.enter_probe_bw(now);
                }
            }
            Bbrv1State::ProbeBw => {
                let cycle_expired = self
                    .cycle_stamp
                    .is_none_or(|stamp| now.saturating_duration_since(stamp) > self.min_rtt);
                if cycle_expired {
                    self.cycle_index = (self.cycle_index + 1) % PACING_GAINS.len();
                    self.pacing_gain = PACING_GAINS[self.cycle_index];
                    self.cycle_stamp = Some(now);
                }
            }
            Bbrv1State::ProbeRtt => {
                let cycle_expired = self
                    .cycle_stamp
                    .is_none_or(|stamp| now.saturating_duration_since(stamp) > PROBE_RTT_DURATION);
                if cycle_expired {
                    self.enter_probe_bw(now);
                }
            }
        }
    }

    fn on_nack(&mut self, _now: Instant) {
        self.loss_count_in_round += 1;
        if self.loss_count_in_round > LOSS_EVENT_THRESHOLD {
            self.cwnd_gain = (self.cwnd_gain * LOSS_REDUCTION_FACTOR).max(MIN_CWND_GAIN);
        }
    }

    fn on_timeout(&mut self, now: Instant) {
        self.loss_count_in_round += 1;
        if self.loss_count_in_round > LOSS_EVENT_THRESHOLD {
            self.cwnd_gain = (self.cwnd_gain * LOSS_REDUCTION_FACTOR).max(MIN_CWND_GAIN);

            // On persistent timeout, we likely have a blackout or major network change.
            // Reset state to re-discover bandwidth.
            self.enter_startup();
            self.max_bw.add(now, 10_000.0); // Reset MaxBW to a small value
        }
    }

    fn cwnd(&self) -> usize {
        if self.state == Bbrv1State::ProbeRtt {
            return MIN_CWND;
        }
        let bdp = self.max_bw.get() * self.min_rtt.as_secs_f32();
        let mtu = crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;

        // BDP + some extra for high throughput on long-fat pipes
        let target = (bdp * self.cwnd_gain / mtu) as usize;
        target.max(MIN_CWND)
    }

    fn pacing_rate(&self) -> f32 {
        if self.state == Bbrv1State::ProbeRtt {
            return (self.max_bw.get() * 0.5).max(MIN_PACING_RATE);
        }

        let rate = self.max_bw.get() * self.pacing_gain;

        if self.state == Bbrv1State::Startup {
            rate.max(STARTUP_MIN_PACING_RATE)
        } else {
            rate.max(MIN_PACING_RATE)
        }
    }

    fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    fn on_fragment_sent(&mut self, _bytes: usize, _now: Instant) {}
}
