use super::CongestionControl;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

const INITIAL_CWND: f32 = 10.0;
const INITIAL_SSTHRESH: f32 = 64.0;
const MIN_CWND: f32 = 2.0;

// CUBIC constants
const C: f32 = 0.4;
const BETA: f32 = 0.7; // Multiplicative decrease factor

#[derive(ToxProto)]
pub struct Cubic {
    cwnd: f32,
    ssthresh: f32,
    w_max: f32,
    k: f32,
    epoch_start: Option<Instant>,
    origin_cwnd: f32,
    tcp_cwnd: f32,
    last_rtt: Duration,
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

impl Cubic {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            w_max: 0.0,
            k: 0.0,
            epoch_start: None,
            origin_cwnd: 0.0,
            tcp_cwnd: INITIAL_CWND,
            last_rtt: Duration::from_millis(200),
        }
    }

    fn update_cwnd(&mut self, now: Instant) {
        if let Some(epoch_start) = self.epoch_start {
            let t = now.duration_since(epoch_start).as_secs_f32();
            let target = C * (t - self.k).powi(3) + self.w_max;

            // Standard TCP friendly region
            if target < self.tcp_cwnd {
                self.cwnd = self.tcp_cwnd;
            } else {
                self.cwnd = target;
            }
        } else {
            // If no epoch started (first slow start), we rely on on_ack's slow start logic
        }
    }
}

impl CongestionControl for Cubic {
    fn on_ack(
        &mut self,
        rtt: Duration,
        _sample: Option<super::DeliverySample>,
        bytes_acked: usize,
        _in_flight: usize,
        now: Instant,
    ) {
        self.last_rtt = rtt;
        let fragments_acked = bytes_acked as f32 / crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;

        if self.cwnd < self.ssthresh {
            // Slow Start
            self.cwnd += fragments_acked;
            self.tcp_cwnd = self.cwnd;
        } else {
            // Congestion Avoidance (Cubic)
            if self.epoch_start.is_none() {
                self.epoch_start = Some(now);
                if self.cwnd < self.w_max {
                    // Concave region
                    self.k = ((self.w_max - self.cwnd) / C).powf(1.0 / 3.0);
                    self.origin_cwnd = self.cwnd;
                } else {
                    // Convex region
                    self.k = 0.0;
                    self.origin_cwnd = self.cwnd;
                }
                self.tcp_cwnd = self.cwnd;
            }

            // TCP-friendly increase (approximate)
            self.tcp_cwnd += fragments_acked / self.tcp_cwnd;

            self.update_cwnd(now);
        }
    }

    fn on_nack(&mut self, _now: Instant) {
        self.epoch_start = None; // Reset epoch
        if self.cwnd < self.w_max {
            self.w_max = self.cwnd * (1.0 + BETA) / 2.0;
        } else {
            self.w_max = self.cwnd;
        }

        self.cwnd = (self.cwnd * BETA).max(MIN_CWND);
        self.ssthresh = self.cwnd;
        self.tcp_cwnd = self.cwnd;
        self.k = (self.w_max * (1.0 - BETA) / C).powf(1.0 / 3.0);
    }

    fn on_timeout(&mut self, _now: Instant) {
        self.epoch_start = None;
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * BETA).max(MIN_CWND);
        self.cwnd = 1.0;
        self.tcp_cwnd = 1.0;
    }

    fn cwnd(&self) -> usize {
        self.cwnd.max(MIN_CWND) as usize
    }

    fn pacing_rate(&self) -> f32 {
        let mtu = crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;
        let rtt_secs = self.last_rtt.as_secs_f32().clamp(0.01, 1.0);
        // Rate = PACING_GAIN * CWND * MTU / RTT
        (self.cwnd * mtu * crate::protocol::PACING_GAIN) / rtt_secs
    }

    fn min_rtt(&self) -> Duration {
        self.last_rtt
    }

    fn on_fragment_sent(&mut self, _bytes: usize, _now: Instant) {}
}
