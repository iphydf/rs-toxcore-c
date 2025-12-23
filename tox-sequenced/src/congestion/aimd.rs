use super::CongestionControl;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

const INITIAL_CWND: f32 = 10.0;
const INITIAL_SSTHRESH: f32 = 64.0;
const MIN_SSTHRESH: f32 = 2.0;

#[derive(ToxProto)]
pub struct Aimd {
    cwnd: f32,
    ssthresh: f32,
    last_rtt: Duration,
}

impl Default for Aimd {
    fn default() -> Self {
        Self::new()
    }
}

impl Aimd {
    pub fn new() -> Self {
        Self::with_cwnd(INITIAL_CWND)
    }

    pub fn with_cwnd(initial_cwnd: f32) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: INITIAL_SSTHRESH,
            last_rtt: Duration::from_millis(200),
        }
    }
}

impl CongestionControl for Aimd {
    fn on_ack(
        &mut self,
        rtt: Duration,
        _sample: Option<super::DeliverySample>,
        bytes_acked: usize,
        _in_flight: usize,
        _now: Instant,
    ) {
        // AIMD: Slow Start until ssthresh, then Additive Increase
        let fragments_acked = bytes_acked as f32 / crate::protocol::ESTIMATED_PAYLOAD_SIZE as f32;

        if self.cwnd < self.ssthresh {
            self.cwnd += fragments_acked;
        } else {
            self.cwnd += fragments_acked / self.cwnd;
        }

        // Store RTT for pacing
        self.last_rtt = rtt;
    }

    fn on_nack(&mut self, _now: Instant) {
        // Multiplicative Decrease / Fast Recovery
        self.ssthresh = (self.cwnd / 2.0).max(MIN_SSTHRESH);
        self.cwnd = self.ssthresh;
    }

    fn on_timeout(&mut self, _now: Instant) {
        // Full Slow Start reset
        self.ssthresh = (self.cwnd / 2.0).max(MIN_SSTHRESH);
        self.cwnd = 1.0;
    }

    fn cwnd(&self) -> usize {
        self.cwnd as usize
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
