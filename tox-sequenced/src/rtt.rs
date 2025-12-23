use std::time::Duration;
use tox_proto::ToxProto;

pub const INITIAL_SRTT: Duration = Duration::from_millis(200);
pub const INITIAL_RTTVAR: Duration = Duration::from_millis(100);
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_millis(5000);
pub const RTT_ALPHA: f32 = 0.125;
pub const RTT_BETA: f32 = 0.25;
pub const RTT_K: u32 = 4;
pub const MAX_BACKOFF_EXPONENT: u32 = 6;

/// An estimator for Round-Trip Time (RTT) and Retransmission Timeout (RTO).
///
/// This implementation follows the algorithms defined in RFC 6298, using
/// Smoothed RTT (SRTT) and RTT Variation (RTTVAR) to calculate a robust
/// timeout for retransmissions.
#[derive(Debug, Clone, Copy, ToxProto)]
pub struct RttEstimator {
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: INITIAL_SRTT,
            rttvar: INITIAL_RTTVAR,
            rto: INITIAL_RTO,
        }
    }

    pub fn update(&mut self, sample: Duration) {
        let alpha = RTT_ALPHA;
        let beta = RTT_BETA;

        let diff = sample.abs_diff(self.srtt);

        self.rttvar = self.rttvar.mul_f32(1.0 - beta) + diff.mul_f32(beta);
        self.srtt = self.srtt.mul_f32(1.0 - alpha) + sample.mul_f32(alpha);

        let var_part = self.rttvar * RTT_K;
        self.rto = (self.srtt + var_part).clamp(MIN_RTO, MAX_RTO);
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn rto_with_backoff(&self, retries: u32) -> Duration {
        self.rto * (1 << retries.min(MAX_BACKOFF_EXPONENT))
    }

    pub fn srtt(&self) -> Duration {
        self.srtt
    }
}
