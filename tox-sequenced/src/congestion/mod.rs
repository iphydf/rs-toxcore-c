use std::fmt;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

/// A sample of delivery information for a single ACKed fragment.
#[derive(Debug, Clone, Copy, ToxProto)]
pub struct DeliverySample {
    pub bytes_delivered: usize,
    pub duration: Duration,
    pub now: Instant,
    pub app_limited: bool,
}

pub trait CongestionControl: Send {
    /// Called when an ACK is received.
    fn on_ack(
        &mut self,
        rtt: Duration,
        sample: Option<DeliverySample>,
        bytes_acked: usize,
        in_flight: usize,
        now: Instant,
    );

    /// Called when a NACK is received (fast recovery candidate).
    fn on_nack(&mut self, now: Instant);

    /// Called when a retransmission timeout (RTO) occurs (slow start candidate).
    fn on_timeout(&mut self, now: Instant);

    /// Current congestion window in number of fragments.
    fn cwnd(&self) -> usize;

    /// Current pacing rate in bytes per second.
    fn pacing_rate(&self) -> f32;

    /// Current minimum RTT estimate.
    fn min_rtt(&self) -> Duration;

    /// Called when a fragment is sent.
    fn on_fragment_sent(&mut self, bytes: usize, now: Instant);
}

pub mod aimd;
pub mod bbrv1;
pub mod bbrv2;
pub mod cubic;

pub use aimd::Aimd;
pub use bbrv1::Bbrv1;
pub use bbrv2::Bbrv2;
pub use cubic::Cubic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ToxProto)]
pub enum AlgorithmType {
    Aimd,
    Cubic,
    Bbrv1,
    Bbrv2,
}

impl AlgorithmType {
    pub const ALL_TYPES: &'static [AlgorithmType] = &[
        AlgorithmType::Aimd,
        AlgorithmType::Cubic,
        AlgorithmType::Bbrv1,
        AlgorithmType::Bbrv2,
    ];
}

impl fmt::Display for AlgorithmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgorithmType::Aimd => write!(f, "AIMD"),
            AlgorithmType::Bbrv1 => write!(f, "BBRv1"),
            AlgorithmType::Bbrv2 => write!(f, "BBRv2"),
            AlgorithmType::Cubic => write!(f, "CUBIC"),
        }
    }
}

#[derive(ToxProto)]
pub enum Algorithm {
    Aimd(Aimd),
    Cubic(Cubic),
    Bbrv1(Bbrv1),
    Bbrv2(Bbrv2),
}

impl Algorithm {
    pub fn new(algo_type: AlgorithmType, rng: rand::rngs::StdRng) -> Self {
        match algo_type {
            AlgorithmType::Aimd => Algorithm::Aimd(Aimd::new()),
            AlgorithmType::Bbrv1 => Algorithm::Bbrv1(Bbrv1::new(rng)),
            AlgorithmType::Bbrv2 => Algorithm::Bbrv2(Bbrv2::new(rng)),
            AlgorithmType::Cubic => Algorithm::Cubic(Cubic::new()),
        }
    }

    pub fn algo_type(&self) -> AlgorithmType {
        match self {
            Algorithm::Aimd(_) => AlgorithmType::Aimd,
            Algorithm::Bbrv1(_) => AlgorithmType::Bbrv1,
            Algorithm::Bbrv2(_) => AlgorithmType::Bbrv2,
            Algorithm::Cubic(_) => AlgorithmType::Cubic,
        }
    }
}

macro_rules! dispatch {
    ($self:ident, $fn:ident $(, $args:expr)*) => {
        match $self {
            Algorithm::Aimd(a) => a.$fn($($args),*),
            Algorithm::Bbrv1(a) => a.$fn($($args),*),
            Algorithm::Bbrv2(a) => a.$fn($($args),*),
            Algorithm::Cubic(a) => a.$fn($($args),*),
        }
    };
}

impl CongestionControl for Algorithm {
    fn on_ack(
        &mut self,
        rtt: Duration,
        sample: Option<DeliverySample>,
        bytes_acked: usize,
        in_flight: usize,
        now: Instant,
    ) {
        dispatch!(self, on_ack, rtt, sample, bytes_acked, in_flight, now)
    }

    fn on_nack(&mut self, now: Instant) {
        dispatch!(self, on_nack, now)
    }

    fn on_timeout(&mut self, now: Instant) {
        dispatch!(self, on_timeout, now)
    }

    fn cwnd(&self) -> usize {
        dispatch!(self, cwnd)
    }

    fn pacing_rate(&self) -> f32 {
        dispatch!(self, pacing_rate)
    }

    fn min_rtt(&self) -> Duration {
        dispatch!(self, min_rtt)
    }

    fn on_fragment_sent(&mut self, bytes: usize, now: Instant) {
        dispatch!(self, on_fragment_sent, bytes, now)
    }
}
