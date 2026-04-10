use std::fmt;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

/// A sample of delivery information from an ACK packet.
#[derive(Debug, Clone, Copy, ToxProto)]
pub struct DeliverySample {
    pub bytes_delivered: usize,
    pub duration: Duration,
    pub now: Instant,
    pub app_limited: bool,
}

/// Hard ceiling on bandwidth-derived quantities (bytes/sec). 1 Gbps
/// covers the realistic peer-to-peer Tox upper bound (LAN gigabit
/// links are common; data-center 10G is not a target deployment).
///
/// Why this is needed at all: the delivery samples fed into BBR-style
/// estimators come from the protocol's cumulative `recv_bytes`
/// counter — a single ACK can report a multi-MB jump when cumulative
/// base catches up across a SACK gap, and the receiver's
/// `ACK_INTERVAL` batching means the time delta between consecutive
/// ACKs can be sub-RTT. Their ratio reads as multi-Gbps even on a
/// 100 Mbps link, which combined with startup pacing gain drives the
/// pacer to tens of Gbps, overruns the bottleneck queue, and
/// triggers loss-driven backoff to ~50 % steady-state util.
///
/// The first iteration of this ceiling sat at 10 Gbps — comfortably
/// above any deployment but, in practice, *too high to bind* during
/// startup: a single spike could push `max_bw` to the ceiling
/// instantly, leaving the pacer sending at 10 Gbps for several
/// seconds while the real link was 100 Mbps. Lowering to 1 Gbps
/// brings the cap closer to the realistic envelope, reducing the
/// startup overshoot from 100× to 10× over a 100 Mbps bottleneck
/// while still allowing genuine LAN-gigabit transfers to fill the
/// pipe.
pub const MAX_BW_CEILING: f32 = 125_000_000.0;

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

    /// Called when loss is detected. `bytes_lost` is the total payload
    /// bytes across all packets declared lost in this scan; algorithms
    /// that count loss *events* (AIMD halve, Cubic β-multiply,
    /// BBRv1's 8-per-round threshold) ignore the byte count, while
    /// BBRv2's loss-rate computation uses it for accurate accounting.
    /// Called at most once per `check_losses` scan in tox-sequenced.
    fn on_loss(&mut self, bytes_lost: usize, now: Instant);

    /// Called when a retransmission timeout (RTO) occurs (slow start candidate).
    fn on_timeout(&mut self, now: Instant);

    /// Current congestion window in bytes.
    fn cwnd(&self) -> usize;

    /// Current pacing rate in bytes per second.
    fn pacing_rate(&self) -> f32;

    /// Current minimum RTT estimate.
    fn min_rtt(&self) -> Duration;

    /// Called when a packet is sent.
    fn on_packet_sent(&mut self, bytes: usize, now: Instant);
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

    fn on_loss(&mut self, bytes_lost: usize, now: Instant) {
        dispatch!(self, on_loss, bytes_lost, now)
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

    fn on_packet_sent(&mut self, bytes: usize, now: Instant) {
        dispatch!(self, on_packet_sent, bytes, now)
    }
}
