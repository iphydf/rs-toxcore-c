use crate::Transport;
use crate::clock::TimeProvider;
use crate::dag::PhysicalDevicePk;
use crossbeam::channel::{Receiver, Sender, unbounded};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Eq, PartialEq)]
struct DelayedPacket {
    from: PhysicalDevicePk,
    to: PhysicalDevicePk,
    data: Vec<u8>,
    delivery_time: Instant,
}

impl Ord for DelayedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap, so we reverse the comparison to get a min-heap on delivery_time
        other.delivery_time.cmp(&self.delivery_time)
    }
}

impl PartialOrd for DelayedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Simulation models for packet loss.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LossModel {
    /// Independent packet loss with a fixed probability.
    Uniform { probability: f32 },
    /// Bursty loss using a 2-state Markov Chain (Good/Bad).
    /// - P(Good -> Bad) = p
    /// - P(Bad -> Good) = r
    /// - Loss in Bad state = 100%
    /// - Loss in Good state = 0%
    GilbertElliot { p: f32, r: f32 },
}

type NodeSender = Sender<(PhysicalDevicePk, Vec<u8>)>;
type GatewaySender = Sender<(PhysicalDevicePk, PhysicalDevicePk, Vec<u8>)>;

/// A virtual network hub for simulated protocol swarms with impairment support.
pub struct VirtualHub {
    nodes: Mutex<HashMap<PhysicalDevicePk, NodeSender>>,
    /// Fallback for packets directed at unknown PhysicalDevicePks (Promotion).
    gateway: Mutex<Option<GatewaySender>>,
    /// Packets currently in transit (Delay Pipe).
    queue: Mutex<BinaryHeap<DelayedPacket>>,
    /// Set of isolated node groups (Partition Table).
    partitions: Mutex<Vec<HashSet<PhysicalDevicePk>>>,
    /// Nodes currently in a blackout (Blackout Engine).
    blackouts: Mutex<HashMap<PhysicalDevicePk, Instant>>,
    /// Current loss model.
    loss_model: Mutex<LossModel>,
    /// State for Gilbert-Elliot model (true if in Bad state).
    loss_state_bad: Mutex<bool>,
    /// Jitter range (e.g. 0.1 means +/- 10% of latency).
    jitter: Mutex<f32>,
    /// Base latency for all packets.
    latency: Mutex<Duration>,
    /// Time provider for deterministic simulation.
    time_provider: Arc<dyn TimeProvider>,
    /// Seeded RNG for deterministic simulation.
    rng: Mutex<StdRng>,
}

impl VirtualHub {
    pub fn new(time_provider: Arc<dyn TimeProvider>) -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
            gateway: Mutex::new(None),
            queue: Mutex::new(BinaryHeap::new()),
            partitions: Mutex::new(Vec::new()),
            blackouts: Mutex::new(HashMap::new()),
            loss_model: Mutex::new(LossModel::Uniform { probability: 0.0 }),
            loss_state_bad: Mutex::new(false),
            jitter: Mutex::new(0.0),
            latency: Mutex::new(Duration::ZERO),
            time_provider,
            rng: Mutex::new(StdRng::seed_from_u64(4)),
        }
    }

    /// Sets the seed for the internal RNG.
    pub fn set_seed(&self, seed: u64) {
        *self.rng.lock().unwrap() = StdRng::seed_from_u64(seed);
    }

    /// Sets global network impairments.
    pub fn set_impairments(&self, loss: f32, latency: Duration, jitter: f32) {
        *self.loss_model.lock().unwrap() = LossModel::Uniform { probability: loss };
        *self.latency.lock().unwrap() = latency;
        *self.jitter.lock().unwrap() = jitter;
    }

    /// Sets a specific loss model.
    pub fn set_loss_model(&self, model: LossModel) {
        *self.loss_model.lock().unwrap() = model;
    }

    /// Adds a network partition: nodes in the set can only talk to each other.
    pub fn add_partition(&self, p: HashSet<PhysicalDevicePk>) {
        self.partitions.lock().unwrap().push(p);
    }

    /// Clears all network partitions.
    pub fn clear_partitions(&self) {
        self.partitions.lock().unwrap().clear();
    }

    /// Starts a blackout for a specific node until the given instant.
    pub fn set_blackout(&self, pk: PhysicalDevicePk, until: Instant) {
        self.blackouts.lock().unwrap().insert(pk, until);
    }

    /// Registers a gateway that will receive packets destined for unknown PhysicalDevicePks.
    pub fn register_gateway(&self) -> Receiver<(PhysicalDevicePk, PhysicalDevicePk, Vec<u8>)> {
        let (tx, rx) = unbounded();
        *self.gateway.lock().unwrap() = Some(tx);
        rx
    }

    /// Registers a new node in the virtual network and returns a receiver for its incoming packets.
    pub fn register(&self, pk: PhysicalDevicePk) -> Receiver<(PhysicalDevicePk, Vec<u8>)> {
        let (tx, rx) = unbounded();
        self.nodes.lock().unwrap().insert(pk, tx);
        rx
    }

    /// Injects a packet from an external network into the virtual hub (Demotion).
    pub fn inject(&self, from: PhysicalDevicePk, to: PhysicalDevicePk, data: Vec<u8>) {
        self.route(from, to, data);
    }

    fn is_blacked_out(&self, pk: &PhysicalDevicePk, now: Instant) -> bool {
        let mut blackouts = self.blackouts.lock().unwrap();
        if let Some(until) = blackouts.get(pk) {
            if now < *until {
                return true;
            } else {
                blackouts.remove(pk);
            }
        }
        false
    }

    fn can_communicate(&self, a: &PhysicalDevicePk, b: &PhysicalDevicePk) -> bool {
        let partitions = self.partitions.lock().unwrap();
        if partitions.is_empty() {
            return true;
        }

        for p in partitions.iter() {
            if p.contains(a) {
                return p.contains(b);
            }
            if p.contains(b) {
                return p.contains(a);
            }
        }
        true
    }

    /// Routes a packet from one virtual node to another, applying impairments.
    pub fn route(&self, from: PhysicalDevicePk, to: PhysicalDevicePk, data: Vec<u8>) {
        let now = self.time_provider.now_instant();

        // 1. Blackout Engine
        if self.is_blacked_out(&from, now) || self.is_blacked_out(&to, now) {
            return;
        }

        // 2. Partition Table
        if !self.can_communicate(&from, &to) {
            return;
        }

        // 3. Drop Filter
        let mut rng = self.rng.lock().unwrap();
        let model = *self.loss_model.lock().unwrap();
        let should_drop = match model {
            LossModel::Uniform { probability } => {
                probability > 0.0 && rng.r#gen::<f32>() < probability
            }
            LossModel::GilbertElliot { p, r } => {
                let mut is_bad = self.loss_state_bad.lock().unwrap();
                if *is_bad {
                    // In Bad state, we might transition to Good
                    if r > 0.0 && rng.r#gen::<f32>() < r {
                        *is_bad = false;
                    }
                } else {
                    // In Good state, we might transition to Bad
                    if p > 0.0 && rng.r#gen::<f32>() < p {
                        *is_bad = true;
                    }
                }
                *is_bad // Loss is 100% in Bad state
            }
        };

        if should_drop {
            return;
        }

        // 4. Delay Pipe
        let base_latency = *self.latency.lock().unwrap();
        let jitter_range = *self.jitter.lock().unwrap();

        let latency = if jitter_range > 0.0 {
            let factor = rng.gen_range((1.0 - jitter_range)..(1.0 + jitter_range));
            Duration::from_secs_f64(base_latency.as_secs_f64() * factor as f64)
        } else {
            base_latency
        };
        drop(rng); // Release RNG lock before potentially routing/queueing

        if latency.is_zero() {
            let nodes = self.nodes.lock().unwrap();
            if let Some(tx) = nodes.get(&to) {
                let _ = tx.send((from, data));
            } else {
                // Promotion: Send to Gateway if destination is unknown
                let gateway = self.gateway.lock().unwrap();
                if let Some(gtx) = gateway.as_ref() {
                    let _ = gtx.send((from, to, data));
                }
            }
        } else {
            self.queue.lock().unwrap().push(DelayedPacket {
                from,
                to,
                data,
                delivery_time: now + latency,
            });
        }
    }

    /// Polls the hub to deliver packets that have completed their delay.
    pub fn poll(&self) {
        let now = self.time_provider.now_instant();
        let mut queue = self.queue.lock().unwrap();
        let nodes = self.nodes.lock().unwrap();
        let gateway = self.gateway.lock().unwrap();

        while let Some(pkt) = queue.peek() {
            if now >= pkt.delivery_time {
                let pkt = queue.pop().unwrap();
                if let Some(tx) = nodes.get(&pkt.to) {
                    let _ = tx.send((pkt.from, pkt.data));
                } else if let Some(gtx) = gateway.as_ref() {
                    // Promotion: Send to Gateway if destination is unknown
                    let _ = gtx.send((pkt.from, pkt.to, pkt.data));
                }
            } else {
                break;
            }
        }
    }
}

/// A transport implementation that connects to a VirtualHub.
pub struct SimulatedTransport {
    pub pk: PhysicalDevicePk,
    pub hub: Arc<VirtualHub>,
}

impl SimulatedTransport {
    pub fn new(pk: PhysicalDevicePk, hub: Arc<VirtualHub>) -> Self {
        Self { pk, hub }
    }
}

impl Transport for SimulatedTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        self.pk
    }

    fn send_raw(&self, to: PhysicalDevicePk, data: Vec<u8>) -> Result<(), crate::TransportError> {
        self.hub.route(self.pk, to, data);
        Ok(())
    }
}
