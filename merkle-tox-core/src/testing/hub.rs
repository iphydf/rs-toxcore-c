use crate::Transport;
use crate::clock::TimeProvider;
use crate::dag::PhysicalDevicePk;
use crossbeam::channel::{Receiver, Sender, unbounded};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-node traffic counters. Bytes accumulated since registration.
/// Used by cost-measurement test harnesses; zero overhead when
/// `record_bytes` is not called.
#[derive(Default)]
pub struct NodeTrafficCounters {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl NodeTrafficCounters {
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            bytes_sent: self.bytes_sent.load(AtomicOrdering::Relaxed),
            bytes_received: self.bytes_received.load(AtomicOrdering::Relaxed),
            packets_sent: self.packets_sent.load(AtomicOrdering::Relaxed),
            packets_received: self.packets_received.load(AtomicOrdering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct DelayedPacket {
    from: PhysicalDevicePk,
    to: PhysicalDevicePk,
    data: Vec<u8>,
    delivery_time: Instant,
    /// Insertion sequence — secondary key so two packets with the same
    /// delivery_time pop in FIFO order (BinaryHeap is otherwise
    /// unspecified for tied keys, which causes simulation non-determinism).
    insertion_seq: u64,
}

impl Ord for DelayedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap, so reverse to get a min-heap on
        // (delivery_time, insertion_seq).
        other
            .delivery_time
            .cmp(&self.delivery_time)
            .then_with(|| other.insertion_seq.cmp(&self.insertion_seq))
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
    /// Per-link bandwidth limit in bits per second. None = unlimited.
    bandwidth_bps: Mutex<Option<f64>>,
    /// Next time each directional link (from, to) becomes free after current transmission.
    link_free_time: Mutex<HashMap<(PhysicalDevicePk, PhysicalDevicePk), Instant>>,
    /// Monotonic counter for DelayedPacket FIFO tiebreaking.
    next_insertion_seq: Mutex<u64>,
    /// Per-node traffic counters (lazily allocated on first send/receive
    /// from that node). For cost-measurement instrumentation.
    traffic: Mutex<HashMap<PhysicalDevicePk, Arc<NodeTrafficCounters>>>,
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
            bandwidth_bps: Mutex::new(None),
            link_free_time: Mutex::new(HashMap::new()),
            next_insertion_seq: Mutex::new(0),
            traffic: Mutex::new(HashMap::new()),
        }
    }

    /// Get (creating if absent) the traffic-counter handle for a node.
    fn counters_for(&self, pk: &PhysicalDevicePk) -> Arc<NodeTrafficCounters> {
        let mut t = self.traffic.lock().unwrap();
        t.entry(*pk)
            .or_insert_with(|| Arc::new(NodeTrafficCounters::default()))
            .clone()
    }

    /// Snapshot the current traffic counters for a node. Returns
    /// `TrafficSnapshot::default()` (all zeros) if the node never
    /// sent or received.
    pub fn traffic_snapshot(&self, pk: &PhysicalDevicePk) -> TrafficSnapshot {
        let t = self.traffic.lock().unwrap();
        t.get(pk).map(|c| c.snapshot()).unwrap_or_default()
    }

    /// Reset all traffic counters. Useful for measuring a specific
    /// window of activity (e.g., after warmup is complete).
    pub fn reset_traffic(&self) {
        for c in self.traffic.lock().unwrap().values() {
            c.bytes_sent.store(0, AtomicOrdering::Relaxed);
            c.bytes_received.store(0, AtomicOrdering::Relaxed);
            c.packets_sent.store(0, AtomicOrdering::Relaxed);
            c.packets_received.store(0, AtomicOrdering::Relaxed);
        }
    }

    fn next_seq(&self) -> u64 {
        let mut s = self.next_insertion_seq.lock().unwrap();
        let seq = *s;
        *s += 1;
        seq
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

    /// Sets the per-link bandwidth limit. None = unlimited.
    pub fn set_bandwidth(&self, bps: Option<f64>) {
        *self.bandwidth_bps.lock().unwrap() = bps;
        self.link_free_time.lock().unwrap().clear();
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
        // Instrumentation: count bytes attempted out from `from` regardless
        // of whether they reach `to`. This captures the bandwidth a
        // realistic device would actually emit, including packets
        // ultimately dropped by impairments — same as real-world cost.
        let sender_counters = self.counters_for(&from);
        let data_len = data.len() as u64;
        sender_counters
            .bytes_sent
            .fetch_add(data_len, AtomicOrdering::Relaxed);
        sender_counters
            .packets_sent
            .fetch_add(1, AtomicOrdering::Relaxed);

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

        // 5. Bandwidth serialization
        let bandwidth = *self.bandwidth_bps.lock().unwrap();
        if let Some(bps) = bandwidth {
            let transmission_secs = (data.len() * 8) as f64 / bps;
            let transmission_duration = Duration::from_secs_f64(transmission_secs);

            let mut link_free = self.link_free_time.lock().unwrap();
            let link_key = (from, to);
            let link_free_time = link_free.get(&link_key).copied().unwrap_or(now);
            let departure = if link_free_time > now {
                link_free_time
            } else {
                now
            };
            let delivery_time = departure + transmission_duration + latency;
            link_free.insert(link_key, departure + transmission_duration);
            drop(link_free);

            let insertion_seq = self.next_seq();
            self.queue.lock().unwrap().push(DelayedPacket {
                from,
                to,
                data,
                delivery_time,
                insertion_seq,
            });
        } else if latency.is_zero() {
            let data_len = data.len() as u64;
            let nodes = self.nodes.lock().unwrap();
            if let Some(tx) = nodes.get(&to) {
                // Instrumentation: count delivery in the latency==0
                // fast path (same as the poll()-based path below).
                let receiver_counters = {
                    let mut t = self.traffic.lock().unwrap();
                    t.entry(to)
                        .or_insert_with(|| Arc::new(NodeTrafficCounters::default()))
                        .clone()
                };
                receiver_counters
                    .bytes_received
                    .fetch_add(data_len, AtomicOrdering::Relaxed);
                receiver_counters
                    .packets_received
                    .fetch_add(1, AtomicOrdering::Relaxed);
                let _ = tx.send((from, data));
            } else {
                // Promotion: Send to Gateway if destination is unknown
                let gateway = self.gateway.lock().unwrap();
                if let Some(gtx) = gateway.as_ref() {
                    let _ = gtx.send((from, to, data));
                }
            }
        } else {
            let insertion_seq = self.next_seq();
            self.queue.lock().unwrap().push(DelayedPacket {
                from,
                to,
                data,
                delivery_time: now + latency,
                insertion_seq,
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
                let data_len = pkt.data.len() as u64;
                if let Some(tx) = nodes.get(&pkt.to) {
                    // Instrumentation: count bytes received by `to` when
                    // delivery succeeds. Mirrors send-side counting in
                    // `route()`.
                    let receiver_counters = {
                        let mut t = self.traffic.lock().unwrap();
                        t.entry(pkt.to)
                            .or_insert_with(|| Arc::new(NodeTrafficCounters::default()))
                            .clone()
                    };
                    receiver_counters
                        .bytes_received
                        .fetch_add(data_len, AtomicOrdering::Relaxed);
                    receiver_counters
                        .packets_received
                        .fetch_add(1, AtomicOrdering::Relaxed);
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
