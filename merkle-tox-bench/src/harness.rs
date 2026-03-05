use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossbeam::channel::Receiver;
use rand::{RngCore, SeedableRng, rngs::StdRng};

use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ConversationId, NodeHash, PhysicalDevicePk, PhysicalDeviceSk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::hub::LossModel;
use merkle_tox_core::testing::{InMemoryStore, SimulatedTransport, TestRoom, VirtualHub};
use merkle_tox_core::{Transport, TransportError};

use crate::metrics::MetricsCollector;
use crate::scenario::{LossModelConfig, NetworkConfig, PhaseAction, Scenario};

/// Transport wrapper that counts bytes sent.
pub struct CountingTransport {
    inner: SimulatedTransport,
    pub bytes_sent: Arc<AtomicU64>,
}

impl CountingTransport {
    pub fn new(inner: SimulatedTransport, bytes_sent: Arc<AtomicU64>) -> Self {
        Self { inner, bytes_sent }
    }
}

impl Transport for CountingTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        self.inner.local_pk()
    }

    fn send_raw(&self, to: PhysicalDevicePk, data: Vec<u8>) -> Result<(), TransportError> {
        self.bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.inner.send_raw(to, data)
    }
}

pub struct BenchNode {
    pub node: MerkleToxNode<CountingTransport, InMemoryStore>,
    pub rx: Receiver<(PhysicalDevicePk, Vec<u8>)>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: AtomicU64,
    pub msgs_authored: usize,
}

pub struct SimulationHarness {
    pub hub: Arc<VirtualHub>,
    pub time_provider: Arc<ManualTimeProvider>,
    pub nodes: Vec<BenchNode>,
    pub conv_id: ConversationId,
    pub room: TestRoom,
    pub metrics: MetricsCollector,
    pub virtual_elapsed: Duration,
    rng: StdRng,
}

impl SimulationHarness {
    /// Create a new harness with `node_count` nodes in a mesh topology.
    pub fn new(node_count: usize, network: &NetworkConfig, seed: u64) -> Self {
        let now_inst = Instant::now();
        let now_sys = 1_700_000_000_000i64; // fixed epoch for determinism
        let time_provider = Arc::new(ManualTimeProvider::new(now_inst, now_sys));
        let hub = Arc::new(VirtualHub::new(time_provider.clone()));
        hub.set_seed(seed);

        apply_network_config(&hub, network);

        // Seed the room construction so all identities and the conversation
        // key are deterministic across runs with the same seed.
        let mut rng = StdRng::seed_from_u64(seed);
        let room = TestRoom::new_seeded(node_count, &mut rng);
        let conv_id = room.conv_id;
        let mut nodes = Vec::with_capacity(node_count);

        for (i, identity) in room.identities.iter().enumerate() {
            let rx = hub.register(identity.device_pk);
            let transport = SimulatedTransport::new(identity.device_pk, hub.clone());
            let bytes_sent = Arc::new(AtomicU64::new(0));
            let counting_transport = CountingTransport::new(transport, bytes_sent.clone());
            let store = InMemoryStore::new();

            let mut engine = MerkleToxEngine::with_sk(
                identity.device_pk,
                identity.master_pk,
                PhysicalDeviceSk::from(identity.device_sk.to_bytes()),
                StdRng::seed_from_u64(rng.next_u64()),
                time_provider.clone(),
            );

            room.setup_engine(&mut engine, &store);
            engine.peer_ephemeral_signing_keys.clear();

            let node = MerkleToxNode::new(engine, counting_transport, store, time_provider.clone());

            nodes.push(BenchNode {
                node,
                rx,
                bytes_sent,
                bytes_received: AtomicU64::new(0),
                msgs_authored: 0,
            });

            let _ = i; // used for indexing only
        }

        // Establish mesh peering: every node syncs with every other node
        let pks: Vec<PhysicalDevicePk> = nodes.iter().map(|bn| bn.node.engine.self_pk).collect();

        #[allow(clippy::needless_range_loop)]
        for i in 0..nodes.len() {
            for (j, &pk_j) in pks.iter().enumerate() {
                if i == j {
                    continue;
                }
                let bn = &mut nodes[i];
                let effects = bn
                    .node
                    .engine
                    .start_sync(conv_id, Some(pk_j), &bn.node.store);
                let now = bn.node.time_provider.now_instant();
                let now_ms = bn.node.time_provider.now_system_ms() as u64;
                let mut wakeup = now;
                let _ = bn.node.process_effects(effects, now, now_ms, &mut wakeup);
            }
        }

        Self {
            hub,
            time_provider,
            nodes,
            conv_id,
            room,
            metrics: MetricsCollector::new(),
            virtual_elapsed: Duration::ZERO,
            rng,
        }
    }

    /// Run a single tick: advance time, deliver packets, poll nodes.
    pub fn tick(&mut self, step: Duration) {
        self.time_provider.advance(step);
        self.virtual_elapsed += step;
        self.hub.poll();

        for bn in &mut self.nodes {
            // Receive before send: process incoming packets (ACKs) first so the
            // congestion controller has up-to-date state before flushing new data.
            // Without this, each tick sends based on stale cwnd/in_flight and has
            // to wait an extra tick for ACKs to take effect.
            while let Ok((from, data)) = bn.rx.try_recv() {
                bn.bytes_received
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                bn.node.handle_packet(from, &data);
            }
            bn.node.poll();
        }

        // Record marker propagation after all nodes have polled this tick.
        // No-op when no markers are registered, so existing scenarios are
        // unaffected.
        if !self.metrics.markers.is_empty() {
            self.metrics.observe_marker_propagation(
                &self.nodes,
                &self.conv_id,
                self.virtual_elapsed,
            );
        }
    }

    /// Run the complete scenario, collecting metrics along the way.
    /// Returns true if all phases completed within timeout.
    pub fn run_scenario(&mut self, scenario: &Scenario) -> bool {
        apply_network_config(&self.hub, &scenario.network);

        let total_start = self.virtual_elapsed;
        let step = Duration::from_millis(10);

        for (phase_idx, phase) in scenario.phases.iter().enumerate() {
            // Execute the phase action
            self.execute_action(&phase.action, scenario);

            // Run the tick loop for the phase duration
            let phase_start = self.virtual_elapsed;
            while self.virtual_elapsed - phase_start < phase.duration {
                self.tick(step);
                self.metrics.collect(
                    &self.nodes,
                    &self.conv_id,
                    self.virtual_elapsed,
                    phase.name,
                    phase_idx,
                    scenario.timeout,
                );

                // Check global timeout
                if self.virtual_elapsed - total_start >= scenario.timeout {
                    return false;
                }

                // Early exit if fully converged and all blobs done
                if self.metrics.aggregated.convergence_pct >= 99.9
                    && self.metrics.aggregated.all_blobs_complete
                    && phase_idx == scenario.phases.len() - 1
                {
                    return true;
                }
            }
        }
        true
    }

    pub fn execute_action(&mut self, action: &PhaseAction, _scenario: &Scenario) {
        match action {
            PhaseAction::Run => {}
            PhaseAction::AuthorMessages { per_node } => {
                self.author_messages(*per_node);
            }
            PhaseAction::AuthorMarkerMessages { count, author_idx } => {
                self.author_marker_messages(*count, *author_idx);
            }
            PhaseAction::SeedBlob { seeder_idx, size } => {
                self.seed_blob(*seeder_idx, *size);
            }
            PhaseAction::ConcurrentBlobs { transfers } => {
                self.seed_concurrent_blobs(transfers);
            }
            PhaseAction::Partition { groups } => {
                self.apply_partition(groups);
            }
            PhaseAction::HealPartitions => {
                self.heal_partitions();
            }
            PhaseAction::AddNode => {
                self.add_node();
            }
            PhaseAction::SetImpairments(config) => {
                apply_network_config(&self.hub, config);
            }
        }
    }

    /// Authors `count` content nodes from `author_idx` and registers
    /// each with the metrics collector for end-to-end latency
    /// measurement. The `author_idx` slot is pre-filled (trivial-zero
    /// latency); each other node's slot fills in once it observes the
    /// marker as verified.
    fn author_marker_messages(&mut self, count: usize, author_idx: usize) {
        let conv_id = self.conv_id;
        let node_count = self.nodes.len();
        if author_idx >= node_count {
            return;
        }
        let bn = &mut self.nodes[author_idx];
        for i in 0..count {
            let text = format!("Marker #{}", i);
            let text_len = text.len() as u64;
            let effects =
                bn.node
                    .engine
                    .author_node(conv_id, Content::Text(text), vec![], &bn.node.store);
            let Ok(effects) = effects else {
                continue;
            };
            let mut authored_hash = None;
            for e in &effects {
                if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
                    authored_hash = Some(node.hash());
                    break;
                }
            }
            let now = bn.node.time_provider.now_instant();
            let now_ms = bn.node.time_provider.now_system_ms() as u64;
            let mut wakeup = now;
            let _ = bn.node.process_effects(effects, now, now_ms, &mut wakeup);
            if let Some(hash) = authored_hash {
                self.metrics.note_marker_authored(
                    hash,
                    author_idx,
                    node_count,
                    self.virtual_elapsed,
                );
                self.metrics.useful_bytes += text_len;
            }
        }
    }

    fn author_messages(&mut self, per_node: usize) {
        let conv_id = self.conv_id;
        for bn in &mut self.nodes {
            for _ in 0..per_node {
                let msg_num = bn.msgs_authored;
                let text = format!("Msg #{}", msg_num);
                let text_len = text.len() as u64;
                let effects = bn.node.engine.author_node(
                    conv_id,
                    Content::Text(text),
                    vec![],
                    &bn.node.store,
                );
                if let Ok(effects) = effects {
                    let now = bn.node.time_provider.now_instant();
                    let now_ms = bn.node.time_provider.now_system_ms() as u64;
                    let mut wakeup = now;
                    let _ = bn.node.process_effects(effects, now, now_ms, &mut wakeup);
                    self.metrics.useful_bytes += text_len;
                }
            }
        }
    }

    fn seed_blob(&mut self, seeder_idx: usize, size: u64) {
        let conv_id = self.conv_id;

        // Generate deterministic blob data
        let mut data = vec![0u8; size as usize];
        self.rng.fill_bytes(&mut data);
        let hash = NodeHash::from(
            merkle_tox_core::cas::ChunkMerkleTree::from_chunks(data.chunks(CHUNK_SIZE as usize))
                .root(),
        );

        self.metrics.blob_hashes.push(hash);
        self.metrics.useful_bytes += size;

        // Store blob info + chunks on the seeder only
        let seeder = &mut self.nodes[seeder_idx];
        let info = BlobInfo {
            hash,
            size,
            status: BlobStatus::Available,
            received_mask: None,
            decryption_key: None,
        };
        let _ = seeder.node.store.put_blob_info(info);

        let num_chunks = size.div_ceil(CHUNK_SIZE);
        for i in 0..num_chunks {
            let start = (i * CHUNK_SIZE) as usize;
            let end = ((i + 1) * CHUNK_SIZE).min(size) as usize;
            let _ = seeder.node.store.put_chunk(
                &conv_id,
                &hash,
                i * CHUNK_SIZE,
                &data[start..end],
                None,
            );
        }

        // Author the blob content node
        let seeder = &mut self.nodes[seeder_idx];
        let effects = seeder.node.engine.author_node(
            conv_id,
            Content::Blob {
                hash,
                name: format!("bench_{}.bin", seeder_idx),
                mime_type: "application/octet-stream".to_string(),
                size,
                metadata: tox_proto::BoundedBytes::new(),
            },
            vec![],
            &seeder.node.store,
        );

        if let Ok(effects) = effects {
            let now = seeder.node.time_provider.now_instant();
            let now_ms = seeder.node.time_provider.now_system_ms() as u64;
            let mut wakeup = now;
            let _ = seeder
                .node
                .process_effects(effects, now, now_ms, &mut wakeup);
        }
    }

    fn seed_concurrent_blobs(&mut self, transfers: &[(usize, u64)]) {
        for &(seeder_idx, size) in transfers {
            self.seed_blob(seeder_idx, size);
        }
    }

    fn apply_partition(&mut self, groups: &[Vec<usize>]) {
        self.hub.clear_partitions();
        for group in groups {
            let pks: HashSet<PhysicalDevicePk> = group
                .iter()
                .filter_map(|&idx| self.nodes.get(idx).map(|bn| bn.node.engine.self_pk))
                .collect();
            self.hub.add_partition(pks);
        }
    }

    fn heal_partitions(&mut self) {
        self.hub.clear_partitions();

        // Re-establish sync after partition heal
        let conv_id = self.conv_id;
        let pks: Vec<PhysicalDevicePk> =
            self.nodes.iter().map(|bn| bn.node.engine.self_pk).collect();

        for i in 0..self.nodes.len() {
            for (j, &pk_j) in pks.iter().enumerate() {
                if i == j {
                    continue;
                }
                let bn = &mut self.nodes[i];
                let effects = bn
                    .node
                    .engine
                    .start_sync(conv_id, Some(pk_j), &bn.node.store);
                let now = bn.node.time_provider.now_instant();
                let now_ms = bn.node.time_provider.now_system_ms() as u64;
                let mut wakeup = now;
                let _ = bn.node.process_effects(effects, now, now_ms, &mut wakeup);
            }
        }
    }

    fn add_node(&mut self) {
        // For late joiner, we add an identity that was already registered in the room
        // but create a new node for it. Since TestRoom only creates N identities,
        // we create a new one with minimal setup. Use the harness rng so the
        // late joiner is deterministic across runs.
        let new_identity = merkle_tox_core::testing::TestIdentity::from_rng(&mut self.rng);
        let rx = self.hub.register(new_identity.device_pk);
        let transport = SimulatedTransport::new(new_identity.device_pk, self.hub.clone());
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let counting_transport = CountingTransport::new(transport, bytes_sent.clone());
        let store = InMemoryStore::new();

        let mut engine = MerkleToxEngine::with_sk(
            new_identity.device_pk,
            new_identity.master_pk,
            PhysicalDeviceSk::from(new_identity.device_sk.to_bytes()),
            StdRng::seed_from_u64(self.rng.next_u64()),
            self.time_provider.clone(),
        );

        // Set up the engine with the room's conversation state
        self.room.setup_engine(&mut engine, &store);
        engine.peer_ephemeral_signing_keys.clear();

        let node = MerkleToxNode::new(
            engine,
            counting_transport,
            store,
            self.time_provider.clone(),
        );
        let mut bench_node = BenchNode {
            node,
            rx,
            bytes_sent,
            bytes_received: AtomicU64::new(0),
            msgs_authored: 0,
        };

        // Peer with all existing nodes
        let conv_id = self.conv_id;
        let existing_pks: Vec<PhysicalDevicePk> =
            self.nodes.iter().map(|bn| bn.node.engine.self_pk).collect();

        for &pk in &existing_pks {
            let effects =
                bench_node
                    .node
                    .engine
                    .start_sync(conv_id, Some(pk), &bench_node.node.store);
            let now = bench_node.node.time_provider.now_instant();
            let now_ms = bench_node.node.time_provider.now_system_ms() as u64;
            let mut wakeup = now;
            let _ = bench_node
                .node
                .process_effects(effects, now, now_ms, &mut wakeup);
        }

        self.nodes.push(bench_node);
    }
}

fn apply_network_config(hub: &VirtualHub, config: &NetworkConfig) {
    hub.set_impairments(config.loss_rate, config.latency, config.jitter);
    match &config.loss_model {
        LossModelConfig::Uniform => {
            hub.set_loss_model(LossModel::Uniform {
                probability: config.loss_rate,
            });
        }
        LossModelConfig::GilbertElliot { p, r } => {
            hub.set_loss_model(LossModel::GilbertElliot { p: *p, r: *r });
        }
    }
    let bps = config.bandwidth_mbps.map(|mbps| mbps as f64 * 1_000_000.0);
    hub.set_bandwidth(bps);
}
