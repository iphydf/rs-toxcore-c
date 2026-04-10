use clap::Parser;
use crossbeam::channel::Receiver;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, MerkleToxGateway, SimulatedTransport, VirtualHub, gateway::TOX_BRIDGED_PACKET_ID,
};
use merkle_tox_core::{Transport, TransportError};
use merkle_tox_tox::{TOX_CUSTOM_PACKET_ID, ToxTransport};
use parking_lot::ReentrantMutex;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use ratatui::widgets::TableState;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use toxcore::tox::{Options as ToxOptions, Tox};
use toxcore::types::{DhtId, PublicKey as ToxPublicKey, ToxConnection};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Number of virtual nodes to spawn.
    #[arg(short, long, default_value_t = 5)]
    pub nodes: usize,

    /// Initial authoring rate (messages per second).
    #[arg(short, long, default_value_t = 1.0)]
    pub rate: f32,

    /// Step simulation manually (frame-by-frame) if true.
    #[arg(short, long)]
    pub step: bool,

    /// Number of real Tox nodes to spawn.
    #[arg(short = 'R', long, default_value_t = 0)]
    pub real_nodes: usize,

    /// Seed for the virtual hub's RNG.
    #[arg(long, default_value_t = 4)]
    pub seed: u64,

    /// Network topology template.
    #[arg(short = 'T', long, value_enum, default_value_t = Topology::Mesh)]
    pub topology: Topology,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Every node connected to every other node.
    Mesh,
    /// All nodes connect to a single central node.
    Star,
    /// Randomly generated graph with 30% peering probability.
    Dynamic,
}

pub enum GenericTransport {
    Sim(SimulatedTransport),
    Tox {
        transport: ToxTransport,
        gateway_pk: Option<PhysicalDevicePk>,
    },
}

impl Transport for GenericTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        match self {
            Self::Sim(t) => t.local_pk(),
            Self::Tox { transport, .. } => {
                PhysicalDevicePk::from(transport.tox.lock().public_key().0)
            }
        }
    }

    fn send_raw(&self, to: PhysicalDevicePk, mut data: Vec<u8>) -> Result<(), TransportError> {
        match self {
            Self::Sim(t) => t.send_raw(to, data),
            Self::Tox {
                transport,
                gateway_pk,
            } => {
                let tox = transport.tox.lock();
                if let Ok(friend) = tox.lookup_friend(&ToxPublicKey(*to.as_bytes())) {
                    // Direct delivery
                    data.insert(0, TOX_CUSTOM_PACKET_ID);
                    friend
                        .send_lossy_packet(&data)
                        .map_err(|e| TransportError::Other(format!("{:?}", e)))?;
                    Ok(())
                } else if let Some(gw_pk) = gateway_pk {
                    // Route via Gateway
                    let mut bridged = vec![TOX_BRIDGED_PACKET_ID];
                    bridged.extend_from_slice(to.as_bytes());
                    bridged.extend_from_slice(&data);

                    let gw_friend = tox
                        .lookup_friend(&ToxPublicKey(*gw_pk.as_bytes()))
                        .map_err(|_| {
                            TransportError::PeerNotFound("Gateway not found".to_string())
                        })?;

                    gw_friend
                        .send_lossy_packet(&bridged)
                        .map_err(|e| TransportError::Other(format!("{:?}", e)))?;
                    Ok(())
                } else {
                    Err(TransportError::PeerNotFound(hex::encode(to.as_bytes())))
                }
            }
        }
    }
}

pub struct NodeWrapper {
    pub node: MerkleToxNode<GenericTransport, InMemoryStore>,
    pub rx: Option<Receiver<(PhysicalDevicePk, Vec<u8>)>>,
    pub last_authoring: Instant,
    pub history: MetricHistory,
}

#[derive(Default)]
pub struct MetricHistory {
    pub rtt: VecDeque<(f64, f32)>, // (virtual_secs, ms)
    pub cwnd: VecDeque<(f64, f32)>,
    pub inflight: VecDeque<(f64, f32)>,
}

impl MetricHistory {
    pub fn push(&mut self, time: f64, rtt: f32, cwnd: f32, inflight: f32) {
        self.rtt.push_back((time, rtt));
        self.cwnd.push_back((time, cwnd));
        self.inflight.push_back((time, inflight));
        if self.rtt.len() > 200 {
            self.rtt.pop_front();
            self.cwnd.pop_front();
            self.inflight.pop_front();
        }
    }
}

pub struct Model {
    pub hub: Arc<VirtualHub>,
    pub nodes: Vec<NodeWrapper>,
    pub gateway: Option<MerkleToxGateway<ToxTransport>>,
    pub table_state: TableState,
    pub conversation_id: ConversationId,
    pub time_provider: Arc<ManualTimeProvider>,
    pub msg_rate: f32,
    pub loss_rate: f32,
    pub jitter_rate: f32,
    pub latency_ms: u64,
    pub virtual_elapsed: Duration,
    pub steps: u64,
    pub rng: StdRng,
    pub is_paused: bool,
    pub run_until_interesting: bool,
    pub last_interesting_state: InterestingState,
    pub current_tab: usize,
    pub active_scenario: Option<Scenario>,
    pub scenario_timer: Option<Instant>,
    pub blob_hash: Option<NodeHash>,
    // Settings Tab State
    pub settings_cursor: usize,
    pub edit_nodes: usize,
    pub edit_real_nodes: usize,
    pub edit_seed: u64,
    pub edit_topology: Topology,
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct InterestingState {
    pub total_verified: usize,
    pub total_speculative: usize,
    pub total_connections: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    LateJoiner,
    PartitionHeal,
    KeyRotationStorm,
    LargeBlobSwarm,
}

impl Model {
    pub fn new(
        num_nodes: usize,
        num_real: usize,
        rate: f32,
        manual: bool,
        seed: u64,
        topology: Topology,
    ) -> Self {
        let now_inst = Instant::now();
        let now_sys = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as i64;
        let time_provider = Arc::new(ManualTimeProvider::new(now_inst, now_sys));

        let hub = Arc::new(VirtualHub::new(time_provider.clone()));
        hub.set_seed(seed);
        let mut seed_rng = StdRng::seed_from_u64(seed);
        let conversation_id = ConversationId::from([0x42u8; 32]);
        let mut nodes = Vec::new();
        let mut real_info: Vec<(DhtId, u16)> = Vec::new();

        // 1. Spawn Real Nodes
        for _ in 0..num_real {
            let mut opts = ToxOptions::new().unwrap();
            opts.set_local_discovery_enabled(false);
            if let Ok(tox) = Tox::new(opts) {
                let pk = PhysicalDevicePk::from(tox.public_key().0);
                let dht_id = tox.dht_id();
                let port = tox.udp_port().unwrap_or(0);
                real_info.push((dht_id, port));

                let transport = ToxTransport {
                    tox: Arc::new(ReentrantMutex::new(tox)),
                    send_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_err: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_err_sendq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_err_not_connected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_err_other: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    recv_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_lock_wait_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_lookup_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    send_ffi_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                };
                let engine = MerkleToxEngine::new(
                    pk,
                    pk.to_logical(),
                    StdRng::seed_from_u64(seed_rng.next_u64()),
                    time_provider.clone(),
                );
                let store = InMemoryStore::new();
                let node = MerkleToxNode::new(
                    engine,
                    GenericTransport::Tox {
                        transport,
                        gateway_pk: None,
                    },
                    store,
                    time_provider.clone(),
                );
                nodes.push(NodeWrapper {
                    node,
                    rx: None,
                    last_authoring: now_inst,
                    history: MetricHistory::default(),
                });
            }
        }

        // 2. Setup Gateway if real nodes are present
        let gateway = if num_real > 0 {
            let transport: Option<ToxTransport> = if let Some(first_real) = nodes.first() {
                match &first_real.node.transport {
                    GenericTransport::Tox { transport, .. } => Some(transport.clone()),
                    _ => None,
                }
            } else {
                let mut opts = ToxOptions::new().unwrap();
                opts.set_local_discovery_enabled(false);
                Tox::new(opts).ok().map(|t| {
                    let dht_id = t.dht_id();
                    let port = t.udp_port().unwrap_or(0);
                    real_info.push((dht_id, port));
                    ToxTransport {
                        tox: Arc::new(ReentrantMutex::new(t)),
                        send_ok: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_err: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_err_sendq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_err_not_connected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_err_other: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        recv_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_lock_wait_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_lookup_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        send_ffi_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    }
                })
            };

            transport.map(|t| MerkleToxGateway::new(hub.clone(), t))
        } else {
            None
        };

        let gateway_pk = gateway.as_ref().map(|gw| gw.real_transport.local_pk());

        // 3. Spawn Virtual Nodes
        for _ in 0..num_nodes {
            let mut pk_bytes = [0u8; 32];
            seed_rng.fill_bytes(&mut pk_bytes);
            let pk = PhysicalDevicePk::from(pk_bytes);
            let rx = hub.register(pk);
            let transport = SimulatedTransport::new(pk, hub.clone());
            let store = InMemoryStore::new();
            let engine = MerkleToxEngine::new(
                pk,
                pk.to_logical(),
                StdRng::seed_from_u64(seed_rng.next_u64()),
                time_provider.clone(),
            );
            let node = MerkleToxNode::new(
                engine,
                GenericTransport::Sim(transport),
                store,
                time_provider.clone(),
            );

            nodes.push(NodeWrapper {
                node,
                rx: Some(rx),
                last_authoring: now_inst,
                history: MetricHistory::default(),
            });
        }

        // 4. Peering Logic based on Topology
        let all_pks: Vec<_> = nodes.iter().map(|n| n.node.engine.self_pk).collect();
        let is_real: Vec<bool> = nodes
            .iter()
            .map(|n| matches!(n.node.transport, GenericTransport::Tox { .. }))
            .collect();

        // Phase 1: Update gateway PK for all real nodes
        for n in &mut nodes {
            if let GenericTransport::Tox { transport, .. } = &n.node.transport {
                let transport = transport.clone();
                n.node.transport = GenericTransport::Tox {
                    transport,
                    gateway_pk,
                };
            }
        }

        // Phase 2: Establish peering relationships
        for i in 0..nodes.len() {
            // Real-world Tox setup (always meshed for DHT stability)
            if let GenericTransport::Tox { transport, .. } = &nodes[i].node.transport {
                let tox_i = transport.tox.lock();
                for (dht_id, port) in &real_info {
                    if *dht_id != tox_i.dht_id() {
                        tox_i.bootstrap("127.0.0.1", *port, dht_id).ok();
                    }
                }
                for (j, pk_j) in all_pks.iter().enumerate().take(nodes.len()) {
                    if i != j && is_real[j] {
                        tox_i
                            .friend_add_norequest(&ToxPublicKey(*pk_j.as_bytes()))
                            .ok();
                    }
                }
                if let Some(gw) = &gateway {
                    let gwpk = gw.real_transport.local_pk();
                    if gwpk != all_pks[i] {
                        tox_i
                            .friend_add_norequest(&ToxPublicKey(*gwpk.as_bytes()))
                            .ok();
                        gw.real_transport
                            .tox
                            .lock()
                            .friend_add_norequest(&ToxPublicKey(*all_pks[i].as_bytes()))
                            .ok();
                    }
                }
            }

            // Merkle-Tox Sync Peering
            for (j, &pk_j) in all_pks.iter().enumerate().take(nodes.len()) {
                if i == j {
                    continue;
                }

                let should_peer = match topology {
                    Topology::Mesh => true,
                    Topology::Star => i == 0 || j == 0,
                    Topology::Dynamic => (seed_rng.next_u32() % 100) < 30,
                };

                if should_peer {
                    let n = &mut nodes[i];
                    let effects =
                        n.node
                            .engine
                            .start_sync(conversation_id, Some(pk_j), &n.node.store);
                    let now = n.node.time_provider.now_instant();
                    let now_ms = n.node.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now;
                    for effect in effects {
                        let _ = n
                            .node
                            .process_effect(effect, now, now_ms, &mut dummy_wakeup);
                    }
                }
            }
        }

        // If gateway is a separate instance, bootstrap it too
        if let Some(gw) = &gateway {
            let gw_tox = gw.real_transport.tox.lock();
            for (dht_id, port) in &real_info {
                if *dht_id != gw_tox.dht_id() {
                    gw_tox.bootstrap("127.0.0.1", *port, dht_id).ok();
                }
            }
        }

        Self {
            hub,
            nodes,
            gateway,
            table_state: TableState::default(),
            conversation_id,
            time_provider,
            msg_rate: rate,
            loss_rate: 0.0,
            jitter_rate: 0.0,
            latency_ms: 0,
            virtual_elapsed: Duration::ZERO,
            steps: 0,
            rng: seed_rng,
            is_paused: manual,
            run_until_interesting: false,
            last_interesting_state: InterestingState::default(),
            current_tab: 0,
            active_scenario: None,
            scenario_timer: None,
            blob_hash: None,
            settings_cursor: 0,
            edit_nodes: num_nodes,
            edit_real_nodes: num_real,
            edit_seed: seed,
            edit_topology: topology,
        }
    }

    pub fn get_interesting_state(&self) -> InterestingState {
        let mut state = InterestingState::default();
        for n in &self.nodes {
            let status = n.node.status(&self.conversation_id);
            state.total_verified += status.verified_count;
            state.total_speculative += status.speculative_count;

            if let GenericTransport::Tox { transport, .. } = &n.node.transport {
                state.total_connections += transport
                    .tox
                    .lock()
                    .friend_list()
                    .iter()
                    .filter(|f| {
                        f.connection_status()
                            .unwrap_or(ToxConnection::TOX_CONNECTION_NONE)
                            != ToxConnection::TOX_CONNECTION_NONE
                    })
                    .count();
            }
        }
        state
    }

    pub fn check_interesting(&mut self) -> bool {
        let current = self.get_interesting_state();
        if current != self.last_interesting_state {
            self.last_interesting_state = current;
            true
        } else {
            false
        }
    }

    pub fn get_convergence_stats(&self) -> (usize, usize) {
        let mut all_heads = HashSet::new();
        for n in &self.nodes {
            for h in n.node.store.get_heads(&self.conversation_id) {
                all_heads.insert(h);
            }
        }

        let mut synced_count = 0;
        for n in &self.nodes {
            let local_heads: HashSet<_> = n
                .node
                .store
                .get_heads(&self.conversation_id)
                .into_iter()
                .collect();
            if local_heads == all_heads && !local_heads.is_empty() {
                synced_count += 1;
            }
        }

        (synced_count, all_heads.len())
    }
}
