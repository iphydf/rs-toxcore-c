use clap::Parser;
use merkle_tox_client::MerkleToxClient;
use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk, PhysicalDeviceSk};
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::{NodeEvent, NodeEventHandler, Transport};
use merkle_tox_fs::FsStore;
use merkle_tox_tox::ToxTransport;
use parking_lot::ReentrantMutex;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use toxcore::tox::{Options, Tox, ToxSavedataType};
use toxcore::types::{PUBLIC_KEY_SIZE, PublicKey};
use tracing::{error, info};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Node {
    ipv4: String,
    ipv6: String,
    port: u16,
    tcp_ports: Option<Vec<u16>>,
    public_key: String,
    status_udp: bool,
    status_tcp: bool,
    maintainer: String,
    location: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct NodesResponse {
    nodes: Vec<Node>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    savedata: Option<String>,
    #[arg(short = 't', long, default_value = "vault_storage")]
    storage: String,
}

type VaultClient = MerkleToxClient<ToxTransport, FsStore>;
type ClientMap = HashMap<ConversationId, Arc<VaultClient>>;

struct Dispatcher {
    node: Arc<Mutex<MerkleToxNode<ToxTransport, FsStore>>>,
    clients: Arc<Mutex<ClientMap>>,
}

impl NodeEventHandler for Dispatcher {
    fn handle_event(&self, event: NodeEvent) {
        let node = self.node.clone();
        let clients = self.clients.clone();
        tokio::spawn(async move {
            match event {
                NodeEvent::NodeVerified {
                    conversation_id, ..
                }
                | NodeEvent::NodeSpeculative {
                    conversation_id, ..
                } => {
                    let mut clients_lock = clients.lock().await;
                    let client = if let Some(c) = clients_lock.get(&conversation_id) {
                        c.clone()
                    } else {
                        info!("Discovered conversation: {:?}", conversation_id);
                        let c = Arc::new(MerkleToxClient::new(node, conversation_id));
                        if let Err(e) = c.refresh_state().await {
                            error!("Failed to refresh state for {:?}: {}", conversation_id, e);
                        }
                        clients_lock.insert(conversation_id, c.clone());
                        c
                    };
                    if let Err(e) = client.handle_event(event).await {
                        error!("Error handling node event: {}", e);
                    }
                }
                NodeEvent::PeerHandshakeComplete { .. } => {
                    let clients_lock = clients.lock().await;
                    for client in clients_lock.values() {
                        let _ = client.handle_event(event.clone()).await;
                    }
                }
                _ => {}
            }
        });
    }
}

struct VaultBot {
    tox: Arc<ReentrantMutex<Tox>>,
    node: Arc<Mutex<MerkleToxNode<ToxTransport, FsStore>>>,
    _clients: Arc<Mutex<ClientMap>>,
    _storage_path: PathBuf,
    savedata_path: Option<PathBuf>,
    shutdown: Arc<AtomicBool>,
    dirty: bool,
}

use merkle_tox_core::vfs::StdFileSystem;

impl VaultBot {
    fn new(
        tox: Tox,
        storage_path: PathBuf,
        savedata_path: Option<PathBuf>,
        shutdown: Arc<AtomicBool>,
        dirty: bool,
    ) -> Self {
        let store_path = storage_path.join("merkle_tox");
        let store =
            FsStore::new(store_path, Arc::new(StdFileSystem)).expect("Failed to create FsStore");
        let self_sk = tox.secret_key();
        let tox_shared = Arc::new(ReentrantMutex::new(tox));
        let transport = ToxTransport {
            tox: tox_shared.clone(),
        };
        let self_pk = transport.local_pk();
        let engine = merkle_tox_core::engine::MerkleToxEngine::with_sk(
            self_pk,
            self_pk.to_logical(),
            PhysicalDeviceSk::from(self_sk),
            rand::SeedableRng::from_entropy(),
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        let node = Arc::new(Mutex::new(MerkleToxNode::new(
            engine,
            transport,
            store,
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        )));
        let clients = Arc::new(Mutex::new(HashMap::new()));

        let dispatcher = Dispatcher {
            node: node.clone(),
            clients: clients.clone(),
        };

        {
            let mut node_lock = node.blocking_lock();
            node_lock.set_event_handler(Arc::new(dispatcher));
        }

        Self {
            tox: tox_shared,
            node,
            _clients: clients,
            _storage_path: storage_path,
            savedata_path,
            shutdown,
            dirty,
        }
    }

    fn save(&mut self) {
        if let Some(path) = &self.savedata_path {
            let data = self.tox.lock().savedata();
            if let Err(e) = fs::write(path, data) {
                error!("Failed to save savedata: {}", e);
            } else {
                info!("Savedata saved to {:?}", path);
                self.dirty = false;
            }
        }
    }

    async fn run(&mut self) {
        let mut last_save = Instant::now();
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("Graceful shutdown...");
                if self.dirty {
                    self.save();
                }
                break;
            }

            // Periodic Save
            if self.dirty && last_save.elapsed() > Duration::from_secs(30) {
                self.save();
                last_save = Instant::now();
            }

            if let Ok(events) = self.tox.lock().events() {
                // Auto-accept friends
                for event in &events {
                    match event {
                        toxcore::tox::events::Event::FriendRequest(e) => {
                            info!("Friend request from {}", hex::encode(e.public_key().0));
                            if self
                                .tox
                                .lock()
                                .friend_add_norequest(&e.public_key())
                                .is_ok()
                            {
                                self.dirty = true;
                            }
                        }
                        toxcore::tox::events::Event::FriendConnectionStatus(e) => {
                            let status = e.connection_status();
                            if status != toxcore::tox::ToxConnection::TOX_CONNECTION_NONE
                                && let Ok(pk) =
                                    self.tox.lock().friend(e.friend_number()).public_key()
                            {
                                info!("Tox friend connected, initiating MT handshake");
                                let caps = merkle_tox_core::ProtocolMessage::CapsAnnounce {
                                    version: 1,
                                    features: 0,
                                };
                                self.node
                                    .lock()
                                    .await
                                    .send_message(PhysicalDevicePk::from(pk.0), caps);
                            }
                        }
                        toxcore::tox::events::Event::FriendLossyPacket(e) => {
                            let data = e.data();
                            if data.first() == Some(&merkle_tox_tox::TOX_CUSTOM_PACKET_ID)
                                && let Ok(pk) =
                                    self.tox.lock().friend(e.friend_number()).public_key()
                            {
                                self.node
                                    .lock()
                                    .await
                                    .handle_packet(PhysicalDevicePk::from(pk.0), &data[1..]);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Poll for retransmissions and background tasks
            let next_mt_wakeup = self.node.lock().await.poll();

            let tox_interval = self.tox.lock().iteration_interval();
            let next_tox_wakeup = Instant::now() + Duration::from_millis(tox_interval as u64);

            let sleep_until = next_mt_wakeup.min(next_tox_wakeup);
            let sleep_duration = sleep_until.saturating_duration_since(Instant::now());

            if !sleep_duration.is_zero() {
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }
}

const NODES_URL: &str = "https://nodes.tox.chat/json";

async fn fetch_nodes() -> Result<Vec<Node>, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp: NodesResponse = client.get(NODES_URL).send().await?.json().await?;
    Ok(resp.nodes)
}

fn get_cached_nodes(storage_path: &std::path::Path) -> Option<Vec<Node>> {
    let nodes_path = storage_path.join("nodes.json");
    if nodes_path.exists()
        && let Ok(data) = fs::read_to_string(&nodes_path)
        && let Ok(nodes) = serde_json::from_str::<Vec<Node>>(&data)
    {
        return Some(nodes);
    }
    None
}

fn save_nodes(storage_path: &std::path::Path, nodes: &[Node]) -> io::Result<()> {
    let nodes_path = storage_path.join("nodes.json");
    let data = serde_json::to_string(nodes)?;
    fs::write(nodes_path, data)
}

async fn setup_nodes(storage_path: &std::path::Path) -> Vec<Node> {
    let mut nodes = get_cached_nodes(storage_path).unwrap_or_default();

    if nodes.is_empty() {
        match fetch_nodes().await {
            Ok(fetched_nodes) => {
                let _ = save_nodes(storage_path, &fetched_nodes);
                nodes = fetched_nodes;
            }
            Err(e) => eprintln!("Failed to fetch nodes: {}", e),
        }
    }
    nodes
}

fn select_random_nodes(nodes: &[Node], count: usize) -> Vec<Node> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let viable_nodes: Vec<Node> = nodes
        .iter()
        .filter(|n| n.status_udp && n.status_tcp)
        .cloned()
        .collect();

    let mut candidates = if viable_nodes.len() >= count {
        viable_nodes
    } else {
        nodes.to_vec()
    };

    candidates.shuffle(&mut rng);
    candidates.into_iter().take(count).collect()
}

fn bootstrap_network(tox: &Tox, nodes: &[Node]) {
    let selected = select_random_nodes(nodes, 4);
    for node in selected {
        if let Ok(pk_bytes) = hex::decode(&node.public_key)
            && pk_bytes.len() == PUBLIC_KEY_SIZE
        {
            let mut pk_arr = [0u8; PUBLIC_KEY_SIZE];
            pk_arr.copy_from_slice(&pk_bytes);
            let pk = PublicKey(pk_arr);
            let _ = tox.bootstrap(&node.ipv4, node.port, &pk);

            if let Some(ports) = &node.tcp_ports {
                for port in ports {
                    let _ = tox.add_tcp_relay(&node.ipv4, *port, &pk);
                }
            } else {
                let _ = tox.add_tcp_relay(&node.ipv4, node.port, &pk);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let storage_path = PathBuf::from(&args.storage);
    fs::create_dir_all(&storage_path)?;

    let mut loaded = false;
    let mut opts = Options::new()?;
    let savedata_path = args.savedata.map(PathBuf::from);
    if let Some(path) = &savedata_path
        && path.exists()
    {
        let data = fs::read(path)?;
        opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
        let _ = opts.set_savedata_data(&data);
        loaded = true;
    }

    let tox = Tox::new(opts)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_ctrlc = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nCtrl-C received, shutting down...");
            shutdown_ctrlc.store(true, Ordering::SeqCst);
        }
    });

    let mut bot = VaultBot::new(tox, storage_path.clone(), savedata_path, shutdown, !loaded);

    let address = bot.tox.lock().address();
    println!("VaultBot started! Tox ID: {:?}", address);

    // Bootstrap
    let nodes = setup_nodes(&storage_path).await;
    bootstrap_network(&bot.tox.lock(), &nodes);

    bot.run().await;

    Ok(())
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
