use crate::utils::decode_hex;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::{error, fs, io};
use toxcore::tox::Tox;
use toxcore::types::{PUBLIC_KEY_SIZE, PublicKey};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Node {
    pub ipv4: String,
    pub ipv6: String,
    pub port: u16,
    pub tcp_ports: Option<Vec<u16>>,
    pub public_key: String,
    pub status_udp: bool,
    pub status_tcp: bool,
    pub maintainer: String,
    pub location: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<Node>,
}

const NODES_URL: &str = "https://nodes.tox.chat/json";

pub async fn fetch_nodes() -> Result<Vec<Node>, Box<dyn error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp: NodesResponse = client.get(NODES_URL).send().await?.json().await?;
    Ok(resp.nodes)
}

pub fn get_cached_nodes(config_dir: &Path) -> Option<Vec<Node>> {
    let nodes_path = config_dir.join("nodes.json");
    if nodes_path.exists()
        && let Ok(data) = fs::read_to_string(&nodes_path)
        && let Ok(nodes) = serde_json::from_str::<Vec<Node>>(&data)
    {
        return Some(nodes);
    }
    None
}

pub fn save_nodes(config_dir: &Path, nodes: &[Node]) -> io::Result<()> {
    let nodes_path = config_dir.join("nodes.json");
    let data = serde_json::to_string(nodes)?;
    let mut file = fs::File::create(nodes_path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

pub async fn setup_nodes(config_dir: &Path) -> (Vec<Node>, Vec<String>) {
    let mut logs = Vec::new();
    let mut nodes = get_cached_nodes(config_dir).unwrap_or_default();

    if nodes.is_empty() {
        logs.push("Fetching bootstrap nodes...".to_owned());
        match fetch_nodes().await {
            Ok(fetched_nodes) => {
                logs.push(format!("Fetched {} nodes.", fetched_nodes.len()));
                let _ = save_nodes(config_dir, &fetched_nodes);
                nodes = fetched_nodes;
            }
            Err(e) => logs.push(format!("Failed to fetch nodes: {}", e)),
        }
    }
    (nodes, logs)
}

pub fn select_random_nodes(nodes: &[Node], count: usize) -> Vec<Node> {
    let mut rng = rand::thread_rng();
    let viable_nodes: Vec<Node> = nodes
        .iter()
        .filter(|n| n.status_udp && n.status_tcp) // Prefer nodes with both UDP and TCP
        .cloned()
        .collect();

    // If not enough perfect nodes, fallback to any
    let mut candidates = if viable_nodes.len() >= count {
        viable_nodes
    } else {
        nodes.to_vec()
    };

    candidates.shuffle(&mut rng);
    candidates.into_iter().take(count).collect()
}

pub fn bootstrap_network(tox: &Tox, nodes: &[Node]) -> Vec<String> {
    let mut logs = Vec::new();
    let selected = select_random_nodes(nodes, 4);
    for node in selected {
        logs.push(format!(
            "Bootstrapping to: {} ({})",
            node.ipv4, node.location
        ));
        if let Some(pk_bytes) = decode_hex(&node.public_key)
            && pk_bytes.len() == PUBLIC_KEY_SIZE
        {
            let mut pk_arr = [0u8; PUBLIC_KEY_SIZE];
            pk_arr.copy_from_slice(&pk_bytes);
            let pk = PublicKey(pk_arr);
            let _ = tox.bootstrap(&node.ipv4, node.port, &pk);

            // Add TCP relays
            if let Some(ports) = &node.tcp_ports {
                for port in ports {
                    let _ = tox.add_tcp_relay(&node.ipv4, *port, &pk);
                }
            } else {
                // Fallback to the main port if no specific TCP ports listed
                let _ = tox.add_tcp_relay(&node.ipv4, node.port, &pk);
            }
        }
    }
    logs
}
