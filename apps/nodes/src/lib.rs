//! Bootstrap nodes. toxcore's own DNS is disabled, so hostnames are resolved
//! here, through Tor when the bot uses it.

use serde::Deserialize;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use toxcore::tox::Tox;
use toxcore::types::{DhtId, PUBLIC_KEY_SIZE};

pub const TOR_PROXY: (&str, u16) = ("127.0.0.1", 9050);

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Used when the node list can't be fetched or none of its nodes resolve.
const FALLBACK_NODES: &[&str] = &[
    "144.217.167.73:33445:7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C",
    "49.12.229.145:33445:B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506",
    "49.13.50.193:33445:70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F",
    "172.105.109.31:33445:D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C",
    "144.172.88.203:33445:2016A0F2797EE3A8B004BA623F11AAFC8146F1B8F45107232A1A1AECCE856674",
    "172.104.215.182:33445:DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239",
    "114.35.245.150:33445:3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25",
    "51.79.254.78:33445:F4FC9398B7167668ED2BCF85634E04D4CDCDD2F95DA5F305BD234888B6E6A771",
    "188.214.122.30:33445:2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705",
    "165.227.194.41:443:5D57B95EE4A7F37BA031DAD0CBD9510A9C96FFE09C1CE24A9C33746F39817D6E",
    "141.95.53.16:33445:DCD342A0D5E2AA8E35C2BD2C7988F906EEB631B35100170A7F30E77D7F596442",
    "86.107.187.54:33445:2C0F90965134C7BEFAFE72B077A19221628D7045BB51C1165A2C75CDB2B32634",
    "119.59.101.63:33445:197F746696062FA3BD07BB3BC0656ABD6692B4DAA27DACF0F474754F2B09B060",
    "167.17.40.142:33445:E84453123B44A47120FFB469CBCDEEF078D3785D7AD7F6C5B2351CB5DDE2C54C",
    "172.86.77.39:33445:AFFD3FAD3460E62A894E439534B27E5A5DCFE379C1C0FB78DEF1B150A87E900F",
    "145.239.1.105:33445:1658A9A64046C20F48FB2A47E56045233AB0AC0706974FC5904F9E74F452D908",
    "5.19.249.240:38296:DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238",
];

#[derive(Debug, Clone)]
pub struct Node {
    pub host: String,
    pub port: u16,
    pub public_key: String,
}

#[derive(Deserialize)]
struct ListedNode {
    ipv4: String,
    port: u16,
    tcp_ports: Vec<u16>,
    public_key: String,
    status_udp: bool,
    status_tcp: bool,
}

#[derive(Deserialize)]
struct NodeList {
    nodes: Vec<ListedNode>,
}

/// Parse a `HOST:PORT:HEXPK` CLI node spec. HEXPK is 64 hex chars; the host may
/// itself contain colons (IPv6), so split off the key and port from the right.
pub fn parse(spec: &str) -> Result<Node, String> {
    let mut it = spec.rsplitn(3, ':');
    let public_key = it.next().ok_or("missing public key")?.to_string();
    let port_str = it.next().ok_or("missing port")?;
    let host = it.next().ok_or("missing host")?.to_string();
    if public_key.len() != PUBLIC_KEY_SIZE * 2 || hex::decode(&public_key).is_err() {
        return Err(format!(
            "public key must be {} hex chars",
            PUBLIC_KEY_SIZE * 2
        ));
    }
    let port: u16 = port_str.parse().map_err(|_| "invalid port".to_string())?;
    Ok(Node {
        host,
        port,
        public_key,
    })
}

/// Fetches the node list from `url` and resolves the nodes usable over UDP or
/// TCP (depending on `udp`), falling back to `FALLBACK_NODES`.
pub async fn discover(url: &str, tor: bool, udp: bool) -> Vec<Node> {
    let listed = match fetch(url, tor).await {
        Ok(listed) => select(listed, udp),
        Err(e) => {
            error!("Failed to fetch nodes from {url}: {e}");
            Vec::new()
        }
    };
    let nodes = resolve(listed, tor).await;
    if !nodes.is_empty() {
        return nodes;
    }
    warn!("No usable nodes from {url}, using the built-in list");
    FALLBACK_NODES
        .iter()
        .map(|spec| parse(spec).expect("valid built-in node"))
        .collect()
}

async fn fetch(url: &str, tor: bool) -> Result<Vec<ListedNode>, Box<dyn Error>> {
    let mut client = reqwest::Client::builder().timeout(Duration::from_secs(60));
    if tor {
        let (host, port) = TOR_PROXY;
        client = client.proxy(reqwest::Proxy::all(format!("socks5h://{host}:{port}"))?);
    }
    let list: NodeList = client
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(list.nodes)
}

fn select(listed: Vec<ListedNode>, udp: bool) -> Vec<Node> {
    listed
        .into_iter()
        .filter(|n| n.ipv4 != "NONE" && n.ipv4 != "-")
        .filter_map(|n| {
            let port = if udp {
                n.status_udp.then_some(n.port)?
            } else if !n.status_tcp {
                return None;
            } else if n.tcp_ports.contains(&n.port) {
                n.port
            } else {
                *n.tcp_ports.first()?
            };
            Some(Node {
                host: n.ipv4,
                port,
                public_key: n.public_key,
            })
        })
        .collect()
}

/// Replaces each node's host with its IP address, dropping nodes that don't
/// resolve.
pub async fn resolve(nodes: Vec<Node>, tor: bool) -> Vec<Node> {
    let mut tasks = JoinSet::new();
    for node in nodes {
        tasks.spawn(async move {
            match tokio::time::timeout(RESOLVE_TIMEOUT, resolve_host(&node.host, tor)).await {
                Ok(Ok(ip)) => Some(Node {
                    host: ip.to_string(),
                    ..node
                }),
                Ok(Err(e)) => {
                    warn!("Failed to resolve {}: {e}", node.host);
                    None
                }
                Err(_) => {
                    warn!("Timed out resolving {}", node.host);
                    None
                }
            }
        });
    }
    let mut resolved = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(node)) = result {
            resolved.push(node);
        }
    }
    resolved
}

async fn resolve_host(host: &str, tor: bool) -> Result<IpAddr, Box<dyn Error + Send + Sync>> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    if tor {
        return tor_resolve(host).await;
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
        .await?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| "no addresses".into())
}

/// Resolves `host` with Tor's SOCKS5 RESOLVE extension (as `tor-resolve` does).
async fn tor_resolve(host: &str) -> Result<IpAddr, Box<dyn Error + Send + Sync>> {
    let mut stream = TcpStream::connect(TOR_PROXY).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err("Tor refused the SOCKS5 handshake".into());
    }

    let mut request = vec![5, 0xf0, 0, 3, u8::try_from(host.len())?];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&[0, 0]);
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(format!("Tor RESOLVE failed with SOCKS error {}", reply[1]).into());
    }
    match reply[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Ok(IpAddr::from(ip))
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Ok(IpAddr::from(ip))
        }
        t => Err(format!("unexpected SOCKS address type {t}").into()),
    }
}

pub fn bootstrap(tox: &Tox, nodes: &[Node]) {
    info!("Bootstrapping from {} nodes", nodes.len());
    for node in nodes {
        if let Ok(pk_bytes) = hex::decode(&node.public_key)
            && pk_bytes.len() == PUBLIC_KEY_SIZE
        {
            let mut pk_arr = [0u8; PUBLIC_KEY_SIZE];
            pk_arr.copy_from_slice(&pk_bytes);
            let dht_id = DhtId(pk_arr);
            if let Err(e) = tox.bootstrap(&node.host, node.port, &dht_id) {
                error!("Failed to bootstrap to node {}: {}", node.host, e);
            }
            if let Err(e) = tox.add_tcp_relay(&node.host, node.port, &dht_id) {
                error!("Failed to add tcp relay {}: {}", node.host, e);
            }
        }
    }
}
