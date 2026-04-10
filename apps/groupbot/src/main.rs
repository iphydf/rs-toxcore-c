use clap::Parser;
use merkle_tox_client::MerkleToxClient;
use merkle_tox_core::dag::{ConversationId, LogicalIdentityPk, PhysicalDeviceSk};
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::{NodeEvent, NodeEventHandler, Transport};
use merkle_tox_fs::FsStore;
use merkle_tox_tox::{ToxMerkleBridge, ToxTransport};
use parking_lot::ReentrantMutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use toxcore::tox::events::Event;
use toxcore::tox::{
    ConferenceNumber, GroupNumber, Options, Tox, ToxProxyType, ToxSavedataType, encryptsave,
};
use toxcore::types::{
    ConferencePeerNumber, DhtId, FriendNumber, GroupPeerNumber, MessageType, PUBLIC_KEY_SIZE,
    PublicKey, ToxConferenceType, ToxConnection,
};

mod plugin;
mod plugins;

use plugin::{CommandContext, CommandSource, Plugin};
use plugins::{Echo, Forwarder, GitHub};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    savefile: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "ToxGroupBot")]
    nick: String,
    #[arg(long, default_value = "Tox Group Bot")]
    status_message: String,
    #[arg(long, default_value = "https://nodes.tox.chat/json")]
    nodes_url: String,
    #[arg(long, default_value = "tools/toktok-backup")]
    github_path: String,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    tor: bool,
}

enum BotEvent {
    SelfConnectionStatus(ToxConnection),
    FriendRequest(PublicKey, String),
    FriendConnectionStatus(FriendNumber, ToxConnection),
    FriendMessage(FriendNumber, MessageType, String),
    GroupMessage(GroupNumber, GroupPeerNumber, MessageType, String),
    ConferenceMessage(ConferenceNumber, ConferencePeerNumber, MessageType, String),
    ConferenceInvite(FriendNumber, ToxConferenceType, Vec<u8>),
    GroupInvite(FriendNumber, Vec<u8>),
    MerkleToxMessage(ConversationId, LogicalIdentityPk, String),
}

type BotClient = MerkleToxClient<ToxTransport, FsStore>;
type ClientMap = HashMap<ConversationId, Arc<BotClient>>;

struct GroupBot {
    tox: Arc<ReentrantMutex<Tox>>,
    bridge: Arc<Mutex<ToxMerkleBridge<FsStore>>>,
    clients: Arc<Mutex<ClientMap>>,
    plugins: Vec<Box<dyn Plugin>>,
    savefile: Option<PathBuf>,
    #[allow(dead_code)]
    password: Option<String>,
}

struct Dispatcher {
    node: Arc<Mutex<MerkleToxNode<ToxTransport, FsStore>>>,
    clients: Arc<Mutex<ClientMap>>,
    bot_event_tx: tokio::sync::mpsc::UnboundedSender<BotEvent>,
}

impl NodeEventHandler for Dispatcher {
    fn handle_event(&self, event: NodeEvent) {
        let node = self.node.clone();
        let clients = self.clients.clone();
        let tx = self.bot_event_tx.clone();

        tokio::spawn(async move {
            match event {
                NodeEvent::NodeVerified {
                    conversation_id,
                    node: merkle_node,
                    hash,
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

                    if let merkle_tox_core::dag::Content::Text(text) = &merkle_node.content
                        && let Err(e) = tx.send(BotEvent::MerkleToxMessage(
                            conversation_id,
                            merkle_node.author_pk,
                            text.clone(),
                        ))
                    {
                        error!("Failed to send MerkleToxMessage to channel: {}", e);
                    }

                    if let Err(e) = client
                        .handle_event(NodeEvent::NodeVerified {
                            conversation_id,
                            hash,
                            node: merkle_node,
                        })
                        .await
                    {
                        error!("Error handling node event: {}", e);
                    }
                }
                NodeEvent::PeerHandshakeComplete { peer_pk } => {
                    let clients_lock = clients.lock().await;
                    for client in clients_lock.values() {
                        if let Err(e) = client
                            .handle_event(NodeEvent::PeerHandshakeComplete { peer_pk })
                            .await
                        {
                            error!("Error handling PeerHandshakeComplete: {}", e);
                        }
                    }
                }
                _ => {}
            }
        });
    }
}

use merkle_tox_core::vfs::StdFileSystem;

impl GroupBot {
    async fn new(
        tox: Tox,
        args: &Args,
        savefile: Option<PathBuf>,
        bot_event_tx: tokio::sync::mpsc::UnboundedSender<BotEvent>,
    ) -> Self {
        let plugins: Vec<Box<dyn Plugin>> = vec![
            Box::new(Forwarder),
            Box::new(Echo),
            Box::new(GitHub::new(PathBuf::from(&args.github_path))),
        ];

        let self_sk = tox.secret_key();
        let tox_shared = Arc::new(ReentrantMutex::new(tox));
        let transport = ToxTransport {
            tox: tox_shared.clone(),
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
        let self_pk = transport.local_pk();
        let engine = merkle_tox_core::engine::MerkleToxEngine::with_sk(
            self_pk,
            self_pk.to_logical(),
            PhysicalDeviceSk::from(self_sk),
            rand::SeedableRng::from_entropy(),
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );

        let store_path = if let Some(ref path) = savefile {
            path.parent()
                .unwrap_or_else(|| Path::new(""))
                .join("merkle_tox_groupbot")
        } else {
            PathBuf::from("merkle_tox_groupbot")
        };
        if let Err(e) = fs::create_dir_all(&store_path) {
            error!("Failed to create directory {}: {}", store_path.display(), e);
        }
        let store =
            FsStore::new(store_path, Arc::new(StdFileSystem)).expect("Failed to create FsStore");
        let node = MerkleToxNode::new(
            engine,
            transport,
            store,
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        let node_arc = Arc::new(Mutex::new(node));
        let bridge = Arc::new(Mutex::new(ToxMerkleBridge::with_node(node_arc.clone())));
        let clients = Arc::new(Mutex::new(ClientMap::new()));

        let dispatcher = Dispatcher {
            node: node_arc.clone(),
            clients: clients.clone(),
            bot_event_tx,
        };

        {
            let mut node_lock = node_arc.lock().await;
            node_lock.set_event_handler(Arc::new(dispatcher));
        }

        Self {
            tox: tox_shared,
            bridge,
            clients,
            plugins,
            savefile,
            password: args.password.clone(),
        }
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        if let Some(path) = &self.savefile {
            let mut data = self.tox.lock().savedata();
            if let Some(password) = &self.password {
                data = encryptsave::encrypt(&data, password.as_bytes())?;
            }
            fs::write(path, data)?;
        }
        Ok(())
    }

    fn is_admin(&self, pk: &PublicKey) -> bool {
        match self.tox.lock().friend(FriendNumber(0)).public_key() {
            Ok(admin_pk) => admin_pk == *pk,
            Err(_) => false,
        }
    }

    async fn handle_command(&mut self, context: &CommandContext, message: &str) -> Option<String> {
        if !message.starts_with('!') {
            return None;
        }

        let parts: Vec<String> = message[1..]
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if parts.is_empty() {
            return None;
        }

        let cmd = &parts[0];
        let args = &parts[1..];

        // Built-in commands
        match cmd.as_str() {
            "save" => {
                if !self.is_admin(&context.sender_pk) {
                    return Some("You must be an admin to use this command.".to_string());
                }
                if let Err(e) = self.save() {
                    return Some(format!("Error saving: {}", e));
                }
                return Some("State saved.".to_string());
            }
            "nick" => {
                if !self.is_admin(&context.sender_pk) {
                    return Some("You must be an admin to use this command.".to_string());
                }
                if args.is_empty() {
                    return Some("Usage: !nick <nickname>".to_string());
                }
                let new_nick = args.join(" ");
                {
                    let tox = self.tox.lock();
                    if let Err(e) = tox.set_name(new_nick.as_bytes()) {
                        error!("Failed to set nick: {}", e);
                    }
                    if let Err(e) = tox.group(GroupNumber(0)).self_set_name(new_nick.as_bytes()) {
                        error!("Failed to set group nick: {}", e);
                    }
                }
                return Some(format!("Nickname set to {}", new_nick));
            }
            "leave" => {
                if !self.is_admin(&context.sender_pk) {
                    return Some("You must be an admin to use this command.".to_string());
                }
                {
                    let tox = self.tox.lock();
                    if let Err(e) = tox.conference(ConferenceNumber(0)).delete() {
                        error!("Failed to delete conference: {}", e);
                    }
                    if let Err(e) = tox.group(GroupNumber(0)).leave(Some(b"Goodbye!")) {
                        error!("Failed to leave group: {}", e);
                    }
                }
                return Some("Left conference and group 0.".to_string());
            }
            _ => {}
        }

        for plugin in &mut self.plugins {
            if plugin.name() == cmd || (cmd == "gh" && plugin.name() == "gh") {
                match plugin.on_command(&self.tox.lock(), context, args) {
                    Ok(Some(reply)) => return Some(reply),
                    Ok(None) => {}
                    Err(e) => return Some(format!("Error in plugin {}: {}", plugin.name(), e)),
                }
            }
        }

        None
    }

    async fn send_reply(&self, source: &CommandSource, message_type: MessageType, text: &str) {
        match source {
            CommandSource::Friend(friend_number) => {
                if let Err(e) = self
                    .tox
                    .lock()
                    .friend(*friend_number)
                    .send_message(message_type, text.as_bytes())
                {
                    error!("Failed to send friend message: {}", e);
                }
            }
            CommandSource::Group(group_number) => {
                if let Err(e) = self
                    .tox
                    .lock()
                    .group(*group_number)
                    .send_message(message_type, text.as_bytes())
                {
                    error!("Failed to send group message: {}", e);
                }
            }
            CommandSource::Conference(conference_number) => {
                if let Err(e) = self
                    .tox
                    .lock()
                    .conference(*conference_number)
                    .send_message(message_type, text.as_bytes())
                {
                    error!("Failed to send conference message: {}", e);
                }
            }
            CommandSource::MerkleTox(conversation_id) => {
                let clients = self.clients.lock().await;
                if let Some(client) = clients.get(conversation_id)
                    && let Err(e) = client.send_message(text.to_string()).await
                {
                    error!("Failed to send MerkleTox message: {}", e);
                }
            }
        }
    }

    async fn run(
        &mut self,
        shutdown: Arc<AtomicBool>,
        mut bot_event_rx: tokio::sync::mpsc::UnboundedReceiver<BotEvent>,
    ) -> Result<(), Box<dyn Error>> {
        {
            let tox = self.tox.lock();
            let conferences = tox.conference_chatlist();
            if !conferences
                .iter()
                .any(|c| c.number() == ConferenceNumber(0))
            {
                error!("Conference 0 not found in chatlist! Invitation logic will fail.");
            } else {
                info!("Conference 0 found.");
            }
            if tox.group_count() == 0 {
                error!("No groups found! Group invitation logic will fail.");
            } else {
                info!("Group 0 found (assuming first group is 0).");
            }
        }
        let mut last_save = Instant::now();
        let mut loop_count = 0;
        let mut last_loop_report = Instant::now();

        while !shutdown.load(Ordering::SeqCst) {
            loop_count += 1;
            let now = Instant::now();
            if now.duration_since(last_loop_report) > Duration::from_secs(1) {
                if loop_count > 1000 {
                    error!("Tight loop detected: {} iterations in 1s", loop_count);
                }
                loop_count = 0;
                last_loop_report = now;
            }

            let mut bot_events = Vec::new();

            // Pull events from receiver (Merkle-Tox)
            while let Ok(event) = bot_event_rx.try_recv() {
                bot_events.push(event);
            }

            if let Ok(events) = self.tox.lock().events() {
                for event in &events {
                    // Dispatch to plugins
                    for plugin in &mut self.plugins {
                        if let Err(e) = plugin.on_event(&self.tox.lock(), &event) {
                            error!("Plugin {} error: {}", plugin.name(), e);
                        }
                    }

                    // Handle Merkle-Tox protocol events via bridge
                    let handled_by_bridge = self.bridge.lock().await.handle_event(&event).await;

                    if handled_by_bridge.is_some()
                        && !matches!(event, Event::FriendConnectionStatus(_))
                    {
                        continue;
                    }

                    match event {
                        Event::SelfConnectionStatus(e) => {
                            bot_events.push(BotEvent::SelfConnectionStatus(e.connection_status()));
                        }
                        Event::FriendRequest(e) => {
                            bot_events.push(BotEvent::FriendRequest(
                                e.public_key(),
                                String::from_utf8_lossy(e.message()).into_owned(),
                            ));
                        }
                        Event::FriendConnectionStatus(e) => {
                            bot_events.push(BotEvent::FriendConnectionStatus(
                                e.friend_number(),
                                e.connection_status(),
                            ));
                        }
                        Event::FriendMessage(e) => {
                            bot_events.push(BotEvent::FriendMessage(
                                e.friend_number(),
                                e.message_type(),
                                String::from_utf8_lossy(e.message()).into_owned(),
                            ));
                        }
                        Event::GroupMessage(e) => {
                            bot_events.push(BotEvent::GroupMessage(
                                e.group_number(),
                                e.peer_id(),
                                e.message_type(),
                                String::from_utf8_lossy(e.message()).into_owned(),
                            ));
                        }
                        Event::ConferenceMessage(e) => {
                            bot_events.push(BotEvent::ConferenceMessage(
                                e.conference_number(),
                                e.peer_number(),
                                e.message_type(),
                                String::from_utf8_lossy(e.message()).into_owned(),
                            ));
                        }
                        Event::ConferenceInvite(e) => {
                            bot_events.push(BotEvent::ConferenceInvite(
                                e.friend_number(),
                                e.conference_type(),
                                e.cookie().to_vec(),
                            ));
                        }
                        Event::GroupInvite(e) => {
                            bot_events.push(BotEvent::GroupInvite(
                                e.friend_number(),
                                e.invite_data().to_vec(),
                            ));
                        }
                        _ => {}
                    }
                }
            }

            for event in bot_events {
                match event {
                    BotEvent::SelfConnectionStatus(status) => {
                        info!("Connection status: {:?}", status);
                    }
                    BotEvent::FriendRequest(pk, message) => {
                        info!(
                            "Friend request from: {} with message: {}",
                            hex::encode(pk.0),
                            message
                        );
                        let _ = self.tox.lock().friend_add_norequest(&pk);
                        if let Err(e) = self.save() {
                            error!("Failed to save state after friend request: {}", e);
                        }
                    }
                    BotEvent::FriendConnectionStatus(friend_number, status) => {
                        debug!("Friend {} status: {:?}", friend_number.0, status);
                        if status != ToxConnection::TOX_CONNECTION_NONE {
                            let tox = self.tox.lock();
                            let friend = tox.friend(friend_number);
                            debug!(
                                "Inviting friend {} to conference 0 and group 0",
                                friend_number.0
                            );

                            if let Err(e) = tox.conference(ConferenceNumber(0)).invite(&friend) {
                                error!(
                                    "Failed to invite friend {} to conference 0: {}",
                                    friend_number.0, e
                                );
                            }
                            if let Err(e) = tox.group(GroupNumber(0)).invite_friend(&friend) {
                                error!(
                                    "Failed to invite friend {} to group 0: {}",
                                    friend_number.0, e
                                );
                            }
                        }
                    }
                    BotEvent::FriendMessage(friend_number, message_type, message) => {
                        let sender_pk = self.tox.lock().friend(friend_number).public_key().ok();
                        if let Some(pk) = sender_pk {
                            let context = CommandContext {
                                source: CommandSource::Friend(friend_number),
                                sender_pk: pk,
                                message_type,
                            };
                            if let Some(reply) = self.handle_command(&context, &message).await {
                                self.send_reply(&context.source, message_type, &reply).await;
                            }
                        }
                    }
                    BotEvent::GroupMessage(group_number, peer_id, message_type, message) => {
                        if message.starts_with('!') {
                            let (pk, peer_name) = {
                                let tox = self.tox.lock();
                                let group = tox.group(group_number);
                                (
                                    group.peer_public_key(peer_id).ok(),
                                    group.peer_name(peer_id).unwrap_or_default(),
                                )
                            };
                            if let Some(pk) = pk {
                                let context = CommandContext {
                                    source: CommandSource::Group(group_number),
                                    sender_pk: pk,
                                    message_type,
                                };
                                if let Some(reply) = self.handle_command(&context, &message).await {
                                    let formatted_reply = format!(
                                        "{}: {}",
                                        String::from_utf8_lossy(&peer_name),
                                        reply
                                    );
                                    self.send_reply(
                                        &context.source,
                                        message_type,
                                        &formatted_reply,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    BotEvent::ConferenceMessage(
                        conference_number,
                        peer_number,
                        message_type,
                        message,
                    ) => {
                        if message.starts_with('!') {
                            let (ours, pk, peer_name) = {
                                let tox = self.tox.lock();
                                let conf = tox.conference(conference_number);
                                (
                                    conf.peer_number_is_ours(peer_number).unwrap_or(false),
                                    conf.peer_public_key(peer_number).ok(),
                                    conf.peer_name(peer_number).unwrap_or_default(),
                                )
                            };
                            if ours {
                                continue;
                            }
                            if let Some(pk) = pk {
                                let context = CommandContext {
                                    source: CommandSource::Conference(conference_number),
                                    sender_pk: pk,
                                    message_type,
                                };
                                if let Some(reply) = self.handle_command(&context, &message).await {
                                    let formatted_reply = format!(
                                        "{}: {}",
                                        String::from_utf8_lossy(&peer_name),
                                        reply
                                    );
                                    self.send_reply(
                                        &context.source,
                                        message_type,
                                        &formatted_reply,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    BotEvent::ConferenceInvite(friend_number, _type, cookie) => {
                        if friend_number.0 == 0 {
                            let tox = self.tox.lock();
                            if let Err(e) = tox.conference_join(&tox.friend(friend_number), &cookie)
                            {
                                error!("Failed to join conference: {}", e);
                            }
                        }
                    }
                    BotEvent::GroupInvite(friend_number, invite_data) => {
                        if friend_number.0 == 0 {
                            let tox = self.tox.lock();
                            if let Err(e) = tox.group_invite_accept(
                                &tox.friend(friend_number),
                                &invite_data,
                                tox.name().as_slice(),
                                None,
                            ) {
                                error!("Failed to accept group invite: {}", e);
                            }
                        }
                    }
                    BotEvent::MerkleToxMessage(conversation_id, sender_pk, message) => {
                        if message.starts_with('!') {
                            let context = CommandContext {
                                source: CommandSource::MerkleTox(conversation_id),
                                sender_pk: PublicKey(*sender_pk.as_bytes()),
                                message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                            };

                            if let Some(reply) = self.handle_command(&context, &message).await {
                                self.send_reply(&context.source, context.message_type, &reply)
                                    .await;
                            }
                        }
                    }
                }
            }

            if now.duration_since(last_save) > Duration::from_secs(600) {
                if let Err(e) = self.save() {
                    error!("Failed to save state during periodic save: {}", e);
                }
                last_save = now;
            }

            let next_mt_wakeup = self.bridge.lock().await.poll().await;
            let tox_interval = self.tox.lock().iteration_interval();
            let next_tox_wakeup = now + Duration::from_millis(tox_interval as u64);

            let sleep_until = next_mt_wakeup.min(next_tox_wakeup);
            let sleep_duration = sleep_until.saturating_duration_since(Instant::now());

            if !sleep_duration.is_zero() {
                tokio::time::sleep(sleep_duration).await;
            }
        }

        self.save()?;
        Ok(())
    }
}
#[derive(Deserialize, Debug, Clone)]
struct Node {
    ipv4: String,
    port: u16,
    public_key: String,
    last_ping: i64,
}

#[derive(Deserialize, Debug)]
struct NodesResponse {
    nodes: Vec<Node>,
}

async fn fetch_nodes(url: &str) -> Result<Vec<Node>, Box<dyn Error>> {
    let resp: NodesResponse = reqwest::get(url).await?.json().await?;
    let mut nodes = resp.nodes;
    // Sort by last_ping descending (most recent first) like the Python bot
    nodes.sort_by(|a, b| b.last_ping.cmp(&a.last_ping));
    Ok(nodes)
}

fn bootstrap(tox: &Tox, nodes: &[Node]) {
    // Select the top 4 most recent nodes like the Python bot
    let selected = nodes.iter().take(4);
    for node in selected {
        if let Ok(pk_bytes) = hex::decode(&node.public_key)
            && pk_bytes.len() == PUBLIC_KEY_SIZE
        {
            let mut pk_arr = [0u8; PUBLIC_KEY_SIZE];
            pk_arr.copy_from_slice(&pk_bytes);
            let dht_id = DhtId(pk_arr);
            if let Err(e) = tox.bootstrap(&node.ipv4, node.port, &dht_id) {
                error!("Failed to bootstrap to node {}: {}", node.ipv4, e);
            }
            if let Err(e) = tox.add_tcp_relay(&node.ipv4, node.port, &dht_id) {
                error!("Failed to add tcp relay {}: {}", node.ipv4, e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut opts = Options::new()?;
    opts.set_experimental_owned_data(true);
    opts.set_experimental_disable_dns(true);
    opts.set_experimental_groups_persistence(true);
    opts.set_local_discovery_enabled(false);
    opts.set_udp_enabled(false);

    if args.tor {
        opts.set_proxy_type(ToxProxyType::TOX_PROXY_TYPE_SOCKS5);
        opts.set_proxy_host("127.0.0.1")?;
        opts.set_proxy_port(9050);
    }

    let savefile = args.savefile.clone().or_else(|| {
        std::env::var("BUILD_WORKSPACE_DIRECTORY")
            .ok()
            .map(|base| format!("{}/rs-toxcore-c/apps/groupbot/groupbot.tox", base))
    });

    if let Some(savefile) = &savefile
        && Path::new(savefile).exists()
    {
        let mut data = fs::read(savefile)?;
        if encryptsave::is_data_encrypted(&data) {
            if let Some(password) = &args.password {
                data = encryptsave::decrypt(&data, password.as_bytes())?;
            } else {
                return Err("Password required to decrypt save data".into());
            }
        }
        opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
        opts.set_savedata_data(&data)?;
    }

    let tox = Tox::new(opts)?;
    if tox.name().is_empty() {
        tox.set_name(args.nick.as_bytes())?;
    }
    if tox.status_message().is_empty() {
        tox.set_status_message(args.status_message.as_bytes())?;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    info!("Bot ID: {}", hex::encode(tox.address().0));

    let nodes = fetch_nodes(&args.nodes_url).await.unwrap_or_default();
    bootstrap(&tox, &nodes);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_ctrlc = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("\nShutting down...");
            shutdown_ctrlc.store(true, Ordering::SeqCst);
        }
    });

    let (bot_event_tx, bot_event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut bot = GroupBot::new(tox, &args, savefile.map(PathBuf::from), bot_event_tx).await;
    bot.run(shutdown, bot_event_rx).await?;

    Ok(())
}
