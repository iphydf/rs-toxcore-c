use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use toxcore::tox::events::Event;
use toxcore::tox::{
    ADDRESS_SIZE, Address, ConferenceNumber, ConferencePeerNumber, DhtId, FileNumber, FriendNumber,
    GroupNumber, GroupPeerNumber, Options, Tox, ToxConnection, ToxGroupPrivacyState, ToxLogger,
    ToxSavedataType, ToxUserStatus,
};
use toxcore::types::{
    GroupChatId, ConferenceId, FileId, GROUP_CHAT_ID_SIZE, PublicKey, Tox_Err_File_Send_Chunk,
    Tox_Err_Friend_Send_Message, ToxError, ToxGroupRole, ToxLogLevel,
};

use crate::bootstrap;
use crate::config;
use crate::model::{ConferenceReconcileInfo, FriendInfo, GroupReconcileInfo, WindowId};
use crate::msg::{IOAction, Msg, SystemEvent, ToxAction, ToxEvent};
use crate::utils::{decode_hex, encode_hex};

fn find_friend(tox: &Tox, pk: &PublicKey) -> Option<FriendNumber> {
    tox.lookup_friend(pk).ok().map(|f| f.get_number())
}

fn find_group(tox: &Tox, chat_id: &GroupChatId) -> Option<GroupNumber> {
    for i in 0..tox.group_count() {
        let gnum = GroupNumber(i);
        let group = tox.group(gnum);
        if let Ok(id) = group.chat_id()
            && &id == chat_id
        {
            return Some(gnum);
        }
    }
    None
}

fn find_conference(tox: &Tox, id: &ConferenceId) -> Option<ConferenceNumber> {
    tox.conference_by_id(id).ok().map(|c| c.number())
}

pub struct InitialState {
    pub tox_id: Address,
    pub public_key: PublicKey,
    pub dht_id: DhtId,
    pub name: String,
    pub status_message: String,
    pub status_type: ToxUserStatus,
    pub friends: Vec<(FriendNumber, FriendInfo)>,
    pub groups: Vec<GroupReconcileInfo>,
    pub conferences: Vec<ConferenceReconcileInfo>,
}

pub fn get_initial_state(savedata_path: &Option<PathBuf>) -> Result<InitialState, Box<dyn Error>> {
    let mut temp_opts = Options::new()?;
    temp_opts.set_ipv6_enabled(false);
    temp_opts.set_udp_enabled(false);
    temp_opts.set_local_discovery_enabled(false);
    temp_opts.set_experimental_groups_persistence(true);

    if let Some(path) = savedata_path
        && path.exists()
        && let Ok(data) = fs::read(path)
    {
        temp_opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
        let _ = temp_opts.set_savedata_data(&data);
    }

    let temp_tox = Tox::new(temp_opts)?;
    let tox_id = temp_tox.address();
    let self_public_key = temp_tox.public_key();
    let self_dht_id = temp_tox.dht_id();
    let self_name = String::from_utf8_lossy(&temp_tox.name()).into_owned();
    let self_status_message = String::from_utf8_lossy(&temp_tox.status_message()).into_owned();
    let self_status_type = temp_tox.status();

    let mut friend_list_cache = Vec::new();
    for friend in temp_tox.friend_list() {
        let name = String::from_utf8_lossy(&friend.name().unwrap_or_default()).into_owned();
        let status_message =
            String::from_utf8_lossy(&friend.status_message().unwrap_or_default()).into_owned();
        let connection = friend
            .connection_status()
            .unwrap_or(ToxConnection::TOX_CONNECTION_NONE);
        let pk = friend.public_key().unwrap();
        friend_list_cache.push((
            friend.get_number(),
            FriendInfo {
                name,
                public_key: Some(pk),
                status_message,
                connection,
                last_sent_message_id: None,
                last_read_receipt: None,
                is_typing: false,
            },
        ));
    }

    let mut groups = Vec::new();
    for i in 0..temp_tox.group_count() {
        let gnum = GroupNumber(i);
        let group = temp_tox.group(gnum);
        let chat_id = group.chat_id()?;
        let gname = group.name().ok().and_then(|n| String::from_utf8(n).ok());
        let grole = group.self_role().ok();
        let gselfname = group
            .self_name()
            .ok()
            .and_then(|n| String::from_utf8(n).ok());
        groups.push(GroupReconcileInfo {
            number: gnum,
            chat_id,
            name: gname,
            role: grole,
            self_name: gselfname,
        });
    }

    let mut conferences = Vec::new();
    for conf in temp_tox.conference_chatlist() {
        let cnum = conf.number();
        let cid = conf.id().ok_or("Failed to get conference ID")?;
        let ctitle = conf.title().ok().and_then(|t| String::from_utf8(t).ok());
        conferences.push(ConferenceReconcileInfo {
            number: cnum,
            id: cid,
            title: ctitle,
        });
    }

    Ok(InitialState {
        tox_id,
        public_key: self_public_key,
        dht_id: self_dht_id,
        name: self_name,
        status_message: self_status_message,
        status_type: self_status_type,
        friends: friend_list_cache,
        groups,
        conferences,
    })
}

struct Logger {
    tx: mpsc::Sender<Msg>,
}

impl ToxLogger for Logger {
    fn log(&mut self, level: ToxLogLevel, file: &str, line: u32, func: &str, message: &str) {
        let _ = self.tx.send(Msg::Tox(ToxEvent::Log(
            level,
            file.to_owned(),
            line,
            func.to_owned(),
            message.to_owned(),
        )));
    }
}

pub fn spawn_tox(
    tx: mpsc::Sender<Msg>,
    tx_io: mpsc::Sender<IOAction>,
    rx_tox_action: mpsc::Receiver<ToxAction>,
    savedata_path: Option<PathBuf>,
    config: &config::Config,
    nodes: Vec<bootstrap::Node>,
    config_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    let mut config = config.clone();

    tokio::task::spawn_blocking(move || {
        let mut exit_thread = false;
        loop {
            let mut opts = match Options::new() {
                Ok(o) => o,
                Err(e) => {
                    let _ = tx.send(Msg::System(SystemEvent::Log {
                        severity: crate::msg::LogSeverity::Error,
                        context: crate::msg::LogContext::Global,
                        message: format!("Failed to create Options: {:?}", e),
                    }));
                    return;
                }
            };
            opts.set_ipv6_enabled(config.ipv6_enabled);
            opts.set_udp_enabled(config.udp_enabled);
            opts.set_local_discovery_enabled(config.local_discovery_enabled);
            opts.set_experimental_groups_persistence(true);
            opts.set_start_port(config.start_port);
            opts.set_end_port(config.end_port);
            opts.set_logger(Logger { tx: tx.clone() });

            if let Some(path) = &savedata_path
                && path.exists()
                && let Ok(data) = fs::read(path)
            {
                opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
                let _ = opts.set_savedata_data(&data);
            }

            let tox = match Tox::new(opts) {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(Msg::System(SystemEvent::Log {
                        severity: crate::msg::LogSeverity::Error,
                        context: crate::msg::LogContext::Global,
                        message: format!("Failed to create Tox: {:?}", e),
                    }));
                    return;
                }
            };

            let _ = tx.send(Msg::Tox(ToxEvent::Address(tox.address())));
            let _ = tx.send(Msg::Tox(ToxEvent::DhtId(tox.dht_id())));

            for conf in tox.conference_chatlist() {
                let cnum = conf.number();
                if let Ok(title_bytes) = conf.title() {
                    let title = String::from_utf8_lossy(&title_bytes).into_owned();
                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(cnum, title)));
                }
            }

            for i in 0..tox.group_count() {
                let gnum = GroupNumber(i);
                let group = tox.group(gnum);
                let name = group.name().ok().and_then(|n| String::from_utf8(n).ok());
                let _ = tx.send(Msg::Tox(ToxEvent::GroupName(
                    gnum,
                    name.unwrap_or_default(),
                )));
                if let Ok(topic_bytes) = group.topic() {
                    let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
                    let _ = tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic)));
                }
                if let Ok(role) = group.self_role() {
                    let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
                }
            }

            if !nodes.is_empty() {
                let _logs = bootstrap::bootstrap_network(&tox, &nodes);
                // Logs suppressed from UI to avoid spam
            }

            let mut last_online = Instant::now();
            let mut last_bootstrap = Instant::now();
            let mut is_connected = false;
            let mut deferred_chunks: VecDeque<(FriendNumber, FileNumber, u64, Vec<u8>)> =
                VecDeque::new();
            let mut conference_peers: HashMap<
                ConferenceNumber,
                HashMap<PublicKey, (ConferencePeerNumber, String)>,
            > = HashMap::new();
            let mut group_peers: HashMap<GroupNumber, HashMap<PublicKey, GroupPeerNumber>> =
                HashMap::new();
            // TODO: Add a hard limit on the size of these maps to prevent potential DoS/OOM.
            let mut file_id_map: HashMap<FileId, (FriendNumber, FileNumber)> = HashMap::new();
            let mut file_number_map: HashMap<(FriendNumber, FileNumber), FileId> = HashMap::new();
            let mut file_size_map: HashMap<(FriendNumber, FileNumber), u64> = HashMap::new();

            loop {
                // Re-bootstrap logic
                if !is_connected {
                    if last_online.elapsed() > Duration::from_secs(10)
                        && last_bootstrap.elapsed() > Duration::from_secs(10)
                    {
                        let logs = bootstrap::bootstrap_network(&tox, &nodes);
                        for log in logs {
                            let _ = tx.send(Msg::System(SystemEvent::Log {
                                severity: crate::msg::LogSeverity::Info,
                                context: crate::msg::LogContext::Global,
                                message: log,
                            }));
                        }
                        last_bootstrap = Instant::now();

                        if last_online.elapsed() > Duration::from_secs(60) {
                            let config_dir = config_dir.clone();
                            tokio::spawn(async move {
                                if let Ok(new_nodes) = bootstrap::fetch_nodes().await {
                                    let _ = bootstrap::save_nodes(&config_dir, &new_nodes);
                                }
                            });
                            last_online = Instant::now();
                        }
                    }
                } else {
                    last_online = Instant::now();
                }

                // Try to process deferred chunks first
                while let Some((friend_number, file_number, position, data)) =
                    deferred_chunks.pop_front()
                {
                    let file = tox.file(&tox.friend(friend_number), file_number);
                    let len = data.len();
                    match file.send_chunk(position, &data) {
                        Ok(_) => {
                            if let Ok(file_id) = file.file_id() {
                                let _ = tx.send(Msg::Tox(ToxEvent::FileChunkSent(
                                    friend_number,
                                    file_id,
                                    position,
                                    len,
                                )));
                            }
                        }
                        Err(ToxError::FileSendChunk(
                            Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_SENDQ,
                        )) => {
                            deferred_chunks.push_front((
                                friend_number,
                                file_number,
                                position,
                                data,
                            ));
                            break; // Still full, stop for this iteration
                        }
                        Err(e) => {
                            let context = if let Ok(pk) = tox.friend(friend_number).public_key() {
                                crate::msg::LogContext::Friend(pk)
                            } else {
                                crate::msg::LogContext::Global
                            };
                            let _ = tx.send(Msg::System(SystemEvent::Log {
                                severity: crate::msg::LogSeverity::Error,
                                context,
                                message: format!("Error sending deferred file chunk: {:?}", e),
                            }));
                        }
                    }
                }

                // Process actions from UI
                let mut reload_requested = false;
                while let Ok(action) = rx_tox_action.try_recv() {
                    match action {
                        ToxAction::Reload(new_config) => {
                            if let Some(path) = &savedata_path {
                                let data = tox.savedata();
                                let _ = fs::write(path, data);
                            }
                            config = *new_config;
                            reload_requested = true;
                        }
                        ToxAction::SendMessage(pk, message_type, msg, internal_id) => {
                            if let Some(friend_number) = find_friend(&tox, &pk) {
                                let friend = tox.friend(friend_number);
                                match friend.send_message(message_type, msg.as_bytes()) {
                                    Ok(id) => {
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSent(friend_number, id, internal_id)));
                                    }
                                    Err(ToxError::FriendSendMessage(Tox_Err_Friend_Send_Message::TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED)) => {
                                        let pk = tox.friend(friend_number).public_key().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(WindowId::Friend(pk), internal_id)));
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Friend(pk),
                                            message: format!("Error sending message: {:?}", e),
                                        }));
                                        let pk = tox.friend(friend_number).public_key().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(WindowId::Friend(pk), internal_id)));
                                    }
                                }
                            } else {
                                // Log error: Friend not found
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!(
                                        "SendMessage: Friend not found for PK {:?}",
                                        pk
                                    ),
                                }));
                                let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                    WindowId::Console,
                                    internal_id,
                                )));
                            }
                        }
                        ToxAction::SendGroupMessage(chat_id, message_type, msg, internal_id) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let group = tox.group(group_number);
                                match group.send_message(message_type, msg.as_bytes()) {
                                    Ok(_) => {
                                        let _ = tx.send(Msg::Tox(ToxEvent::GroupMessageSent(
                                            group_number,
                                            internal_id,
                                        )));
                                    }
                                    Err(_) => {
                                        let chat_id = tox.group(group_number).chat_id().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                            WindowId::Group(chat_id),
                                            internal_id,
                                        )));
                                    }
                                }
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!(
                                        "SendGroupMessage: Group not found for GroupChatId {:?}",
                                        chat_id
                                    ),
                                }));
                                let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                    WindowId::Console,
                                    internal_id,
                                )));
                            }
                        }
                        ToxAction::SendConferenceMessage(
                            conference_id,
                            message_type,
                            msg,
                            internal_id,
                        ) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id) {
                                let conference = tox.conference(conference_number);
                                match conference.send_message(message_type, msg.as_bytes()) {
                                    Ok(_) => {
                                        let _ = tx.send(Msg::Tox(ToxEvent::ConferenceMessageSent(
                                            conference_number,
                                            internal_id,
                                        )));
                                    }
                                    Err(_) => {
                                        let conf_id =
                                            tox.conference(conference_number).id().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                            WindowId::Conference(conf_id),
                                            internal_id,
                                        )));
                                    }
                                }
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!(
                                        "SendConferenceMessage: Conference not found for ID {:?}",
                                        conference_id
                                    ),
                                }));
                                let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                    WindowId::Console,
                                    internal_id,
                                )));
                            }
                        }
                        ToxAction::AddFriend(tox_id_hex, msg) => {
                            if let Some(bytes) = decode_hex(&tox_id_hex)
                                && bytes.len() == ADDRESS_SIZE
                            {
                                let mut addr_bytes = [0u8; ADDRESS_SIZE];
                                addr_bytes.copy_from_slice(&bytes);
                                let address = Address(addr_bytes);
                                match tox.friend_add(&address, msg.as_bytes()) {
                                    Ok(f) => {
                                        let pk = f.public_key().ok();
                                        let _ = tx.send(Msg::Tox(ToxEvent::FriendStatus(
                                            f.get_number(),
                                            ToxConnection::TOX_CONNECTION_NONE,
                                            pk,
                                        )));
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Global,
                                            message: format!("Error adding friend: {:?}", e),
                                        }));
                                    }
                                }
                            }
                        }
                        ToxAction::AcceptFriend(pk) => {
                            if let Ok(f) = tox.friend_add_norequest(&pk) {
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendStatus(
                                    f.get_number(),
                                    ToxConnection::TOX_CONNECTION_NONE,
                                    Some(pk),
                                )));
                            }
                        }
                        ToxAction::DeleteFriend(pk) => {
                            if let Some(friend_number) = find_friend(&tox, &pk) {
                                let _ = tox.friend(friend_number).delete();
                            }
                        }
                        ToxAction::CreateGroup(name) => {
                            if let Ok(group) = tox.group_new(
                                ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC,
                                name.as_bytes(),
                                &tox.name(),
                            ) {
                                if let Ok(chat_id) = group.chat_id() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                        group.get_number(),
                                        chat_id,
                                        Some(name),
                                    )));
                                } else {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Global,
                                        message: "Failed to get chat_id for created group".into(),
                                    }));
                                }
                            } else if let Err(e) = tox.group_new(
                                ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC,
                                name.as_bytes(),
                                &tox.name(),
                            ) {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!("Failed to create group: {:?}", e),
                                }));
                            }
                        }
                        ToxAction::CreateConference => {
                            if let Ok(conf) = tox.conference_new() {
                                if let Some(cid) = conf.id() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceCreated(
                                        conf.number(),
                                        cid,
                                    )));
                                } else {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Global,
                                        message:
                                            "Failed to get conference ID for created conference"
                                                .into(),
                                    }));
                                }
                            }
                        }
                        ToxAction::LeaveGroup(chat_id) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let _ = tox.group(group_number).leave(None);
                            }
                        }
                        ToxAction::DeleteConference(conference_id) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id) {
                                let _ = tox.conference(conference_number).delete();
                            }
                        }
                        ToxAction::JoinGroup(pk_hex, _name, pass) => {
                            if let Some(bytes) = decode_hex(&pk_hex)
                                && bytes.len() == GROUP_CHAT_ID_SIZE
                            {
                                let mut chat_id_bytes = [0u8; GROUP_CHAT_ID_SIZE];
                                chat_id_bytes.copy_from_slice(&bytes);
                                let chat_id = GroupChatId(chat_id_bytes);
                                match tox.group_join(
                                    &chat_id,
                                    &tox.name(),
                                    if pass.is_empty() {
                                        None
                                    } else {
                                        Some(pass.as_bytes())
                                    },
                                ) {
                                    Ok(group) => {
                                        let name = group
                                            .name()
                                            .ok()
                                            .and_then(|n| String::from_utf8(n).ok());
                                        if let Ok(chat_id) = group.chat_id() {
                                            let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                                group.get_number(),
                                                chat_id,
                                                name,
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Global,
                                            message: format!("Failed to join group: {:?}", e),
                                        }));
                                    }
                                }
                            }
                        }
                        ToxAction::AcceptGroupInvite(pk, invite_hex, _name, pass) => {
                            if let Some(friend_number) = find_friend(&tox, &pk)
                                && let Some(invite_data) = decode_hex(&invite_hex)
                            {
                                match tox.group_invite_accept(
                                    &tox.friend(friend_number),
                                    &invite_data,
                                    &tox.name(),
                                    if pass.is_empty() {
                                        None
                                    } else {
                                        Some(pass.as_bytes())
                                    },
                                ) {
                                    Ok(group) => {
                                        let name = group
                                            .name()
                                            .ok()
                                            .and_then(|n| String::from_utf8(n).ok());
                                        if let Ok(chat_id) = group.chat_id() {
                                            let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                                group.get_number(),
                                                chat_id,
                                                name,
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Global,
                                            message: format!(
                                                "Failed to accept group invite: {:?}",
                                                e
                                            ),
                                        }));
                                    }
                                }
                            }
                        }
                        ToxAction::JoinConference(pk, cookie_hex) => {
                            if let Some(friend_number) = find_friend(&tox, &pk)
                                && let Some(cookie) = decode_hex(&cookie_hex)
                            {
                                match tox.conference_join(&tox.friend(friend_number), &cookie) {
                                    Ok(conf) => {
                                        if let Some(cid) = conf.id() {
                                            let _ = tx.send(Msg::Tox(ToxEvent::ConferenceCreated(
                                                conf.number(),
                                                cid,
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Global,
                                            message: format!("Failed to join conference: {:?}", e),
                                        }));
                                    }
                                }
                            }
                        }
                        ToxAction::InviteFriendToGroup(chat_id, pk) => {
                            if let Some(group_number) = find_group(&tox, &chat_id)
                                && let Some(friend_number) = find_friend(&tox, &pk)
                            {
                                let _ = tox
                                    .group(group_number)
                                    .invite_friend(&tox.friend(friend_number));
                            }
                        }
                        ToxAction::InviteFriendToConference(conference_id, pk) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id)
                                && let Some(friend_number) = find_friend(&tox, &pk)
                            {
                                let _ = tox
                                    .conference(conference_number)
                                    .invite(&tox.friend(friend_number));
                            }
                        }
                        ToxAction::SetGroupPeerIgnore(chat_id, pk, ignore) => {
                            if let Some(group_number) = find_group(&tox, &chat_id)
                                && let Some(peers) = group_peers.get(&group_number)
                                && let Some(peer_id) = peers.get(&pk)
                            {
                                let _ = tox.group(group_number).set_ignore(*peer_id, ignore);
                            }
                        }
                        ToxAction::SetStatusMessage(msg) => {
                            let _ = tox.set_status_message(msg.as_bytes());
                        }
                        ToxAction::SetStatusType(status) => {
                            tox.set_status(status);
                        }
                        ToxAction::SetTyping(pk, is_typing) => {
                            if let Some(friend_number) = find_friend(&tox, &pk) {
                                let _ = tox.friend(friend_number).set_typing(is_typing);
                            }
                        }
                        ToxAction::SetName(name) => {
                            if let Err(e) = tox.set_name(name.as_bytes()) {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!("Error setting name: {:?}", e),
                                }));
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Info,
                                    context: crate::msg::LogContext::Global,
                                    message: format!("Name successfully set to: {}", name),
                                }));
                            }
                        }
                        ToxAction::SetGroupNickname(chat_id, name_str) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let group = tox.group(group_number);
                                if let Err(e) = group.self_set_name(name_str.as_bytes()) {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Group(chat_id),
                                        message: format!("Error setting group nickname: {:?}", e),
                                    }));
                                } else {
                                    let pk = tox.public_key();
                                    let role = group
                                        .self_role()
                                        .unwrap_or(ToxGroupRole::TOX_GROUP_ROLE_USER);
                                    let peer_id =
                                        group.self_peer_id().unwrap_or(GroupPeerNumber(0));
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerName(
                                        group_number,
                                        peer_id,
                                        name_str,
                                        role,
                                        pk,
                                    )));
                                }
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Group(chat_id),
                                    message: format!(
                                        "SetGroupNickname: Group not found for GroupChatId {:?}",
                                        chat_id
                                    ),
                                }));
                            }
                        }
                        ToxAction::SetGroupTopic(chat_id, topic) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                if let Err(e) = tox.group(group_number).set_topic(topic.as_bytes())
                                {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Group(chat_id),
                                        message: format!("Error setting group topic: {:?}", e),
                                    }));
                                } else {
                                    let _ = tx
                                        .send(Msg::Tox(ToxEvent::GroupTopic(group_number, topic)));
                                }
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!(
                                        "SetGroupTopic: Group not found for GroupChatId {:?}",
                                        chat_id
                                    ),
                                }));
                            }
                        }
                        ToxAction::SetConferenceTopic(conference_id, topic) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id) {
                                if let Err(e) = tox
                                    .conference(conference_number)
                                    .set_title(topic.as_bytes())
                                {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Global,
                                        message: format!("Error setting conference title: {:?}", e),
                                    }));
                                }
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: crate::msg::LogSeverity::Error,
                                    context: crate::msg::LogContext::Global,
                                    message: format!(
                                        "SetConferenceTopic: Conference not found for ID {:?}",
                                        conference_id
                                    ),
                                }));
                            }
                        }
                        ToxAction::Bootstrap(host, port, dht_id) => {
                            let _ = tox.add_tcp_relay(&host, port, &dht_id);
                            let _ = tox.bootstrap(&host, port, &dht_id);
                        }
                        ToxAction::FileSend(
                            pk,
                            kind,
                            file_size,
                            filename,
                            path,
                            resume_file_id,
                        ) => {
                            if let Some(friend_number) = find_friend(&tox, &pk) {
                                let friend = tox.friend(friend_number);
                                match tox.file_send(
                                    &friend,
                                    kind,
                                    file_size,
                                    resume_file_id.as_ref(),
                                    filename.as_bytes(),
                                ) {
                                    Ok(file) => {
                                        if let Ok(file_id) = file.file_id() {
                                            file_id_map
                                                .insert(file_id, (friend_number, file.number()));
                                            file_number_map
                                                .insert((friend_number, file.number()), file_id);
                                            file_size_map
                                                .insert((friend_number, file.number()), file_size);
                                            let _ =
                                                tx.send(Msg::IO(crate::msg::IOEvent::FileStarted(
                                                    pk, file_id, path, file_size,
                                                )));
                                        } else {
                                            let _ = tx.send(Msg::System(SystemEvent::Log {
                                                severity: crate::msg::LogSeverity::Error,
                                                context: crate::msg::LogContext::Friend(pk),
                                                message: "Failed to get FileId for sent file"
                                                    .into(),
                                            }));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Friend(pk),
                                            message: format!("Error sending file: {:?}", e),
                                        }));
                                    }
                                }
                            }
                        }
                        ToxAction::FileControl(_pk, file_id, control) => {
                            if let Some((friend_number, file_number)) = file_id_map.get(&file_id) {
                                let friend_number = *friend_number;
                                let file_number = *file_number;
                                if let Err(e) = tox
                                    .file(&tox.friend(friend_number), file_number)
                                    .control(control)
                                {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Global,
                                        message: format!(
                                            "Error controlling file (ID: {}): {:?}",
                                            file_id, e
                                        ),
                                    }));
                                }

                                if control
                                    == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL
                                {
                                    file_id_map.remove(&file_id);
                                    file_number_map.remove(&(friend_number, file_number));
                                    file_size_map.remove(&(friend_number, file_number));
                                }
                            }
                        }
                        ToxAction::FileSendChunk(pk, file_id, position, data) => {
                            if let Some((friend_number, file_number)) = file_id_map.get(&file_id) {
                                let friend_number = *friend_number;
                                let file_number = *file_number;

                                if !deferred_chunks.is_empty() {
                                    deferred_chunks.push_back((
                                        friend_number,
                                        file_number,
                                        position,
                                        data,
                                    ));
                                    continue;
                                }
                                let file = tox.file(&tox.friend(friend_number), file_number);
                                let len = data.len();
                                match file.send_chunk(position, &data) {
                                    Ok(_) => {
                                        let _ = tx.send(Msg::Tox(ToxEvent::FileChunkSent(
                                            friend_number,
                                            file_id,
                                            position,
                                            len,
                                        )));
                                    }
                                    Err(ToxError::FileSendChunk(
                                        Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_SENDQ,
                                    )) => {
                                        deferred_chunks.push_back((
                                            friend_number,
                                            file_number,
                                            position,
                                            data,
                                        ));
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: crate::msg::LogSeverity::Error,
                                            context: crate::msg::LogContext::Friend(pk),
                                            message: format!("Error sending file chunk: {:?}", e),
                                        }));
                                    }
                                }

                                // Check for completion
                                if let Some(size) = file_size_map.get(&(friend_number, file_number))
                                    && position + len as u64 >= *size
                                {
                                    file_id_map.remove(&file_id);
                                    file_number_map.remove(&(friend_number, file_number));
                                    file_size_map.remove(&(friend_number, file_number));
                                }
                            }
                        }
                        ToxAction::FileSeek(_pk, file_id, position) => {
                            if let Some((friend_number, file_number)) = file_id_map.get(&file_id) {
                                let _ = tox
                                    .file(&tox.friend(*friend_number), *file_number)
                                    .seek(position);
                            }
                        }
                        ToxAction::Shutdown => {
                            if let Some(path) = &savedata_path {
                                let data = tox.savedata();
                                let _ = fs::write(path, data);
                            }
                            reload_requested = true;
                            exit_thread = true;
                        }
                    }
                    if reload_requested {
                        break;
                    }
                }
                if reload_requested {
                    break;
                }

                // Process Tox Events
                if let Ok(events) = tox.events() {
                    for event in &events {
                        match event {
                            Event::SelfConnectionStatus(e) => {
                                let status = e.connection_status();
                                is_connected = status != ToxConnection::TOX_CONNECTION_NONE;
                                let _ = tx.send(Msg::Tox(ToxEvent::ConnectionStatus(status)));
                            }
                            Event::FriendMessage(e) => {
                                let msg = String::from_utf8_lossy(e.message()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::Message(
                                    e.friend_number(),
                                    e.message_type(),
                                    msg,
                                )));
                            }
                            Event::FriendRequest(e) => {
                                let msg = String::from_utf8_lossy(e.message()).into_owned();
                                let _ =
                                    tx.send(Msg::Tox(ToxEvent::FriendRequest(e.public_key(), msg)));
                            }
                            Event::FriendConnectionStatus(e) => {
                                let pk = tox.friend(e.friend_number()).public_key().ok();
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendStatus(
                                    e.friend_number(),
                                    e.connection_status(),
                                    pk,
                                )));
                            }
                            Event::FriendName(e) => {
                                let name = String::from_utf8_lossy(e.name()).into_owned();
                                let _ = tx
                                    .send(Msg::Tox(ToxEvent::FriendName(e.friend_number(), name)));
                            }
                            Event::FriendStatusMessage(e) => {
                                let msg = String::from_utf8_lossy(e.message()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendStatusMessage(
                                    e.friend_number(),
                                    msg,
                                )));
                            }
                            Event::FriendTyping(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendTyping(
                                    e.friend_number(),
                                    e.typing(),
                                )));
                            }
                            Event::FriendReadReceipt(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::ReadReceipt(
                                    e.friend_number(),
                                    e.message_id(),
                                )));
                            }
                            Event::GroupMessage(e) => {
                                let group = tox.group(e.group_number());
                                let name = group
                                    .peer_name(e.peer_id())
                                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                                    .unwrap_or_else(|_| format!("Peer {}", e.peer_id().0));
                                let pk = group.peer_public_key(e.peer_id()).ok();
                                let content = String::from_utf8_lossy(e.message()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupMessage(
                                    e.group_number(),
                                    e.message_type(),
                                    name,
                                    content,
                                    pk,
                                )));
                            }
                            Event::ConferenceMessage(e) => {
                                let conf = tox.conference(e.conference_number());
                                if !conf.peer_number_is_ours(e.peer_number()).unwrap_or(false) {
                                    let name = conf
                                        .peer_name(e.peer_number())
                                        .map(|n| String::from_utf8_lossy(&n).into_owned())
                                        .unwrap_or_else(|_| format!("Peer {}", e.peer_number().0));
                                    let pk = conf.peer_public_key(e.peer_number()).ok();
                                    let content = String::from_utf8_lossy(e.message()).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceMessage(
                                        e.conference_number(),
                                        e.message_type(),
                                        name,
                                        content,
                                        pk,
                                    )));
                                }
                            }
                            Event::GroupInvite(e) => {
                                let invite_data = encode_hex(e.invite_data());
                                let name = String::from_utf8_lossy(e.group_name()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupInvite(
                                    e.friend_number(),
                                    invite_data,
                                    name,
                                )));
                            }
                            Event::ConferenceInvite(e) => {
                                let cookie = encode_hex(e.cookie());
                                let _ = tx.send(Msg::Tox(ToxEvent::ConferenceInvite(
                                    e.friend_number(),
                                    e.conference_type(),
                                    cookie,
                                )));
                            }
                            Event::GroupTopic(e) => {
                                let gnum = e.group_number();
                                let group = tox.group(gnum);
                                if let Ok(name_bytes) = group.name() {
                                    let name = String::from_utf8_lossy(&name_bytes).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupName(gnum, name)));
                                }
                                if let Ok(role) = group.self_role() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
                                }
                                let topic = String::from_utf8_lossy(e.topic()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic)));
                            }
                            Event::GroupSelfJoin(e) => {
                                let gnum = e.group_number();
                                let group = tox.group(gnum);
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfJoin(gnum)));
                                if let Ok(name_bytes) = group.name() {
                                    let name = String::from_utf8_lossy(&name_bytes).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupName(gnum, name)));
                                }
                                if let Ok(role) = group.self_role() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
                                }
                                if let Ok(topic_bytes) = group.topic() {
                                    let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic)));
                                }
                            }
                            Event::ConferenceTitle(e) => {
                                let title = String::from_utf8_lossy(e.title()).into_owned();
                                let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(
                                    e.conference_number(),
                                    title,
                                )));
                            }
                            Event::GroupPeerJoin(e) => {
                                let group = tox.group(e.group_number());
                                let name = group
                                    .peer_name(e.peer_id())
                                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                                    .unwrap_or_else(|_| format!("Peer {}", e.peer_id().0));
                                let role = group
                                    .peer_role(e.peer_id())
                                    .unwrap_or(ToxGroupRole::TOX_GROUP_ROLE_USER);
                                let pk = group
                                    .peer_public_key(e.peer_id())
                                    .unwrap_or(PublicKey([0u8; 32]));

                                group_peers
                                    .entry(e.group_number())
                                    .or_default()
                                    .insert(pk, e.peer_id());

                                let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerJoin(
                                    e.group_number(),
                                    e.peer_id(),
                                    name,
                                    role,
                                    pk,
                                )));
                            }
                            Event::GroupPeerName(e) => {
                                let group = tox.group(e.group_number());
                                let name = String::from_utf8_lossy(e.name()).into_owned();
                                let role = group
                                    .peer_role(e.peer_id())
                                    .unwrap_or(ToxGroupRole::TOX_GROUP_ROLE_USER);
                                let pk = group
                                    .peer_public_key(e.peer_id())
                                    .unwrap_or(PublicKey([0u8; 32]));

                                // Ensure mapping is up to date (e.g. for self peer which doesn't get a JOIN event initially)
                                group_peers
                                    .entry(e.group_number())
                                    .or_default()
                                    .insert(pk, e.peer_id());

                                let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerName(
                                    e.group_number(),
                                    e.peer_id(),
                                    name,
                                    role,
                                    pk,
                                )));
                            }
                            Event::GroupPeerStatus(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerStatus(
                                    e.group_number(),
                                    e.peer_id(),
                                    e.status(),
                                )));
                            }
                            Event::GroupPeerExit(e) => {
                                if let Some(peers) = group_peers.get_mut(&e.group_number()) {
                                    peers.retain(|_, v| *v != e.peer_id());
                                }

                                let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerLeave(
                                    e.group_number(),
                                    e.peer_id(),
                                )));
                            }
                            Event::GroupModeration(e) => {
                                let gnum = e.group_number();
                                let group = tox.group(gnum);
                                if let Ok(role) = group.peer_role(e.target_peer_id())
                                    && let Ok(name_bytes) = group.peer_name(e.target_peer_id())
                                {
                                    let name = String::from_utf8_lossy(&name_bytes).into_owned();
                                    let pk = group
                                        .peer_public_key(e.target_peer_id())
                                        .unwrap_or(PublicKey([0u8; 32]));
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerName(
                                        gnum,
                                        e.target_peer_id(),
                                        name,
                                        role,
                                        pk,
                                    )));
                                }
                                if let Ok(role) = group.self_role() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
                                }
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupModeration(
                                    gnum,
                                    e.source_peer_id(),
                                    e.target_peer_id(),
                                    e.mod_type(),
                                )));
                            }
                            Event::ConferencePeerListChanged(e) => {
                                let conf = tox.conference(e.conference_number());
                                if let Ok(title_bytes) = conf.title() {
                                    let title = String::from_utf8_lossy(&title_bytes).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(
                                        e.conference_number(),
                                        title,
                                    )));
                                }
                                if let Ok(peers) = conf.peer_list() {
                                    let mut current_peers = HashMap::new();
                                    for peer_idx in peers {
                                        if let Ok(true) = conf.peer_number_is_ours(peer_idx) {
                                            continue;
                                        }
                                        if let Ok(pk) = conf.peer_public_key(peer_idx) {
                                            let name = conf
                                                .peer_name(peer_idx)
                                                .map(|n| String::from_utf8_lossy(&n).into_owned())
                                                .unwrap_or_else(|_| format!("Peer {}", peer_idx.0));
                                            current_peers.insert(pk, (peer_idx, name));
                                        }
                                    }

                                    let old_peers =
                                        conference_peers.entry(e.conference_number()).or_default();

                                    // Peers that joined
                                    for (pk, (idx, name)) in &current_peers {
                                        if !old_peers.contains_key(pk) {
                                            let _ =
                                                tx.send(Msg::Tox(ToxEvent::ConferencePeerJoin(
                                                    e.conference_number(),
                                                    *idx,
                                                    name.clone(),
                                                    *pk,
                                                )));
                                        } else if let Some((old_idx, old_name)) = old_peers.get(pk)
                                        {
                                            if old_idx != idx {
                                                // Index changed, but it's the same peer.
                                                // We might want to emit something, but toxxi's PeerId::Conference(pk)
                                                // doesn't care about the index.
                                            }
                                            if old_name != name {
                                                let _ = tx.send(Msg::Tox(
                                                    ToxEvent::ConferencePeerName(
                                                        e.conference_number(),
                                                        *idx,
                                                        name.clone(),
                                                        *pk,
                                                    ),
                                                ));
                                            }
                                        }
                                    }

                                    // Peers that left
                                    for (pk, (idx, _name)) in old_peers.iter() {
                                        if !current_peers.contains_key(pk) {
                                            let _ =
                                                tx.send(Msg::Tox(ToxEvent::ConferencePeerLeave(
                                                    e.conference_number(),
                                                    *idx,
                                                    *pk,
                                                )));
                                        }
                                    }

                                    *old_peers = current_peers;
                                }
                            }
                            Event::ConferencePeerName(e) => {
                                let conf = tox.conference(e.conference_number());
                                if let Ok(pk) = conf.peer_public_key(e.peer_number()) {
                                    let name = String::from_utf8_lossy(e.name()).into_owned();
                                    if let Some(peers) =
                                        conference_peers.get_mut(&e.conference_number())
                                        && let Some(peer_info) = peers.get_mut(&pk)
                                    {
                                        peer_info.1 = name.clone();
                                    }
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferencePeerName(
                                        e.conference_number(),
                                        e.peer_number(),
                                        name,
                                        pk,
                                    )));
                                }
                            }
                            Event::FileRecv(e) => {
                                let filename = String::from_utf8_lossy(e.filename()).into_owned();
                                let file =
                                    tox.file(&tox.friend(e.friend_number()), e.file_number());
                                if let Ok(file_id) = file.file_id() {
                                    file_id_map
                                        .insert(file_id, (e.friend_number(), e.file_number()));
                                    file_number_map
                                        .insert((e.friend_number(), e.file_number()), file_id);
                                    file_size_map.insert(
                                        (e.friend_number(), e.file_number()),
                                        e.file_size(),
                                    );
                                    let _ = tx.send(Msg::Tox(ToxEvent::FileRecv(
                                        e.friend_number(),
                                        file_id,
                                        e.kind(),
                                        e.file_size(),
                                        filename,
                                    )));
                                }
                            }
                            Event::FileChunkRequest(e) => {
                                let file =
                                    tox.file(&tox.friend(e.friend_number()), e.file_number());
                                let file_id_opt = file.file_id().ok().or_else(|| {
                                    file_number_map
                                        .get(&(e.friend_number(), e.file_number()))
                                        .cloned()
                                });

                                if let Some(file_id) = file_id_opt {
                                    let _ = tx.send(Msg::Tox(ToxEvent::FileChunkRequest(
                                        e.friend_number(),
                                        file_id,
                                        e.position(),
                                        e.length(),
                                    )));
                                }
                            }
                            Event::FileRecvChunk(e) => {
                                let pk = tox.friend(e.friend_number()).public_key().unwrap();
                                let file =
                                    tox.file(&tox.friend(e.friend_number()), e.file_number());
                                let file_id_opt = file.file_id().ok().or_else(|| {
                                    file_number_map
                                        .get(&(e.friend_number(), e.file_number()))
                                        .cloned()
                                });

                                if let Some(file_id) = file_id_opt {
                                    let _ = tx_io.send(IOAction::WriteChunk(
                                        pk,
                                        file_id,
                                        e.position(),
                                        e.data().to_vec(),
                                    ));
                                    // Notify UI for testing
                                    let _ = tx.send(Msg::Tox(ToxEvent::FileRecvChunk(
                                        e.friend_number(),
                                        file_id,
                                        e.position(),
                                        e.data().to_vec(),
                                    )));

                                    // Check for completion
                                    if let Some(size) =
                                        file_size_map.get(&(e.friend_number(), e.file_number()))
                                        && e.position() + e.data().len() as u64 >= *size
                                    {
                                        file_id_map.remove(&file_id);
                                        file_number_map
                                            .remove(&(e.friend_number(), e.file_number()));
                                        file_size_map.remove(&(e.friend_number(), e.file_number()));
                                    }
                                } else {
                                    let _ = tx.send(Msg::System(SystemEvent::Log {
                                        severity: crate::msg::LogSeverity::Error,
                                        context: crate::msg::LogContext::Global,
                                        message: format!(
                                            "Failed to get FileId for RecvChunk friend={} file={}",
                                            e.friend_number().0,
                                            e.file_number().0
                                        ),
                                    }));
                                }
                            }
                            Event::FileRecvControl(e) => {
                                let file =
                                    tox.file(&tox.friend(e.friend_number()), e.file_number());
                                let file_id_opt = file.file_id().ok().or_else(|| {
                                    file_number_map
                                        .get(&(e.friend_number(), e.file_number()))
                                        .cloned()
                                });

                                if let Some(file_id) = file_id_opt {
                                    let _ = tx.send(Msg::Tox(ToxEvent::FileRecvControl(
                                        e.friend_number(),
                                        file_id,
                                        e.control(),
                                    )));

                                    if e.control()
                                        == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL
                                    {
                                        file_id_map.remove(&file_id);
                                        file_number_map
                                            .remove(&(e.friend_number(), e.file_number()));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let interval = tox.iteration_interval();
                thread::sleep(Duration::from_millis(interval.max(1) as u64));
            }
            if exit_thread {
                break;
            }
        }
    })
}
