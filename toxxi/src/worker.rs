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
    ConferenceId, FileId, GROUP_CHAT_ID_SIZE, GroupChatId, PublicKey, Tox_Err_File_Send_Chunk,
    Tox_Err_Friend_Custom_Packet, Tox_Err_Friend_Send_Message, ToxError, ToxGroupRole,
    ToxGroupTopicLock, ToxLogLevel,
};

use crate::bootstrap;
use crate::call_bridge::{CallBridge, CallEvent};
use crate::config;
use crate::model::{
    ConferenceReconcileInfo, FriendInfo, GroupReconcileInfo, GroupSettings, WindowId,
};
use crate::msg::{
    GroupSetting, IOAction, LogContext, LogSeverity, Msg, SystemEvent, ToxAction, ToxEvent,
};
use crate::sync::event::{ChatId, ChatKind};
use crate::sync::fact::Privacy;
use crate::sync::frame::{Outbox, PACKET_ID, Reassembler, SendError};
use crate::utils::{decode_hex, encode_hex};

fn find_friend(tox: &Tox, pk: &PublicKey) -> Option<FriendNumber> {
    tox.lookup_friend(pk).ok().map(|f| f.get_number())
}

// Unlike the group list, it finds groups that are still joining.
fn find_group(tox: &Tox, chat_id: &GroupChatId) -> Option<GroupNumber> {
    tox.group_by_id(chat_id)
        .ok()
        .map(|group| group.get_number())
}

fn group_settings(tox: &Tox, gnum: GroupNumber) -> Option<GroupSettings> {
    let group = tox.group(gnum);
    Some(GroupSettings {
        privacy: group.privacy_state().ok()?,
        peer_limit: group.peer_limit().ok()?,
        password: String::from_utf8_lossy(&group.password().ok()?).into_owned(),
        topic_lock: group.topic_lock().ok()? == ToxGroupTopicLock::TOX_GROUP_TOPIC_LOCK_ENABLED,
        voice_state: group.voice_state().ok()?,
        self_pk: group.self_public_key().ok()?,
    })
}

fn send_group_settings(tox: &Tox, tx: &mpsc::Sender<Msg>, gnum: GroupNumber) {
    if let Some(settings) = group_settings(tox, gnum) {
        let _ = tx.send(Msg::Tox(ToxEvent::GroupSettings(gnum, settings)));
    }
}

fn log_error(tx: &mpsc::Sender<Msg>, context: LogContext, message: impl Into<String>) {
    let _ = tx.send(Msg::System(SystemEvent::Log {
        severity: LogSeverity::Error,
        context,
        message: message.into(),
    }));
}

fn find_conference(tox: &Tox, id: &ConferenceId) -> Option<ConferenceNumber> {
    tox.conference_by_id(id).ok().map(|c| c.number())
}

pub struct InitialState {
    pub tox_id: Address,
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
                is_typing: false,
            },
        ));
    }

    let mut groups = Vec::new();
    for group in temp_tox.group_list() {
        let gnum = group.get_number();
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
                    log_error(
                        &tx,
                        LogContext::Global,
                        format!("Failed to create Options: {e:?}"),
                    );
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
                    log_error(
                        &tx,
                        LogContext::Global,
                        format!("Failed to create Tox: {e:?}"),
                    );
                    return;
                }
            };

            let _ = tx.send(Msg::Tox(ToxEvent::Started));
            let _ = tx.send(Msg::Tox(ToxEvent::Address(tox.address())));
            let _ = tx.send(Msg::Tox(ToxEvent::DhtId(tox.dht_id())));

            for conf in tox.conference_chatlist() {
                let cnum = conf.number();
                if let Ok(title_bytes) = conf.title() {
                    let title = String::from_utf8_lossy(&title_bytes).into_owned();
                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(cnum, title, None)));
                }
            }

            for group in tox.group_list() {
                let gnum = group.get_number();
                let name = group.name().ok().and_then(|n| String::from_utf8(n).ok());
                let _ = tx.send(Msg::Tox(ToxEvent::GroupName(
                    gnum,
                    name.unwrap_or_default(),
                )));
                if let Ok(topic_bytes) = group.topic() {
                    let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
                    let _ = tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, None)));
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
            let mut sync_out = Outbox::default();
            let mut sync_in: HashMap<FriendNumber, Reassembler> = HashMap::new();
            let mut calls = match CallBridge::new(&tox) {
                Ok(calls) => Some(calls),
                Err(e) => {
                    log_error(&tx, LogContext::Global, format!("No calls: {e:?}"));
                    None
                }
            };
            let call_events = |events: Vec<CallEvent>| {
                for event in events {
                    let Ok(pk) = tox.friend(event.friend()).public_key() else {
                        continue;
                    };
                    let _ = tx.send(Msg::Tox(match event {
                        CallEvent::Ringing { video, .. } => ToxEvent::CallRinging(pk, video),
                        CallEvent::Connected { .. } => ToxEvent::CallConnected(pk),
                        CallEvent::Ended { .. } => ToxEvent::CallEnded(pk),
                    }));
                }
            };

            loop {
                // Re-bootstrap logic
                if !is_connected {
                    if last_online.elapsed() > Duration::from_secs(10)
                        && last_bootstrap.elapsed() > Duration::from_secs(10)
                    {
                        let logs = bootstrap::bootstrap_network(&tox, &nodes);
                        for log in logs {
                            let _ = tx.send(Msg::System(SystemEvent::Log {
                                severity: LogSeverity::Info,
                                context: LogContext::Global,
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
                                LogContext::Friend(pk)
                            } else {
                                LogContext::Global
                            };
                            log_error(
                                &tx,
                                context,
                                format!("Error sending deferred file chunk: {e:?}"),
                            );
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
                                match friend.send_message(message_type, &msg) {
                                    Ok(id) => {
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSent(friend_number, id, internal_id)));
                                    }
                                    Err(ToxError::FriendSendMessage(Tox_Err_Friend_Send_Message::TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED)) => {
                                        let pk = tox.friend(friend_number).public_key().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(WindowId::Friend(pk), internal_id)));
                                    }
                                    Err(e) => {
                                        log_error(&tx, LogContext::Friend(pk), format!("Error sending message: {e:?}"));
                                        let pk = tox.friend(friend_number).public_key().unwrap();
                                        let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(WindowId::Friend(pk), internal_id)));
                                    }
                                }
                            } else {
                                // Log error: Friend not found
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!("SendMessage: Friend not found for PK {pk:?}"),
                                );
                                let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                    WindowId::Console,
                                    internal_id,
                                )));
                            }
                        }
                        ToxAction::SendGroupMessage(chat_id, message_type, msg, internal_id) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let group = tox.group(group_number);
                                match group.send_message(message_type, &msg) {
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
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!(
                                        "SendGroupMessage: Group not found for GroupChatId {chat_id:?}"
                                    ),
                                );
                                let _ = tx.send(Msg::Tox(ToxEvent::MessageSendFailed(
                                    WindowId::Console,
                                    internal_id,
                                )));
                            }
                        }
                        ToxAction::SendGroupPrivateMessage(
                            chat_id,
                            pk,
                            message_type,
                            msg,
                            internal_id,
                        ) => {
                            let sent = find_group(&tox, &chat_id).and_then(|gnum| {
                                let peer_id = group_peers.get(&gnum)?.get(&pk).copied()?;
                                match tox.group(gnum).send_private_message(
                                    peer_id,
                                    message_type,
                                    &msg,
                                ) {
                                    Ok(_) => Some(gnum),
                                    Err(e) => {
                                        log_error(
                                            &tx,
                                            LogContext::Group(chat_id),
                                            format!("Error sending a private message: {e:?}"),
                                        );
                                        None
                                    }
                                }
                            });
                            let _ = tx.send(Msg::Tox(match sent {
                                Some(gnum) => ToxEvent::GroupMessageSent(gnum, internal_id),
                                None => ToxEvent::MessageSendFailed(
                                    WindowId::Group(chat_id),
                                    internal_id,
                                ),
                            }));
                        }
                        ToxAction::SendConferenceMessage(
                            conference_id,
                            message_type,
                            msg,
                            internal_id,
                        ) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id) {
                                let conference = tox.conference(conference_number);
                                match conference.send_message(message_type, &msg) {
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
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!(
                                        "SendConferenceMessage: Conference not found for ID {conference_id:?}"
                                    ),
                                );
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
                                        log_error(
                                            &tx,
                                            LogContext::Global,
                                            format!("Error adding friend: {e:?}"),
                                        );
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
                        ToxAction::CreateGroup(name) => match tox.group_new(
                            ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC,
                            name.as_bytes(),
                            &tox.name(),
                        ) {
                            Ok(group) => {
                                if let Ok(chat_id) = group.chat_id() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                        group.get_number(),
                                        chat_id,
                                        Some(name),
                                    )));
                                } else {
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        "Failed to get chat_id for created group",
                                    );
                                }
                            }
                            Err(e) => {
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!("Failed to create group: {e:?}"),
                                );
                            }
                        },
                        ToxAction::CreateConference => {
                            if let Ok(conf) = tox.conference_new() {
                                if let Some(cid) = conf.id() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceCreated(
                                        conf.number(),
                                        cid,
                                    )));
                                } else {
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        "Failed to get conference ID for created conference",
                                    );
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
                                match tox
                                    .group_join(
                                        &chat_id,
                                        &tox.name(),
                                        if pass.is_empty() {
                                            None
                                        } else {
                                            Some(pass.as_bytes())
                                        },
                                    )
                                    // Rejoining a group it has, Tox gives 0, not its number.
                                    .and_then(|_| tox.group_by_id(&chat_id))
                                {
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
                                        log_error(
                                            &tx,
                                            LogContext::Global,
                                            format!("Failed to join group: {e:?}"),
                                        );
                                    }
                                }
                            }
                        }
                        ToxAction::AcceptGroupInvite(pk, invite_hex, _name, pass, invite) => {
                            let mut joined = None;
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
                                            joined = Some(ChatId::Group(chat_id));
                                            let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                                group.get_number(),
                                                chat_id,
                                                name,
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        log_error(
                                            &tx,
                                            LogContext::Global,
                                            format!("Failed to accept group invite: {e:?}"),
                                        );
                                    }
                                }
                            }
                            if let Some(invite) = invite {
                                let _ = tx.send(Msg::Tox(ToxEvent::InviteJoined(invite, joined)));
                            }
                        }
                        ToxAction::JoinConference(pk, cookie_hex, invite) => {
                            let mut joined = None;
                            if let Some(friend_number) = find_friend(&tox, &pk)
                                && let Some(cookie) = decode_hex(&cookie_hex)
                            {
                                match tox.conference_join(&tox.friend(friend_number), &cookie) {
                                    Ok(conf) => {
                                        if let Some(cid) = conf.id() {
                                            joined = Some(ChatId::Conference(cid));
                                            let _ = tx.send(Msg::Tox(ToxEvent::ConferenceCreated(
                                                conf.number(),
                                                cid,
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        log_error(
                                            &tx,
                                            LogContext::Global,
                                            format!("Failed to join conference: {e:?}"),
                                        );
                                    }
                                }
                            }
                            if let Some(invite) = invite {
                                let _ = tx.send(Msg::Tox(ToxEvent::InviteJoined(invite, joined)));
                            }
                        }
                        ToxAction::MakeChat(intent, kind, privacy, name) => {
                            let made = match kind {
                                ChatKind::Group => tox
                                    .group_new(
                                        if privacy == Privacy::Private {
                                            ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE
                                        } else {
                                            ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC
                                        },
                                        name.as_bytes(),
                                        &tox.name(),
                                    )
                                    .ok()
                                    .and_then(|group| {
                                        let chat_id = group.chat_id().ok()?;
                                        let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                            group.get_number(),
                                            chat_id,
                                            Some(name.clone()),
                                        )));
                                        Some(ChatId::Group(chat_id))
                                    }),
                                ChatKind::Conference => {
                                    tox.conference_new().ok().and_then(|conf| {
                                        let _ = conf.set_title(name.as_bytes());
                                        let cid = conf.id()?;
                                        let _ = tx.send(Msg::Tox(ToxEvent::ConferenceCreated(
                                            conf.number(),
                                            cid,
                                        )));
                                        Some(ChatId::Conference(cid))
                                    })
                                }
                                ChatKind::Unknown { .. } => None,
                            };
                            let _ = tx.send(Msg::Tox(ToxEvent::ChatMade(intent, made)));
                        }
                        ToxAction::JoinChatById(intent, chat_id, password) => {
                            let joined = tox
                                .group_join(
                                    &chat_id,
                                    &tox.name(),
                                    password.as_deref().map(str::as_bytes),
                                )
                                // Rejoining a group it has, Tox gives 0, not its number.
                                .and_then(|_| tox.group_by_id(&chat_id))
                                .ok()
                                .map(|group| {
                                    let name =
                                        group.name().ok().and_then(|n| String::from_utf8(n).ok());
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupCreated(
                                        group.get_number(),
                                        chat_id,
                                        name,
                                    )));
                                    ChatId::Group(chat_id)
                                });
                            let _ = tx.send(Msg::Tox(ToxEvent::ChatMade(intent, joined)));
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
                        ToxAction::SetGroupSetting(chat_id, setting) => {
                            if let Some(gnum) = find_group(&tox, &chat_id) {
                                let group = tox.group(gnum);
                                let result = match setting {
                                    GroupSetting::Privacy(privacy) => group
                                        .set_privacy_state(privacy)
                                        .map_err(|e| format!("{e:?}")),
                                    GroupSetting::PeerLimit(limit) => {
                                        group.set_peer_limit(limit).map_err(|e| format!("{e:?}"))
                                    }
                                    GroupSetting::Password(password) => group
                                        .set_password(Some(password.as_bytes()))
                                        .map_err(|e| format!("{e:?}")),
                                    GroupSetting::TopicLock(lock) => group
                                        .set_topic_lock(if lock {
                                            ToxGroupTopicLock::TOX_GROUP_TOPIC_LOCK_ENABLED
                                        } else {
                                            ToxGroupTopicLock::TOX_GROUP_TOPIC_LOCK_DISABLED
                                        })
                                        .map_err(|e| format!("{e:?}")),
                                    GroupSetting::VoiceState(voice_state) => group
                                        .set_voice_state(voice_state)
                                        .map_err(|e| format!("{e:?}")),
                                };
                                match result {
                                    Ok(()) => send_group_settings(&tox, &tx, gnum),
                                    Err(e) => {
                                        log_error(
                                            &tx,
                                            LogContext::Group(chat_id),
                                            format!("Error changing group settings: {e}"),
                                        );
                                    }
                                }
                            }
                        }
                        ToxAction::ModerateGroupPeer(chat_id, pk, role) => {
                            if let Some(gnum) = find_group(&tox, &chat_id)
                                && let Some(peer_id) = group_peers
                                    .get(&gnum)
                                    .and_then(|peers| peers.get(&pk))
                                    .copied()
                            {
                                let group = tox.group(gnum);
                                let result = match role {
                                    Some(role) => group.set_role(peer_id, role),
                                    None => group.kick_peer(peer_id),
                                };
                                match (result, role) {
                                    (Ok(()), Some(role)) => {
                                        let name = group
                                            .peer_name(peer_id)
                                            .map(|n| String::from_utf8_lossy(&n).into_owned())
                                            .unwrap_or_default();
                                        let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerName(
                                            gnum, peer_id, name, role, pk,
                                        )));
                                    }
                                    (Ok(()), None) => {
                                        if let Some(peers) = group_peers.get_mut(&gnum) {
                                            peers.remove(&pk);
                                        }
                                        let _ = tx.send(Msg::Tox(ToxEvent::GroupPeerLeave(
                                            gnum, peer_id,
                                        )));
                                    }
                                    (Err(e), _) => {
                                        log_error(
                                            &tx,
                                            LogContext::Group(chat_id),
                                            format!("Error moderating a peer: {e:?}"),
                                        );
                                    }
                                }
                            }
                        }
                        ToxAction::SetNospam(nospam) => {
                            tox.set_nospam(nospam);
                            // Kept at once, as a request to the old ID mustn't
                            // come back after a crash.
                            if let Some(path) = &savedata_path {
                                let _ = fs::write(path, tox.savedata());
                            }
                            let _ = tx.send(Msg::Tox(ToxEvent::Address(tox.address())));
                        }
                        ToxAction::SetStatusMessage(msg) => {
                            let _ = tox.set_status_message(msg.as_bytes());
                        }
                        ToxAction::SetStatusType(status) => {
                            tox.set_status(status);
                            // Groups show their members' status apart from Tox's.
                            for group in tox.group_list() {
                                let _ = group.self_set_status(status);
                            }
                        }
                        ToxAction::SetTyping(pk, is_typing) => {
                            if let Some(friend_number) = find_friend(&tox, &pk) {
                                let _ = tox.friend(friend_number).set_typing(is_typing);
                            }
                        }
                        ToxAction::SetName(name) => {
                            if let Err(e) = tox.set_name(name.as_bytes()) {
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!("Error setting name: {e:?}"),
                                );
                            } else {
                                let _ = tx.send(Msg::System(SystemEvent::Log {
                                    severity: LogSeverity::Info,
                                    context: LogContext::Global,
                                    message: format!("Name successfully set to: {}", name),
                                }));
                            }
                        }
                        ToxAction::SetGroupNickname(chat_id, name_str) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let group = tox.group(group_number);
                                if let Err(e) = group.self_set_name(name_str.as_bytes()) {
                                    log_error(
                                        &tx,
                                        LogContext::Group(chat_id),
                                        format!("Error setting group nickname: {e:?}"),
                                    );
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
                                log_error(
                                    &tx,
                                    LogContext::Group(chat_id),
                                    format!(
                                        "SetGroupNickname: Group not found for GroupChatId {chat_id:?}"
                                    ),
                                );
                            }
                        }
                        ToxAction::SetGroupTopic(chat_id, topic) => {
                            if let Some(group_number) = find_group(&tox, &chat_id) {
                                let group = tox.group(group_number);
                                if let Err(e) = group.set_topic(topic.as_bytes()) {
                                    log_error(
                                        &tx,
                                        LogContext::Group(chat_id),
                                        format!("Error setting group topic: {e:?}"),
                                    );
                                } else {
                                    let setter = group
                                        .self_name()
                                        .ok()
                                        .map(|n| String::from_utf8_lossy(&n).into_owned());
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupTopic(
                                        group_number,
                                        topic,
                                        setter,
                                    )));
                                }
                            } else {
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!(
                                        "SetGroupTopic: Group not found for GroupChatId {chat_id:?}"
                                    ),
                                );
                            }
                        }
                        ToxAction::SetConferenceTopic(conference_id, topic) => {
                            if let Some(conference_number) = find_conference(&tox, &conference_id) {
                                if let Err(e) = tox
                                    .conference(conference_number)
                                    .set_title(topic.as_bytes())
                                {
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        format!("Error setting conference title: {e:?}"),
                                    );
                                } else {
                                    // Tox tells of others' titles, not our own.
                                    let setter = String::from_utf8_lossy(&tox.name()).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(
                                        conference_number,
                                        topic,
                                        Some(setter),
                                    )));
                                }
                            } else {
                                log_error(
                                    &tx,
                                    LogContext::Global,
                                    format!(
                                        "SetConferenceTopic: Conference not found for ID {conference_id:?}"
                                    ),
                                );
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
                                            log_error(
                                                &tx,
                                                LogContext::Friend(pk),
                                                "Failed to get FileId for sent file",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        log_error(
                                            &tx,
                                            LogContext::Friend(pk),
                                            format!("Error sending file: {e:?}"),
                                        );
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
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        format!("Error controlling file (ID: {file_id}): {e:?}"),
                                    );
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
                                        log_error(
                                            &tx,
                                            LogContext::Friend(pk),
                                            format!("Error sending file chunk: {e:?}"),
                                        );
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
                        ToxAction::SyncSend(pk, message) => {
                            if let Some(friend) = find_friend(&tox, &pk) {
                                sync_out.push(friend, &message);
                            }
                        }
                        ToxAction::CallConnect {
                            friend,
                            device,
                            video,
                        } => {
                            match (
                                &mut calls,
                                find_friend(&tox, &friend),
                                find_friend(&tox, &device),
                            ) {
                                (Some(calls), Some(friend), Some(device)) => {
                                    call_events(calls.connect(friend, device, video));
                                }
                                _ => {
                                    let _ = tx.send(Msg::Tox(ToxEvent::CallEnded(friend)));
                                }
                            }
                        }
                        ToxAction::CallHangUp(pk) => {
                            if let (Some(calls), Some(friend)) =
                                (&mut calls, find_friend(&tox, &pk))
                            {
                                calls.hang_up(friend);
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

                sync_out.flush(|friend, packet| {
                    match tox.friend(friend).send_lossless_packet(packet) {
                        Ok(()) => Ok(()),
                        Err(ToxError::FriendCustomPacket(
                            Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ,
                        )) => Err(SendError::Full),
                        Err(_) => Err(SendError::Gone),
                    }
                });

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
                                let _ = tx.send(Msg::Tox(ToxEvent::Message(
                                    e.friend_number(),
                                    e.message_type(),
                                    e.message().to_vec(),
                                )));
                            }
                            Event::FriendRequest(e) => {
                                let msg = String::from_utf8_lossy(e.message()).into_owned();
                                let _ =
                                    tx.send(Msg::Tox(ToxEvent::FriendRequest(e.public_key(), msg)));
                            }
                            Event::FriendConnectionStatus(e) => {
                                if e.connection_status() == ToxConnection::TOX_CONNECTION_NONE {
                                    sync_in.remove(&e.friend_number());
                                    sync_out.remove(e.friend_number());
                                }
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
                            Event::FriendStatus(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendUserStatus(
                                    e.friend_number(),
                                    e.status(),
                                )));
                            }
                            Event::GroupPrivacyState(e) => {
                                send_group_settings(&tox, &tx, e.group_number());
                            }
                            Event::GroupVoiceState(e) => {
                                send_group_settings(&tox, &tx, e.group_number());
                            }
                            Event::GroupTopicLock(e) => {
                                send_group_settings(&tox, &tx, e.group_number());
                            }
                            Event::GroupPeerLimit(e) => {
                                send_group_settings(&tox, &tx, e.group_number());
                            }
                            Event::GroupPassword(e) => {
                                send_group_settings(&tox, &tx, e.group_number());
                            }
                            Event::FriendTyping(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::FriendTyping(
                                    e.friend_number(),
                                    e.typing(),
                                )));
                            }
                            Event::FriendLosslessPacket(e)
                                if e.data().first() == Some(&PACKET_ID) =>
                            {
                                let friend = e.friend_number();
                                match sync_in.entry(friend).or_default().push(e.data()) {
                                    Ok(Some(message)) => {
                                        let _ = tx
                                            .send(Msg::Tox(ToxEvent::SyncMessage(friend, message)));
                                    }
                                    Ok(None) => {}
                                    Err(err) => {
                                        let _ = tx.send(Msg::System(SystemEvent::Log {
                                            severity: LogSeverity::Warning,
                                            context: LogContext::Global,
                                            message: format!(
                                                "Dropped sync message from friend {}: {:?}",
                                                friend.0, err
                                            ),
                                        }));
                                    }
                                }
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
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupMessage(
                                    e.group_number(),
                                    e.message_type(),
                                    name,
                                    e.message().to_vec(),
                                    pk,
                                )));
                            }
                            Event::GroupPrivateMessage(e) => {
                                let group = tox.group(e.group_number());
                                let name = group
                                    .peer_name(e.peer_id())
                                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                                    .unwrap_or_else(|_| format!("Peer {}", e.peer_id().0));
                                if let Ok(pk) = group.peer_public_key(e.peer_id()) {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupPrivateMessage(
                                        e.group_number(),
                                        e.message_type(),
                                        name,
                                        e.message().to_vec(),
                                        pk,
                                    )));
                                }
                            }
                            Event::ConferenceMessage(e) => {
                                let conf = tox.conference(e.conference_number());
                                if !conf.peer_number_is_ours(e.peer_number()).unwrap_or(false) {
                                    let name = conf
                                        .peer_name(e.peer_number())
                                        .map(|n| String::from_utf8_lossy(&n).into_owned())
                                        .unwrap_or_else(|_| format!("Peer {}", e.peer_number().0));
                                    let pk = conf.peer_public_key(e.peer_number()).ok();
                                    let _ = tx.send(Msg::Tox(ToxEvent::ConferenceMessage(
                                        e.conference_number(),
                                        e.message_type(),
                                        name,
                                        e.message().to_vec(),
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
                                let setter = group
                                    .peer_name(e.peer_id())
                                    .ok()
                                    .map(|n| String::from_utf8_lossy(&n).into_owned());
                                let _ =
                                    tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, setter)));
                            }
                            Event::GroupJoinFail(e) => {
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupJoinFail(
                                    e.group_number(),
                                    e.fail_type(),
                                )));
                            }
                            Event::GroupSelfJoin(e) => {
                                let gnum = e.group_number();
                                let group = tox.group(gnum);
                                let _ = group.self_set_status(tox.status());
                                let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfJoin(gnum)));
                                send_group_settings(&tox, &tx, gnum);
                                if let Ok(name_bytes) = group.name() {
                                    let name = String::from_utf8_lossy(&name_bytes).into_owned();
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupName(gnum, name)));
                                }
                                if let Ok(role) = group.self_role() {
                                    let _ = tx.send(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
                                }
                                if let Ok(topic_bytes) = group.topic() {
                                    let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
                                    let _ =
                                        tx.send(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, None)));
                                }
                            }
                            Event::ConferenceTitle(e) => {
                                let title = String::from_utf8_lossy(e.title()).into_owned();
                                let setter = tox
                                    .conference(e.conference_number())
                                    .peer_name(e.peer_number())
                                    .ok()
                                    .map(|n| String::from_utf8_lossy(&n).into_owned());
                                let _ = tx.send(Msg::Tox(ToxEvent::ConferenceTitle(
                                    e.conference_number(),
                                    title,
                                    setter,
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
                                        None,
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
                                // Tox ends each transfer with an empty chunk,
                                // after the last byte ended it here.
                                } else if !e.data().is_empty() {
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        format!(
                                            "Failed to get FileId for RecvChunk friend={} file={}",
                                            e.friend_number().0,
                                            e.file_number().0
                                        ),
                                    );
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

                let mut interval = Duration::from_millis(tox.iteration_interval().max(1).into());
                if let Some(calls) = &mut calls {
                    call_events(calls.iterate());
                    interval = interval.min(calls.iteration_interval());
                }
                thread::sleep(interval);
            }
            if exit_thread {
                break;
            }
        }
    })
}
