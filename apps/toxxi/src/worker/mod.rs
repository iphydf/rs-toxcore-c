//! The Tox thread: it runs Tox, carries out toxxi's actions and sends toxxi
//! the events.

mod conferences;
mod files;
mod groups;

use crate::utils::Tell;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use toxcore::tox::events::{Event, EventFriendLosslessPacket};
use toxcore::tox::{
    Address, ConferenceNumber, ConferencePeerNumber, Connection, DhtId, FriendNumber, GroupNumber,
    GroupPeerNumber, Options, SavedataType, Tox, ToxLogger, UserStatus,
};
use toxcore::types::{
    ConferenceSendMessageError, FriendCustomPacketError, FriendSendMessageError,
    GroupSendMessageError, GroupSendPrivateMessageError, LogLevel, MessageType, Port, PublicKey,
    ToxError,
};

use crate::bootstrap;
use crate::call_bridge::{CallBridge, CallEvent};
use crate::config;
use crate::model::{
    ConferenceReconcileInfo, FriendInfo, GroupReconcileInfo, InternalMessageId, WindowId,
};
use crate::msg::{
    IOAction, LogContext, LogSeverity, Msg, SendFailure, SystemEvent, ToxAction, ToxEvent,
};
use crate::sync::event::ChatKind;
use crate::sync::frame::{Outbox, PACKET_ID, Reassembler, SendError};
use crate::sync::trace::SyncTrace;
use crate::utils::write_atomically;

fn find_friend(tox: &Tox, pk: &PublicKey) -> Option<FriendNumber> {
    tox.lookup_friend(pk).ok().map(|f| f.number())
}

/// Decides whether to retry a message Tox didn't take. Only an offline chat or
/// a full queue clears up, so only those are retried, and the rest are logged.
fn send_failure(tx: &mpsc::Sender<Msg>, context: LogContext, e: &ToxError) -> SendFailure {
    let later = matches!(
        e,
        ToxError::FriendSendMessage(
            FriendSendMessageError::FriendNotConnected | FriendSendMessageError::Sendq
        ) | ToxError::GroupSendMessage(
            GroupSendMessageError::FailSend | GroupSendMessageError::Disconnected
        ) | ToxError::GroupSendPrivateMessage(
            GroupSendPrivateMessageError::FailSend | GroupSendPrivateMessageError::Disconnected
        ) | ToxError::ConferenceSendMessage(
            ConferenceSendMessageError::NoConnection | ConferenceSendMessageError::FailSend
        )
    );
    if later {
        SendFailure::Later
    } else {
        log_error(tx, context, format!("Error sending a message: {e:?}"));
        SendFailure::Never
    }
}

fn log_error(tx: &mpsc::Sender<Msg>, context: LogContext, message: impl Into<String>) {
    tx.tell(Msg::System(SystemEvent::Log {
        severity: LogSeverity::Error,
        context,
        message: message.into(),
    }));
}

pub struct InitialState {
    pub tox_id: Address,
    pub dht_id: DhtId,
    pub name: String,
    pub status_message: String,
    pub status_type: UserStatus,
    pub friends: Vec<FriendInfo>,
    pub groups: Vec<GroupReconcileInfo>,
    pub conferences: Vec<ConferenceReconcileInfo>,
}

/// How often we save when no action changed the profile, for what changes by
/// itself: DHT nodes, friends' names, groups.
const SAVE_INTERVAL: Duration = Duration::from_secs(600);

/// Gives Tox the profile at `path`, if there is one. One there that can't be
/// read stops toxxi: a new profile would be saved over it.
fn load_savedata(opts: &mut Options, path: &Option<PathBuf>) -> Result<(), String> {
    let Some(path) = path.as_ref().filter(|path| path.exists()) else {
        return Ok(());
    };
    let data = fs::read(path).map_err(|e| format!("Can't read {}: {e}", path.display()))?;
    opts.set_savedata_type(SavedataType::ToxSave);
    opts.set_savedata_data(&data)
        .map_err(|e| format!("Can't load {}: {e:?}", path.display()))
}

pub fn get_initial_state(savedata_path: &Option<PathBuf>) -> Result<InitialState, Box<dyn Error>> {
    let mut temp_opts = Options::new()?;
    temp_opts.set_ipv6_enabled(false);
    temp_opts.set_udp_enabled(false);
    temp_opts.set_local_discovery_enabled(false);
    temp_opts.set_experimental_groups_persistence(true);

    load_savedata(&mut temp_opts, savedata_path)?;

    let temp_tox = Tox::new(temp_opts)?;
    // Save a new profile immediately, or the worker would make another one.
    if let Some(path) = savedata_path
        && !path.exists()
    {
        write_atomically(path, &temp_tox.savedata())?;
    }
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
        let connection = friend.connection_status().unwrap_or(Connection::None);
        let Ok(pk) = friend.public_key() else {
            continue;
        };
        friend_list_cache.push(FriendInfo {
            name,
            public_key: Some(pk),
            status_message,
            connection,
            is_typing: false,
        });
    }

    let mut groups = Vec::new();
    for group in temp_tox.group_list() {
        let gnum = group.number();
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
    fn log(&mut self, level: LogLevel, file: &str, line: u32, func: &str, message: &str) {
        self.tx.tell(Msg::Tox(ToxEvent::Log {
            level,
            file: file.to_owned(),
            line,
            func: func.to_owned(),
            message: message.to_owned(),
        }));
    }
}

/// State of one Tox instance: a reload makes a new one.
struct Session<'t> {
    tox: &'t Tox,
    tx: &'t mpsc::Sender<Msg>,
    tx_io: &'t mpsc::Sender<IOAction>,
    is_connected: bool,
    conference_peers: HashMap<ConferenceNumber, HashMap<PublicKey, (ConferencePeerNumber, String)>>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per peer toxcore has in a group"))]
    group_peers: HashMap<GroupNumber, HashMap<PublicKey, GroupPeerNumber>>,
    transfers: files::Transfers,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("what our devices haven't taken yet, like the history in memory")
    )]
    sync_out: Outbox,
    sync_in: HashMap<FriendNumber, Reassembler>,
    sync_trace: SyncTrace,
    calls: Option<CallBridge<'t>>,
}

impl<'t> Session<'t> {
    fn new(
        tox: &'t Tox,
        tx: &'t mpsc::Sender<Msg>,
        tx_io: &'t mpsc::Sender<IOAction>,
        sync_trace: SyncTrace,
    ) -> Self {
        let calls = match CallBridge::new(tox) {
            Ok(calls) => Some(calls),
            Err(e) => {
                log_error(tx, LogContext::Global, format!("No calls: {e:?}"));
                None
            }
        };
        Self {
            tox,
            tx,
            tx_io,
            is_connected: false,
            conference_peers: HashMap::new(),
            group_peers: HashMap::new(),
            transfers: files::Transfers::default(),
            sync_out: Outbox::default(),
            sync_in: HashMap::new(),
            sync_trace,
            calls,
        }
    }

    /// Sends toxxi a friend event, with the friend's key instead of their
    /// number. Does nothing if the friend is gone.
    fn friend_event(&self, friend: FriendNumber, event: impl FnOnce(PublicKey) -> ToxEvent) {
        if let Ok(pk) = self.tox.friend(friend).public_key() {
            self.tx.tell(Msg::Tox(event(pk)));
        }
    }

    /// Logs a failure, e.g. "Error leaving the group: ...".
    fn check<T, E: std::fmt::Debug>(&self, context: LogContext, what: &str, result: Result<T, E>) {
        if let Err(e) = result {
            log_error(self.tx, context, format!("Error {what}: {e:?}"));
        }
    }

    fn call_events(&self, events: Vec<CallEvent>) {
        for event in events {
            self.friend_event(event.friend(), |pk| match event {
                CallEvent::Ringing { video, .. } => ToxEvent::CallRinging { friend: pk, video },
                CallEvent::Connected { .. } => ToxEvent::CallConnected(pk),
                CallEvent::Ended { .. } => ToxEvent::CallEnded(pk),
            });
        }
    }

    /// Reload, Shutdown and Save are handled by the loop in `spawn_tox`.
    fn act(&mut self, action: ToxAction) {
        match action {
            ToxAction::SendMessage(pk, message_type, msg, internal_id) => {
                self.send_message(pk, message_type, msg, internal_id)
            }
            ToxAction::SendGroupMessage(chat_id, message_type, msg, internal_id) => {
                self.send_group_message(chat_id, message_type, msg, internal_id)
            }
            ToxAction::SendGroupPrivateMessage(chat_id, pk, message_type, msg, internal_id) => {
                self.send_group_private_message(chat_id, pk, message_type, msg, internal_id)
            }
            ToxAction::SendConferenceMessage(conference_id, message_type, msg, internal_id) => {
                self.send_conference_message(conference_id, message_type, msg, internal_id)
            }
            ToxAction::AddFriend(address, msg) => {
                match self.tox.friend_add(&address, msg.as_bytes()) {
                    Ok(f) => {
                        self.friend_event(f.number(), |pk| {
                            ToxEvent::FriendStatus(pk, Connection::None)
                        });
                    }
                    Err(e) => log_error(
                        self.tx,
                        LogContext::Global,
                        format!("Error adding friend: {e:?}"),
                    ),
                }
            }
            ToxAction::AcceptFriend(pk) => {
                if self.tox.friend_add_norequest(&pk).is_ok() {
                    self.tx
                        .tell(Msg::Tox(ToxEvent::FriendStatus(pk, Connection::None)));
                }
            }
            ToxAction::DeleteFriend(pk) => {
                if let Some(friend_number) = find_friend(self.tox, &pk) {
                    let deleted = self.tox.friend(friend_number).delete();
                    self.check(LogContext::Friend(pk), "deleting the friend", deleted);
                }
            }
            ToxAction::CreateGroup(name) => self.create_group(name),
            ToxAction::CreateConference => self.create_conference(),
            ToxAction::LeaveGroup(chat_id) => self.leave_group(chat_id),
            ToxAction::DeleteConference(conference_id) => self.delete_conference(conference_id),
            ToxAction::JoinGroup(chat_id, password) => self.join_group(chat_id, password),
            ToxAction::AcceptGroupInvite {
                friend,
                invite,
                password,
                recorded,
            } => {
                let joined = self.accept_group_invite(friend, invite, password);
                if let Some(invite) = recorded {
                    self.tx
                        .tell(Msg::Tox(ToxEvent::InviteJoined(invite, joined)));
                }
            }
            ToxAction::JoinConference {
                friend,
                cookie,
                recorded,
            } => {
                let joined = self.join_conference(friend, cookie);
                if let Some(invite) = recorded {
                    self.tx
                        .tell(Msg::Tox(ToxEvent::InviteJoined(invite, joined)));
                }
            }
            ToxAction::MakeChat(intent, kind, privacy, name) => {
                let made = match kind {
                    ChatKind::Group => self.make_group(privacy, name),
                    ChatKind::Conference => self.make_conference(&name),
                    ChatKind::Unknown { .. } => None,
                };
                self.tx.tell(Msg::Tox(ToxEvent::ChatMade(intent, made)));
            }
            ToxAction::JoinChatById(intent, chat_id, password) => {
                let joined = self.join_chat_by_id(chat_id, password);
                self.tx.tell(Msg::Tox(ToxEvent::ChatMade(intent, joined)));
            }
            ToxAction::InviteFriendToGroup(chat_id, pk) => self.invite_friend_to_group(chat_id, pk),
            ToxAction::InviteFriendToConference(conference_id, pk) => {
                self.invite_friend_to_conference(conference_id, pk)
            }
            ToxAction::SetGroupPeerIgnore(chat_id, pk, ignore) => {
                self.set_group_peer_ignore(chat_id, pk, ignore)
            }
            ToxAction::SetGroupSetting(chat_id, setting) => {
                self.set_group_setting(chat_id, setting)
            }
            ToxAction::ModerateGroupPeer(chat_id, pk, role) => {
                self.moderate_group_peer(chat_id, pk, role)
            }
            ToxAction::SetNospam(nospam) => {
                self.tox.set_nospam(nospam);
                self.tx
                    .tell(Msg::Tox(ToxEvent::Address(self.tox.address())));
            }
            ToxAction::SetStatusMessage(msg) => {
                let set = self.tox.set_status_message(msg.as_bytes());
                self.check(LogContext::Global, "setting the status message", set);
            }
            ToxAction::SetStatusType(status) => {
                self.tox.set_status(status);
                // Groups show their members' status apart from Tox's.
                for group in self.tox.group_list() {
                    let set = group.self_set_status(status);
                    self.check(LogContext::Global, "setting the status in a group", set);
                }
            }
            ToxAction::SetTyping(pk, is_typing) => {
                if let Some(friend_number) = find_friend(self.tox, &pk) {
                    let set = self.tox.friend(friend_number).set_typing(is_typing);
                    self.check(LogContext::Friend(pk), "setting typing", set);
                }
            }
            ToxAction::SetName(name) | ToxAction::SetDeviceName(name) => {
                if let Err(e) = self.tox.set_name(name.as_bytes()) {
                    log_error(
                        self.tx,
                        LogContext::Global,
                        format!("Error setting name: {e:?}"),
                    );
                } else {
                    self.tx.tell(Msg::System(SystemEvent::Log {
                        severity: LogSeverity::Info,
                        context: LogContext::Global,
                        message: format!("Name successfully set to: {}", name),
                    }));
                }
            }
            ToxAction::SetGroupNickname(chat_id, name) => self.set_group_nickname(chat_id, name),
            ToxAction::SetGroupTopic(chat_id, topic) => self.set_group_topic(chat_id, topic),
            ToxAction::SetConferenceTopic(conference_id, topic) => {
                self.set_conference_topic(conference_id, topic)
            }
            ToxAction::Bootstrap(host, port, dht_id) => {
                let relay = self.tox.add_tcp_relay(&host, Port(port), &dht_id);
                self.check(LogContext::Global, "adding the TCP relay", relay);
                let bootstrapped = self.tox.bootstrap(&host, Port(port), &dht_id);
                self.check(LogContext::Global, "bootstrapping", bootstrapped);
            }
            ToxAction::FileSend {
                friend,
                kind,
                size,
                name,
                path,
                resume,
            } => self.file_send(friend, kind, size, name, path, resume),
            ToxAction::FileControl(_pk, file_id, control) => self.file_control(file_id, control),
            ToxAction::FileSendChunk(_pk, file, position, data) => {
                self.file_send_chunk(file, position, data)
            }
            ToxAction::FileSeek(_pk, file_id, position) => self.file_seek(file_id, position),
            ToxAction::SyncSend(pk, message) => {
                self.sync_trace.record("out", &pk, &message);
                if let Some(friend) = find_friend(self.tox, &pk) {
                    self.sync_out.push(friend, &message);
                }
            }
            ToxAction::CallConnect {
                friend,
                device,
                video,
            } => match (
                &mut self.calls,
                find_friend(self.tox, &friend),
                find_friend(self.tox, &device),
            ) {
                (Some(calls), Some(friend), Some(device)) => {
                    let events = calls.connect(friend, device, video);
                    self.call_events(events);
                }
                _ => {
                    self.tx.tell(Msg::Tox(ToxEvent::CallEnded(friend)));
                }
            },
            ToxAction::CallHangUp(pk) => {
                if let (Some(calls), Some(friend)) = (&mut self.calls, find_friend(self.tox, &pk)) {
                    calls.hang_up(friend);
                }
            }
            ToxAction::Reload(_) | ToxAction::Save | ToxAction::Shutdown => {}
        }
    }

    fn send_message(
        &mut self,
        pk: PublicKey,
        message_type: MessageType,
        msg: Vec<u8>,
        internal_id: InternalMessageId,
    ) {
        let sent = find_friend(self.tox, &pk)
            .ok_or(SendFailure::Never)
            .and_then(|friend| {
                self.tox
                    .friend(friend)
                    .send_message(message_type, &msg)
                    .map_err(|e| send_failure(self.tx, LogContext::Friend(pk), &e))
            });
        self.tx.tell(Msg::Tox(match sent {
            Ok(id) => ToxEvent::MessageSent(pk, id, internal_id),
            Err(failure) => ToxEvent::MessageSendFailed(WindowId::Friend(pk), internal_id, failure),
        }));
    }

    fn event(&mut self, event: &Event) {
        match event {
            Event::SelfConnectionStatus(e) => {
                let status = e.connection_status();
                self.is_connected = status != Connection::None;
                self.tx.tell(Msg::Tox(ToxEvent::ConnectionStatus(status)));
            }
            Event::FriendMessage(e) => self.friend_event(e.friend_number(), |pk| {
                ToxEvent::Message(pk, e.message_type(), e.message().to_vec())
            }),
            Event::FriendRequest(e) => {
                let msg = String::from_utf8_lossy(e.message()).into_owned();
                self.tx
                    .tell(Msg::Tox(ToxEvent::FriendRequest(e.public_key(), msg)));
            }
            Event::FriendConnectionStatus(e) => {
                if e.connection_status() == Connection::None {
                    self.sync_in.remove(&e.friend_number());
                    self.sync_out.remove(e.friend_number());
                }
                self.friend_event(e.friend_number(), |pk| {
                    ToxEvent::FriendStatus(pk, e.connection_status())
                });
            }
            Event::FriendName(e) => {
                let name = String::from_utf8_lossy(e.name()).into_owned();
                self.friend_event(e.friend_number(), |pk| ToxEvent::FriendName(pk, name));
            }
            Event::FriendStatusMessage(e) => {
                let msg = String::from_utf8_lossy(e.message()).into_owned();
                self.friend_event(e.friend_number(), |pk| {
                    ToxEvent::FriendStatusMessage(pk, msg)
                });
            }
            Event::FriendStatus(e) => self.friend_event(e.friend_number(), |pk| {
                ToxEvent::FriendUserStatus(pk, e.status())
            }),
            Event::FriendTyping(e) => self.friend_event(e.friend_number(), |pk| {
                ToxEvent::FriendTyping(pk, e.typing())
            }),
            Event::FriendReadReceipt(e) => self.friend_event(e.friend_number(), |pk| {
                ToxEvent::ReadReceipt(pk, e.message_id())
            }),
            Event::FriendLosslessPacket(e) if e.data().first() == Some(&PACKET_ID) => {
                self.sync_packet(e)
            }
            Event::GroupPrivacyState(e) => self.send_group_settings(e.group_number()),
            Event::GroupVoiceState(e) => self.send_group_settings(e.group_number()),
            Event::GroupTopicLock(e) => self.send_group_settings(e.group_number()),
            Event::GroupPeerLimit(e) => self.send_group_settings(e.group_number()),
            Event::GroupPassword(e) => self.send_group_settings(e.group_number()),
            Event::GroupMessage(e) => self.group_message(e),
            Event::GroupPrivateMessage(e) => self.group_private_message(e),
            Event::GroupInvite(e) => self.group_invite(e),
            Event::GroupTopic(e) => self.group_topic(e),
            Event::GroupJoinFail(e) => {
                self.tx.tell(Msg::Tox(ToxEvent::GroupJoinFail(
                    e.group_number(),
                    e.fail_type(),
                )));
            }
            Event::GroupSelfJoin(e) => self.group_self_join(e),
            Event::GroupPeerJoin(e) => self.group_peer_join(e),
            Event::GroupPeerName(e) => self.group_peer_name(e),
            Event::GroupPeerStatus(e) => {
                self.tx.tell(Msg::Tox(ToxEvent::GroupPeerStatus(
                    e.group_number(),
                    e.peer_id(),
                    e.status(),
                )));
            }
            Event::GroupPeerExit(e) => self.group_peer_exit(e),
            Event::GroupModeration(e) => self.group_moderation(e),
            Event::ConferenceMessage(e) => self.conference_message(e),
            Event::ConferenceInvite(e) => self.conference_invite(e),
            Event::ConferenceTitle(e) => self.conference_title(e),
            Event::ConferencePeerListChanged(e) => self.conference_peer_list_changed(e),
            Event::ConferencePeerName(e) => self.conference_peer_name(e),
            Event::FileRecv(e) => self.file_recv(e),
            Event::FileChunkRequest(e) => self.file_chunk_request(e),
            Event::FileRecvChunk(e) => self.file_recv_chunk(e),
            Event::FileRecvControl(e) => self.file_recv_control(e),
            Event::FriendLossyPacket(_)
            | Event::FriendLosslessPacket(_)
            | Event::ConferenceConnected(_)
            | Event::GroupCustomPacket(_)
            | Event::GroupCustomPrivatePacket(_)
            | Event::DhtNodesResponse(_)
            | Event::Unknown => {}
        }
    }

    fn sync_packet(&mut self, e: &EventFriendLosslessPacket) {
        let friend = e.friend_number();
        match self.sync_in.entry(friend).or_default().push(e.data()) {
            Ok(Some(message)) => {
                if let Ok(pk) = self.tox.friend(friend).public_key() {
                    self.sync_trace.record("in", &pk, &message);
                    self.tx.tell(Msg::Tox(ToxEvent::SyncMessage(pk, message)));
                }
            }
            Ok(None) => {}
            Err(err) => {
                self.tx.tell(Msg::System(SystemEvent::Log {
                    severity: LogSeverity::Warning,
                    context: LogContext::Global,
                    message: format!("Dropped sync message from friend {}: {:?}", friend.0, err),
                }));
            }
        }
    }

    fn flush_sync(&mut self) {
        let tox = self.tox;
        self.sync_out.flush(|friend, packet| {
            match tox.friend(friend).send_lossless_packet(packet) {
                Ok(()) => Ok(()),
                Err(ToxError::FriendCustomPacket(FriendCustomPacketError::Sendq)) => {
                    Err(SendError::Full)
                }
                Err(_) => Err(SendError::Gone),
            }
        });
    }

    /// Runs the calls and returns how long to sleep until Tox or the calls need
    /// to run again.
    fn iterate_calls(&mut self) -> Duration {
        let mut interval = Duration::from_millis(self.tox.iteration_interval().max(1).into());
        if let Some(calls) = &mut self.calls {
            let events = calls.iterate();
            interval = interval.min(calls.iteration_interval());
            self.call_events(events);
        }
        interval
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
            opts.set_start_port(Port(config.start_port));
            opts.set_end_port(Port(config.end_port));
            opts.set_logger(Logger { tx: tx.clone() });

            if let Err(e) = load_savedata(&mut opts, &savedata_path) {
                log_error(&tx, LogContext::Global, e);
                return;
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

            tx.tell(Msg::Tox(ToxEvent::Started));
            tx.tell(Msg::Tox(ToxEvent::Address(tox.address())));
            tx.tell(Msg::Tox(ToxEvent::DhtId(tox.dht_id())));
            conferences::announce(&tox, &tx);
            groups::announce(&tox, &tx);

            if !nodes.is_empty() {
                // Don't show these logs: they would flood the Status window.
                let _logs = bootstrap::bootstrap_network(&tox, &nodes);
            }

            let mut last_online = Instant::now();
            let mut last_save = Instant::now();
            let mut last_bootstrap = Instant::now();
            let mut session = Session::new(&tox, &tx, &tx_io, SyncTrace::new(&config_dir));

            loop {
                if !session.is_connected {
                    if last_online.elapsed() > Duration::from_secs(10)
                        && last_bootstrap.elapsed() > Duration::from_secs(10)
                    {
                        let logs = bootstrap::bootstrap_network(&tox, &nodes);
                        for log in logs {
                            tx.tell(Msg::System(SystemEvent::Log {
                                severity: LogSeverity::Info,
                                context: LogContext::Global,
                                message: log,
                            }));
                        }
                        last_bootstrap = Instant::now();

                        if last_online.elapsed() > Duration::from_secs(60) {
                            let config_dir = config_dir.clone();
                            let tx = tx.clone();
                            tokio::spawn(async move {
                                if let Ok(new_nodes) = bootstrap::fetch_nodes().await
                                    && let Err(e) = bootstrap::save_nodes(&config_dir, &new_nodes)
                                {
                                    log_error(
                                        &tx,
                                        LogContext::Global,
                                        format!("Error saving the nodes: {e}"),
                                    );
                                }
                            });
                            last_online = Instant::now();
                        }
                    }
                } else {
                    last_online = Instant::now();
                }

                session.send_waiting_chunks();

                let mut reload_requested = false;
                let mut changed = false;
                while let Ok(action) = rx_tox_action.try_recv() {
                    changed |= action.changes_savedata();
                    match action {
                        ToxAction::Reload(new_config) => {
                            config = *new_config;
                            reload_requested = true;
                        }
                        ToxAction::Shutdown => {
                            reload_requested = true;
                            exit_thread = true;
                        }
                        // Saved below.
                        ToxAction::Save => {}
                        action @ (ToxAction::SendMessage(..)
                        | ToxAction::SendGroupMessage(..)
                        | ToxAction::SetNospam(_)
                        | ToxAction::SendGroupPrivateMessage(..)
                        | ToxAction::SendConferenceMessage(..)
                        | ToxAction::AddFriend(..)
                        | ToxAction::AcceptFriend(_)
                        | ToxAction::DeleteFriend(_)
                        | ToxAction::CreateGroup(_)
                        | ToxAction::CreateConference
                        | ToxAction::LeaveGroup(_)
                        | ToxAction::DeleteConference(_)
                        | ToxAction::JoinGroup(..)
                        | ToxAction::AcceptGroupInvite { .. }
                        | ToxAction::JoinConference { .. }
                        | ToxAction::InviteFriendToGroup(..)
                        | ToxAction::InviteFriendToConference(..)
                        | ToxAction::MakeChat(..)
                        | ToxAction::JoinChatById(..)
                        | ToxAction::SetGroupPeerIgnore(..)
                        | ToxAction::SetStatusMessage(_)
                        | ToxAction::SetStatusType(_)
                        | ToxAction::SetTyping(..)
                        | ToxAction::SetName(_)
                        | ToxAction::SetDeviceName(_)
                        | ToxAction::SetGroupNickname(..)
                        | ToxAction::SetGroupTopic(..)
                        | ToxAction::SetGroupSetting(..)
                        | ToxAction::ModerateGroupPeer(..)
                        | ToxAction::SetConferenceTopic(..)
                        | ToxAction::Bootstrap(..)
                        | ToxAction::FileSend { .. }
                        | ToxAction::FileControl(..)
                        | ToxAction::FileSendChunk(..)
                        | ToxAction::FileSeek(..)
                        | ToxAction::SyncSend(..)
                        | ToxAction::CallConnect { .. }
                        | ToxAction::CallHangUp(_)) => session.act(action),
                    }
                    if reload_requested {
                        break;
                    }
                }
                // Also save before Tox stops: after a reload, the new Tox loads the
                // profile.
                if let Some(path) = &savedata_path
                    && (changed || reload_requested || last_save.elapsed() >= SAVE_INTERVAL)
                {
                    if let Err(e) = write_atomically(path, &tox.savedata()) {
                        log_error(
                            &tx,
                            LogContext::Global,
                            format!("Failed to save {}: {e}", path.display()),
                        );
                    }
                    last_save = Instant::now();
                }
                if reload_requested {
                    break;
                }

                session.flush_sync();

                if let Ok(events) = tox.events() {
                    for event in &events {
                        session.event(&event);
                    }
                }

                thread::sleep(session.iterate_calls());
            }
            if exit_thread {
                break;
            }
        }
    })
}
