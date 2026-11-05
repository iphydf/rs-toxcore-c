//! toxxi as a device of an account another toxxi, its home, runs on Tox
//! (`/link`). Its own Tox runs only a device key, whose one friend is the
//! home, and everything it shows comes from the account's events and facts.

use std::collections::{HashMap, HashSet};

use toxcore::tox::{Address, Connection};
use toxcore::types::{ADDRESS_SIZE, PublicKey};

use super::event::ChatKind;
use super::event::Content;
use super::event::{ChatId, EventId, GraphId};
use super::fact::Privacy;
use super::fact::{Facts, Subject, Value};
use super::facts::{privacy, role, status, tox_connection, tox_role, tox_status, voice_state};
use super::pairing::PairingCode;
use super::protocol::SessionMessage;
use super::replica::Replica;
use crate::model::{
    ConsoleMessageType, FriendInfo, Model, PeerId, PeerInfo, PendingItem, WindowId,
};
use crate::msg::{Cmd, GroupSetting, IOAction, ToxAction, ToxEvent};
use crate::utils::parse_address;

/// Reads a link the home hands out with `/device pair`:
/// `tox:<home's Tox ID>?pair=<code>`.
pub fn parse_link(link: &str) -> Result<(Address, PairingCode), String> {
    let (address, code) = link
        .strip_prefix("tox:")
        .and_then(|rest| rest.split_once("?pair="))
        .ok_or("a link from /device pair looks like tox:<Tox ID>?pair=<code>")?;
    let address = parse_address(address)?;
    let code = PairingCode::from_hex(code).ok_or("its pairing code isn't 32 hex digits")?;
    Ok((address, code))
}

/// Makes this profile a device of the account whose home handed out `link`, and
/// asks the home to accept its key. Only a profile without friends can be
/// linked: its key becomes the device's, whose one friend is the home.
pub fn link(model: &mut Model, link: &str) -> Result<Vec<Cmd>, String> {
    if model.config.home.is_some() {
        return Err("this profile is linked already".to_owned());
    }
    if !model.domain.friends.is_empty() {
        return Err("only a profile without friends can be linked".to_owned());
    }
    // Its Tox would stay in them, and every member shares their history graphs.
    if !model.session.group_numbers.is_empty() || !model.session.conference_numbers.is_empty() {
        return Err("leave this profile's groups and conferences first (/close)".to_owned());
    }
    let (address, code) = parse_link(link)?;
    let home = address.public_key();
    for config in [&mut model.config, &mut model.saved_config] {
        config.home = Some(home);
    }
    let device = model.domain.tox_id;
    model.domain.tox_id = address;
    // The profile's own history is another account's: a group's history is
    // the same graph for every member, so the account's would grow from it.
    model.events = Default::default();
    model.message_events.clear();
    model.domain.conversations.clear();
    model.ui.window_ids = vec![WindowId::Console];
    model.ui.active_window_index = 0;
    started(model, device, home);
    model.add_console_message(
        ConsoleMessageType::Status,
        format!("Linking to {home}: the home takes this device when it comes online."),
    );
    Ok(vec![
        Cmd::IO(IOAction::SetAsideEvents(format!(
            "events-{}.log",
            device.public_key()
        ))),
        Cmd::IO(IOAction::SaveConfig(model.saved_config.clone())),
        // The home names the device as it names itself.
        Cmd::Tox(ToxAction::SetDeviceName("toxxi".to_owned())),
        Cmd::Tox(ToxAction::AddFriend(address, code.request_message())),
    ])
}

/// Sets up a linked profile whose Tox has the key `device`, and shows what
/// its copy of the account holds.
pub fn started(model: &mut Model, device: Address, home: PublicKey) {
    model.session.device = Some(device);
    model.session.replica = Some(Replica::new(device.public_key(), &home));
    show_account(model, home);
    let windows: Vec<WindowId> = model.domain.conversations.keys().copied().collect();
    for window_id in windows {
        model.show_history(window_id);
    }
}

/// Handles a linked profile's Tox events: only the home and syncing with it
/// matter.
pub fn tox_event(model: &mut Model, home: PublicKey, event: ToxEvent) -> Vec<Cmd> {
    match event {
        ToxEvent::FriendStatus(pk, status) => {
            if pk != home {
                return Vec::new();
            }
            model.session.home_online = status != Connection::None;
            if model.session.home_online {
                to_home(home, vec![Replica::hello()])
            } else {
                if let Some(replica) = &mut model.session.replica {
                    replica.offline();
                }
                // The home's live facts no longer hold.
                show_account(model, home);
                Vec::new()
            }
        }
        ToxEvent::SyncMessage(pk, message) if pk == home => received(model, home, &message),
        ToxEvent::Address(address) => {
            model.session.device = Some(address);
            Vec::new()
        }
        ToxEvent::Started => {
            model.session.home_online = false;
            if let Some(replica) = &mut model.session.replica {
                replica.offline();
            }
            Vec::new()
        }
        ToxEvent::Message(..)
        | ToxEvent::GroupMessage(..)
        | ToxEvent::GroupPrivateMessage(..)
        | ToxEvent::ConferenceMessage(..)
        | ToxEvent::ConnectionStatus(_)
        | ToxEvent::DhtId(_)
        | ToxEvent::FriendName(..)
        | ToxEvent::FriendStatusMessage(..)
        | ToxEvent::FriendTyping(..)
        | ToxEvent::FriendUserStatus(..)
        | ToxEvent::ReadReceipt(..)
        | ToxEvent::SyncMessage(..)
        | ToxEvent::CallRinging { .. }
        | ToxEvent::CallConnected(_)
        | ToxEvent::CallEnded(_)
        | ToxEvent::MessageSent(..)
        | ToxEvent::GroupMessageSent(..)
        | ToxEvent::ConferenceMessageSent(..)
        | ToxEvent::MessageSendFailed(..)
        | ToxEvent::FriendRequest(..)
        | ToxEvent::GroupInvite { .. }
        | ToxEvent::ConferenceInvite { .. }
        | ToxEvent::GroupCreated(..)
        | ToxEvent::ConferenceCreated(..)
        | ToxEvent::InviteJoined(..)
        | ToxEvent::ChatMade(..)
        | ToxEvent::GroupTopic(..)
        | ToxEvent::GroupName(..)
        | ToxEvent::ConferenceTitle(..)
        | ToxEvent::GroupSelfJoin(_)
        | ToxEvent::GroupJoinFail(..)
        | ToxEvent::GroupSelfRole(..)
        | ToxEvent::GroupSettings(..)
        | ToxEvent::GroupPeerJoin(..)
        | ToxEvent::GroupPeerLeave(..)
        | ToxEvent::GroupPeerName(..)
        | ToxEvent::GroupPeerStatus(..)
        | ToxEvent::GroupModeration { .. }
        | ToxEvent::ConferencePeerJoin(..)
        | ToxEvent::ConferencePeerLeave(..)
        | ToxEvent::ConferencePeerName(..)
        | ToxEvent::FileRecv(..)
        | ToxEvent::FileChunkRequest(..)
        | ToxEvent::FileRecvControl(..)
        | ToxEvent::FileChunkSent(..)
        | ToxEvent::Log { .. } => Vec::new(),
    }
}

/// What a linked profile does for the Tox actions toxxi asks for: its own
/// Tox only syncs with the home, which carries out the account's actions as
/// it hears of them. Messages go as the `Send` events recorded with them.
pub fn redirect(model: &mut Model, home: PublicKey, cmds: Vec<Cmd>) -> Vec<Cmd> {
    let mut out = Vec::new();
    let mut wishes = Vec::new();
    let mut unsupported = false;
    for cmd in cmds {
        let Cmd::Tox(action) = cmd else {
            out.push(cmd);
            continue;
        };
        match action {
            ToxAction::SyncSend(..)
            | ToxAction::SetDeviceName(..)
            | ToxAction::Bootstrap(..)
            | ToxAction::Reload(..)
            | ToxAction::Save
            | ToxAction::Shutdown => out.push(Cmd::Tox(action)),
            ToxAction::AddFriend(address, _) if address.public_key() == home => {
                out.push(Cmd::Tox(action));
            }
            ToxAction::SendMessage(..)
            | ToxAction::SendGroupMessage(..)
            | ToxAction::SendGroupPrivateMessage(..)
            | ToxAction::SendConferenceMessage(..)
            | ToxAction::SetTyping(..) => {}
            action @ (ToxAction::SetNospam(_)
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
            | ToxAction::SetName(_)
            | ToxAction::SetGroupNickname(..)
            | ToxAction::SetGroupTopic(..)
            | ToxAction::SetGroupSetting(..)
            | ToxAction::ModerateGroupPeer(..)
            | ToxAction::SetConferenceTopic(..)
            | ToxAction::FileSend { .. }
            | ToxAction::FileControl(..)
            | ToxAction::FileSendChunk(..)
            | ToxAction::FileSeek(..)
            | ToxAction::CallConnect { .. }
            | ToxAction::CallHangUp(_)) => match wish(action) {
                Some(content) => wishes.push(content),
                None => unsupported = true,
            },
        }
    }
    if unsupported {
        model.add_console_message(
            ConsoleMessageType::Error,
            "A linked profile can't do that yet: do it on the home.".to_owned(),
        );
    }
    out.extend(model.record_in_account(wishes));
    out
}

/// The event that asks the home for what `action` does.
fn wish(action: ToxAction) -> Option<Content> {
    let want = |subject, value| Some(Content::Want { subject, value });
    let group = |id| Subject::Chat(ChatId::Group(id));
    let conference = |id| Subject::Chat(ChatId::Conference(id));
    match action {
        ToxAction::SetName(name) => want(Subject::Account, Value::Name(name)),
        ToxAction::SetStatusMessage(message) => {
            want(Subject::Account, Value::StatusMessage(message))
        }
        ToxAction::SetStatusType(user_status) => {
            want(Subject::Account, Value::Status(status(user_status)))
        }
        ToxAction::AddFriend(address, message) => Some(Content::WantFriend {
            pk: address.public_key(),
            request_message: Some(message),
            nospam: Some(address.nospam()),
        }),
        ToxAction::AcceptFriend(pk) => Some(Content::WantFriend {
            pk,
            request_message: None,
            nospam: None,
        }),
        ToxAction::DeleteFriend(pk) => Some(Content::UnwantFriend { pk }),
        ToxAction::CreateGroup(name) => Some(Content::NewChat {
            kind: ChatKind::Group,
            name,
            privacy: Privacy::Public,
        }),
        ToxAction::CreateConference => Some(Content::NewChat {
            kind: ChatKind::Conference,
            name: String::new(),
            privacy: Privacy::Public,
        }),
        ToxAction::JoinGroup(chat_id, password) => Some(Content::JoinChat { chat_id, password }),
        ToxAction::InviteFriendToGroup(id, friend) => Some(Content::InviteToChat {
            chat: ChatId::Group(id),
            friend,
        }),
        ToxAction::InviteFriendToConference(id, friend) => Some(Content::InviteToChat {
            chat: ChatId::Conference(id),
            friend,
        }),
        ToxAction::LeaveGroup(id) => want(group(id), Value::Joined(false)),
        ToxAction::DeleteConference(id) => want(conference(id), Value::Joined(false)),
        ToxAction::SetGroupTopic(id, topic) => want(group(id), Value::Topic(topic)),
        ToxAction::SetConferenceTopic(id, title) => want(conference(id), Value::Name(title)),
        ToxAction::SetGroupNickname(id, name) => want(group(id), Value::SelfName(name)),
        ToxAction::SetGroupSetting(id, setting) => want(
            group(id),
            match setting {
                GroupSetting::Privacy(p) => Value::Privacy(privacy(p)),
                GroupSetting::PeerLimit(limit) => Value::PeerLimit(u32::from(limit)),
                GroupSetting::Password(password) => Value::Password(password),
                GroupSetting::TopicLock(lock) => Value::TopicLock(lock),
                GroupSetting::VoiceState(v) => Value::VoiceState(voice_state(v)),
            },
        ),
        ToxAction::ModerateGroupPeer(id, pk, new_role) => want(
            Subject::Peer {
                chat: ChatId::Group(id),
                pk,
            },
            new_role.map_or(Value::Present(false), |r| Value::Role(role(r))),
        ),
        ToxAction::SendMessage(..)
        | ToxAction::SendGroupMessage(..)
        | ToxAction::SetNospam(_)
        | ToxAction::SendGroupPrivateMessage(..)
        | ToxAction::SendConferenceMessage(..)
        | ToxAction::AcceptGroupInvite { .. }
        | ToxAction::JoinConference { .. }
        | ToxAction::MakeChat(..)
        | ToxAction::JoinChatById(..)
        | ToxAction::SetGroupPeerIgnore(..)
        | ToxAction::SetTyping(..)
        | ToxAction::SetDeviceName(_)
        | ToxAction::Bootstrap(..)
        | ToxAction::FileSend { .. }
        | ToxAction::FileControl(..)
        | ToxAction::FileSendChunk(..)
        | ToxAction::FileSeek(..)
        | ToxAction::SyncSend(..)
        | ToxAction::CallConnect { .. }
        | ToxAction::CallHangUp(_)
        | ToxAction::Reload(_)
        | ToxAction::Save
        | ToxAction::Shutdown => None,
    }
}

/// Asks the home for the page of messages before the oldest one we have.
pub fn older(model: &mut Model, home: PublicKey, window_id: WindowId) -> Vec<Cmd> {
    let me = model.domain.self_public_key();
    let (Some(graph), Some(replica)) = (
        super::history::graph_of(&me, window_id),
        &mut model.session.replica,
    ) else {
        return Vec::new();
    };
    to_home(home, replica.older(&model.events, graph))
}

fn to_home(home: PublicKey, messages: Vec<SessionMessage>) -> Vec<Cmd> {
    messages
        .iter()
        .map(|message| Cmd::Tox(ToxAction::SyncSend(home, message.encode())))
        .collect()
}

fn received(model: &mut Model, home: PublicKey, message: &[u8]) -> Vec<Cmd> {
    let message = match SessionMessage::decode(message) {
        Ok(Some(message)) => message,
        Ok(None) => return Vec::new(),
        Err(_) => {
            model.add_console_message(
                ConsoleMessageType::Error,
                "Malformed sync message from the home".to_owned(),
            );
            return Vec::new();
        }
    };
    let came: Vec<EventId> = match &message {
        SessionMessage::Events(events) => events
            .iter()
            .map(|bytes| EventId::of(bytes))
            .filter(|id| !model.events.contains(id))
            .collect(),
        SessionMessage::Hello { .. }
        | SessionMessage::Summary(_)
        | SessionMessage::Heads { .. }
        | SessionMessage::Want(_)
        | SessionMessage::History { .. }
        | SessionMessage::WantBlob(_)
        | SessionMessage::NoBlob(_)
        | SessionMessage::Facts { .. }
        | SessionMessage::Call { .. }
        | SessionMessage::Unknown { .. } => Vec::new(),
    };
    let facts = matches!(message, SessionMessage::Facts { .. });
    let Some(replica) = &mut model.session.replica else {
        return Vec::new();
    };
    let replies = replica.received(&mut model.events, message);

    let added: Vec<EventId> = came
        .into_iter()
        .filter(|id| model.events.contains(id))
        .collect();
    let records = added
        .iter()
        .filter_map(|id| model.events.bytes(id).map(<[u8]>::to_vec))
        .collect();
    let mut cmds = model.persist_from(records, Some(home));
    show(model, home, &added, facts);
    cmds.extend(to_home(home, replies));
    cmds
}

/// Shows what new events and live facts change.
fn show(model: &mut Model, home: PublicKey, added: &[EventId], facts: bool) {
    let graphs: HashSet<GraphId> = added
        .iter()
        .filter_map(|id| model.events.get(id).map(|event| event.graph))
        .collect();
    let account = GraphId::account(&home);
    if facts || graphs.contains(&account) {
        show_account(model, home);
    }
    for graph in graphs.iter().filter(|graph| **graph != account) {
        let Some(window_id) = model.window_of(graph) else {
            continue;
        };
        model.ensure_window(window_id);
        model.show_history(window_id);
    }
}

/// Shows the account as its events and the live facts say: the profile,
/// friends, friend requests and chats.
fn show_account(model: &mut Model, home: PublicKey) {
    model.account = super::account::AccountState::of(&model.events, &GraphId::account(&home));
    let mut facts = model.account.facts.clone();
    if model.session.home_online
        && let Some(replica) = &model.session.replica
    {
        facts.update(replica.live().iter().map(|(s, v)| (*s, v.clone())));
    }
    show_profile(model, &facts);
    show_friends(model, home, &facts);
    show_chats(model, &facts);
    // As on the home, every friend has a window; its history may have come
    // before the friend.
    let new: Vec<WindowId> = model
        .domain
        .friends
        .keys()
        .map(|pk| WindowId::Friend(*pk))
        .filter(|window_id| !model.domain.conversations.contains_key(window_id))
        .collect();
    for window_id in new {
        model.ensure_window(window_id);
        model.show_history(window_id);
    }
    model.invalidate_sidebar_cache();
}

fn show_profile(model: &mut Model, facts: &Facts) {
    let domain = &mut model.domain;
    for value in facts.of(&Subject::Account) {
        match value {
            Value::Name(name) => domain.self_name = name.clone(),
            Value::StatusMessage(message) => domain.self_status_message = message.clone(),
            Value::Status(status) => {
                if let Some(status) = tox_status(status) {
                    domain.self_status_type = status;
                }
            }
            Value::Address(address) => {
                if let Ok(address) = <[u8; ADDRESS_SIZE]>::try_from(address.as_slice()) {
                    domain.tox_id = Address(address);
                }
            }
            Value::Connection(_)
            | Value::Typing(_)
            | Value::Topic(_)
            | Value::Role(_)
            | Value::Privacy(_)
            | Value::PeerLimit(_)
            | Value::Password(_)
            | Value::TopicLock(_)
            | Value::VoiceState(_)
            | Value::Joined(_)
            | Value::SelfName(_)
            | Value::Present(_)
            | Value::Call(_)
            | Value::CallRelay(_)
            | Value::SelfKey(_)
            | Value::Avatar(_)
            | Value::Unknown { .. } => {}
        }
    }
    domain.self_connection_status = facts
        .find(&Subject::Account, |value| match value {
            Value::Connection(connection) => Some(tox_connection(connection)),
            Value::Name(_)
            | Value::StatusMessage(_)
            | Value::Status(_)
            | Value::Typing(_)
            | Value::Topic(_)
            | Value::Role(_)
            | Value::Privacy(_)
            | Value::PeerLimit(_)
            | Value::Password(_)
            | Value::TopicLock(_)
            | Value::VoiceState(_)
            | Value::Joined(_)
            | Value::SelfName(_)
            | Value::Present(_)
            | Value::Address(_)
            | Value::Call(_)
            | Value::CallRelay(_)
            | Value::SelfKey(_)
            | Value::Avatar(_)
            | Value::Unknown { .. } => None,
        })
        .unwrap_or(Connection::None);
}

fn show_friends(model: &mut Model, home: PublicKey, facts: &Facts) {
    let account = &model.account;
    let mut friends = HashMap::new();
    let mut requests = Vec::new();
    for (pk, friend) in &account.friends {
        // The account's devices are its own, not friends.
        if *pk == home || account.devices.contains_key(pk) {
            continue;
        }
        if !friend.wanted {
            if let Some(message) = &friend.request {
                requests.push(PendingItem::FriendRequest {
                    pk: *pk,
                    message: message.clone(),
                });
            }
            continue;
        }
        let subject = Subject::Friend(*pk);
        let mut info = FriendInfo::new(*pk, Connection::None);
        for value in facts.of(&subject) {
            match value {
                Value::Name(name) => info.name = name.clone(),
                Value::StatusMessage(message) => info.status_message = message.clone(),
                Value::Connection(connection) => info.connection = tox_connection(connection),
                Value::Typing(typing) => info.is_typing = *typing,
                Value::Status(status) => {
                    if let Some(status) = tox_status(status) {
                        model.session.friend_statuses.insert(*pk, status);
                    }
                }
                Value::Topic(_)
                | Value::Role(_)
                | Value::Privacy(_)
                | Value::PeerLimit(_)
                | Value::Password(_)
                | Value::TopicLock(_)
                | Value::VoiceState(_)
                | Value::Joined(_)
                | Value::SelfName(_)
                | Value::Present(_)
                | Value::Address(_)
                | Value::Call(_)
                | Value::CallRelay(_)
                | Value::SelfKey(_)
                | Value::Avatar(_)
                | Value::Unknown { .. } => {}
            }
        }
        friends.insert(*pk, info);
    }
    for invite in model
        .account
        .invites
        .values()
        .filter(|invite| invite.is_open())
    {
        requests.push(match invite.kind {
            ChatKind::Group => PendingItem::GroupInvite {
                friend: invite.from,
                invite_data: invite.invite.clone(),
                group_name: invite.name.clone(),
            },
            ChatKind::Conference => PendingItem::ConferenceInvite {
                friend: invite.from,
                conference_type: toxcore::types::ConferenceType::Text,
                cookie: invite.invite.clone(),
            },
            ChatKind::Unknown { .. } => continue,
        });
    }
    model.domain.friends = friends;
    // The account decides all of them.
    model.domain.pending_items = requests;
}

fn show_chats(model: &mut Model, facts: &Facts) {
    let chats: Vec<_> = model.account.chats().collect();
    for chat in &chats {
        let window_id = WindowId::from(*chat);
        model.ensure_window(window_id);
        let subject = Subject::Chat(*chat);
        let peers: Vec<PeerInfo> = facts
            .subjects()
            .filter_map(|subject| match subject {
                Subject::Peer { chat: of, pk } if of == chat => Some(*pk),
                Subject::Account | Subject::Friend(_) | Subject::Chat(_) | Subject::Peer { .. } => {
                    None
                }
            })
            .map(|pk| peer(facts, *chat, pk))
            .collect();
        let Some(conv) = model.domain.conversations.get_mut(&window_id) else {
            continue;
        };
        for value in facts.of(&subject) {
            match value {
                Value::Name(name) => conv.name = name.clone(),
                Value::Topic(topic) => conv.topic = Some(topic.clone()),
                Value::SelfName(name) => conv.self_name = Some(name.clone()),
                Value::Role(role) => conv.self_role = tox_role(role),
                Value::StatusMessage(_)
                | Value::Status(_)
                | Value::Connection(_)
                | Value::Typing(_)
                | Value::Privacy(_)
                | Value::PeerLimit(_)
                | Value::Password(_)
                | Value::TopicLock(_)
                | Value::VoiceState(_)
                | Value::Joined(_)
                | Value::Present(_)
                | Value::Address(_)
                | Value::Call(_)
                | Value::CallRelay(_)
                | Value::SelfKey(_)
                | Value::Avatar(_)
                | Value::Unknown { .. } => {}
            }
        }
        conv.peers = peers
            .into_iter()
            .map(|peer| PeerInfo {
                is_ignored: conv.ignored_peers.contains(&peer.id.0),
                ..peer
            })
            .collect();
        model.invalidate_window_cache(window_id);
    }
    // Close chats the account left.
    model.retain_windows(|window_id| match window_id {
        WindowId::Group(id) => chats.contains(&ChatId::Group(*id)),
        WindowId::Conference(id) => chats.contains(&ChatId::Conference(*id)),
        WindowId::Console | WindowId::Friend(_) | WindowId::Logs | WindowId::Files => true,
    });
}

fn peer(facts: &Facts, chat: ChatId, pk: PublicKey) -> PeerInfo {
    let mut peer = PeerInfo {
        id: PeerId(pk),
        name: String::new(),
        role: None,
        status: toxcore::tox::UserStatus::None,
        is_ignored: false,
        seen_online: true,
    };
    for value in facts.of(&Subject::Peer { chat, pk }) {
        match value {
            Value::Name(name) => peer.name = name.clone(),
            Value::Role(role) => peer.role = tox_role(role),
            Value::Status(status) => peer.status = tox_status(status).unwrap_or(peer.status),
            Value::StatusMessage(_)
            | Value::Connection(_)
            | Value::Typing(_)
            | Value::Topic(_)
            | Value::Privacy(_)
            | Value::PeerLimit(_)
            | Value::Password(_)
            | Value::TopicLock(_)
            | Value::VoiceState(_)
            | Value::Joined(_)
            | Value::SelfName(_)
            | Value::Present(_)
            | Value::Address(_)
            | Value::Call(_)
            | Value::CallRelay(_)
            | Value::SelfKey(_)
            | Value::Avatar(_)
            | Value::Unknown { .. } => {}
        }
    }
    peer
}
