//! What toxxi knows of Tox, as facts for the account's other devices, and
//! their wishes carried out.

use toxcore::tox;
use toxcore::types::{
    GroupPrivacyState, GroupRole, GroupVoiceState, MAX_NAME_LENGTH, MAX_STATUS_MESSAGE_LENGTH,
    PublicKey,
};

use super::event::{ChatId, Content};
use super::fact::{
    CallState, Connection, Facts, Privacy, Role, Subject, UserStatus, Value, VoiceState, is_kept,
};
use super::protocol::SessionMessage;
use crate::model::{Conversation, Model, WindowId};
use crate::msg::{Cmd, GroupSetting, ToxAction};

pub fn connection(status: tox::Connection) -> Connection {
    match status {
        tox::Connection::Tcp => Connection::Tcp,
        tox::Connection::Udp => Connection::Udp,
        tox::Connection::None => Connection::None,
    }
}

pub fn tox_connection(connection: &Connection) -> tox::Connection {
    match connection {
        Connection::Tcp => tox::Connection::Tcp,
        Connection::Udp => tox::Connection::Udp,
        Connection::None | Connection::Unknown { .. } => tox::Connection::None,
    }
}

pub fn status(status: tox::UserStatus) -> UserStatus {
    match status {
        tox::UserStatus::None => UserStatus::Online,
        tox::UserStatus::Away => UserStatus::Away,
        tox::UserStatus::Busy => UserStatus::Busy,
    }
}

pub fn tox_status(status: &UserStatus) -> Option<tox::UserStatus> {
    match status {
        UserStatus::Online => Some(tox::UserStatus::None),
        UserStatus::Away => Some(tox::UserStatus::Away),
        UserStatus::Busy => Some(tox::UserStatus::Busy),
        UserStatus::Unknown { .. } => None,
    }
}

pub fn role(role: GroupRole) -> Role {
    match role {
        GroupRole::Founder => Role::Founder,
        GroupRole::Moderator => Role::Moderator,
        GroupRole::User => Role::User,
        GroupRole::Observer => Role::Observer,
    }
}

pub fn tox_role(role: &Role) -> Option<GroupRole> {
    match role {
        Role::Founder => Some(GroupRole::Founder),
        Role::Moderator => Some(GroupRole::Moderator),
        Role::User => Some(GroupRole::User),
        Role::Observer => Some(GroupRole::Observer),
        Role::Unknown { .. } => None,
    }
}

pub fn privacy(privacy: GroupPrivacyState) -> Privacy {
    match privacy {
        GroupPrivacyState::Public => Privacy::Public,
        GroupPrivacyState::Private => Privacy::Private,
    }
}

fn tox_privacy(privacy: &Privacy) -> Option<GroupPrivacyState> {
    match privacy {
        Privacy::Public => Some(GroupPrivacyState::Public),
        Privacy::Private => Some(GroupPrivacyState::Private),
        Privacy::Unknown { .. } => None,
    }
}

pub fn voice_state(voice_state: GroupVoiceState) -> VoiceState {
    match voice_state {
        GroupVoiceState::All => VoiceState::Everyone,
        GroupVoiceState::Moderator => VoiceState::Moderators,
        GroupVoiceState::Founder => VoiceState::Founder,
    }
}

fn tox_voice_state(voice_state: &VoiceState) -> Option<GroupVoiceState> {
    match voice_state {
        VoiceState::Everyone => Some(GroupVoiceState::All),
        VoiceState::Moderators => Some(GroupVoiceState::Moderator),
        VoiceState::Founder => Some(GroupVoiceState::Founder),
        VoiceState::Unknown { .. } => None,
    }
}

pub fn chats(model: &Model) -> Vec<(ChatId, &Conversation)> {
    model
        .session
        .group_numbers
        .values()
        .map(|id| (ChatId::Group(*id), WindowId::Group(*id)))
        .chain(
            model
                .session
                .conference_numbers
                .values()
                .map(|id| (ChatId::Conference(*id), WindowId::Conference(*id))),
        )
        .filter_map(|(chat, window_id)| {
            model
                .domain
                .conversations
                .get(&window_id)
                .map(|conv| (chat, conv))
        })
        .collect()
}

/// Everything Tox says, kept and live alike.
fn facts(model: &Model) -> Facts {
    let domain = &model.domain;
    let mut facts = Facts::default();
    let mut set = |subject, value| {
        facts.set(subject, value);
    };

    set(Subject::Account, Value::Name(domain.self_name.clone()));
    set(
        Subject::Account,
        Value::StatusMessage(domain.self_status_message.clone()),
    );
    set(
        Subject::Account,
        Value::Status(status(domain.self_status_type)),
    );
    set(Subject::Account, Value::Address(domain.tox_id.0.to_vec()));
    set(
        Subject::Account,
        Value::Connection(connection(domain.self_connection_status)),
    );
    set(Subject::Account, Value::CallRelay(true));

    for (pk, info) in &domain.friends {
        let friend = Subject::Friend(*pk);
        set(friend, Value::Name(info.name.clone()));
        set(friend, Value::StatusMessage(info.status_message.clone()));
        set(friend, Value::Connection(connection(info.connection)));
        set(friend, Value::Typing(info.is_typing));
        set(
            friend,
            Value::Call(
                model
                    .session
                    .calls
                    .get(pk)
                    .map_or(CallState::None, |call| call.state()),
            ),
        );
        let friend_status = model.session.friend_statuses.get(pk).copied();
        set(
            friend,
            Value::Status(status(friend_status.unwrap_or(tox::UserStatus::None))),
        );
    }

    for (chat, conv) in chats(model) {
        let subject = Subject::Chat(chat);
        if !conv.name.is_empty() {
            set(subject, Value::Name(conv.name.clone()));
        }
        set(subject, Value::Joined(true));
        // Conferences have only a title, their name.
        if let (ChatId::Group(_), Some(topic)) = (chat, &conv.topic) {
            set(subject, Value::Topic(topic.clone()));
        }
        if let Some(self_name) = &conv.self_name {
            set(subject, Value::SelfName(self_name.clone()));
        }
        if let Some(self_role) = conv.self_role {
            set(subject, Value::Role(role(self_role)));
        }
        let mut selves = vec![domain.self_public_key()];
        if let ChatId::Group(id) = chat
            && let Some(settings) = model.session.group_settings.get(&id)
        {
            set(subject, Value::Privacy(privacy(settings.privacy)));
            set(subject, Value::PeerLimit(u32::from(settings.peer_limit)));
            set(subject, Value::Password(settings.password.clone()));
            set(subject, Value::TopicLock(settings.topic_lock));
            set(
                subject,
                Value::VoiceState(voice_state(settings.voice_state)),
            );
            set(subject, Value::SelfKey(settings.self_pk));
            selves.push(settings.self_pk);
        }
        for peer in &conv.peers {
            let pk: PublicKey = peer.id.0;
            if !peer.seen_online || selves.contains(&pk) {
                continue;
            }
            let subject = Subject::Peer { chat, pk };
            set(subject, Value::Present(true));
            set(subject, Value::Name(peer.name.clone()));
            set(subject, Value::Status(status(peer.status)));
            if let Some(peer_role) = peer.role {
                set(subject, Value::Role(role(peer_role)));
            }
        }
    }
    facts
}

/// What Tox says, split into kept and live facts.
pub fn split(model: &Model) -> (Facts, Facts) {
    let mut kept = Facts::default();
    let mut live = Facts::default();
    for (subject, value) in facts(model).iter() {
        let facts = if is_kept(subject, value) {
            &mut kept
        } else {
            &mut live
        };
        facts.set(*subject, value.clone());
    }
    (kept, live)
}

/// The `kept` facts Tox has changed since the account last recorded them.
pub fn changes(model: &Model, kept: &Facts) -> Vec<Content> {
    let known = &model.account.facts;
    let mut contents: Vec<Content> = kept
        .iter()
        .filter(|(subject, value)| !known.of(subject).contains(value))
        .map(|(subject, value)| Content::Fact {
            subject: *subject,
            value: value.clone(),
        })
        .collect();
    let joined: Vec<ChatId> = chats(model).into_iter().map(|(chat, _)| chat).collect();
    contents.extend(
        model
            .account
            .chats()
            .filter(|chat| !joined.contains(chat))
            .map(|chat| Content::Fact {
                subject: Subject::Chat(chat),
                value: Value::Joined(false),
            }),
    );
    contents
}

/// Sends the devices in session the live facts that changed.
pub fn push_live(model: &mut Model) -> Vec<Cmd> {
    let (_, live) = split(model);
    push(model, live)
}

/// Sends the devices in session the `live` facts that changed.
pub fn push(model: &mut Model, live: Facts) -> Vec<Cmd> {
    let changes = model.session.live.changes(&live);
    model.session.live = live;
    if changes.is_empty() {
        return Vec::new();
    }
    let message = SessionMessage::Facts {
        facts: changes,
        all: false,
    };
    super::to_devices(&model.session.sync_sessions, &message.encode())
}

/// Every live fact, for a new session.
pub fn all_live(model: &Model) -> SessionMessage {
    SessionMessage::Facts {
        facts: model
            .session
            .live
            .iter()
            .map(|(subject, value)| (*subject, value.clone()))
            .collect(),
        all: true,
    }
}

/// Makes Tox match a device's wish, which `fact::is_wishable` allows. What
/// Tox wouldn't take changes nothing, so the facts stay as Tox has them.
pub fn wish(model: &mut Model, subject: Subject, value: Value) -> Vec<Cmd> {
    let setting = |id, setting| Some(ToxAction::SetGroupSetting(id, setting));
    let action = match (subject, value) {
        (Subject::Account, Value::Name(name)) if name.len() <= MAX_NAME_LENGTH => {
            model.domain.self_name = name.clone();
            Some(ToxAction::SetName(name))
        }
        (Subject::Account, Value::StatusMessage(message))
            if message.len() <= MAX_STATUS_MESSAGE_LENGTH =>
        {
            model.domain.self_status_message = message.clone();
            Some(ToxAction::SetStatusMessage(message))
        }
        (Subject::Account, Value::Status(user_status)) => {
            tox_status(&user_status).map(|user_status| {
                model.domain.self_status_type = user_status;
                ToxAction::SetStatusType(user_status)
            })
        }
        (Subject::Chat(chat), Value::Joined(false)) => {
            return model.close_window(chat.into());
        }
        (Subject::Chat(ChatId::Conference(id)), Value::Name(title)) => {
            Some(ToxAction::SetConferenceTopic(id, title))
        }
        (Subject::Chat(ChatId::Group(id)), Value::Topic(topic)) => {
            Some(ToxAction::SetGroupTopic(id, topic))
        }
        (Subject::Chat(ChatId::Group(id)), Value::SelfName(name))
            if !name.is_empty() && name.len() <= MAX_NAME_LENGTH =>
        {
            if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Group(id)) {
                conv.self_name = Some(name.clone());
            }
            Some(ToxAction::SetGroupNickname(id, name))
        }
        (Subject::Chat(ChatId::Group(id)), Value::Privacy(p)) => {
            tox_privacy(&p).and_then(|p| setting(id, GroupSetting::Privacy(p)))
        }
        (Subject::Chat(ChatId::Group(id)), Value::PeerLimit(limit)) => u16::try_from(limit)
            .ok()
            .and_then(|limit| setting(id, GroupSetting::PeerLimit(limit))),
        (Subject::Chat(ChatId::Group(id)), Value::Password(password)) => {
            setting(id, GroupSetting::Password(password))
        }
        (Subject::Chat(ChatId::Group(id)), Value::TopicLock(lock)) => {
            setting(id, GroupSetting::TopicLock(lock))
        }
        (Subject::Chat(ChatId::Group(id)), Value::VoiceState(v)) => {
            tox_voice_state(&v).and_then(|v| setting(id, GroupSetting::VoiceState(v)))
        }
        (
            Subject::Peer {
                chat: ChatId::Group(id),
                pk,
            },
            Value::Role(r),
        ) => tox_role(&r).map(|r| ToxAction::ModerateGroupPeer(id, pk, Some(r))),
        (
            Subject::Peer {
                chat: ChatId::Group(id),
                pk,
            },
            Value::Present(false),
        ) => Some(ToxAction::ModerateGroupPeer(id, pk, None)),
        _ => None,
    };
    action.map(Cmd::Tox).into_iter().collect()
}
