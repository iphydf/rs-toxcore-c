//! What toxxi knows of Tox, as facts for the account's other devices, and
//! their wishes carried out.

use toxcore::tox::{ToxConnection, ToxUserStatus};
use toxcore::types::{
    MAX_NAME_LENGTH, MAX_STATUS_MESSAGE_LENGTH, PublicKey, ToxGroupPrivacyState, ToxGroupRole,
    ToxGroupVoiceState,
};

use super::event::{ChatId, Content};
use super::fact::{
    CallState, Connection, Facts, Privacy, Role, Subject, UserStatus, Value, VoiceState, is_kept,
};
use super::protocol::SessionMessage;
use crate::model::{Conversation, Model, WindowId};
use crate::msg::{Cmd, GroupSetting, ToxAction};

pub fn connection(status: ToxConnection) -> Connection {
    match status {
        ToxConnection::TOX_CONNECTION_TCP => Connection::Tcp,
        ToxConnection::TOX_CONNECTION_UDP => Connection::Udp,
        ToxConnection::TOX_CONNECTION_NONE => Connection::None,
    }
}

fn status(status: ToxUserStatus) -> UserStatus {
    match status {
        ToxUserStatus::TOX_USER_STATUS_NONE => UserStatus::Online,
        ToxUserStatus::TOX_USER_STATUS_AWAY => UserStatus::Away,
        ToxUserStatus::TOX_USER_STATUS_BUSY => UserStatus::Busy,
    }
}

fn tox_status(status: &UserStatus) -> Option<ToxUserStatus> {
    match status {
        UserStatus::Online => Some(ToxUserStatus::TOX_USER_STATUS_NONE),
        UserStatus::Away => Some(ToxUserStatus::TOX_USER_STATUS_AWAY),
        UserStatus::Busy => Some(ToxUserStatus::TOX_USER_STATUS_BUSY),
        UserStatus::Unknown { .. } => None,
    }
}

fn role(role: ToxGroupRole) -> Role {
    match role {
        ToxGroupRole::TOX_GROUP_ROLE_FOUNDER => Role::Founder,
        ToxGroupRole::TOX_GROUP_ROLE_MODERATOR => Role::Moderator,
        ToxGroupRole::TOX_GROUP_ROLE_USER => Role::User,
        ToxGroupRole::TOX_GROUP_ROLE_OBSERVER => Role::Observer,
    }
}

fn tox_role(role: &Role) -> Option<ToxGroupRole> {
    match role {
        Role::Founder => Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
        Role::Moderator => Some(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR),
        Role::User => Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
        Role::Observer => Some(ToxGroupRole::TOX_GROUP_ROLE_OBSERVER),
        Role::Unknown { .. } => None,
    }
}

fn privacy(privacy: ToxGroupPrivacyState) -> Privacy {
    match privacy {
        ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC => Privacy::Public,
        ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE => Privacy::Private,
    }
}

fn tox_privacy(privacy: &Privacy) -> Option<ToxGroupPrivacyState> {
    match privacy {
        Privacy::Public => Some(ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC),
        Privacy::Private => Some(ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE),
        Privacy::Unknown { .. } => None,
    }
}

fn voice_state(voice_state: ToxGroupVoiceState) -> VoiceState {
    match voice_state {
        ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_ALL => VoiceState::Everyone,
        ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_MODERATOR => VoiceState::Moderators,
        ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_FOUNDER => VoiceState::Founder,
    }
}

fn tox_voice_state(voice_state: &VoiceState) -> Option<ToxGroupVoiceState> {
    match voice_state {
        VoiceState::Everyone => Some(ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_ALL),
        VoiceState::Moderators => Some(ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_MODERATOR),
        VoiceState::Founder => Some(ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_FOUNDER),
        VoiceState::Unknown { .. } => None,
    }
}

/// The chats toxxi is in.
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
            Value::Status(status(
                friend_status.unwrap_or(ToxUserStatus::TOX_USER_STATUS_NONE),
            )),
        );
    }

    for (chat, conv) in chats(model) {
        let subject = Subject::Chat(chat);
        set(subject, Value::Name(conv.name.clone()));
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

/// Tells the devices in session what changed of the live facts.
pub fn push_live(model: &mut Model) -> Vec<Cmd> {
    let (_, live) = split(model);
    push(model, live)
}

/// Tells the devices in session what changed of the `live` facts.
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
