//! toxxi's side of account sync. The protocol itself is in `tox_sync`.

pub mod avatars;
pub mod calls;
pub mod facts;
pub mod files;
pub mod history;
pub mod invites;
pub mod trace;

pub use tox_sync::{
    account, event, fact, frame, pairing, protocol, replica, session, setting, store,
};

use std::collections::HashSet;

use toxcore::tox::ToxConnection;
use toxcore::types::{Address, PublicKey};

use crate::config::Config;
use crate::model::{ConsoleMessageType, FriendInfo, Model, PendingItem, WindowId};
use crate::msg::{Cmd, IOAction, ToxAction};
use account::AccountState;
use event::{ChatId, Content, Event, EventId, GraphId};
use fact::is_wishable;
use fact::{Subject, Value};
use protocol::{Features, SessionMessage};
use setting::Scope;

pub fn is_device(config: &Config, pk: &PublicKey) -> bool {
    config.sync_devices.contains(pk)
}

pub fn set_device(model: &mut Model, pk: PublicKey, allowed: bool) -> Vec<Cmd> {
    for config in [&mut model.config, &mut model.saved_config] {
        config.sync_devices.retain(|device| *device != pk);
        if allowed {
            config.sync_devices.push(pk);
        }
    }
    if !allowed {
        model.session.sync_sessions.remove(&pk);
        model
            .session
            .blob_queue
            .retain(|(device, ..)| *device != pk);
        forget_held(model, pk);
    }
    let mut cmds = vec![Cmd::IO(IOAction::SaveConfig(None))];
    let changes = model.device_changes();
    cmds.extend(model.record_in_account(changes));
    // A new Hello tells the device what it may do now.
    if model
        .domain
        .friends
        .get(&pk)
        .is_some_and(|info| info.connection != ToxConnection::TOX_CONNECTION_NONE)
    {
        model.session.greeted.insert(pk);
        cmds.push(Cmd::Tox(ToxAction::SyncSend(pk, hello(&model.config, &pk))));
        // One whose Hello came offering account sync starts it now.
        if allowed
            && model
                .session
                .hellos
                .get(&pk)
                .is_some_and(|features| features.contains(Features::ACCOUNT_SYNC))
        {
            model.session.sync_sessions.insert(pk);
            cmds.extend(start_session(model, pk));
            cmds.extend(files::send_pending(model));
        }
    }
    cmds
}

/// Our Hello, which must be the first message of each connection. A friend's
/// Hello can arrive before Tox reports them online.
fn greet(model: &mut Model, pk: PublicKey) -> Option<Cmd> {
    model
        .session
        .greeted
        .insert(pk)
        .then(|| Cmd::Tox(ToxAction::SyncSend(pk, hello(&model.config, &pk))))
}

pub fn hello(config: &Config, pk: &PublicKey) -> Vec<u8> {
    let features = if is_device(config, pk) {
        Features::ACCOUNT_SYNC
    } else {
        Features::NONE
    };
    SessionMessage::hello(features).encode()
}

pub fn to_devices(devices: &HashSet<PublicKey>, message: &[u8]) -> Vec<Cmd> {
    devices
        .iter()
        .map(|device| Cmd::Tox(ToxAction::SyncSend(*device, message.to_vec())))
        .collect()
}

/// A new Tox has no friends online and no calls.
pub fn started(model: &mut Model) -> Vec<Cmd> {
    let friends: Vec<PublicKey> = model.domain.friends.keys().copied().collect();
    let mut cmds = Vec::new();
    for pk in friends {
        if let Some(info) = model.domain.friends.get_mut(&pk) {
            info.connection = ToxConnection::TOX_CONNECTION_NONE;
        }
        cmds.extend(friend_status(model, pk, ToxConnection::TOX_CONNECTION_NONE));
    }
    cmds.extend(calls::restarted(model));
    cmds
}

pub fn friend_status(model: &mut Model, pk: PublicKey, status: ToxConnection) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    if status == ToxConnection::TOX_CONNECTION_NONE {
        model.session.sync_sessions.remove(&pk);
        model.session.greeted.remove(&pk);
        model.session.hellos.remove(&pk);
        forget_held(model, pk);
        cmds.extend(files::offline(model, pk));
    } else {
        cmds.extend(greet(model, pk));
        // Tox joins invited chats through the friend who invited.
        cmds.extend(invites::join(model));
        cmds.extend(avatars::send(model, pk));
    }
    cmds
}

// The next session asks for them again.
fn forget_held(model: &mut Model, device: PublicKey) {
    model.session.held.retain(|_, held| held.device != device);
    model.session.dropped.retain(|_, from| *from != device);
}

fn name(model: &Model, pk: &PublicKey) -> String {
    model
        .domain
        .friends
        .get(pk)
        .map_or_else(|| pk.to_string(), |info| info.name.clone())
}

pub fn received(model: &mut Model, pk: PublicKey, message: &[u8]) -> Vec<Cmd> {
    match SessionMessage::decode(message) {
        Ok(Some(SessionMessage::Hello { version, features })) => {
            let account_sync = features.contains(Features::ACCOUNT_SYNC);
            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "{} speaks sync v{}{}",
                    name(model, &pk),
                    version,
                    if account_sync { ", account sync" } else { "" }
                ),
            );
            // A device's Hello again means it started over without Tox
            // noticing, and waits for ours again. Devices don't answer a
            // Hello, so this can't go back and forth.
            let again = model.session.hellos.insert(pk, features).is_some();
            let mut cmds: Vec<Cmd> = if again && is_device(&model.config, &pk) {
                vec![Cmd::Tox(ToxAction::SyncSend(pk, hello(&model.config, &pk)))]
            } else {
                greet(model, pk).into_iter().collect()
            };
            if account_sync && is_device(&model.config, &pk) {
                model.session.sync_sessions.insert(pk);
                cmds.extend(start_session(model, pk));
                cmds.extend(files::send_pending(model));
            } else {
                model.session.sync_sessions.remove(&pk);
            }
            cmds
        }
        Ok(Some(SessionMessage::Events(events))) if model.session.sync_sessions.contains(&pk) => {
            accept(model, pk, &events)
        }
        Ok(Some(SessionMessage::WantBlob(blob))) if model.session.sync_sessions.contains(&pk) => {
            files::wanted(model, pk, blob)
        }
        Ok(Some(SessionMessage::NoBlob(blob))) if model.session.sync_sessions.contains(&pk) => {
            files::unavailable(model, pk, blob)
        }
        Ok(Some(SessionMessage::Call { friend, action }))
            if model.session.sync_sessions.contains(&pk) =>
        {
            calls::control(model, pk, friend, action)
        }
        Ok(Some(message)) if model.session.sync_sessions.contains(&pk) => {
            to_device(pk, session::answer(&model.events, &message))
        }
        Ok(_) => Vec::new(),
        Err(_) => {
            model.add_console_message(
                ConsoleMessageType::Error,
                format!("Malformed sync message from {}", name(model, &pk)),
            );
            Vec::new()
        }
    }
}

fn to_device(device: PublicKey, messages: Vec<SessionMessage>) -> Vec<Cmd> {
    messages
        .iter()
        .map(|message| Cmd::Tox(ToxAction::SyncSend(device, message.encode())))
        .collect()
}

/// A device's event waiting for its parents.
pub struct Held {
    device: PublicKey,
    bytes: Vec<u8>,
    event: Event,
}

/// Whether devices may write an event, and where toxxi carries it out.
enum Allowed {
    /// Kept, though its chat is gone, so the graph has no gap.
    Kept,
    In(WindowId),
}

/// Whether `device` may write `event`: the messages and files they send,
/// their answers to files, the chats they read and merge, and settings, of
/// the account or its conversations, the friends they add or remove, and
/// their wishes and answers to invites, which are for the console. toxxi
/// records the rest of the account itself.
fn allowed(model: &Model, device: PublicKey, event: &Event) -> Option<Allowed> {
    if event.author != device {
        return None;
    }
    let in_account = event.graph == GraphId::account(&model.domain.self_public_key());
    let kept = |window_id: Option<WindowId>| Some(window_id.map_or(Allowed::Kept, Allowed::In));
    match &event.content {
        Content::Send { .. } | Content::FileAnswered { .. } => {
            model.window_of(&event.graph).map(Allowed::In)
        }
        Content::SendPrivately { .. } => model
            .window_of(&event.graph)
            .filter(|window_id| matches!(window_id, WindowId::Group(_)))
            .map(Allowed::In),
        Content::File {
            incoming: false,
            file_id: None,
            blob: Some(_),
            ..
        } => model
            .window_of(&event.graph)
            .filter(|window_id| matches!(window_id, WindowId::Friend(_)))
            .map(Allowed::In),
        Content::ReadUpTo { graph, .. } if in_account => kept(model.window_of(graph)),
        Content::MergeChat { chat, into, .. } if in_account => kept(
            model
                .window_of(&into.graph())
                .and(model.window_of(&chat.graph())),
        ),
        Content::RelayBot { chat, .. } if in_account => kept(model.window_of(&chat.graph())),
        Content::NewChat { .. } | Content::JoinChat { .. } if in_account => kept(None),
        Content::InviteToChat { chat, .. } if in_account => kept(model.window_of(&chat.graph())),
        // Any device adds, accepts or removes friends, but not the account's
        // devices, which sync goes through.
        Content::WantFriend { pk, .. } | Content::UnwantFriend { pk }
            if in_account
                && !is_device(&model.config, pk)
                && *pk != model.domain.self_public_key() =>
        {
            kept(None)
        }
        // Any device adds, renames or removes devices, but this one, which
        // the account is named after, stays one.
        Content::Device { .. } if in_account => kept(None),
        Content::DeviceGone { pk } if in_account && *pk != model.domain.self_public_key() => {
            kept(None)
        }
        Content::Setting { scope, setting } if in_account && setting::fits(setting) => {
            kept(window_of_scope(model, scope))
        }
        Content::ClearSetting { scope, .. } if in_account => kept(window_of_scope(model, scope)),
        Content::AnswerInvite { invite, .. } if in_account => kept(
            model
                .account
                .invites
                .contains_key(invite)
                .then_some(WindowId::Console),
        ),
        Content::Want { subject, value } if in_account && is_wishable(subject, value) => {
            match subject {
                Subject::Chat(chat) | Subject::Peer { chat, .. } => {
                    kept(model.window_of(&chat.graph()).map(|_| WindowId::Console))
                }
                _ => kept(Some(WindowId::Console)),
            }
        }
        _ => None,
    }
}

fn window_of_scope(model: &Model, scope: &Scope) -> Option<WindowId> {
    match scope {
        Scope::Account => Some(WindowId::Console),
        Scope::Conversation(graph) => model.window_of(graph),
        Scope::Unknown { .. } => None,
    }
}

fn rebuild_account(model: &mut Model) {
    model.account = AccountState::of(
        &model.events,
        &GraphId::account(&model.domain.self_public_key()),
    );
}

/// Takes a device's events in the order they were written, each once its
/// parents are here: a device's offline events come newest first, as each
/// is asked for after its child.
fn accept(model: &mut Model, device: PublicKey, events: &[Vec<u8>]) -> Vec<Cmd> {
    let mut dropped = 0;
    for bytes in events {
        let id = EventId::of(bytes);
        if model.events.contains(&id)
            || model.session.held.contains_key(&id)
            || model.session.dropped.contains_key(&id)
        {
            continue;
        }
        match Event::decode(bytes) {
            // Devices write events with no parents only as the first.
            Ok(event) if !event.parents.is_empty() || event.rank == 0 => {
                model.session.held.insert(
                    id,
                    Held {
                        device,
                        bytes: bytes.clone(),
                        event,
                    },
                );
            }
            _ => {
                model.session.dropped.insert(id, device);
                dropped += 1;
            }
        }
    }

    // By author, who has them already.
    let mut records: Vec<(PublicKey, Vec<Vec<u8>>)> = Vec::new();
    let mut cmds = Vec::new();
    while let Some(id) = model
        .session
        .held
        .iter()
        .filter(|(_, held)| held.event.parents.iter().all(|p| model.events.contains(p)))
        .map(|(id, held)| (held.event.rank, *id))
        .min()
        .map(|(_, id)| id)
    {
        let Held {
            device,
            bytes,
            event,
        } = model.session.held.remove(&id).unwrap();
        match allowed(model, device, &event).map(|a| (a, model.events.insert(&bytes))) {
            Some((allowed, Ok(_))) => {
                match records.iter_mut().find(|(author, _)| *author == device) {
                    Some((_, bytes_of)) => bytes_of.push(bytes),
                    None => records.push((device, vec![bytes])),
                }
                cmds.extend(apply(model, allowed, event, id));
            }
            _ => {
                model.session.dropped.insert(id, device);
                dropped += 1;
            }
        }
    }
    // Those after a dropped one can never be taken.
    loop {
        let doomed: Vec<EventId> = model
            .session
            .held
            .iter()
            .filter(|(_, held)| {
                held.event
                    .parents
                    .iter()
                    .any(|p| model.session.dropped.contains_key(p))
            })
            .map(|(id, _)| *id)
            .collect();
        if doomed.is_empty() {
            break;
        }
        for id in doomed {
            if let Some(held) = model.session.held.remove(&id) {
                model.session.dropped.insert(id, held.device);
                dropped += 1;
            }
        }
    }
    if dropped > 0 {
        model.add_console_message(
            ConsoleMessageType::Error,
            format!("Dropped {} events from device {}", dropped, device),
        );
    }

    let missing: HashSet<EventId> = model
        .session
        .held
        .values()
        .filter(|held| held.device == device)
        .flat_map(|held| &held.event.parents)
        .filter(|parent| !model.events.contains(parent) && !model.session.held.contains_key(parent))
        .copied()
        .collect();
    let mut all: Vec<Cmd> = records
        .into_iter()
        .flat_map(|(author, bytes)| model.persist_from(bytes, Some(author)))
        .collect();
    all.extend(cmds);
    all.extend(to_device(device, session::want(missing)));
    all
}

/// Carries out a device's event.
fn apply(model: &mut Model, allowed: Allowed, event: Event, id: EventId) -> Vec<Cmd> {
    let window_id = match allowed {
        Allowed::In(window_id) => Some(window_id),
        Allowed::Kept => None,
    };
    // A device's change can arrive after a later one, written while it was
    // offline, which then wins.
    if matches!(
        event.content,
        Content::WantFriend { .. } | Content::UnwantFriend { .. } | Content::Want { .. }
    ) {
        rebuild_account(model);
    }
    let wanted = |model: &Model, pk| model.account.friends.get(&pk).is_some_and(|f| f.wanted);
    match (event.content, window_id) {
        (
            Content::WantFriend {
                pk,
                request_message,
                nospam,
            },
            _,
        ) if wanted(model, pk) => want_friend(model, pk, request_message, nospam),
        (Content::UnwantFriend { pk }, _) if !wanted(model, pk) => unwant_friend(model, pk),
        (Content::WantFriend { .. } | Content::UnwantFriend { .. }, _) => Vec::new(),
        (Content::Want { subject, value }, _)
            if !model.account.is_last_said(&subject, &value, &id) =>
        {
            Vec::new()
        }
        (content @ Content::ReadUpTo { .. }, Some(window_id)) => {
            model.read_elsewhere(window_id, id, &content);
            Vec::new()
        }
        // Another device's change can rank before one already applied.
        (
            Content::MergeChat { .. }
            | Content::RelayBot { .. }
            | Content::Setting { .. }
            | Content::ClearSetting { .. },
            _,
        ) => {
            rebuild_account(model);
            Vec::new()
        }
        (Content::Device { pk, .. }, _) => {
            rebuild_account(model);
            if is_device(&model.config, &pk) {
                Vec::new()
            } else {
                // Another device paired it: they connect once both are friends.
                let mut cmds = vec![Cmd::Tox(ToxAction::AcceptFriend(pk))];
                cmds.extend(set_device(model, pk, true));
                cmds
            }
        }
        (Content::DeviceGone { pk }, _) => {
            rebuild_account(model);
            if is_device(&model.config, &pk) {
                set_device(model, pk, false)
            } else {
                Vec::new()
            }
        }
        (
            Content::NewChat {
                kind,
                name,
                privacy,
            },
            _,
        ) => vec![Cmd::Tox(ToxAction::MakeChat(id, kind, privacy, name))],
        (Content::JoinChat { chat_id, password }, _) => {
            vec![Cmd::Tox(ToxAction::JoinChatById(id, chat_id, password))]
        }
        (Content::InviteToChat { chat, friend }, _) => vec![Cmd::Tox(match chat {
            ChatId::Group(chat_id) => ToxAction::InviteFriendToGroup(chat_id, friend),
            ChatId::Conference(conference_id) => {
                ToxAction::InviteFriendToConference(conference_id, friend)
            }
        })],
        (Content::AnswerInvite { .. }, _) => {
            rebuild_account(model);
            invites::join(model)
        }
        (Content::FileAnswered { file, accepted }, Some(window_id)) => {
            crate::update::answer_file(model, window_id, &file, accepted)
        }
        (
            Content::Want {
                subject: Subject::Account,
                value: Value::Avatar(avatar),
            },
            Some(_),
        ) => avatars::wish(model, event.author, avatar),
        (Content::Want { subject, value }, Some(_)) => facts::wish(model, subject, value),
        (Content::File { .. }, Some(window_id)) => {
            model.add_device_message(window_id, id);
            files::send_pending(model)
        }
        (
            Content::Send { message, .. } | Content::SendPrivately { message, .. },
            Some(window_id),
        ) => match model.add_device_message(window_id, id) {
            Some(msg) => crate::update::send_pending(
                model,
                window_id,
                msg.internal_id,
                msg.message_type,
                message,
            ),
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// A device's wish for `pk` as a friend: accepting their request, or sending
/// one to the address it names.
fn want_friend(
    model: &mut Model,
    pk: PublicKey,
    request_message: Option<String>,
    nospam: Option<u32>,
) -> Vec<Cmd> {
    if model.domain.friends.contains_key(&pk) {
        return Vec::new();
    }
    let requested = model
        .domain
        .pending_items
        .iter()
        .any(|item| matches!(item, PendingItem::FriendRequest { pk: from, .. } if *from == pk));
    let action = match nospam {
        _ if requested => ToxAction::AcceptFriend(pk),
        Some(nospam) => ToxAction::AddFriend(
            crate::utils::encode_hex(&Address::from_public_key(pk, nospam).0),
            request_message
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| "Hello".to_owned()),
        ),
        None => return Vec::new(),
    };
    // As Tox will say, so the account doesn't record them gone meanwhile.
    model
        .domain
        .friends
        .insert(pk, FriendInfo::new(pk, ToxConnection::TOX_CONNECTION_NONE));
    model.invalidate_sidebar_cache();
    vec![Cmd::Tox(action)]
}

/// A device's wish to be rid of `pk`: the friend deleted, or their request
/// declined.
fn unwant_friend(model: &mut Model, pk: PublicKey) -> Vec<Cmd> {
    if model.domain.friends.contains_key(&pk) {
        return model.remove_friend(pk);
    }
    model
        .domain
        .pending_items
        .retain(|item| !matches!(item, PendingItem::FriendRequest { pk: from, .. } if *from == pk));
    model.invalidate_sidebar_cache();
    Vec::new()
}

fn start_session(model: &Model, device: PublicKey) -> Vec<Cmd> {
    to_device(
        device,
        vec![session::summary(&model.events), facts::all_live(model)],
    )
}
