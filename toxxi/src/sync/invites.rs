//! The account's invites to chats, which its devices answer: toxxi joins the
//! chats they answer to join, through the friends who invited, and records
//! how that went.

use toxcore::tox::ToxConnection;

use crate::model::{Model, WindowId};
use crate::msg::{Cmd, ToxAction};
use crate::utils::encode_hex;

use super::account::InviteStatus;
use toxcore::types::GroupChatId;

use super::event::{ChatId, ChatKind, Content, EventId, GraphId};

/// Records `content` in the account graph.
fn record(model: &mut Model, content: Content) -> Vec<Cmd> {
    let me = model.domain.self_public_key();
    let time = model.time_provider.now_local().timestamp_millis();
    let (id, bytes) = model
        .events
        .create(GraphId::account(&me), me, time, content.clone());
    model.account.apply(id, &content);
    model.persist(vec![bytes])
}

/// An answer given here, as a device gives one.
pub fn answer(
    model: &mut Model,
    invite: EventId,
    join: bool,
    password: Option<String>,
) -> Vec<Cmd> {
    let mut cmds = record(
        model,
        Content::AnswerInvite {
            invite,
            join,
            password,
        },
    );
    cmds.extend(self::join(model));
    cmds
}

/// After an invite was answered here or on a device, or its friend came
/// online: joins the chats of invites answered to join, through the friend
/// who invited, and those joined or declined are no longer pending here.
pub fn join(model: &mut Model) -> Vec<Cmd> {
    let online = |model: &Model, friend| {
        model
            .domain
            .friends
            .get(friend)
            .is_some_and(|info| info.connection != ToxConnection::TOX_CONNECTION_NONE)
    };
    let ready: Vec<_> = model
        .account
        .invites
        .iter()
        .filter(|(id, invite)| {
            invite.status == InviteStatus::Joining
                && !model.session.joining.contains(id)
                && (invite.chat.is_some() || online(model, &invite.from))
        })
        .map(|(id, invite)| (*id, invite.clone()))
        .collect();
    let mut cmds = Vec::new();
    for (id, invite) in ready {
        let data = encode_hex(&invite.invite);
        let action = match (invite.kind, invite.chat) {
            // Tox takes an invite only once: one that reached its chat is
            // joined while the home is in the chat, and spent once it isn't.
            (_, Some(chat)) => {
                let here = model.domain.conversations.contains_key(&chat.into());
                cmds.extend(settle(model, id, here.then_some(chat)));
                continue;
            }
            (ChatKind::Group, None) => ToxAction::AcceptGroupInvite(
                invite.from,
                data,
                invite.name,
                invite.password.unwrap_or_default(),
                Some(id),
            ),
            (ChatKind::Conference, None) => ToxAction::JoinConference(invite.from, data, Some(id)),
            (ChatKind::Unknown { .. }, None) => {
                cmds.extend(settle(model, id, None));
                continue;
            }
        };
        model.session.joining.insert(id);
        cmds.push(Cmd::Tox(action));
    }
    // Tox invites again with the same bytes, which a spent invite shares.
    let invites = &model.account.invites;
    let any = |from, data: &[u8], open| {
        invites
            .values()
            .any(|invite| invite.from == from && invite.invite == data && invite.is_open() == open)
    };
    model.domain.pending_items.retain(|item| {
        item.invite()
            .is_none_or(|(from, _, _, data)| any(from, &data, true) || !any(from, &data, false))
    });
    cmds
}

/// Records how joining the chat of `invite` went.
fn settle(model: &mut Model, invite: EventId, chat: Option<ChatId>) -> Vec<Cmd> {
    if let Some(ChatId::Group(group)) = chat {
        model.session.group_invites.insert(group, invite);
    }
    record(
        model,
        Content::InviteJoined {
            invite,
            chat,
            needs_password: false,
        },
    )
}

/// How Tox joining the chat of `invite` went.
pub fn joined(model: &mut Model, invite: EventId, chat: Option<ChatId>) -> Vec<Cmd> {
    model.session.joining.remove(&invite);
    let mut cmds = settle(model, invite, chat);
    cmds.extend(join(model));
    cmds
}

/// The group turned the home away after it joined from an invite: for a
/// missing or wrong password where `needs_password`. It's left, and as Tox
/// takes an invite only once, the invite is spent.
pub fn refused(model: &mut Model, group: GroupChatId, needs_password: bool) -> Vec<Cmd> {
    let Some(invite) = model.session.group_invites.remove(&group) else {
        return Vec::new();
    };
    let mut cmds = model.close_window(WindowId::Group(group));
    cmds.extend(record(
        model,
        Content::InviteJoined {
            invite,
            chat: None,
            needs_password,
        },
    ));
    cmds
}
