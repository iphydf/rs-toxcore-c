//! The account's invites to chats, which its devices answer: toxxi joins the
//! chats they answer to join, through the friends who invited, and records
//! how that went.

use toxcore::tox::Connection;

use crate::model::{Model, WindowId};
use crate::msg::{Cmd, ToxAction};

use super::account::InviteStatus;
use toxcore::types::GroupChatId;

use super::event::{ChatId, ChatKind, Content, EventId};

fn record(model: &mut Model, content: Content) -> Vec<Cmd> {
    model.record_in_account(vec![content])
}

/// An answer given here, as a device gives one. On a linked profile, the
/// home joins.
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
    if model.config.home.is_none() {
        cmds.extend(self::join(model));
    }
    cmds
}

/// Joins the chats of invites answered to join, through the friend who invited.
/// Invites joined or declined are no longer pending here.
pub fn join(model: &mut Model) -> Vec<Cmd> {
    let online = |model: &Model, friend| {
        model
            .domain
            .friends
            .get(friend)
            .is_some_and(|info| info.connection != Connection::None)
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
        let action = match (invite.kind, invite.chat) {
            // Tox takes an invite only once: one that reached its chat is
            // joined while the home is in the chat, and spent once it isn't.
            (_, Some(chat)) => {
                let here = model.domain.conversations.contains_key(&chat.into());
                cmds.extend(settle(model, id, here.then_some(chat)));
                continue;
            }
            (ChatKind::Group, None) => ToxAction::AcceptGroupInvite {
                friend: invite.from,
                invite: invite.invite,
                password: invite.password,
                recorded: Some(id),
            },
            (ChatKind::Conference, None) => ToxAction::JoinConference {
                friend: invite.from,
                cookie: invite.invite,
                recorded: Some(id),
            },
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

/// Tox joined the chat of `invite`, or failed to.
pub fn joined(model: &mut Model, invite: EventId, chat: Option<ChatId>) -> Vec<Cmd> {
    model.session.joining.remove(&invite);
    let mut cmds = settle(model, invite, chat);
    cmds.extend(join(model));
    cmds
}

/// The group refused the home after it joined from an invite, because of a
/// missing or wrong password if `needs_password`. We leave the group, and the
/// invite is spent: Tox takes an invite only once.
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
