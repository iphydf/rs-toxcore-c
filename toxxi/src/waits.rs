use crate::model::{MessageStatus, Model, WindowId};
use crate::msg::{Msg, ToxEvent};
use crate::script::ScriptRequest;
use toxcore::tox::{FriendNumber, ToxConnection};

pub struct WaitDef {
    pub name: &'static str,
    pub is_fulfilled: fn(&Model, &Msg, Option<&ScriptRequest>) -> bool,
}

pub const WAITS: &[WaitDef] = &[
    WaitDef {
        name: "WaitOnline",
        is_fulfilled: |model, _msg, _req| {
            model.domain.self_connection_status != ToxConnection::TOX_CONNECTION_NONE
        },
    },
    WaitDef {
        name: "WaitFriendOnline",
        is_fulfilled: |model, _msg, req| {
            if let Some(ScriptRequest::WaitFriendOnline(id)) = req
                && let Some(pk) = model.session.friend_numbers.get(&FriendNumber(*id))
            {
                model
                    .domain
                    .friends
                    .get(pk)
                    .is_some_and(|f| f.connection != ToxConnection::TOX_CONNECTION_NONE)
            } else {
                false
            }
        },
    },
    WaitDef {
        name: "WaitReadReceipt",
        is_fulfilled: |model, _msg, req| {
            if let Some(ScriptRequest::WaitReadReceipt(id)) = req
                && let Some(pk) = model.session.friend_numbers.get(&FriendNumber(*id))
            {
                model
                    .domain
                    .conversations
                    .get(&WindowId::Friend(*pk))
                    .and_then(|conv| conv.messages.iter().rev().find(|m| m.is_self))
                    .is_some_and(|m| m.status == MessageStatus::Received)
            } else {
                false
            }
        },
    },
    WaitDef {
        name: "WaitFriendMessage",
        is_fulfilled: |_model, msg, req| {
            if let (
                Msg::Tox(ToxEvent::Message(f, _t, m)),
                Some(ScriptRequest::WaitFriendMessage(id, sub)),
            ) = (msg, req)
            {
                f.0 == *id && crate::text::of(m).contains(sub.as_str())
            } else {
                false
            }
        },
    },
    WaitDef {
        name: "WaitFileRecv",
        is_fulfilled: |_model, msg, req| {
            if let (
                Msg::Tox(ToxEvent::FileRecv(f, _n, _k, _s, _nm)),
                Some(ScriptRequest::WaitFileRecv(id)),
            ) = (msg, req)
            {
                f.0 == *id
            } else {
                false
            }
        },
    },
];
