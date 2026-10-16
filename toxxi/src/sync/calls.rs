//! The account's calls with its friends, which its devices take: toxxi rings
//! them, connects the device that answers or calls, and keeps the history.

use std::collections::HashSet;

use toxcore::types::PublicKey;

use crate::model::{ConsoleMessageType, Model};
use crate::msg::{Cmd, ToxAction};

use super::event::{Content, EventId, GraphId};
use super::fact::CallState;
use super::protocol::CallAction;

/// A call with a friend.
#[derive(Debug, Clone)]
pub struct Call {
    /// Its Call event.
    pub started: EventId,
    pub incoming: bool,
    pub video: bool,
    /// The device it goes to, once one answered or placed it.
    pub device: Option<PublicKey>,
    /// When it connected, in ms.
    pub connected_at: Option<i64>,
}

impl Call {
    pub fn state(&self) -> CallState {
        match self.device {
            Some(_) => CallState::Answered,
            None => CallState::Ringing { video: self.video },
        }
    }
}

fn now(model: &Model) -> i64 {
    model.time_provider.now_local().timestamp_millis()
}

/// Records `content` in the chat with `friend`.
fn record(model: &mut Model, friend: PublicKey, content: Content) -> (EventId, Vec<Cmd>) {
    let me = model.domain.self_public_key();
    let time = now(model);
    let (id, bytes) = model
        .events
        .create(GraphId::friend(&me, &friend), me, time, content);
    (id, model.persist(vec![bytes]))
}

fn name(model: &Model, friend: &PublicKey) -> String {
    model
        .domain
        .friends
        .get(friend)
        .map_or_else(|| friend.to_string(), |info| info.name.clone())
}

/// A friend calls the account. It rings on the devices, unless another call
/// goes on: then it's declined, and missed.
pub fn ringing(model: &mut Model, friend: PublicKey, video: bool) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    // Devices don't call the account; it calls them.
    if super::is_device(&model.config, &friend) {
        cmds.push(Cmd::Tox(ToxAction::CallHangUp(friend)));
        return cmds;
    }
    let sender = name(model, &friend);
    let (started, recorded) = record(
        model,
        friend,
        Content::Call {
            sender: sender.clone(),
            incoming: true,
            video,
        },
    );
    cmds.extend(recorded);
    if !model.session.calls.is_empty() {
        cmds.push(Cmd::Tox(ToxAction::CallHangUp(friend)));
        cmds.extend(
            record(
                model,
                friend,
                Content::CallEnded {
                    call: started,
                    duration: None,
                    declined: false,
                },
            )
            .1,
        );
        return cmds;
    }
    model.session.calls.insert(
        friend,
        Call {
            started,
            incoming: true,
            video,
            device: None,
            connected_at: None,
        },
    );
    model.add_console_message(ConsoleMessageType::Info, format!("{sender} is calling"));
    cmds.extend(super::facts::push_live(model));
    cmds
}

/// What a device asks of the call with `friend`.
pub fn control(
    model: &mut Model,
    device: PublicKey,
    friend: PublicKey,
    action: CallAction,
) -> Vec<Cmd> {
    match action {
        CallAction::Connect { video } => connect(model, device, friend, video),
        CallAction::HangUp => match model.session.calls.get(&friend) {
            Some(call) if call.device.is_none_or(|d| d == device) => {
                let mut cmds = vec![Cmd::Tox(ToxAction::CallHangUp(friend))];
                cmds.extend(end(model, friend, true));
                cmds
            }
            _ => Vec::new(),
        },
        CallAction::Unknown { .. } => Vec::new(),
    }
}

/// Answers the friend's call ringing, or places one when none goes on.
fn connect(model: &mut Model, device: PublicKey, friend: PublicKey, video: bool) -> Vec<Cmd> {
    if !model.domain.friends.contains_key(&friend) || super::is_device(&model.config, &friend) {
        return Vec::new();
    }
    let mut cmds = Vec::new();
    let busy = !model.session.calls.is_empty();
    match model.session.calls.get_mut(&friend) {
        Some(call) if call.device.is_none() => call.device = Some(device),
        // Another device took it, or another call goes on.
        Some(_) => return cmds,
        None if busy => return cmds,
        None => {
            let sender = model.domain.self_name.clone();
            let (started, recorded) = record(
                model,
                friend,
                Content::Call {
                    sender,
                    incoming: false,
                    video,
                },
            );
            cmds.extend(recorded);
            model.session.calls.insert(
                friend,
                Call {
                    started,
                    incoming: false,
                    video,
                    device: Some(device),
                    connected_at: None,
                },
            );
        }
    }
    cmds.push(Cmd::Tox(ToxAction::CallConnect {
        friend,
        device,
        video,
    }));
    cmds.extend(super::facts::push_live(model));
    cmds
}

pub fn connected(model: &mut Model, friend: PublicKey) -> Vec<Cmd> {
    let time = now(model);
    if let Some(call) = model.session.calls.get_mut(&friend) {
        call.connected_at = Some(time);
    }
    Vec::new()
}

/// The calls Tox had ended with it, as did those a crash left unended.
pub fn restarted(model: &mut Model) -> Vec<Cmd> {
    model.session.calls.clear();
    let me = model.domain.self_public_key();
    let graphs: Vec<GraphId> = model.events.heads().map(|(graph, _)| *graph).collect();
    let mut open = Vec::new();
    for graph in graphs {
        let events = model.events.graph(&graph);
        let ended: HashSet<EventId> = events
            .iter()
            .filter_map(|(_, event)| match event.content {
                Content::CallEnded { call, .. } => Some(call),
                _ => None,
            })
            .collect();
        open.extend(
            events
                .iter()
                .filter(|(id, event)| {
                    matches!(event.content, Content::Call { .. }) && !ended.contains(id)
                })
                .map(|(id, _)| (graph, *id)),
        );
    }
    let time = now(model);
    let records = open
        .into_iter()
        .map(|(graph, call)| {
            let content = Content::CallEnded {
                call,
                duration: None,
                declined: false,
            };
            model.events.create(graph, me, time, content).1
        })
        .collect();
    let mut cmds = model.persist(records);
    cmds.extend(super::facts::push_live(model));
    cmds
}

pub fn ended(model: &mut Model, friend: PublicKey) -> Vec<Cmd> {
    end(model, friend, false)
}

/// Records the end of the call with `friend`: `declined` where a device
/// declined it ringing, so it wasn't missed.
fn end(model: &mut Model, friend: PublicKey, declined: bool) -> Vec<Cmd> {
    let Some(call) = model.session.calls.remove(&friend) else {
        return Vec::new();
    };
    let time = now(model);
    let (_, mut cmds) = record(
        model,
        friend,
        Content::CallEnded {
            call: call.started,
            duration: call.connected_at.map(|at| (time - at).max(0) as u64),
            declined: declined && call.incoming && call.device.is_none(),
        },
    );
    cmds.extend(super::facts::push_live(model));
    cmds
}
