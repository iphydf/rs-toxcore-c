//! toxxi's conversation messages recorded as events.

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use toxcore::types::{MessageType, PublicKey};

use super::event::{Content, EventId, GraphId};
use super::store::EventStore;
use crate::model::{
    InternalMessageId, Message, MessageContent, MessageStatus, SYSTEM_SENDER, WindowId,
};
use crate::text;

pub fn graph_of(account: &PublicKey, window_id: WindowId) -> Option<GraphId> {
    match window_id {
        WindowId::Friend(pk) => Some(GraphId::friend(account, &pk)),
        WindowId::Group(id) => Some(GraphId::group(&id)),
        WindowId::Conference(id) => Some(GraphId::conference(&id)),
        WindowId::Console | WindowId::Logs | WindowId::Files => None,
    }
}

/// How far a message has got. It only ever moves forward. A file transfer
/// is `Sent` once it has ended, either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Created,
    Sent,
    Delivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    pub id: EventId,
    stage: Stage,
}

impl Recorded {
    pub fn new(id: EventId, window_id: WindowId, msg: &Message) -> Self {
        Self {
            id,
            stage: stage(window_id, msg),
        }
    }
}

fn stage(window_id: WindowId, msg: &Message) -> Stage {
    match (&msg.content, msg.status) {
        (
            MessageContent::FileTransfer { .. },
            MessageStatus::Failed | MessageStatus::Received | MessageStatus::Sent(_),
        ) => Stage::Sent,
        (MessageContent::FileTransfer { .. }, _) => Stage::Created,
        // Group messages have no receipts; they're Received once sent.
        (_, MessageStatus::Received) if msg.is_self => match window_id {
            WindowId::Friend(_) => Stage::Delivered,
            _ => Stage::Sent,
        },
        (_, MessageStatus::Sent(_)) if msg.is_self => Stage::Sent,
        _ => Stage::Created,
    }
}

fn reached(msg: &Message, id: EventId, stage: Stage) -> Content {
    match (&msg.content, stage) {
        (MessageContent::FileTransfer { blob, .. }, _) => {
            let ok = msg.status != MessageStatus::Failed;
            Content::FileEnded {
                file: id,
                ok,
                blob: blob.filter(|_| ok),
            }
        }
        (_, Stage::Delivered) => Content::Delivered { intent: id },
        _ => Content::Sent { intent: id },
    }
}

fn created(window_id: WindowId, msg: &Message, bytes: Option<Vec<u8>>) -> Option<Content> {
    let message = |text: &String| bytes.unwrap_or_else(|| text.as_bytes().to_vec());
    match &msg.content {
        MessageContent::FileTransfer {
            file_id,
            name,
            size,
            is_incoming,
            blob,
            ..
        } => Some(Content::File {
            sender: msg.sender.clone(),
            file_id: *file_id,
            name: name.clone(),
            size: *size,
            incoming: *is_incoming,
            blob: *blob,
        }),
        MessageContent::Text(text) if msg.is_self => Some(Content::Send {
            sender: msg.sender.clone(),
            message: message(text),
            kind: msg.message_type,
        }),
        MessageContent::Text(text) if msg.is_system() => {
            Some(Content::Notice { text: text.clone() })
        }
        MessageContent::Text(text) => Some(Content::Received {
            // In friend chats, the sender is the friend.
            from: match window_id {
                WindowId::Friend(_) => None,
                _ => msg.sender_pk,
            },
            sender: msg.sender.clone(),
            message: message(text),
            kind: msg.message_type,
        }),
        MessageContent::List(_) | MessageContent::GameInvite { .. } => None,
    }
}

/// Creates the events for whatever is new about `msg` since `recorded`, and
/// returns their encodings. A new text message is recorded as `bytes`, or as
/// its text.
pub fn record(
    store: &mut EventStore,
    author: PublicKey,
    time: i64,
    window_id: WindowId,
    msg: &Message,
    recorded: Option<Recorded>,
    bytes: Option<Vec<u8>>,
) -> (Option<Recorded>, Vec<Vec<u8>>) {
    let mut records = Vec::new();
    let Some(graph) = graph_of(&author, window_id) else {
        return (None, records);
    };
    let (id, from) = match recorded {
        Some(recorded) => (recorded.id, recorded.stage),
        None => {
            let Some(content) = created(window_id, msg, bytes) else {
                return (None, records);
            };
            let (id, bytes) =
                store.create(graph, author, msg.timestamp.timestamp_millis(), content);
            records.push(bytes);
            (id, Stage::Created)
        }
    };
    let to = stage(window_id, msg);
    for step in [Stage::Sent, Stage::Delivered] {
        if from < step && step <= to {
            records.push(store.create(graph, author, time, reached(msg, id, step)).1);
        }
    }
    (
        Some(Recorded {
            id,
            stage: from.max(to),
        }),
        records,
    )
}

/// What showing a conversation's events as messages depends on.
pub struct Viewer {
    pub me: PublicKey,
    // In friend chats, the friend.
    pub friend: Option<PublicKey>,
    pub offset: FixedOffset,
    pub patterns: Vec<Regex>,
}

impl Viewer {
    fn highlighted(&self, text: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(text))
    }
}

/// The message an event adds, if it adds one rather than changing another.
pub fn message_of(
    viewer: &Viewer,
    internal_id: InternalMessageId,
    time: i64,
    content: Content,
) -> Option<Message> {
    let base = Message {
        internal_id,
        sender: SYSTEM_SENDER.to_owned(),
        sender_pk: None,
        is_self: false,
        content: MessageContent::Text(String::new()),
        timestamp: DateTime::from_timestamp_millis(time)
            .unwrap_or_default()
            .with_timezone(&viewer.offset),
        status: MessageStatus::Incoming,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };
    match content {
        Content::Received {
            from,
            sender,
            message,
            kind,
        } => {
            let text = text::of(&message);
            Some(Message {
                sender,
                sender_pk: from.or(viewer.friend),
                highlighted: viewer.highlighted(&text),
                content: MessageContent::Text(text),
                message_type: kind,
                ..base
            })
        }
        Content::Send {
            sender,
            message,
            kind,
        } => Some(Message {
            sender,
            sender_pk: Some(viewer.me),
            is_self: true,
            content: MessageContent::Text(text::of(&message)),
            status: MessageStatus::Pending,
            message_type: kind,
            ..base
        }),
        Content::Notice { text } => Some(Message {
            highlighted: viewer.highlighted(&text),
            content: MessageContent::Text(text),
            ..base
        }),
        Content::File {
            sender,
            file_id,
            name,
            size,
            incoming,
            blob,
        } => Some(Message {
            sender,
            sender_pk: if incoming {
                viewer.friend
            } else {
                Some(viewer.me)
            },
            is_self: !incoming,
            content: MessageContent::FileTransfer {
                file_id,
                name,
                size,
                progress: 0.0,
                speed: String::new(),
                is_incoming: incoming,
                blob,
            },
            status: if incoming {
                MessageStatus::Incoming
            } else {
                MessageStatus::Pending
            },
            ..base
        }),
        _ => None,
    }
}
