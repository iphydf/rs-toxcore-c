//! Reads an account's event log and turns its messages into lines to print or
//! search.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{Local, TimeZone};
use regex::Regex;
use serde::Serialize;
use tox_sync::event::{ChatId, Content, Event, GraphId};
use tox_sync::fact::{Subject, Value};
use tox_sync::store::read_log;
use toxcore::types::{MessageType, PublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Message,
    Action,
    Private,
    Event,
}

/// A message or event in a chat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    /// Milliseconds since the Unix epoch, by the author's clock.
    pub time: i64,
    pub chat: String,
    pub kind: Kind,
    /// Empty for events.
    pub sender: String,
    pub text: String,
}

/// Reads the log's events. Also returns the number of records it couldn't
/// decode, which a newer client may have written.
pub fn read_events(path: &Path) -> std::io::Result<(Vec<Event>, usize)> {
    let records = read_log(path)?;
    let events: Vec<Event> = records
        .iter()
        .filter_map(|r| Event::decode(r).ok())
        .collect();
    let unread = records.len() - events.len();
    Ok((events, unread))
}

/// Returns the name of each conversation: `#name` for a group, `&name` for a
/// conference and the friend's name for a friend.
fn chat_names(events: &[Event]) -> HashMap<GraphId, String> {
    // The account's key is the author whose account graph is in the log.
    let graphs: HashSet<GraphId> = events.iter().map(|e| e.graph).collect();
    let account: Option<PublicKey> = events
        .iter()
        .map(|e| e.author)
        .find(|author| graphs.contains(&GraphId::account(author)));
    let mut names = HashMap::new();
    for event in events {
        match &event.content {
            Content::Fact {
                subject: Subject::Chat(chat),
                value: Value::Name(name),
            } => {
                let mark = match chat {
                    ChatId::Group(_) => '#',
                    ChatId::Conference(_) => '&',
                };
                names.insert(chat.graph(), format!("{mark}{name}"));
            }
            Content::Fact {
                subject: Subject::Friend(friend),
                value: Value::Name(name),
            } => {
                if let Some(account) = &account {
                    names.insert(GraphId::friend(account, friend), name.clone());
                }
            }
            _ => {}
        }
    }
    names
}

fn said(sender: &str, message: &[u8], kind: &MessageType, private: bool) -> (Kind, String, String) {
    let kind = match kind {
        _ if private => Kind::Private,
        MessageType::Action => Kind::Action,
        _ => Kind::Message,
    };
    (
        kind,
        sender.to_owned(),
        String::from_utf8_lossy(message).into_owned(),
    )
}

/// Returns how to show an event, or nothing for events we don't show.
fn shown(content: &Content) -> Option<(Kind, String, String)> {
    let event = |text: String| Some((Kind::Event, String::new(), text));
    match content {
        Content::Received {
            sender,
            message,
            kind,
            ..
        }
        | Content::Send {
            sender,
            message,
            kind,
        } => Some(said(sender, message, kind, false)),
        Content::ReceivedPrivately {
            sender,
            message,
            kind,
            ..
        }
        | Content::SendPrivately {
            sender,
            message,
            kind,
            ..
        } => Some(said(sender, message, kind, true)),
        Content::Notice { text } => event(text.clone()),
        Content::PeerJoined { name, .. } => event(format!("{name} joined")),
        Content::PeerLeft { name, .. } => event(format!("{name} left")),
        Content::PeerRenamed { old, name, .. } => event(format!("{old} is now {name}")),
        Content::TopicSet { name, topic, .. } => event(format!("{name} set the topic: {topic}")),
        Content::TitleSet { name, title, .. } => event(format!("{name} set the title: {title}")),
        Content::File {
            sender,
            name,
            size,
            incoming,
            ..
        } => {
            let way = if *incoming { "sent" } else { "was sent" };
            event(format!("{sender} {way} the file {name} ({size} bytes)"))
        }
        Content::Call {
            sender,
            incoming,
            video,
        } => {
            let what = if *video { "video call" } else { "call" };
            let way = if *incoming { "from" } else { "to" };
            event(format!("{what} {way} {sender}"))
        }
        _ => None,
    }
}

/// Returns the lines of all chats, oldest first.
pub fn lines(events: &[Event]) -> Vec<Line> {
    let names = chat_names(events);
    let mut lines: Vec<Line> = events
        .iter()
        .filter_map(|event| {
            let (kind, sender, text) = shown(&event.content)?;
            // Chats without a name are shown by the start of their graph ID.
            let chat = names.get(&event.graph).cloned().unwrap_or_else(|| {
                event.graph.0[..4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            });
            Some(Line {
                time: event.time,
                chat,
                kind,
                sender,
                text,
            })
        })
        .collect();
    lines.sort_by_key(|line| line.time);
    lines
}

/// Which lines to keep.
#[derive(Default)]
pub struct Filter {
    pub chat: Option<String>,
    pub from: Option<String>,
    pub grep: Option<Regex>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub events: bool,
    pub last: Option<usize>,
}

impl Filter {
    pub fn apply(&self, lines: Vec<Line>) -> Vec<Line> {
        let has = |text: &str, part: &Option<String>| {
            part.as_ref()
                .is_none_or(|p| text.to_lowercase().contains(&p.to_lowercase()))
        };
        let mut kept: Vec<Line> = lines
            .into_iter()
            .filter(|line| {
                (self.events || line.kind != Kind::Event)
                    && has(&line.chat, &self.chat)
                    && has(&line.sender, &self.from)
                    && self.grep.as_ref().is_none_or(|re| re.is_match(&line.text))
                    && self.since.is_none_or(|t| line.time >= t)
                    && self.until.is_none_or(|t| line.time < t)
            })
            .collect();
        if let Some(last) = self.last {
            kept.drain(..kept.len().saturating_sub(last));
        }
        kept
    }
}

pub fn local(time: i64) -> String {
    Local.timestamp_millis_opt(time).earliest().map_or_else(
        || time.to_string(),
        |t| t.format("%Y-%m-%d %H:%M").to_string(),
    )
}

/// Formats a line as text. A message's further lines are indented.
pub fn plain(line: &Line) -> String {
    let text = line.text.replace('\n', "\n    ");
    let said = match line.kind {
        Kind::Message => format!("<{}> {text}", line.sender),
        Kind::Action => format!("* {} {text}", line.sender),
        Kind::Private => format!("<{}> (privately) {text}", line.sender),
        Kind::Event => format!("-- {text}"),
    };
    format!("{}  {}  {said}", local(line.time), line.chat)
}
