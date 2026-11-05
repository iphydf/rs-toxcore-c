//! Runs the cases in `sync/conformance`, which bTox runs too, so every
//! implementation encodes, decodes and syncs the same way. With `BLESS=1`, it
//! writes what this one computes into them instead. README.md there describes
//! them.

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::{Map, Value as J, json};
use tox_proto::Kept;
use tox_sync::account::{AccountState, InviteStatus};
use tox_sync::event::{BlobId, ChatId, ChatKind, Content, Event, EventId, GraphId};
use tox_sync::fact::{
    CallState, Connection, Facts, Privacy, Role, Subject, UserStatus, Value, VoiceState,
};
use tox_sync::frame::{Reassembler, frames};
use tox_sync::pairing::PairingCode;
use tox_sync::protocol::{CallAction, Features, HeadsDigest, SessionMessage};
use tox_sync::replica::Replica;
use tox_sync::session;
use tox_sync::setting::{Mute, PictureEncoding, PictureFormat, Scope, Setting};
use tox_sync::store::EventStore;
use toxcore::types::{Address, ConferenceId, FileId, GroupChatId, MessageType, PublicKey};

/// More than any session takes.
const MAX_ROUNDS: usize = 1000;

#[test]
fn test_codec() {
    run(
        "codec.json",
        include_str!("../conformance/codec.json"),
        codec,
    );
}

#[test]
fn test_state() {
    run(
        "state.json",
        include_str!("../conformance/state.json"),
        state,
    );
}

#[test]
fn test_store() {
    run(
        "store.json",
        include_str!("../conformance/store.json"),
        store,
    );
}

#[test]
fn test_session() {
    run(
        "session.json",
        include_str!("../conformance/session.json"),
        session_cases,
    );
}

fn run(name: &str, text: &str, cases: fn(&mut Run, &mut J)) {
    let mut file: J = serde_json::from_str(text).unwrap();
    let mut run = Run {
        bless: std::env::var_os("BLESS").is_some(),
        failures: Vec::new(),
    };
    cases(&mut run, &mut file);
    if run.bless {
        let dir = match std::env::var("BUILD_WORKSPACE_DIRECTORY") {
            Ok(workspace) => PathBuf::from(workspace).join("rs-toxcore-c/sync"),
            Err(_) => PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()),
        };
        let mut text = String::new();
        pretty(&mut text, &file, 0, 0, false);
        text.push('\n');
        std::fs::write(dir.join("conformance").join(name), text).unwrap();
    }
    assert!(run.failures.is_empty(), "\n{}", run.failures.join("\n"));
}

struct Run {
    bless: bool,
    failures: Vec<String>,
}

impl Run {
    /// Checks `actual` against `case[key]`, or writes it there when blessing,
    /// with the labels it holds put back.
    fn expect(&mut self, labels: &Labels, name: &str, case: &mut J, key: &str, actual: J) {
        if self.bless {
            case[key] = labels.unresolve(&actual);
        } else {
            let expected = labels.resolve(&case[key]);
            self.check(name, key, &expected, &actual);
        }
    }

    fn check(&mut self, name: &str, what: &str, expected: &J, actual: &J) {
        let (expected, actual) = (canonical(expected), canonical(actual));
        if expected != actual {
            self.failures.push(format!(
                "{name}: {what}\n  expected {expected}\n  actual   {actual}"
            ));
        }
    }
}

// Reading and writing JSON.

fn canonical(j: &J) -> String {
    match j {
        J::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .iter()
                .map(|key| format!("{}:{}", J::from(key.as_str()), canonical(&map[*key])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        J::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => j.to_string(),
    }
}

fn inline(j: &J) -> String {
    match j {
        J::Object(map) if map.is_empty() => "{}".to_string(),
        J::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .iter()
                .map(|key| format!("{}: {}", J::from(key.as_str()), inline(&map[*key])))
                .collect();
            format!("{{ {} }}", fields.join(", "))
        }
        J::Array(items) => format!(
            "[{}]",
            items.iter().map(inline).collect::<Vec<_>>().join(", ")
        ),
        _ => j.to_string(),
    }
}

/// The most columns a line takes, as prettier formats JSON.
const PRINT_WIDTH: usize = 80;

/// Formats JSON as prettier does, so that restyled leaves blessed files as
/// they are: sorted keys, and each value on one line where it fits, with the
/// text before it on the line (`column`) and any comma after it.
fn pretty(out: &mut String, j: &J, indent: usize, column: usize, comma: bool) {
    let line = inline(j);
    let pad = |n| " ".repeat(n);
    // Prettier always breaks a list of several objects or lists that each
    // hold more than one item.
    let many = |item: &J| match item {
        J::Object(map) => map.len() > 1,
        J::Array(items) => items.len() > 1,
        _ => false,
    };
    let same_kind = |a: &J, b: &J| {
        matches!(
            (a, b),
            (J::Object(_), J::Object(_)) | (J::Array(_), J::Array(_))
        )
    };
    let must_break = match j {
        J::Array(items) => {
            items.len() > 1
                && items
                    .iter()
                    .all(|item| many(item) && same_kind(item, &items[0]))
        }
        _ => false,
    };
    match j {
        _ if !must_break && column + line.len() + usize::from(comma) <= PRINT_WIDTH => {
            out.push_str(&line)
        }
        J::Object(map) if !map.is_empty() => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            out.push_str("{\n");
            for (i, key) in keys.iter().enumerate() {
                let prefix = format!("{}{}: ", pad(indent + 2), J::from(key.as_str()));
                out.push_str(&prefix);
                let comma = i + 1 < keys.len();
                pretty(out, &map[*key], indent + 2, prefix.len(), comma);
                out.push_str(if comma { ",\n" } else { "\n" });
            }
            out.push_str(&format!("{}}}", pad(indent)));
        }
        J::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad(indent + 2));
                let comma = i + 1 < items.len();
                pretty(out, item, indent + 2, indent + 2, comma);
                out.push_str(if comma { ",\n" } else { "\n" });
            }
            out.push_str(&format!("{}]", pad(indent)));
        }
        _ => out.push_str(&line),
    }
}

fn sorted(mut items: Vec<J>) -> J {
    items.sort_by_key(canonical);
    J::Array(items)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn bytes(j: &J) -> Vec<u8> {
    let text = j.as_str().expect("hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn b32(j: &J) -> [u8; 32] {
    bytes(j).try_into().expect("32 bytes")
}

fn pk(j: &J) -> PublicKey {
    PublicKey(b32(j))
}

fn id(j: &J) -> EventId {
    EventId(b32(j))
}

fn text(j: &J) -> String {
    j.as_str().expect("text").to_owned()
}

fn uint(j: &J) -> u64 {
    j.as_u64().expect("uint")
}

fn flag(j: &J) -> bool {
    j.as_bool().expect("bool")
}

fn opt<T>(j: &J, read: impl Fn(&J) -> T) -> Option<T> {
    (!j.is_null()).then(|| read(j))
}

fn list<T>(j: &J, read: impl Fn(&J) -> T) -> Vec<T> {
    j.as_array().expect("list").iter().map(read).collect()
}

static NULL: J = J::Null;

/// `"tag"` or `{"tag": payload}`.
fn variant(j: &J) -> (&str, &J) {
    match j {
        J::String(tag) => (tag, &NULL),
        J::Object(map) if map.len() == 1 => {
            let (tag, payload) = map.iter().next().unwrap();
            (tag, payload)
        }
        _ => panic!("not a variant: {j}"),
    }
}

// The values of the protocol, as JSON.

fn chat(j: &J) -> ChatId {
    match variant(j) {
        ("group", id) => ChatId::Group(GroupChatId(b32(id))),
        ("conference", id) => ChatId::Conference(ConferenceId(b32(id))),
        other => panic!("not a chat: {other:?}"),
    }
}

fn chat_json(chat: &ChatId) -> J {
    match chat {
        ChatId::Group(id) => json!({"group": hex(&id.0)}),
        ChatId::Conference(id) => json!({"conference": hex(&id.0)}),
    }
}

fn chat_kind(j: &J) -> ChatKind {
    match j.as_str() {
        Some("group") => ChatKind::Group,
        Some("conference") => ChatKind::Conference,
        _ => panic!("not a chat kind: {j}"),
    }
}

fn chat_kind_json(kind: &ChatKind) -> Option<J> {
    match kind {
        ChatKind::Group => Some(json!("group")),
        ChatKind::Conference => Some(json!("conference")),
        ChatKind::Unknown { .. } => None,
    }
}

fn subject(j: &J) -> Subject {
    match variant(j) {
        ("account", _) => Subject::Account,
        ("friend", key) => Subject::Friend(pk(key)),
        ("chat", c) => Subject::Chat(chat(c)),
        ("peer", peer) => Subject::Peer {
            chat: chat(&peer["chat"]),
            pk: pk(&peer["pk"]),
        },
        other => panic!("not a subject: {other:?}"),
    }
}

fn subject_json(subject: &Subject) -> J {
    match subject {
        Subject::Account => json!("account"),
        Subject::Friend(key) => json!({"friend": hex(&key.0)}),
        Subject::Chat(c) => json!({"chat": chat_json(c)}),
        Subject::Peer { chat, pk } => {
            json!({"peer": {"chat": chat_json(chat), "pk": hex(&pk.0)}})
        }
    }
}

/// Names of Tox's values, in the order Tox numbers them.
fn named<T>(names: &[&str], values: Vec<T>, j: &J) -> T {
    let name = j.as_str().expect("name");
    let index = names.iter().position(|n| *n == name).expect(name);
    values.into_iter().nth(index).unwrap()
}

const STATUSES: [&str; 3] = ["online", "away", "busy"];
const CONNECTIONS: [&str; 3] = ["none", "tcp", "udp"];
const ROLES: [&str; 4] = ["founder", "moderator", "user", "observer"];
const PRIVACIES: [&str; 2] = ["public", "private"];
const VOICE_STATES: [&str; 3] = ["everyone", "moderators", "founder"];

fn value(j: &J) -> Value {
    let (kind, v) = variant(j);
    match kind {
        "name" => Value::Name(text(v)),
        "status_message" => Value::StatusMessage(text(v)),
        "status" => Value::Status(named(
            &STATUSES,
            vec![UserStatus::Online, UserStatus::Away, UserStatus::Busy],
            v,
        )),
        "connection" => Value::Connection(named(
            &CONNECTIONS,
            vec![Connection::None, Connection::Tcp, Connection::Udp],
            v,
        )),
        "typing" => Value::Typing(flag(v)),
        "topic" => Value::Topic(text(v)),
        "role" => Value::Role(named(
            &ROLES,
            vec![Role::Founder, Role::Moderator, Role::User, Role::Observer],
            v,
        )),
        "privacy" => Value::Privacy(named(
            &PRIVACIES,
            vec![Privacy::Public, Privacy::Private],
            v,
        )),
        "peer_limit" => Value::PeerLimit(uint(v).try_into().unwrap()),
        "password" => Value::Password(text(v)),
        "topic_lock" => Value::TopicLock(flag(v)),
        "voice_state" => Value::VoiceState(named(
            &VOICE_STATES,
            vec![
                VoiceState::Everyone,
                VoiceState::Moderators,
                VoiceState::Founder,
            ],
            v,
        )),
        "joined" => Value::Joined(flag(v)),
        "self_name" => Value::SelfName(text(v)),
        "present" => Value::Present(flag(v)),
        "address" => Value::Address(bytes(v)),
        "call" => Value::Call(match variant(v) {
            ("none", _) => CallState::None,
            ("ringing", ringing) => CallState::Ringing {
                video: flag(&ringing["video"]),
            },
            ("answered", _) => CallState::Answered,
            other => panic!("not a call: {other:?}"),
        }),
        "call_relay" => Value::CallRelay(flag(v)),
        "self_key" => Value::SelfKey(pk(v)),
        "avatar" => Value::Avatar(opt(v, |b| BlobId(b32(b)))),
        other => panic!("not a value: {other}"),
    }
}

/// A value of a known kind but an unknown one of Tox's is unknown as a
/// whole, as it shows nothing.
fn value_json(value: &Value) -> J {
    let unknown = json!({"unknown": value.kind()});
    match value {
        Value::Name(v) => json!({"name": v}),
        Value::StatusMessage(v) => json!({"status_message": v}),
        Value::Status(v) => match v {
            UserStatus::Online => json!({"status": "online"}),
            UserStatus::Away => json!({"status": "away"}),
            UserStatus::Busy => json!({"status": "busy"}),
            UserStatus::Unknown { .. } => unknown,
        },
        Value::Connection(v) => match v {
            Connection::None => json!({"connection": "none"}),
            Connection::Tcp => json!({"connection": "tcp"}),
            Connection::Udp => json!({"connection": "udp"}),
            Connection::Unknown { .. } => unknown,
        },
        Value::Typing(v) => json!({"typing": v}),
        Value::Topic(v) => json!({"topic": v}),
        Value::Role(v) => match v {
            Role::Founder => json!({"role": "founder"}),
            Role::Moderator => json!({"role": "moderator"}),
            Role::User => json!({"role": "user"}),
            Role::Observer => json!({"role": "observer"}),
            Role::Unknown { .. } => unknown,
        },
        Value::Privacy(v) => match v {
            Privacy::Public => json!({"privacy": "public"}),
            Privacy::Private => json!({"privacy": "private"}),
            Privacy::Unknown { .. } => unknown,
        },
        Value::PeerLimit(v) => json!({"peer_limit": v}),
        Value::Password(v) => json!({"password": v}),
        Value::TopicLock(v) => json!({"topic_lock": v}),
        Value::VoiceState(v) => match v {
            VoiceState::Everyone => json!({"voice_state": "everyone"}),
            VoiceState::Moderators => json!({"voice_state": "moderators"}),
            VoiceState::Founder => json!({"voice_state": "founder"}),
            VoiceState::Unknown { .. } => unknown,
        },
        Value::Joined(v) => json!({"joined": v}),
        Value::SelfName(v) => json!({"self_name": v}),
        Value::Present(v) => json!({"present": v}),
        Value::Address(v) => json!({"address": hex(v)}),
        Value::Call(v) => match v {
            CallState::None => json!({"call": "none"}),
            CallState::Ringing { video } => json!({"call": {"ringing": {"video": video}}}),
            CallState::Answered => json!({"call": "answered"}),
            CallState::Unknown { .. } => unknown,
        },
        Value::CallRelay(v) => json!({"call_relay": v}),
        Value::SelfKey(v) => json!({"self_key": hex(&v.0)}),
        Value::Avatar(v) => json!({"avatar": v.map(|b| hex(&b.0))}),
        Value::Unknown { .. } => unknown,
    }
}

fn fact_json((subject, value): (&Subject, &Value)) -> J {
    json!([subject_json(subject), value_json(value)])
}

fn scope(j: &J) -> Scope {
    match variant(j) {
        ("account", _) => Scope::Account,
        ("conversation", graph) => Scope::Conversation(GraphId(b32(graph))),
        other => panic!("not a scope: {other:?}"),
    }
}

fn scope_json(scope: &Scope) -> J {
    match scope {
        Scope::Account => json!("account"),
        Scope::Conversation(graph) => json!({"conversation": hex(&graph.0)}),
        Scope::Unknown { discriminant, .. } => json!({"unknown": discriminant}),
    }
}

fn setting(j: &J) -> Setting {
    match variant(j) {
        ("mute", mute) => Setting::Mute(Mute {
            until: opt(&mute["until"], uint),
            mentions: flag(&mute["mentions"]),
        }),
        ("picture_format", format) => Setting::PictureFormat(PictureFormat {
            format: match format.as_str() {
                Some("original") => PictureEncoding::Original,
                Some("qoi") => PictureEncoding::Qoi,
                _ => panic!("not a picture format: {format}"),
            },
        }),
        other => panic!("not a setting: {other:?}"),
    }
}

/// An unknown picture format sends pictures as they are.
fn setting_json(setting: &Setting) -> J {
    match setting {
        Setting::Mute(Mute { until, mentions }) => {
            json!({"mute": {"until": until, "mentions": mentions}})
        }
        Setting::PictureFormat(PictureFormat { format }) => json!({"picture_format": match format {
            PictureEncoding::Qoi => "qoi",
            PictureEncoding::Original | PictureEncoding::Unknown { .. } => "original",
        }}),
        Setting::Unknown { discriminant, .. } => json!({"unknown": discriminant}),
    }
}

fn message_kind(j: &J) -> MessageType {
    match j.as_str() {
        Some("normal") => MessageType::TOX_MESSAGE_TYPE_NORMAL,
        Some("action") => MessageType::TOX_MESSAGE_TYPE_ACTION,
        _ => panic!("not a message kind: {j}"),
    }
}

fn message_kind_json(kind: &MessageType) -> J {
    json!(match kind {
        MessageType::TOX_MESSAGE_TYPE_NORMAL => "normal",
        MessageType::TOX_MESSAGE_TYPE_ACTION => "action",
    })
}

fn content(j: &J) -> Content {
    let (tag, c) = variant(j);
    let blob = |j: &J| opt(j, |b| BlobId(b32(b)));
    match tag {
        "received" => Content::Received {
            from: opt(&c["from"], pk),
            sender: text(&c["sender"]),
            message: bytes(&c["message"]),
            kind: message_kind(&c["kind"]),
        },
        "send" => Content::Send {
            sender: text(&c["sender"]),
            message: bytes(&c["message"]),
            kind: message_kind(&c["kind"]),
        },
        "sent" => Content::Sent {
            intent: id(&c["intent"]),
        },
        "delivered" => Content::Delivered {
            intent: id(&c["intent"]),
        },
        "notice" => Content::Notice {
            text: text(&c["text"]),
        },
        "file" => Content::File {
            sender: text(&c["sender"]),
            file_id: opt(&c["file_id"], |f| FileId(b32(f))),
            name: text(&c["name"]),
            size: uint(&c["size"]),
            incoming: flag(&c["incoming"]),
            blob: blob(&c["blob"]),
        },
        "file_ended" => Content::FileEnded {
            file: id(&c["file"]),
            ok: flag(&c["ok"]),
            blob: blob(&c["blob"]),
        },
        "file_answered" => Content::FileAnswered {
            file: id(&c["file"]),
            accepted: flag(&c["accepted"]),
        },
        "call" => Content::Call {
            sender: text(&c["sender"]),
            incoming: flag(&c["incoming"]),
            video: flag(&c["video"]),
        },
        "call_ended" => Content::CallEnded {
            call: id(&c["call"]),
            duration: opt(&c["duration"], uint),
            declined: flag(&c["declined"]),
        },
        "want_friend" => Content::WantFriend {
            pk: pk(&c["pk"]),
            request_message: opt(&c["request_message"], text),
            nospam: opt(&c["nospam"], |n| uint(n).try_into().unwrap()),
        },
        "unwant_friend" => Content::UnwantFriend { pk: pk(&c["pk"]) },
        "read_up_to" => Content::ReadUpTo {
            graph: GraphId(b32(&c["graph"])),
            event: id(&c["event"]),
            rank: uint(&c["rank"]),
        },
        "friend_request" => Content::FriendRequest {
            pk: pk(&c["pk"]),
            message: text(&c["message"]),
        },
        "merge_chat" => Content::MergeChat {
            chat: chat(&c["chat"]),
            bot: pk(&c["bot"]),
            into: chat(&c["into"]),
            into_bot: pk(&c["into_bot"]),
            merged: flag(&c["merged"]),
        },
        "relay_bot" => Content::RelayBot {
            chat: chat(&c["chat"]),
            bot: pk(&c["bot"]),
            relays: flag(&c["relays"]),
        },
        "fact" => Content::Fact {
            subject: subject(&c["subject"]),
            value: value(&c["value"]),
        },
        "want" => Content::Want {
            subject: subject(&c["subject"]),
            value: value(&c["value"]),
        },
        "chat_invite" => Content::ChatInvite {
            from: pk(&c["from"]),
            kind: chat_kind(&c["kind"]),
            name: text(&c["name"]),
            invite: bytes(&c["invite"]),
        },
        "answer_invite" => Content::AnswerInvite {
            invite: id(&c["invite"]),
            join: flag(&c["join"]),
            password: opt(&c["password"], text),
        },
        "invite_joined" => Content::InviteJoined {
            invite: id(&c["invite"]),
            chat: opt(&c["chat"], chat),
            needs_password: flag(&c["needs_password"]),
        },
        "setting" => Content::Setting {
            scope: scope(&c["scope"]),
            setting: Kept::from(setting(&c["setting"])),
        },
        "clear_setting" => Content::ClearSetting {
            scope: scope(&c["scope"]),
            kind: uint(&c["kind"]).try_into().unwrap(),
        },
        "received_privately" => Content::ReceivedPrivately {
            from: pk(&c["from"]),
            sender: text(&c["sender"]),
            message: bytes(&c["message"]),
            kind: message_kind(&c["kind"]),
        },
        "send_privately" => Content::SendPrivately {
            to: pk(&c["to"]),
            sender: text(&c["sender"]),
            message: bytes(&c["message"]),
            kind: message_kind(&c["kind"]),
        },
        "device" => Content::Device {
            pk: pk(&c["pk"]),
            name: text(&c["name"]),
        },
        "device_gone" => Content::DeviceGone { pk: pk(&c["pk"]) },
        "new_chat" => Content::NewChat {
            kind: chat_kind(&c["kind"]),
            name: text(&c["name"]),
            privacy: named(
                &PRIVACIES,
                vec![Privacy::Public, Privacy::Private],
                &c["privacy"],
            ),
        },
        "join_chat" => Content::JoinChat {
            chat_id: GroupChatId(b32(&c["chat_id"])),
            password: opt(&c["password"], text),
        },
        "invite_to_chat" => Content::InviteToChat {
            chat: chat(&c["chat"]),
            friend: pk(&c["friend"]),
        },
        "chat_joined" => Content::ChatJoined {
            intent: id(&c["intent"]),
            chat: opt(&c["chat"], chat),
        },
        other => panic!("not content: {other}"),
    }
}

/// An invite to a chat of a kind this version doesn't know shows nothing,
/// as content it doesn't know.
fn content_json(content: &Content) -> J {
    let blob = |b: &Option<BlobId>| b.map(|b| hex(&b.0));
    match content {
        Content::Received {
            from,
            sender,
            message,
            kind,
        } => json!({"received": {
            "from": from.map(|k| hex(&k.0)),
            "sender": sender,
            "message": hex(message),
            "kind": message_kind_json(kind),
        }}),
        Content::Send {
            sender,
            message,
            kind,
        } => json!({"send": {
            "sender": sender,
            "message": hex(message),
            "kind": message_kind_json(kind),
        }}),
        Content::Sent { intent } => json!({"sent": {"intent": hex(&intent.0)}}),
        Content::Delivered { intent } => json!({"delivered": {"intent": hex(&intent.0)}}),
        Content::Notice { text } => json!({"notice": {"text": text}}),
        Content::File {
            sender,
            file_id,
            name,
            size,
            incoming,
            blob: b,
        } => json!({"file": {
            "sender": sender,
            "file_id": file_id.map(|f| hex(&f.0)),
            "name": name,
            "size": size,
            "incoming": incoming,
            "blob": blob(b),
        }}),
        Content::FileEnded { file, ok, blob: b } => json!({"file_ended": {
            "file": hex(&file.0),
            "ok": ok,
            "blob": blob(b),
        }}),
        Content::FileAnswered { file, accepted } => json!({"file_answered": {
            "file": hex(&file.0),
            "accepted": accepted,
        }}),
        Content::Call {
            sender,
            incoming,
            video,
        } => json!({"call": {"sender": sender, "incoming": incoming, "video": video}}),
        Content::CallEnded {
            call,
            duration,
            declined,
        } => json!({"call_ended": {
            "call": hex(&call.0),
            "duration": duration,
            "declined": declined,
        }}),
        Content::WantFriend {
            pk,
            request_message,
            nospam,
        } => json!({"want_friend": {
            "pk": hex(&pk.0),
            "request_message": request_message,
            "nospam": nospam,
        }}),
        Content::UnwantFriend { pk } => json!({"unwant_friend": {"pk": hex(&pk.0)}}),
        Content::ReadUpTo { graph, event, rank } => json!({"read_up_to": {
            "graph": hex(&graph.0),
            "event": hex(&event.0),
            "rank": rank,
        }}),
        Content::FriendRequest { pk, message } => json!({"friend_request": {
            "pk": hex(&pk.0),
            "message": message,
        }}),
        Content::MergeChat {
            chat,
            bot,
            into,
            into_bot,
            merged,
        } => json!({"merge_chat": {
            "chat": chat_json(chat),
            "bot": hex(&bot.0),
            "into": chat_json(into),
            "into_bot": hex(&into_bot.0),
            "merged": merged,
        }}),
        Content::RelayBot { chat, bot, relays } => json!({"relay_bot": {
            "chat": chat_json(chat),
            "bot": hex(&bot.0),
            "relays": relays,
        }}),
        Content::Fact { subject, value } => json!({"fact": {
            "subject": subject_json(subject),
            "value": value_json(value),
        }}),
        Content::Want { subject, value } => json!({"want": {
            "subject": subject_json(subject),
            "value": value_json(value),
        }}),
        Content::ChatInvite {
            from,
            kind,
            name,
            invite,
        } => match chat_kind_json(kind) {
            Some(kind) => json!({"chat_invite": {
                "from": hex(&from.0),
                "kind": kind,
                "name": name,
                "invite": hex(invite),
            }}),
            None => json!({"unknown": 72}),
        },
        Content::AnswerInvite {
            invite,
            join,
            password,
        } => json!({"answer_invite": {
            "invite": hex(&invite.0),
            "join": join,
            "password": password,
        }}),
        Content::InviteJoined {
            invite,
            chat,
            needs_password,
        } => json!({"invite_joined": {
            "invite": hex(&invite.0),
            "chat": chat.as_ref().map(chat_json),
            "needs_password": needs_password,
        }}),
        Content::Setting { scope, setting } => json!({"setting": {
            "scope": scope_json(scope),
            "setting": setting_json(setting),
        }}),
        Content::ClearSetting { scope, kind } => json!({"clear_setting": {
            "scope": scope_json(scope),
            "kind": kind,
        }}),
        Content::ReceivedPrivately {
            from,
            sender,
            message,
            kind,
        } => json!({"received_privately": {
            "from": hex(&from.0),
            "sender": sender,
            "message": hex(message),
            "kind": message_kind_json(kind),
        }}),
        Content::SendPrivately {
            to,
            sender,
            message,
            kind,
        } => json!({"send_privately": {
            "to": hex(&to.0),
            "sender": sender,
            "message": hex(message),
            "kind": message_kind_json(kind),
        }}),
        Content::Device { pk, name } => json!({"device": {"pk": hex(&pk.0), "name": name}}),
        Content::DeviceGone { pk } => json!({"device_gone": {"pk": hex(&pk.0)}}),
        // Of a kind or privacy this version doesn't know, it founds nothing.
        Content::NewChat {
            kind,
            name,
            privacy,
        } => match (chat_kind_json(kind), privacy) {
            (Some(kind), Privacy::Public | Privacy::Private) => json!({"new_chat": {
                "kind": kind,
                "name": name,
                "privacy": if *privacy == Privacy::Public { "public" } else { "private" },
            }}),
            _ => json!({"unknown": 79}),
        },
        Content::JoinChat { chat_id, password } => json!({"join_chat": {
            "chat_id": hex(&chat_id.0),
            "password": password,
        }}),
        Content::InviteToChat { chat, friend } => json!({"invite_to_chat": {
            "chat": chat_json(chat),
            "friend": hex(&friend.0),
        }}),
        Content::ChatJoined { intent, chat } => json!({"chat_joined": {
            "intent": hex(&intent.0),
            "chat": chat.as_ref().map(chat_json),
        }}),
        Content::Unknown { discriminant, .. } => json!({"unknown": discriminant}),
    }
}

fn event(j: &J) -> Event {
    Event {
        graph: GraphId(b32(&j["graph"])),
        author: pk(&j["author"]),
        parents: list(&j["parents"], id),
        rank: uint(&j["rank"]),
        time: j["time"].as_i64().expect("time"),
        content: content(&j["content"]),
    }
}

fn event_json(event: &Event) -> J {
    json!({
        "graph": hex(&event.graph.0),
        "author": hex(&event.author.0),
        "parents": event.parents.iter().map(|p| hex(&p.0)).collect::<Vec<_>>(),
        "rank": event.rank,
        "time": event.time,
        "content": content_json(&event.content),
    })
}

/// `Features` keeps its bits to itself, so they go through their encoding.
fn features(bits: u64) -> Features {
    tox_proto::deserialize_exact(&tox_proto::serialize(&bits).unwrap()).unwrap()
}

fn bits(features: &Features) -> u64 {
    tox_proto::deserialize_exact(&tox_proto::serialize(features).unwrap()).unwrap()
}

fn ids(j: &J) -> Vec<EventId> {
    list(j, id)
}

fn ids_json(ids: &[EventId]) -> J {
    J::Array(ids.iter().map(|i| json!(hex(&i.0))).collect())
}

fn message(j: &J) -> SessionMessage {
    let (tag, m) = variant(j);
    match tag {
        "hello" => SessionMessage::Hello {
            version: uint(&m["version"]),
            features: features(uint(&m["features"])),
        },
        "summary" => SessionMessage::Summary(list(m, |entry| {
            (GraphId(b32(&entry[0])), HeadsDigest(b32(&entry[1])))
        })),
        "heads" => SessionMessage::Heads {
            graph: GraphId(b32(&m["graph"])),
            heads: ids(&m["heads"]),
        },
        "want" => SessionMessage::Want(ids(m)),
        "events" => SessionMessage::Events(list(m, bytes)),
        "history" => SessionMessage::History {
            graph: GraphId(b32(&m["graph"])),
            before: ids(&m["before"]),
            limit: uint(&m["limit"]),
        },
        "want_blob" => SessionMessage::WantBlob(BlobId(b32(m))),
        "no_blob" => SessionMessage::NoBlob(BlobId(b32(m))),
        "facts" => SessionMessage::Facts {
            facts: list(&m["facts"], |f| (subject(&f[0]), value(&f[1]))),
            all: flag(&m["all"]),
        },
        "call" => SessionMessage::Call {
            friend: pk(&m["friend"]),
            action: match variant(&m["action"]) {
                ("connect", c) => CallAction::Connect {
                    video: flag(&c["video"]),
                },
                ("hang_up", _) => CallAction::HangUp,
                other => panic!("not a call action: {other:?}"),
            },
        },
        other => panic!("not a message: {other}"),
    }
}

/// Null for a message this version doesn't act on: of a kind it doesn't
/// know, or a call action it doesn't.
fn message_json(message: &SessionMessage) -> J {
    match message {
        SessionMessage::Hello { version, features } => {
            json!({"hello": {"version": version, "features": bits(features)}})
        }
        SessionMessage::Summary(graphs) => json!({"summary": graphs
            .iter()
            .map(|(graph, digest)| json!([hex(&graph.0), hex(&digest.0)]))
            .collect::<Vec<_>>()}),
        SessionMessage::Heads { graph, heads } => {
            json!({"heads": {"graph": hex(&graph.0), "heads": ids_json(heads)}})
        }
        SessionMessage::Want(wanted) => json!({"want": ids_json(wanted)}),
        SessionMessage::Events(events) => {
            json!({"events": events.iter().map(|e| hex(e)).collect::<Vec<_>>()})
        }
        SessionMessage::History {
            graph,
            before,
            limit,
        } => json!({"history": {
            "graph": hex(&graph.0),
            "before": ids_json(before),
            "limit": limit,
        }}),
        SessionMessage::WantBlob(blob) => json!({"want_blob": hex(&blob.0)}),
        SessionMessage::NoBlob(blob) => json!({"no_blob": hex(&blob.0)}),
        SessionMessage::Facts { facts, all } => json!({"facts": {
            "facts": facts.iter().map(|(s, v)| fact_json((s, v))).collect::<Vec<_>>(),
            "all": all,
        }}),
        SessionMessage::Call { friend, action } => match action {
            CallAction::Connect { video } => json!({"call": {
                "friend": hex(&friend.0),
                "action": {"connect": {"video": video}},
            }}),
            CallAction::HangUp => {
                json!({"call": {"friend": hex(&friend.0), "action": "hang_up"}})
            }
            CallAction::Unknown { .. } => J::Null,
        },
        SessionMessage::Unknown { .. } => J::Null,
    }
}

/// Replies, whose order says nothing, as the lists in them whose order says
/// nothing: all but events, which come in the order asked for.
fn replies_json(messages: &[SessionMessage]) -> J {
    let normal = |mut j: J| {
        match variant(&j.clone()) {
            ("summary", _) => j["summary"] = sorted(j["summary"].as_array().unwrap().clone()),
            ("heads", _) => {
                j["heads"]["heads"] = sorted(j["heads"]["heads"].as_array().unwrap().clone())
            }
            ("want", _) => j["want"] = sorted(j["want"].as_array().unwrap().clone()),
            ("history", _) => {
                j["history"]["before"] = sorted(j["history"]["before"].as_array().unwrap().clone())
            }
            _ => {}
        }
        j
    };
    sorted(messages.iter().map(|m| normal(message_json(m))).collect())
}

fn state_json(state: &AccountState) -> J {
    let friends = state
        .friends
        .iter()
        .filter(|(_, friend)| friend.wanted || friend.request.is_some())
        .map(|(key, friend)| {
            json!({"pk": hex(&key.0), "wanted": friend.wanted, "request": friend.request})
        })
        .collect();
    let merges = state
        .merges
        .iter()
        .map(|(c, merge)| {
            json!({
                "chat": chat_json(c),
                "bot": hex(&merge.bot.0),
                "into": chat_json(&merge.into),
                "into_bot": hex(&merge.into_bot.0),
            })
        })
        .collect();
    let relay_bots = state
        .relay_bots
        .iter()
        .map(|(c, bot)| json!({"chat": chat_json(c), "bot": hex(&bot.0)}))
        .collect();
    let read = state
        .read
        .iter()
        .map(|(graph, (rank, event))| {
            json!({"graph": hex(&graph.0), "rank": rank, "event": hex(&event.0)})
        })
        .collect();
    let settings = state
        .settings
        .iter()
        .flat_map(|(scope, kinds)| {
            kinds.iter().map(move |(kind, kept)| {
                json!({
                    "scope": scope_json(scope),
                    "kind": kind,
                    "setting": setting_json(kept),
                    "bytes": hex(&tox_proto::serialize(kept).unwrap()),
                })
            })
        })
        .collect();
    let invites = state
        .invites
        .iter()
        .filter_map(|(invite_id, invite)| {
            Some(json!({
                "invite": hex(&invite_id.0),
                "from": hex(&invite.from.0),
                "kind": chat_kind_json(&invite.kind)?,
                "name": invite.name,
                "status": match invite.status {
                    InviteStatus::Pending => "pending",
                    InviteStatus::Joining => "joining",
                    InviteStatus::Joined(_) => "joined",
                    InviteStatus::Failed { .. } => "failed",
                    InviteStatus::Declined => "declined",
                },
                "chat": invite.chat.as_ref().map(chat_json),
                "needs_password": matches!(
                    invite.status,
                    InviteStatus::Failed { needs_password: true }
                ),
            }))
        })
        .collect();
    json!({
        "facts": facts_json(&state.facts),
        "friends": sorted(friends),
        "merges": sorted(merges),
        "relay_bots": sorted(relay_bots),
        "read": sorted(read),
        "settings": sorted(settings),
        "invites": sorted(invites),
        "devices": sorted(
            state
                .devices
                .iter()
                .map(|(pk, name)| json!({"pk": hex(&pk.0), "name": name}))
                .collect()
        ),
        "chats_joined": sorted(
            state
                .chats_joined
                .iter()
                .map(|(intent, chat)| json!({"intent": hex(&intent.0), "chat": chat.as_ref().map(chat_json)}))
                .collect()
        ),
    })
}

fn facts_json(facts: &Facts) -> J {
    sorted(facts.iter().map(fact_json).collect())
}

fn counts_json(store: &EventStore) -> J {
    sorted(
        store
            .heads()
            .map(|(graph, _)| json!({"graph": hex(&graph.0), "count": store.graph(graph).len()}))
            .collect(),
    )
}

// Labels, which name what the behaviour cases are made of.

/// `%key`, `&chat` and `$graph` from a file's tables, and `@event` and
/// `#event`, its ID and bytes, from a case's events.
#[derive(Clone, Default)]
struct Labels {
    values: HashMap<String, J>,
    // The first label of each value, to write it back as.
    names: HashMap<String, String>,
}

impl Labels {
    fn of(file: &J) -> Self {
        let mut labels = Self::default();
        for (sigil, table) in [("%", "keys"), ("&", "chats")] {
            for (name, value) in file[table].as_object().into_iter().flatten() {
                let value = labels.resolve(value);
                labels.add(format!("{sigil}{name}"), value);
            }
        }
        for (name, spec) in file["graphs"].as_object().into_iter().flatten() {
            let spec = labels.resolve(spec);
            let graph = match variant(&spec) {
                ("account", key) => GraphId::account(&pk(key)),
                ("friend", keys) => GraphId::friend(&pk(&keys[0]), &pk(&keys[1])),
                ("group", id) => GraphId::group(&GroupChatId(b32(id))),
                ("conference", id) => GraphId::conference(&ConferenceId(b32(id))),
                other => panic!("not a graph: {other:?}"),
            };
            labels.add(format!("${name}"), json!(hex(&graph.0)));
        }
        labels
    }

    fn add(&mut self, label: String, value: J) {
        self.names.entry(canonical(&value)).or_insert(label.clone());
        self.values.insert(label, value);
    }

    fn add_event(&mut self, label: &str, bytes: &[u8]) {
        self.add(format!("@{label}"), json!(hex(&EventId::of(bytes).0)));
        self.add(format!("#{label}"), json!(hex(bytes)));
    }

    fn resolve(&self, j: &J) -> J {
        match j {
            J::String(s) => match self.values.get(s) {
                Some(value) => value.clone(),
                None if s.starts_with(['%', '&', '$', '@', '#']) => panic!("no label {s}"),
                None => j.clone(),
            },
            J::Array(items) => J::Array(items.iter().map(|i| self.resolve(i)).collect()),
            J::Object(map) => J::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), self.resolve(v)))
                    .collect(),
            ),
            _ => j.clone(),
        }
    }

    fn unresolve(&self, j: &J) -> J {
        if let Some(label) = self.names.get(&canonical(j))
            && !matches!(j, J::Bool(_) | J::Number(_) | J::Null)
        {
            return json!(label);
        }
        match j {
            J::Array(items) => J::Array(items.iter().map(|i| self.unresolve(i)).collect()),
            J::Object(map) => J::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), self.unresolve(v)))
                    .collect(),
            ),
            _ => j.clone(),
        }
    }
}

/// A case's events, by label, in the order they're listed; chains are
/// groups of events.
struct Pool {
    events: Vec<(String, Vec<u8>)>,
    chains: HashMap<String, Vec<String>>,
}

impl Pool {
    fn bytes(&self, label: &str) -> Vec<Vec<u8>> {
        match self.chains.get(label) {
            Some(members) => members.iter().flat_map(|m| self.bytes(m)).collect(),
            None => vec![
                self.events
                    .iter()
                    .find(|(l, _)| l == label)
                    .unwrap_or_else(|| panic!("no event {label}"))
                    .1
                    .clone(),
            ],
        }
    }

    fn store(&self, labels: &J) -> EventStore {
        let mut store = EventStore::default();
        for label in labels.as_array().into_iter().flatten() {
            for bytes in self.bytes(label.as_str().unwrap()) {
                store.insert(&bytes).unwrap();
            }
        }
        store
    }
}

fn pool(run: &mut Run, labels: &mut Labels, defaults: &J, case: &mut J) -> Pool {
    let mut pool = Pool {
        events: Vec::new(),
        chains: HashMap::new(),
    };
    let mut ranks: HashMap<EventId, u64> = HashMap::new();
    let entries = case["events"].as_array_mut().unwrap();
    for entry in entries.iter_mut() {
        let mut spec = defaults.clone();
        for (key, value) in entry.as_object().unwrap() {
            spec[key] = value.clone();
        }
        if let Some(raw) = entry.get("raw") {
            let label = text(&entry["label"]);
            let raw = bytes(raw);
            labels.add_event(&label, &raw);
            pool.events.push((label, raw));
            continue;
        }
        if let Some(name) = entry.get("chain") {
            let name = text(name);
            let spec = labels.resolve(&spec);
            let mut parent = entry
                .get("after")
                .map(|after| EventId::of(&pool.bytes(after.as_str().unwrap())[0]));
            let mut members = Vec::new();
            for i in 0..uint(&entry["count"]) {
                let event = Event {
                    graph: GraphId(b32(&spec["graph"])),
                    author: pk(&spec["author"]),
                    parents: parent.into_iter().collect(),
                    rank: parent.map_or(0, |p| ranks[&p] + 1),
                    time: i as i64,
                    content: Content::Notice {
                        text: i.to_string(),
                    },
                };
                let bytes = event.encode();
                let id = EventId::of(&bytes);
                ranks.insert(id, event.rank);
                let label = format!("{name}{i}");
                labels.add_event(&label, &bytes);
                pool.events.push((label.clone(), bytes));
                members.push(label);
                parent = Some(id);
            }
            pool.chains.insert(name, members);
            continue;
        }
        let spec = labels.resolve(&spec);
        let parents = ids(spec.get("parents").unwrap_or(&json!([])));
        let rank = match spec.get("rank") {
            Some(rank) => uint(rank),
            None => parents
                .iter()
                .filter_map(|p| ranks.get(p))
                .map(|rank| rank + 1)
                .max()
                .unwrap_or(0),
        };
        let event = Event {
            graph: GraphId(b32(&spec["graph"])),
            author: pk(&spec["author"]),
            parents,
            rank,
            time: spec["time"].as_i64().expect("time"),
            content: content(&spec["content"]),
        };
        let bytes = event.encode();
        ranks.insert(EventId::of(&bytes), rank);
        let label = text(&entry["label"]);
        run.expect(labels, &label, entry, "bytes", json!(hex(&bytes)));
        labels.add_event(&label, &bytes);
        pool.events.push((label, bytes));
    }
    pool
}

fn cases<'a>(file: &'a mut J, key: &str) -> impl Iterator<Item = &'a mut J> {
    file[key].as_array_mut().unwrap().iter_mut()
}

// The cases.

fn codec(run: &mut Run, file: &mut J) {
    let none = Labels::default();
    for case in cases(file, "ids") {
        let name = text(&case["name"]);
        let digest = match variant(&case["of"]) {
            ("account", key) => GraphId::account(&pk(key)).0,
            ("friend", keys) => GraphId::friend(&pk(&keys[0]), &pk(&keys[1])).0,
            ("group", g) => GraphId::group(&GroupChatId(b32(g))).0,
            ("conference", c) => GraphId::conference(&ConferenceId(b32(c))).0,
            ("blob", data) => BlobId::of(&bytes(data)[..]).unwrap().0,
            ("heads", heads) => HeadsDigest::of(&ids(heads)).0,
            other => panic!("not an ID: {other:?}"),
        };
        run.expect(&none, &name, case, "id", json!(hex(&digest)));
    }
    for case in cases(file, "events") {
        let name = text(&case["name"]);
        let encoded = event(&case["event"]).encode();
        run.expect(&none, &name, case, "bytes", json!(hex(&encoded)));
        run.expect(
            &none,
            &name,
            case,
            "id",
            json!(hex(&EventId::of(&encoded).0)),
        );
        let decoded = Event::decode(&bytes(&case["bytes"])).map(|e| event_json(&e));
        run.check(
            &name,
            "decoded",
            &case["event"],
            &decoded.unwrap_or(json!("error")),
        );
    }
    for case in cases(file, "event_decodings") {
        let name = text(&case["name"]);
        let decoded = Event::decode(&bytes(&case["bytes"]));
        let decoded = decoded.map_or(json!("error"), |e| event_json(&e));
        run.expect(&none, &name, case, "event", decoded);
    }
    for case in cases(file, "messages") {
        let name = text(&case["name"]);
        let encoded = message(&case["message"]).encode();
        run.expect(&none, &name, case, "bytes", json!(hex(&encoded)));
        let decoded = match SessionMessage::decode(&bytes(&case["bytes"])) {
            Ok(Some(m)) => message_json(&m),
            Ok(None) => J::Null,
            Err(_) => json!("error"),
        };
        run.check(&name, "decoded", &case["message"], &decoded);
    }
    for case in cases(file, "message_decodings") {
        let name = text(&case["name"]);
        let decoded = match SessionMessage::decode(&bytes(&case["bytes"])) {
            Ok(Some(m)) => message_json(&m),
            Ok(None) => J::Null,
            Err(_) => json!("error"),
        };
        run.expect(&none, &name, case, "message", decoded);
    }
    for case in cases(file, "packets") {
        let name = text(&case["name"]);
        let packets: Vec<String> = frames(&bytes(&case["message"]))
            .iter()
            .map(|p| hex(p))
            .collect();
        run.expect(&none, &name, case, "packets", json!(packets));
    }
    for case in cases(file, "reassembly") {
        let name = text(&case["name"]);
        let mut reassembler = Reassembler::default();
        let results: Vec<J> = list(&case["packets"], bytes)
            .iter()
            .map(|packet| match reassembler.push(packet) {
                Ok(None) => J::Null,
                Ok(Some(message)) => json!(hex(&message)),
                Err(_) => json!("error"),
            })
            .collect();
        run.expect(&none, &name, case, "results", json!(results));
    }
    for case in cases(file, "setting_edits") {
        let name = text(&case["name"]);
        let kept: Kept<Setting> = tox_proto::deserialize_exact(&bytes(&case["setting"])).unwrap();
        let edited = match setting(&case["value"]) {
            Setting::Mute(mute) => kept.with(mute),
            Setting::PictureFormat(format) => kept.with(format),
            Setting::Unknown { .. } => unreachable!(),
        }
        .unwrap();
        let edited = hex(&tox_proto::serialize(&edited).unwrap());
        run.expect(&none, &name, case, "bytes", json!(edited));
    }
    for case in cases(file, "pairing") {
        let name = text(&case["name"]);
        let code = PairingCode::from_hex(&text(&case["code"])).unwrap();
        let address = Address(bytes(&case["address"]).try_into().unwrap());
        run.expect(&none, &name, case, "link", json!(code.link(&address)));
        run.expect(&none, &name, case, "request", json!(code.request_message()));
    }
}

fn state(run: &mut Run, file: &mut J) {
    let base = Labels::of(file);
    let defaults = file["defaults"].clone();
    let account = GraphId(b32(&base.resolve(&defaults["graph"])));
    for case in cases(file, "account_states") {
        let name = text(&case["name"]);
        let mut labels = base.clone();
        let pool = pool(run, &mut labels, &defaults, case);
        let fold = |events: &mut dyn Iterator<Item = &(String, Vec<u8>)>| {
            let mut store = EventStore::default();
            for (_, bytes) in events {
                store.insert(bytes).unwrap();
            }
            state_json(&AccountState::of(&store, &account))
        };
        let state = fold(&mut pool.events.iter());
        // Any order of the same events adds up to the same.
        let reversed = fold(&mut pool.events.iter().rev());
        run.check(&name, "state, from the events reversed", &state, &reversed);
        run.expect(&labels, &name, case, "state", state);
    }
    for case in cases(file, "live_facts") {
        let name = text(&case["name"]);
        let fact = |f: &J| (subject(&f[0]), value(&f[1]));
        let mut facts = Facts::default();
        for (s, v) in list(&base.resolve(&case["before"]), fact) {
            facts.set(s, v);
        }
        facts.update(list(&base.resolve(&case["update"]), fact));
        run.expect(&base, &name, case, "after", facts_json(&facts));
    }
}

fn store(run: &mut Run, file: &mut J) {
    let base = Labels::of(file);
    let defaults = file["defaults"].clone();
    for case in cases(file, "stores") {
        let name = text(&case["name"]);
        let mut labels = base.clone();
        let pool = pool(run, &mut labels, &defaults, case);
        let mut store = EventStore::default();
        let mut results = Vec::new();
        for label in list(&case["inserts"], text) {
            for bytes in pool.bytes(&label) {
                results.push(json!(store.insert(&bytes).is_ok()));
            }
        }
        run.expect(&labels, &name, case, "results", json!(results));
        let graphs = store
            .heads()
            .map(|(graph, heads)| {
                json!({
                    "graph": hex(&graph.0),
                    "heads": sorted(ids_json(heads).as_array().unwrap().clone()),
                    "frontier": sorted(store
                        .frontier(graph)
                        .iter()
                        .map(|(i, _)| json!(hex(&i.0)))
                        .collect()),
                    "count": store.graph(graph).len(),
                })
            })
            .collect();
        run.expect(&labels, &name, case, "graphs", sorted(graphs));
        if case.get("display").is_some() {
            let orders: Vec<J> = list(&labels.resolve(&case["display"]), |g| {
                let graph = GraphId(b32(g));
                let order: Vec<EventId> = store.graph(&graph).iter().map(|(i, _)| *i).collect();
                ids_json(&order)
            });
            run.expect(&labels, &name, case, "display_order", json!(orders));
        }
    }
}

fn session_cases(run: &mut Run, file: &mut J) {
    let base = Labels::of(file);
    let defaults = file["defaults"].clone();
    for case in cases(file, "answers") {
        let name = text(&case["name"]);
        let mut labels = base.clone();
        let pool = pool(run, &mut labels, &defaults, case);
        let store = pool.store(&case["store"]);
        let message = match case["message"].as_str() {
            Some("summary") => session::summary(&store),
            _ => message(&labels.resolve(&case["message"])),
        };
        let replies = replies_json(&session::answer(&store, &message));
        run.expect(&labels, &name, case, "replies", replies);
    }
    for case in cases(file, "replicas") {
        let name = text(&case["name"]);
        let mut labels = base.clone();
        let pool = pool(run, &mut labels, &defaults, case);
        let device = pk(&labels.resolve(&case["device"]));
        let home_key = pk(&labels.resolve(&case["home"]));
        let mut home = pool.store(&case["home_store"]);
        let mut replica = Replica::new(device, &home_key, EventStore::default());
        for step in case["steps"].as_array_mut().unwrap() {
            let (action, spec) = variant_of_step(step);
            match action.as_str() {
                "receive" => {
                    let replies = replica.received(message(&labels.resolve(&spec)));
                    run.expect(&labels, &name, step, "replies", replies_json(&replies));
                }
                "offline" => replica.offline(),
                "home_add" => {
                    for label in list(&spec, text) {
                        for bytes in pool.bytes(&label) {
                            home.insert(&bytes).unwrap();
                        }
                    }
                }
                "author" => {
                    let spec = labels.resolve(&spec);
                    let (new, push) = replica.author(
                        GraphId(b32(&spec["graph"])),
                        spec["time"].as_i64().unwrap(),
                        content(&spec["content"]),
                    );
                    let bytes = replica.store().bytes(&new).unwrap().to_vec();
                    labels.add_event(&text(&spec["label"]), &bytes);
                    for message in &push {
                        if let SessionMessage::Events(events) = message {
                            for bytes in events {
                                home.insert(bytes).unwrap();
                            }
                        }
                    }
                    let authored = event_json(replica.store().get(&new).unwrap());
                    run.expect(&labels, &name, step, "event", authored);
                    run.expect(&labels, &name, step, "push", replies_json(&push));
                }
                "converse" => {
                    let start = match spec.as_str() {
                        Some("session") => vec![Replica::hello(), session::summary(&home)],
                        _ => list(&labels.resolve(&spec), message),
                    };
                    if !converse(&mut home, &mut replica, start) {
                        run.failures.push(format!("{name}: the session never ends"));
                    }
                    run.expect(
                        &labels,
                        &name,
                        step,
                        "replica",
                        counts_json(replica.store()),
                    );
                    run.expect(&labels, &name, step, "home", counts_json(&home));
                }
                other => panic!("not a step: {other}"),
            }
        }
    }
}

/// The step's action, the key that isn't one of its results.
fn variant_of_step(step: &J) -> (String, J) {
    const RESULTS: [&str; 5] = ["replies", "event", "push", "replica", "home"];
    let map: &Map<String, J> = step.as_object().unwrap();
    let (action, spec) = map
        .iter()
        .find(|(key, _)| !RESULTS.contains(&key.as_str()))
        .expect("an action");
    (action.clone(), spec.clone())
}

/// Runs a session between a home's store and a replica until neither has
/// anything left to say. The home answers from its store, History too, and
/// takes the events it's sent. False if it doesn't end.
fn converse(home: &mut EventStore, replica: &mut Replica, start: Vec<SessionMessage>) -> bool {
    let mut to_replica = start;
    for _ in 0..MAX_ROUNDS {
        if to_replica.is_empty() {
            return true;
        }
        let to_home: Vec<SessionMessage> = to_replica
            .into_iter()
            .flat_map(|message| replica.received(message))
            .collect();
        to_replica = to_home
            .into_iter()
            .flat_map(|message| match message {
                SessionMessage::Events(events) => {
                    for bytes in &events {
                        let _ = home.insert(bytes);
                    }
                    Vec::new()
                }
                message => session::answer(home, &message),
            })
            .collect();
    }
    false
}
