//! Events: the immutable, content-addressed records all account state is
//! derived from. Encoded with tox-proto.

use std::io::{self, Read};

use sha2::{Digest, Sha256};
use tox_proto::{Kept, ToxProto};
use toxcore::types::{ConferenceId, FileId, GroupChatId, MessageType, PublicKey};

use crate::fact::{Subject, Value};
use crate::setting::{Scope, Setting};

pub type DecodeError = tox_proto::Error;

const VERSION: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ToxProto)]
#[tox(flat)]
pub struct EventId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToxProto)]
#[tox(flat)]
pub struct GraphId(pub [u8; 32]);

/// A file's bytes, named by their SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToxProto)]
#[tox(flat)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    pub fn of(mut bytes: impl Read) -> io::Result<Self> {
        let mut hash = Sha256::new();
        let mut buf = [0; 64 * 1024];
        loop {
            match bytes.read(&mut buf)? {
                0 => return Ok(Self(hash.finalize().into())),
                n => hash.update(&buf[..n]),
            }
        }
    }
}

impl EventId {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl GraphId {
    fn of(parts: &[&[u8]]) -> Self {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        Self(hash.finalize().into())
    }

    pub fn account(account: &PublicKey) -> Self {
        Self::of(&[b"account", &account.0])
    }

    pub fn friend(account: &PublicKey, friend: &PublicKey) -> Self {
        Self::of(&[b"friend", &account.0, &friend.0])
    }

    pub fn group(chat_id: &GroupChatId) -> Self {
        Self::of(&[b"group", &chat_id.0])
    }

    pub fn conference(id: &ConferenceId) -> Self {
        Self::of(&[b"conference", &id.0])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToxProto)]
#[repr(u8)]
pub enum ChatId {
    Group(GroupChatId) = 0,
    Conference(ConferenceId) = 1,
}

/// What a `ChatId` is of.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum ChatKind {
    Group = 0,
    Conference = 1,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

impl ChatId {
    /// The graph of its conversation.
    pub fn graph(&self) -> GraphId {
        match self {
            Self::Group(id) => GraphId::group(id),
            Self::Conference(id) => GraphId::conference(id),
        }
    }
}

/// Each variant's discriminant is its tag on the wire. A variant with a
/// single field is encoded as `[tag, field]`, so it can't gain fields later;
/// new fields go on variants with several, marked `#[tox(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum Content {
    // Conversation kinds, in a conversation's graph, are numbered from 0 and
    // account kinds from 64; account-sync.md says why.

    // A message's bytes are as Tox carries them; only clients showing them
    // decode them.
    Received {
        from: Option<PublicKey>,
        sender: String,
        message: Vec<u8>,
        kind: MessageType,
    } = 0,
    Send {
        sender: String,
        message: Vec<u8>,
        kind: MessageType,
    } = 1,
    Sent {
        intent: EventId,
    } = 2,
    Delivered {
        intent: EventId,
    } = 3,
    Notice {
        text: String,
    } = 4,
    /// From a device, `blob` is the file it asks the home to send.
    File {
        sender: String,
        file_id: Option<FileId>,
        name: String,
        size: u64,
        incoming: bool,
        #[tox(default)]
        blob: Option<BlobId>,
    } = 5,
    /// `blob` is the file's, which the home holds, when it ended well.
    FileEnded {
        file: EventId,
        ok: bool,
        #[tox(default)]
        blob: Option<BlobId>,
    } = 6,
    /// A device's answer to a file offered to the home device.
    FileAnswered {
        file: EventId,
        accepted: bool,
    } = 7,
    /// A call with the friend, ringing.
    Call {
        sender: String,
        incoming: bool,
        video: bool,
    } = 8,
    /// `duration` is how long the call was connected, in ms, if it was.
    CallEnded {
        call: EventId,
        duration: Option<u64>,
        /// It rang here and was declined, so it wasn't missed.
        #[tox(default)]
        declined: bool,
    } = 9,

    WantFriend {
        pk: PublicKey,
        request_message: Option<String>,
        /// With `pk`, the address a friend request goes to.
        #[tox(default)]
        nospam: Option<u32>,
    } = 64,
    UnwantFriend {
        pk: PublicKey,
    } = 65,
    /// Messages in `graph` up to `event`, whose rank is `rank`, have been read.
    ReadUpTo {
        graph: GraphId,
        event: EventId,
        rank: u64,
    } = 66,
    FriendRequest {
        pk: PublicKey,
        message: String,
    } = 67,
    /// `chat` shows with `into`, as `bot` in `chat` and `into_bot` in `into`
    /// relay messages between them; unmerged where `merged` is false.
    MergeChat {
        chat: ChatId,
        bot: PublicKey,
        into: ChatId,
        into_bot: PublicKey,
        merged: bool,
    } = 68,
    /// `bot` in `chat` relays messages from another chat as `<name> text`;
    /// no more where `relays` is false.
    RelayBot {
        chat: ChatId,
        bot: PublicKey,
        relays: bool,
    } = 69,
    /// What Tox says `subject` has.
    Fact {
        subject: Subject,
        value: Value,
    } = 70,
    /// What a device wants Tox to say `subject` has.
    Want {
        subject: Subject,
        value: Value,
    } = 71,
    /// Friend `from` invites the account to a chat named `name`, empty for a
    /// conference; `invite` is what Tox joins it with.
    ChatInvite {
        from: PublicKey,
        kind: ChatKind,
        name: String,
        invite: Vec<u8>,
    } = 72,
    /// A device's answer to the invite `invite`: join the chat, with the
    /// group's password if it has one, or decline.
    AnswerInvite {
        invite: EventId,
        join: bool,
        #[tox(default)]
        password: Option<String>,
    } = 73,
    /// The home carried out a join of the invite `invite`: the chat it
    /// joined, or none where Tox refused, `needs_password` where for a
    /// missing or wrong password.
    InviteJoined {
        invite: EventId,
        chat: Option<ChatId>,
        #[tox(default)]
        needs_password: bool,
    } = 74,
    /// Sets `setting` for `scope`; per scope and kind, the last writer wins.
    Setting {
        scope: Scope,
        setting: Kept<Setting>,
    } = 75,
    /// Back to the default: no setting of `kind` for `scope`.
    ClearSetting {
        scope: Scope,
        kind: u32,
    } = 76,
    /// From a newer version: stored and passed on, but not understood.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// The most milliseconds from the epoch an event's time may be, either way:
/// as far as ECMAScript's and Dart's dates go.
pub const MAX_TIME: i64 = 8_640_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub struct Event {
    pub graph: GraphId,
    pub author: PublicKey,
    pub parents: Vec<EventId>,
    pub rank: u64,
    /// Milliseconds since the Unix epoch, by the author's clock.
    pub time: i64,
    pub content: Content,
}

impl Event {
    /// `[version, event]`. Its hash is the event's ID.
    pub fn encode(&self) -> Vec<u8> {
        tox_proto::serialize(&(VERSION, self)).expect("events always encode")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match tox_proto::deserialize_exact::<(u8, Event)>(bytes)? {
            (VERSION, event) if (-MAX_TIME..=MAX_TIME).contains(&event.time) => Ok(event),
            (VERSION, event) => Err(DecodeError::Deserialize(format!(
                "Time {} out of range",
                event.time
            ))),
            (version, _) => Err(DecodeError::Deserialize(format!(
                "Unknown event version {}",
                version
            ))),
        }
    }
}
