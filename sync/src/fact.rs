//! Facts: what Tox says about the account, its friends, its chats and the
//! people in them, as values of subjects. A wish is a fact a device wants to
//! be true.

use std::collections::HashMap;

use tox_proto::ToxProto;
use toxcore::types::PublicKey;

use crate::event::ChatId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToxProto)]
#[repr(u8)]
pub enum Subject {
    Account = 0,
    Friend(PublicKey) = 1,
    Chat(ChatId) = 2,
    Peer { chat: ChatId, pk: PublicKey } = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum UserStatus {
    Online = 0,
    Away = 1,
    Busy = 2,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum Connection {
    None = 0,
    Tcp = 1,
    Udp = 2,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum Role {
    Founder = 0,
    Moderator = 1,
    User = 2,
    Observer = 3,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum Privacy {
    Public = 0,
    Private = 1,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum VoiceState {
    Everyone = 0,
    Moderators = 1,
    Founder = 2,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// A friend's call, as the home device has it.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum CallState {
    None = 0,
    /// Ringing at the home device, for a device to answer.
    Ringing {
        video: bool,
    } = 1,
    /// Going on, through one of the account's devices.
    Answered = 2,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// Each variant's discriminant is its kind on the wire; a subject has at most
/// one value of each kind.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum Value {
    Name(String) = 0,
    StatusMessage(String) = 1,
    Status(UserStatus) = 2,
    Connection(Connection) = 3,
    Typing(bool) = 4,
    Topic(String) = 5,
    Role(Role) = 6,
    Privacy(Privacy) = 7,
    PeerLimit(u32) = 8,
    /// Empty for none.
    Password(String) = 9,
    TopicLock(bool) = 10,
    VoiceState(VoiceState) = 11,
    Joined(bool) = 12,
    /// Our name in a chat, where it has its own.
    SelfName(String) = 13,
    Present(bool) = 14,
    Address(Vec<u8>) = 15,
    Call(CallState) = 16,
    /// The home device connects devices to the account's calls.
    CallRelay(bool) = 17,
    /// Our key in a group, which is its own.
    SelfKey(PublicKey) = 18,
    /// From a newer version: kept and passed on, but not understood.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// Facts are kept as events where they change seldom enough to be history;
/// the rest are live, sent only within a session.
pub fn is_kept(subject: &Subject, value: &Value) -> bool {
    !matches!(
        (subject, value),
        (Subject::Peer { .. }, _)
            | (
                _,
                Value::Connection(_)
                    | Value::Typing(_)
                    | Value::Present(_)
                    | Value::Call(_)
                    | Value::CallRelay(_)
            )
            | (Subject::Friend(_), Value::Status(_))
    )
}

/// Whether a device may wish for `value`: the home device can make Tox
/// match it.
pub fn is_wishable(subject: &Subject, value: &Value) -> bool {
    match subject {
        Subject::Account => matches!(
            value,
            Value::Name(_) | Value::StatusMessage(_) | Value::Status(_)
        ),
        Subject::Chat(ChatId::Conference(_)) => {
            matches!(value, Value::Name(_) | Value::Joined(false))
        }
        Subject::Chat(ChatId::Group(_)) => matches!(
            value,
            Value::Topic(_)
                | Value::Privacy(_)
                | Value::PeerLimit(_)
                | Value::Password(_)
                | Value::TopicLock(_)
                | Value::VoiceState(_)
                | Value::Joined(false)
                | Value::SelfName(_)
        ),
        Subject::Peer {
            chat: ChatId::Group(_),
            ..
        } => matches!(value, Value::Role(_) | Value::Present(false)),
        _ => false,
    }
}

/// What each subject has, of each kind of value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts(HashMap<Subject, Vec<Value>>);

impl Facts {
    pub fn of(&self, subject: &Subject) -> &[Value] {
        self.0.get(subject).map_or(&[], Vec::as_slice)
    }

    /// The first of a subject's values `pick` takes.
    pub fn find<'a, T>(
        &'a self,
        subject: &Subject,
        pick: impl Fn(&'a Value) -> Option<T>,
    ) -> Option<T> {
        self.of(subject).iter().find_map(pick)
    }

    pub fn name(&self, subject: &Subject) -> Option<&str> {
        self.find(subject, |value| match value {
            Value::Name(name) => Some(name.as_str()),
            _ => None,
        })
    }

    pub fn subjects(&self) -> impl Iterator<Item = &Subject> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Subject, &Value)> {
        self.0
            .iter()
            .flat_map(|(subject, values)| values.iter().map(move |value| (subject, value)))
    }

    /// Whether it changed anything.
    pub fn set(&mut self, subject: Subject, value: Value) -> bool {
        let values = self.0.entry(subject).or_default();
        match values.iter_mut().find(|v| v.kind() == value.kind()) {
            Some(old) if *old == value => false,
            Some(old) => {
                *old = value;
                true
            }
            None => {
                values.push(value);
                true
            }
        }
    }

    /// Takes in live facts: `Present(false)` drops a subject.
    pub fn update(&mut self, facts: impl IntoIterator<Item = (Subject, Value)>) {
        for (subject, value) in facts {
            if value == Value::Present(false) {
                self.0.remove(&subject);
            } else {
                self.set(subject, value);
            }
        }
    }

    /// What tells a device that knows `self` what's in `now`.
    pub fn changes(&self, now: &Facts) -> Vec<(Subject, Value)> {
        let mut changes: Vec<(Subject, Value)> = now
            .iter()
            .filter(|(subject, value)| !self.of(subject).contains(value))
            .map(|(subject, value)| (*subject, value.clone()))
            .collect();
        changes.extend(
            self.subjects()
                .filter(|subject| !now.0.contains_key(subject))
                .map(|subject| (*subject, Value::Present(false))),
        );
        changes
    }
}
