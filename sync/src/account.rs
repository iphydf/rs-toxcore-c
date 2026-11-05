//! What the events of an account's graph add up to.

use std::collections::HashMap;

use tox_proto::{Kept, ToxSerialize, Variant};
use toxcore::types::PublicKey;

use crate::event::{ChatId, ChatKind, Content, EventId, GraphId};
use crate::fact::{Facts, Subject, Value};
use crate::setting::{Scope, Setting};
use crate::store::EventStore;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Friend {
    pub wanted: bool,
    /// A friend request waiting for an answer.
    pub request: Option<String>,
}

/// A chat shown with another, `into`, by the keys of the bot that relays
/// between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    pub bot: PublicKey,
    pub into: ChatId,
    pub into_bot: PublicKey,
}

/// Where an invite to a chat is, by its last answer and what the home did
/// with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Pending,
    /// Answered to join, which the home hasn't carried out yet.
    Joining,
    Joined(ChatId),
    /// The home couldn't join it, for a missing or wrong password where
    /// `needs_password`.
    Failed {
        needs_password: bool,
    },
    Declined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub from: PublicKey,
    pub kind: ChatKind,
    pub name: String,
    pub invite: Vec<u8>,
    pub status: InviteStatus,
    /// The password the last answer to join gave.
    pub password: Option<String>,
    /// The chat the home joined, even where Tox failed it later.
    pub chat: Option<ChatId>,
}

impl Invite {
    /// Whether answering it can still join its chat: a chat that turned the
    /// home away has spent it.
    pub fn is_open(&self) -> bool {
        match self.status {
            InviteStatus::Pending | InviteStatus::Joining => true,
            InviteStatus::Failed { .. } => self.chat.is_none(),
            InviteStatus::Joined(_) | InviteStatus::Declined => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountState {
    /// The kept facts; live ones are only in sessions.
    pub facts: Facts,
    pub friends: HashMap<PublicKey, Friend>,
    pub merges: HashMap<ChatId, Merge>,
    /// Per chat, the bot relaying another chat's messages in it.
    pub relay_bots: HashMap<ChatId, PublicKey>,
    /// Per conversation, the rank and ID of the last event read.
    pub read: HashMap<GraphId, (u64, EventId)>,
    /// Per scope, its settings by kind.
    pub settings: HashMap<Scope, HashMap<u32, Kept<Setting>>>,
    /// By their `ChatInvite` events.
    pub invites: HashMap<EventId, Invite>,
    /// The account's devices, by key, with their names.
    pub devices: HashMap<PublicKey, String>,
    /// The chats the home founded or joined for `NewChat` and `JoinChat`
    /// events, or none where Tox refused, by those events.
    pub chats_joined: HashMap<EventId, Option<ChatId>>,
    /// Per subject and value kind, the last `Fact` or `Want` about it.
    pub last_said: HashMap<(Subject, u32), EventId>,
}

impl AccountState {
    /// What the account graph `graph` of `store` adds up to: its events in
    /// rank order, so the last writer wins.
    pub fn of(store: &EventStore, graph: &GraphId) -> Self {
        let mut state = Self::default();
        for (id, event) in store.by_rank(graph) {
            state.apply(id, &event.content);
        }
        state
    }

    /// Whether the wish `id` for `subject` to have `value` is the last thing
    /// said about that kind of value, so nothing newer overrides it.
    pub fn is_last_said(&self, subject: &Subject, value: &Value, id: &EventId) -> bool {
        self.last_said.get(&(*subject, value.kind())) == Some(id)
    }

    /// The setting of `scope` of `T`'s kind.
    pub fn setting<T: Variant<Setting>>(&self, scope: &Scope) -> Option<&T> {
        T::of(self.settings.get(scope)?.get(&T::KIND)?)
    }

    /// The setting of `scope` of `T`'s kind changed by `change`, to write:
    /// the fields of it this version doesn't know stay as they came.
    pub fn edit<T: Variant<Setting> + ToxSerialize + Clone>(
        &self,
        scope: &Scope,
        change: impl FnOnce(&mut T),
    ) -> Option<Kept<Setting>> {
        let kept = self.settings.get(scope)?.get(&T::KIND)?;
        let mut value = T::of(kept)?.clone();
        change(&mut value);
        kept.with(value).ok()
    }

    /// The chats the account is in.
    pub fn chats(&self) -> impl Iterator<Item = ChatId> + '_ {
        self.facts.subjects().filter_map(|subject| match subject {
            Subject::Chat(chat) if self.facts.of(subject).contains(&Value::Joined(true)) => {
                Some(*chat)
            }
            _ => None,
        })
    }

    /// Applies the event `id`, whose content is `content`, after all events
    /// of lower rank.
    pub fn apply(&mut self, id: EventId, content: &Content) {
        match content {
            Content::Fact { subject, value } => {
                self.facts.set(*subject, value.clone());
                self.last_said.insert((*subject, value.kind()), id);
            }
            Content::Want { subject, value } => {
                self.last_said.insert((*subject, value.kind()), id);
            }
            Content::WantFriend { pk, .. } => {
                let friend = self.friends.entry(*pk).or_default();
                friend.wanted = true;
                friend.request = None;
            }
            Content::UnwantFriend { pk } => {
                let friend = self.friends.entry(*pk).or_default();
                friend.wanted = false;
                friend.request = None;
            }
            Content::ReadUpTo { graph, event, rank } => {
                let read = self.read.entry(*graph).or_insert((*rank, *event));
                *read = (*read).max((*rank, *event));
            }
            Content::FriendRequest { pk, message } => {
                self.friends.entry(*pk).or_default().request = Some(message.clone());
            }
            Content::MergeChat {
                chat,
                bot,
                into,
                into_bot,
                merged,
            } => {
                if *merged {
                    self.merges.insert(
                        *chat,
                        Merge {
                            bot: *bot,
                            into: *into,
                            into_bot: *into_bot,
                        },
                    );
                } else {
                    self.merges.remove(chat);
                }
            }
            Content::RelayBot { chat, bot, relays } => {
                if *relays {
                    self.relay_bots.insert(*chat, *bot);
                } else {
                    self.relay_bots.remove(chat);
                }
            }
            Content::Setting { scope, setting } => {
                self.settings
                    .entry(scope.clone())
                    .or_default()
                    .insert(setting.kind(), setting.clone());
            }
            Content::ClearSetting { scope, kind } => {
                if let Some(settings) = self.settings.get_mut(scope) {
                    settings.remove(kind);
                    if settings.is_empty() {
                        self.settings.remove(scope);
                    }
                }
            }
            Content::ChatInvite {
                from,
                kind,
                name,
                invite,
            } => {
                self.invites.insert(
                    id,
                    Invite {
                        from: *from,
                        kind: kind.clone(),
                        name: name.clone(),
                        invite: invite.clone(),
                        status: InviteStatus::Pending,
                        password: None,
                        chat: None,
                    },
                );
            }
            Content::AnswerInvite {
                invite,
                join,
                password,
            } => {
                if let Some(invite) = self.invites.get_mut(invite) {
                    invite.status = if *join {
                        InviteStatus::Joining
                    } else {
                        InviteStatus::Declined
                    };
                    invite.password = password.clone();
                }
            }
            Content::InviteJoined {
                invite,
                chat,
                needs_password,
            } => {
                if let Some(invite) = self.invites.get_mut(invite) {
                    invite.status = match chat {
                        Some(chat) => InviteStatus::Joined(*chat),
                        None => InviteStatus::Failed {
                            needs_password: *needs_password,
                        },
                    };
                    invite.chat = chat.or(invite.chat);
                }
            }
            Content::Device { pk, name } => {
                self.devices.insert(*pk, name.clone());
            }
            Content::DeviceGone { pk } => {
                self.devices.remove(pk);
            }
            Content::ChatJoined { intent, chat } => {
                self.chats_joined.insert(*intent, *chat);
            }
            _ => {}
        }
    }
}
