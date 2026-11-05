//! Keeping a copy of an account, for a device whose home device runs it on
//! Tox. The copy is the device's event store, which the caller keeps.

use std::collections::{BTreeSet, HashSet};

use toxcore::types::PublicKey;

use crate::event::{Content, EventId, GraphId};
use crate::fact::Facts;
use crate::protocol::{Features, SessionMessage};
use crate::session;
use crate::store::EventStore;

/// Conversations start from their latest events; older ones are asked for
/// when wanted.
pub const HISTORY_PAGE: u64 = 50;

pub struct Replica {
    device: PublicKey,
    account: GraphId,
    session: bool,
    // Conversations whose latest page has been asked for in this session.
    paged: HashSet<GraphId>,
    // Conversations whose older page we asked for and haven't received yet.
    asking: HashSet<GraphId>,
    live: Facts,
}

impl Replica {
    pub fn new(device: PublicKey, home: &PublicKey) -> Self {
        Self {
            device,
            account: GraphId::account(home),
            session: false,
            paged: HashSet::new(),
            asking: HashSet::new(),
            live: Facts::default(),
        }
    }

    /// Whether the home is syncing with this device now.
    pub fn in_session(&self) -> bool {
        self.session
    }

    pub fn live(&self) -> &Facts {
        &self.live
    }

    pub fn hello() -> SessionMessage {
        SessionMessage::hello(Features::ACCOUNT_SYNC)
    }

    pub fn offline(&mut self) {
        self.session = false;
        self.paged.clear();
        self.asking.clear();
    }

    /// Asks for the page before the oldest events we have of a conversation.
    /// The answer comes as `Events`. Returns nothing outside a session, once we
    /// have the whole conversation, or while the last request is unanswered.
    #[cfg_attr(tokstyle, tokstyle::pure)]
    pub fn older(&mut self, store: &EventStore, graph: GraphId) -> Vec<SessionMessage> {
        let before: Vec<EventId> = store
            .frontier(&graph)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        if !self.session || before.is_empty() || !self.asking.insert(graph) {
            return Vec::new();
        }
        vec![SessionMessage::History {
            graph,
            before,
            limit: HISTORY_PAGE,
        }]
    }

    /// Adds an event by this device, and what to send the home device for
    /// it: nothing outside a session, where the next one's summaries catch up.
    #[cfg_attr(tokstyle, tokstyle::pure)]
    pub fn author(
        &mut self,
        store: &mut EventStore,
        graph: GraphId,
        time: i64,
        content: Content,
    ) -> (EventId, Vec<SessionMessage>) {
        let (id, bytes) = store.create(graph, self.device, time, content);
        let push = if self.session {
            session::batches([bytes])
        } else {
            Vec::new()
        };
        (id, push)
    }

    /// The replies to a message from the home device, whose events go into
    /// `store`.
    #[cfg_attr(tokstyle, tokstyle::pure)]
    pub fn received(
        &mut self,
        store: &mut EventStore,
        message: SessionMessage,
    ) -> Vec<SessionMessage> {
        if let SessionMessage::Hello { features, .. } = message {
            self.session = features.contains(Features::ACCOUNT_SYNC);
            self.paged.clear();
            self.asking.clear();
            return if self.session {
                vec![session::summary(store)]
            } else {
                Vec::new()
            };
        }
        if !self.session {
            return Vec::new();
        }
        match message {
            SessionMessage::Events(events) => self.add(store, &events),
            SessionMessage::Facts { facts, all } => {
                if all {
                    self.live = Facts::default();
                }
                self.live.update(facts);
                Vec::new()
            }
            message @ (SessionMessage::Hello { .. }
            | SessionMessage::Summary(_)
            | SessionMessage::Heads { .. }
            | SessionMessage::Want(_)
            | SessionMessage::History { .. }
            | SessionMessage::WantBlob(_)
            | SessionMessage::NoBlob(_)
            | SessionMessage::Call { .. }
            | SessionMessage::Unknown { .. }) => session::answer(store, &message),
        }
    }

    fn add(&mut self, store: &mut EventStore, events: &[Vec<u8>]) -> Vec<SessionMessage> {
        // The graphs of what came, also of events held already.
        let mut came = HashSet::new();
        let mut grew = HashSet::new();
        for bytes in events {
            if let Some(held) = store.get(&EventId::of(bytes)) {
                came.insert(held.graph);
            } else if let Ok(id) = store.insert(bytes)
                && let Some(event) = store.get(&id)
            {
                came.insert(event.graph);
                grew.insert(event.graph);
            }
        }
        let mut replies = Vec::new();
        for graph in came {
            self.asking.remove(&graph);
            let grown = grew.contains(&graph);
            if let Some(gap) = self.gap(store, &graph) {
                if grown {
                    replies.push(SessionMessage::History {
                        graph,
                        before: gap,
                        limit: session::MAX_HISTORY,
                    });
                } else {
                    // History brought nothing new: the missing parents are
                    // further back than it goes.
                    let missing: BTreeSet<EventId> = gap
                        .iter()
                        .filter_map(|id| store.get(id))
                        .flat_map(|event| &event.parents)
                        .filter(|parent| !store.contains(parent))
                        .copied()
                        .collect();
                    replies.extend(session::want(missing));
                }
            } else if grown && graph != self.account && self.paged.insert(graph) {
                replies.push(SessionMessage::History {
                    graph,
                    before: store.heads_of(&graph).to_vec(),
                    limit: HISTORY_PAGE,
                });
            }
        }
        replies
    }

    /// The events to ask for the ancestors of, while `graph` has a gap: all
    /// the account's, and of a conversation the part between its latest
    /// events and the older ones held here.
    fn gap(&self, store: &EventStore, graph: &GraphId) -> Option<Vec<EventId>> {
        let oldest = if *graph == self.account {
            None
        } else {
            store.graph(graph).iter().map(|(_, e)| e.rank).min()
        };
        let gap: Vec<EventId> = store
            .frontier(graph)
            .into_iter()
            .filter(|(_, event)| oldest.is_none_or(|oldest| event.rank > oldest))
            .map(|(id, _)| id)
            .collect();
        (!gap.is_empty()).then_some(gap)
    }
}
