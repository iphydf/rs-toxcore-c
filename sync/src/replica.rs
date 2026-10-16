//! Keeping a copy of an account, for a device whose home device runs it on
//! Tox.

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
    store: EventStore,
    session: bool,
    // Conversations whose latest page has been asked for in this session.
    paged: HashSet<GraphId>,
    live: Facts,
}

impl Replica {
    pub fn new(device: PublicKey, home: &PublicKey, store: EventStore) -> Self {
        Self {
            device,
            account: GraphId::account(home),
            store,
            session: false,
            paged: HashSet::new(),
            live: Facts::default(),
        }
    }

    pub fn store(&self) -> &EventStore {
        &self.store
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
    }

    /// Adds an event by this device, and what to send the home device for
    /// it: nothing outside a session, where the next one's summaries catch up.
    pub fn author(
        &mut self,
        graph: GraphId,
        time: i64,
        content: Content,
    ) -> (EventId, Vec<SessionMessage>) {
        let (id, bytes) = self.store.create(graph, self.device, time, content);
        let push = if self.session {
            session::batches([bytes])
        } else {
            Vec::new()
        };
        (id, push)
    }

    /// The replies to a message from the home device.
    pub fn received(&mut self, message: SessionMessage) -> Vec<SessionMessage> {
        if let SessionMessage::Hello { features, .. } = message {
            self.session = features.contains(Features::ACCOUNT_SYNC);
            self.paged.clear();
            return if self.session {
                vec![session::summary(&self.store)]
            } else {
                Vec::new()
            };
        }
        if !self.session {
            return Vec::new();
        }
        match message {
            SessionMessage::Events(events) => self.add(&events),
            SessionMessage::Facts { facts, all } => {
                if all {
                    self.live = Facts::default();
                }
                self.live.update(facts);
                Vec::new()
            }
            message => session::answer(&self.store, &message),
        }
    }

    fn add(&mut self, events: &[Vec<u8>]) -> Vec<SessionMessage> {
        // The graphs of what came, also of events held already.
        let mut came = HashSet::new();
        let mut grew = HashSet::new();
        for bytes in events {
            if let Some(held) = self.store.get(&EventId::of(bytes)) {
                came.insert(held.graph);
            } else if let Ok(id) = self.store.insert(bytes)
                && let Some(event) = self.store.get(&id)
            {
                came.insert(event.graph);
                grew.insert(event.graph);
            }
        }
        let mut replies = Vec::new();
        for graph in came {
            let grown = grew.contains(&graph);
            if let Some(gap) = self.gap(&graph) {
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
                        .filter_map(|id| self.store.get(id))
                        .flat_map(|event| &event.parents)
                        .filter(|parent| !self.store.contains(parent))
                        .copied()
                        .collect();
                    replies.extend(session::want(missing));
                }
            } else if grown && graph != self.account && self.paged.insert(graph) {
                replies.push(SessionMessage::History {
                    graph,
                    before: self.store.heads_of(&graph).to_vec(),
                    limit: HISTORY_PAGE,
                });
            }
        }
        replies
    }

    /// The events to ask for the ancestors of, while `graph` has a gap: all
    /// the account's, and of a conversation the part between its latest
    /// events and the older ones held here.
    fn gap(&self, graph: &GraphId) -> Option<Vec<EventId>> {
        let oldest = if *graph == self.account {
            None
        } else {
            self.store.graph(graph).iter().map(|(_, e)| e.rank).min()
        };
        let gap: Vec<EventId> = self
            .store
            .frontier(graph)
            .into_iter()
            .filter(|(_, event)| oldest.is_none_or(|oldest| event.rank > oldest))
            .map(|(id, _)| id)
            .collect();
        (!gap.is_empty()).then_some(gap)
    }
}
