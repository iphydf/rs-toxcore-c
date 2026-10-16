//! The exchange both ends of a session run: each sends a `Summary`, answers
//! the other's with `Heads` where they differ, asks with `Want` for heads it
//! lacks, and answers `Want` and `History` from its own store.

use std::collections::HashMap;

use crate::event::{EventId, GraphId};
use crate::protocol::{HeadsDigest, SessionMessage};
use crate::store::EventStore;

/// Keeps replies small, so live events aren't stuck behind them.
const MAX_EVENTS_BYTES: usize = 64 * 1024;
const MAX_WANT: usize = 64;
/// The most a `History` answer holds.
pub const MAX_HISTORY: u64 = 500;

pub fn summary(store: &EventStore) -> SessionMessage {
    SessionMessage::Summary(
        store
            .heads()
            .map(|(graph, heads)| (*graph, HeadsDigest::of(heads)))
            .collect(),
    )
}

/// Our heads of each graph the other side holds differently or not at all.
/// Graphs only they have come back in their `Heads` for our summary.
pub fn heads_for(store: &EventStore, theirs: &[(GraphId, HeadsDigest)]) -> Vec<SessionMessage> {
    let theirs: HashMap<_, _> = theirs.iter().copied().collect();
    store
        .heads()
        .filter(|(graph, heads)| theirs.get(graph) != Some(&HeadsDigest::of(heads)))
        .map(|(graph, heads)| SessionMessage::Heads {
            graph: *graph,
            heads: heads.to_vec(),
        })
        .collect()
}

pub fn want(ids: impl IntoIterator<Item = EventId>) -> Vec<SessionMessage> {
    let ids: Vec<EventId> = ids.into_iter().collect();
    ids.chunks(MAX_WANT)
        .map(|chunk| SessionMessage::Want(chunk.to_vec()))
        .collect()
}

/// Encoded events, in as many `Events` messages as they need.
pub fn batches(events: impl IntoIterator<Item = Vec<u8>>) -> Vec<SessionMessage> {
    let mut messages = Vec::new();
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut size = 0;
    for bytes in events {
        if size + bytes.len() > MAX_EVENTS_BYTES && !batch.is_empty() {
            messages.push(SessionMessage::Events(std::mem::take(&mut batch)));
            size = 0;
        }
        size += bytes.len();
        batch.push(bytes);
    }
    if !batch.is_empty() {
        messages.push(SessionMessage::Events(batch));
    }
    messages
}

fn events<'a>(
    store: &EventStore,
    ids: impl IntoIterator<Item = &'a EventId>,
) -> Vec<SessionMessage> {
    batches(
        ids.into_iter()
            .filter_map(|id| store.bytes(id))
            .map(<[u8]>::to_vec),
    )
}

/// The replies to a message, as far as they only need the store. `Events`
/// and `Live` are for the caller, which knows what to accept.
pub fn answer(store: &EventStore, message: &SessionMessage) -> Vec<SessionMessage> {
    match message {
        SessionMessage::Summary(theirs) => heads_for(store, theirs),
        SessionMessage::Heads { heads, .. } => {
            want(heads.iter().copied().filter(|head| !store.contains(head)))
        }
        SessionMessage::Want(ids) => events(store, ids.iter().take(MAX_WANT)),
        SessionMessage::History {
            graph,
            before,
            limit,
        } => {
            let found = store.ancestors(before, (*limit).min(MAX_HISTORY) as usize);
            events(
                store,
                found
                    .iter()
                    .filter(|id| store.get(id).is_some_and(|e| e.graph == *graph)),
            )
        }
        _ => Vec::new(),
    }
}
