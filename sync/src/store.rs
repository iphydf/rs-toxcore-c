//! Every event this device knows, kept in memory and in `events.log` as
//! records of `[length: u32 big-endian][event bytes]`.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use toxcore::types::PublicKey;

use crate::event::{Content, DecodeError, Event, EventId, GraphId};

pub const EVENTS_FILE: &str = "events.log";
pub const MAX_EVENT: usize = 64 * 1024;
/// Ranks stay below this, so one more always fits, also where numbers are
/// doubles.
pub const MAX_RANK: u64 = 1 << 53;

const LENGTH: usize = size_of::<u32>();

struct Stored {
    event: Event,
    // Forwarded as received, so every device computes the same IDs.
    bytes: Vec<u8>,
}

#[derive(Default)]
pub struct EventStore {
    events: HashMap<EventId, Stored>,
    graphs: HashMap<GraphId, Vec<EventId>>,
    heads: HashMap<GraphId, Vec<EventId>>,
    // Per graph, the events its events have as parents.
    referenced: HashMap<GraphId, HashSet<EventId>>,
}

impl EventStore {
    pub fn insert(&mut self, bytes: &[u8]) -> Result<EventId, DecodeError> {
        if bytes.len() > MAX_EVENT {
            return Err(DecodeError::Deserialize("Event too long".into()));
        }
        let id = EventId::of(bytes);
        if !self.events.contains_key(&id) {
            let event = Event::decode(bytes)?;
            self.check_rank(&event)?;
            self.add(id, event, bytes.to_vec());
        }
        Ok(id)
    }

    /// An event's rank is one more than its highest parent's. Only the
    /// parents here can be checked: the others may come later, as history is
    /// paged in newest first.
    fn check_rank(&self, event: &Event) -> Result<(), DecodeError> {
        let known: Vec<u64> = event
            .parents
            .iter()
            .filter_map(|parent| self.get(parent))
            .map(|parent| parent.rank)
            .collect();
        let fits = event.rank < MAX_RANK
            && match known.iter().max() {
                Some(&highest) if known.len() == event.parents.len() => event.rank == highest + 1,
                Some(&highest) => event.rank > highest,
                None => true,
            };
        if fits {
            Ok(())
        } else {
            Err(DecodeError::Deserialize(format!(
                "Rank {} doesn't follow its parents'",
                event.rank
            )))
        }
    }

    pub fn create(
        &mut self,
        graph: GraphId,
        author: PublicKey,
        time: i64,
        content: Content,
    ) -> (EventId, Vec<u8>) {
        let mut parents = self.heads.get(&graph).cloned().unwrap_or_default();
        parents.sort();
        let rank = parents
            .iter()
            .filter_map(|parent| self.get(parent))
            .map(|parent| parent.rank + 1)
            .max()
            .unwrap_or(0);
        let event = Event {
            graph,
            author,
            parents,
            rank,
            time,
            content,
        };
        let bytes = event.encode();
        let id = EventId::of(&bytes);
        self.add(id, event, bytes.clone());
        (id, bytes)
    }

    fn add(&mut self, id: EventId, event: Event, bytes: Vec<u8>) {
        let heads = self.heads.entry(event.graph).or_default();
        heads.retain(|head| !event.parents.contains(head));
        let referenced = self.referenced.entry(event.graph).or_default();
        if !referenced.contains(&id) {
            heads.push(id);
        }
        referenced.extend(event.parents.iter().copied());
        self.graphs.entry(event.graph).or_default().push(id);
        self.events.insert(id, Stored { event, bytes });
    }

    pub fn get(&self, id: &EventId) -> Option<&Event> {
        self.events.get(id).map(|stored| &stored.event)
    }

    pub fn contains(&self, id: &EventId) -> bool {
        self.events.contains_key(id)
    }

    pub fn bytes(&self, id: &EventId) -> Option<&[u8]> {
        self.events.get(id).map(|stored| stored.bytes.as_slice())
    }

    fn event(&self, id: &EventId) -> &Event {
        &self.events[id].event
    }

    pub fn heads_of(&self, graph: &GraphId) -> &[EventId] {
        self.heads.get(graph).map_or(&[], Vec::as_slice)
    }

    pub fn heads(&self) -> impl Iterator<Item = (&GraphId, &[EventId])> {
        self.heads
            .iter()
            .map(|(graph, heads)| (graph, heads.as_slice()))
    }

    /// Parents of the graph's events that aren't here.
    pub fn missing(&self, graph: &GraphId) -> HashSet<EventId> {
        self.graphs
            .get(graph)
            .into_iter()
            .flatten()
            .flat_map(|id| &self.event(id).parents)
            .filter(|parent| !self.contains(parent))
            .copied()
            .collect()
    }

    /// The graph's events whose parents aren't all here: where its history
    /// stops here, or has a gap.
    pub fn frontier(&self, graph: &GraphId) -> Vec<(EventId, &Event)> {
        self.graphs
            .get(graph)
            .into_iter()
            .flatten()
            .map(|id| (*id, self.event(id)))
            .filter(|(_, event)| !event.parents.iter().all(|p| self.contains(p)))
            .collect()
    }

    /// Up to `limit` ancestors of `events`, newest (highest rank) first.
    pub fn ancestors(&self, events: &[EventId], limit: usize) -> Vec<EventId> {
        let mut queue: BinaryHeap<(u64, EventId)> = BinaryHeap::new();
        let mut seen = HashSet::new();
        let mut push = |queue: &mut BinaryHeap<_>, id: &EventId| {
            if let Some(event) = self.get(id)
                && seen.insert(*id)
            {
                queue.push((event.rank, *id));
            }
        };
        for id in events {
            for parent in self.get(id).into_iter().flat_map(|e| &e.parents) {
                push(&mut queue, parent);
            }
        }
        let mut found = Vec::new();
        while found.len() < limit
            && let Some((_, id)) = queue.pop()
        {
            for parent in &self.event(&id).parents {
                push(&mut queue, parent);
            }
            found.push(id);
        }
        found
    }

    /// In the order last-writer-wins rules apply them: by rank, then ID.
    pub fn by_rank(&self, graph: &GraphId) -> Vec<(EventId, &Event)> {
        let mut ids: Vec<_> = self.graphs.get(graph).into_iter().flatten().collect();
        ids.sort_by_key(|id| (self.event(id).rank, **id));
        ids.into_iter().map(|id| (*id, self.event(id))).collect()
    }

    /// In display order: by rank, then effective time, then ID. An event's
    /// effective time is never before its parents', so a fast clock can't move
    /// it back in history.
    pub fn graph(&self, graph: &GraphId) -> Vec<(EventId, &Event)> {
        let mut events: Vec<_> = self
            .graphs
            .get(graph)
            .into_iter()
            .flatten()
            .map(|id| (*id, self.event(id)))
            .collect();
        // Parents have lower ranks, so they get their effective time first.
        events.sort_by_key(|(id, event)| (event.rank, *id));
        let mut effective = HashMap::new();
        for (id, event) in &events {
            let time = event
                .parents
                .iter()
                .filter_map(|parent| effective.get(parent).copied())
                .fold(event.time, i64::max);
            effective.insert(*id, time);
        }
        events.sort_by_key(|(id, event)| (event.rank, effective[id], *id));
        events
    }
}

/// Reads the log's records. A crash can leave half a record at the end; it's
/// cut off, so later records don't follow it. Anything else that doesn't fit
/// is an error, not something to repair by dropping data.
pub fn read_log(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut data = Vec::new();
    match File::open(path) {
        Ok(mut file) => file.read_to_end(&mut data)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut records = Vec::new();
    let mut pos = 0;
    while let Some(length) = data.get(pos..pos + LENGTH) {
        let length = u32::from_be_bytes(length.try_into().unwrap()) as usize;
        if length > MAX_EVENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("record of {} bytes at offset {}", length, pos),
            ));
        }
        let Some(record) = data.get(pos + LENGTH..pos + LENGTH + length) else {
            break;
        };
        records.push(record.to_vec());
        pos += LENGTH + length;
    }
    if pos < data.len() {
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(pos as u64)?;
    }
    Ok(records)
}

/// Appends `records`, which are on disk once it returns.
pub fn append_log(path: &Path, records: &[Vec<u8>]) -> io::Result<()> {
    let mut data = Vec::new();
    for record in records {
        data.extend((record.len() as u32).to_be_bytes());
        data.extend(record);
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&data)?;
    file.sync_data()
}
