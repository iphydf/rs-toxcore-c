//! One line per sync message sent or received, with what it is but none of
//! its content, to see what devices send each other. A full file becomes the
//! old one, so it never takes more than two files.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use toxcore::types::PublicKey;

use super::event::EventId;
use super::protocol::SessionMessage;
use crate::utils::encode_hex;

const MAX_SIZE: u64 = 1024 * 1024;

/// IDs shown of a longer list.
const SHOWN_IDS: usize = 4;

pub struct SyncTrace {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl SyncTrace {
    pub fn new(dir: &Path) -> Self {
        let path = dir.join("sync-trace.log");
        let size = fs::metadata(&path).map_or(0, |m| m.len());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        Self { path, file, size }
    }

    /// `direction` is "in" or "out".
    pub fn record(&mut self, direction: &str, device: &PublicKey, message: &[u8]) {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let line = format!(
            "{millis} {direction} {} {}\n",
            short(&device.0),
            describe(message)
        );
        if self.size + line.len() as u64 > MAX_SIZE {
            let _ = fs::rename(&self.path, self.path.with_extension("log.1"));
            self.file = File::create(&self.path).ok();
            self.size = 0;
        }
        if let Some(file) = &mut self.file
            && file.write_all(line.as_bytes()).is_ok()
        {
            self.size += line.len() as u64;
        }
    }
}

fn short(bytes: &[u8]) -> String {
    encode_hex(&bytes[..bytes.len().min(4)])
}

fn ids<'a>(list: impl ExactSizeIterator<Item = &'a [u8; 32]>) -> String {
    let n = list.len();
    let shown: Vec<String> = list.take(SHOWN_IDS).map(|i| short(i)).collect();
    let more = if n > SHOWN_IDS { " ..." } else { "" };
    format!("{n} [{}{more}]", shown.join(" "))
}

fn describe(message: &[u8]) -> String {
    match SessionMessage::decode(message) {
        Ok(Some(message)) => match message {
            SessionMessage::Hello { version, features } => {
                format!("Hello v{version} {features:?}")
            }
            SessionMessage::Summary(graphs) => {
                format!("Summary {}", ids(graphs.iter().map(|(g, _)| &g.0)))
            }
            SessionMessage::Heads { graph, heads } => {
                format!(
                    "Heads {} {}",
                    short(&graph.0),
                    ids(heads.iter().map(|i| &i.0))
                )
            }
            SessionMessage::Want(wanted) => format!("Want {}", ids(wanted.iter().map(|i| &i.0))),
            SessionMessage::Events(events) => {
                let bytes: usize = events.iter().map(Vec::len).sum();
                let got: Vec<EventId> = events.iter().map(|e| EventId::of(e)).collect();
                format!("Events {bytes} bytes {}", ids(got.iter().map(|i| &i.0)))
            }
            SessionMessage::History {
                graph,
                before,
                limit,
            } => format!(
                "History {} limit {limit} {}",
                short(&graph.0),
                ids(before.iter().map(|i| &i.0))
            ),
            SessionMessage::WantBlob(blob) => format!("WantBlob {}", short(&blob.0)),
            SessionMessage::NoBlob(blob) => format!("NoBlob {}", short(&blob.0)),
            SessionMessage::Facts { facts, all } => format!("Facts {} all {all}", facts.len()),
            SessionMessage::Call { action, .. } => format!("Call {action:?}"),
            SessionMessage::Unknown { discriminant, .. } => format!("Unknown {discriminant}"),
        },
        Ok(None) => "empty".to_owned(),
        Err(_) => "undecodable".to_owned(),
    }
}
