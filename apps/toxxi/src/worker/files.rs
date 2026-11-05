use crate::utils::Tell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use toxcore::tox::events::{
    EventFileChunkRequest, EventFileRecv, EventFileRecvChunk, EventFileRecvControl,
};
use toxcore::tox::{FileNumber, FriendNumber};
use toxcore::types::{FileControl, FileId, FileKind, FileSendChunkError, PublicKey, ToxError};

use super::{Session, find_friend, log_error};
use crate::msg::{IOAction, IOEvent, LogContext, Msg, ToxEvent};

/// Tox's numbers for a transfer toxxi knows by its ID.
#[derive(Clone, Copy)]
struct Transfer {
    friend: FriendNumber,
    file: FileNumber,
    size: u64,
}

/// A chunk Tox's queue had no room for yet.
struct Chunk {
    file: FileId,
    position: u64,
    data: Vec<u8>,
}

/// The transfers Tox has, by ID and by Tox's numbers, and the chunks waiting to
/// be sent.
// TODO(iphydf): Limit the number of transfers.
#[derive(Default)]
pub(super) struct Transfers {
    #[cfg_attr(tokstyle, tokstyle::bounded("one per transfer toxcore has"))]
    by_id: HashMap<FileId, Transfer>,
    by_number: HashMap<(FriendNumber, FileNumber), FileId>,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("one per chunk toxcore asked for, which it limits")
    )]
    waiting: VecDeque<Chunk>,
}

impl Transfers {
    fn add(&mut self, id: FileId, friend: FriendNumber, file: FileNumber, size: u64) {
        // Tox reuses a number once its transfer ended.
        if let Some(old) = self.by_number.get(&(friend, file)).copied() {
            self.remove(&old);
        }
        self.remove(&id);
        self.by_id.insert(id, Transfer { friend, file, size });
        self.by_number.insert((friend, file), id);
    }

    fn get(&self, id: &FileId) -> Option<Transfer> {
        self.by_id.get(id).copied()
    }

    fn id_of(&self, friend: FriendNumber, file: FileNumber) -> Option<FileId> {
        self.by_number.get(&(friend, file)).copied()
    }

    fn remove(&mut self, id: &FileId) {
        if let Some(transfer) = self.by_id.remove(id) {
            self.by_number.remove(&(transfer.friend, transfer.file));
        }
        self.waiting.retain(|chunk| chunk.file != *id);
    }

    /// Ends a transfer once a chunk reaches its end.
    fn end_at(&mut self, id: &FileId, end: u64) {
        if self.get(id).is_some_and(|transfer| end >= transfer.size) {
            self.remove(id);
        }
    }
}

impl Session<'_> {
    /// Chunks that waited go first, in order.
    pub(super) fn send_waiting_chunks(&mut self) {
        while let Some(chunk) = self.transfers.waiting.pop_front() {
            if let Err(chunk) = self.send_chunk(chunk) {
                self.transfers.waiting.push_front(chunk);
                break;
            }
        }
    }

    /// Sends a chunk, unless Tox has no room for it: then it's returned.
    fn send_chunk(&mut self, chunk: Chunk) -> Result<(), Chunk> {
        // Drop chunks of a transfer that ended.
        let Some(transfer) = self.transfers.get(&chunk.file) else {
            return Ok(());
        };
        let friend = self.tox.friend(transfer.friend);
        let len = chunk.data.len();
        match self
            .tox
            .file(&friend, transfer.file)
            .send_chunk(chunk.position, &chunk.data)
        {
            Ok(()) => {
                self.friend_event(transfer.friend, |pk| {
                    ToxEvent::FileChunkSent(pk, chunk.file, chunk.position, len)
                });
            }
            Err(ToxError::FileSendChunk(FileSendChunkError::Sendq)) => return Err(chunk),
            Err(e) => log_error(
                self.tx,
                friend
                    .public_key()
                    .map_or(LogContext::Global, LogContext::Friend),
                format!("Error sending file chunk: {e:?}"),
            ),
        }
        self.transfers
            .end_at(&chunk.file, chunk.position + len as u64);
        Ok(())
    }

    pub(super) fn file_send(
        &mut self,
        pk: PublicKey,
        kind: FileKind,
        file_size: u64,
        name: String,
        path: PathBuf,
        resume: Option<FileId>,
    ) {
        let Some(friend_number) = find_friend(self.tox, &pk) else {
            return;
        };
        let friend = self.tox.friend(friend_number);
        match self
            .tox
            .file_send(&friend, kind, file_size, resume.as_ref(), name.as_bytes())
        {
            Ok(file) => {
                if let Ok(file_id) = file.file_id() {
                    self.transfers
                        .add(file_id, friend_number, file.number(), file_size);
                    self.tx
                        .tell(Msg::IO(IOEvent::FileStarted(pk, file_id, path, file_size)));
                } else {
                    log_error(
                        self.tx,
                        LogContext::Friend(pk),
                        "Failed to get FileId for sent file",
                    );
                }
            }
            Err(e) => {
                log_error(
                    self.tx,
                    LogContext::Friend(pk),
                    format!("Error sending file: {e:?}"),
                );
            }
        }
    }

    pub(super) fn file_control(&mut self, file_id: FileId, control: FileControl) {
        let Some(transfer) = self.transfers.get(&file_id) else {
            return;
        };
        if let Err(e) = self
            .tox
            .file(&self.tox.friend(transfer.friend), transfer.file)
            .control(control)
        {
            log_error(
                self.tx,
                LogContext::Global,
                format!("Error controlling file (ID: {file_id}): {e:?}"),
            );
        }
        if control == FileControl::Cancel {
            self.transfers.remove(&file_id);
        }
    }

    pub(super) fn file_send_chunk(&mut self, file: FileId, position: u64, data: Vec<u8>) {
        let chunk = Chunk {
            file,
            position,
            data,
        };
        // Queue behind any waiting chunks, so they all go in order.
        if !self.transfers.waiting.is_empty() {
            self.transfers.waiting.push_back(chunk);
        } else if let Err(chunk) = self.send_chunk(chunk) {
            self.transfers.waiting.push_back(chunk);
        }
    }

    pub(super) fn file_seek(&mut self, file_id: FileId, position: u64) {
        if let Some(transfer) = self.transfers.get(&file_id) {
            let seek = self
                .tox
                .file(&self.tox.friend(transfer.friend), transfer.file)
                .seek(position);
            self.check(LogContext::Global, "seeking in the file", seek);
        }
    }

    fn file_id_of(&self, friend: FriendNumber, file: FileNumber) -> Option<FileId> {
        self.tox
            .file(&self.tox.friend(friend), file)
            .file_id()
            .ok()
            .or_else(|| self.transfers.id_of(friend, file))
    }

    pub(super) fn file_recv(&mut self, e: &EventFileRecv) {
        let filename = String::from_utf8_lossy(e.filename()).into_owned();
        let file = self
            .tox
            .file(&self.tox.friend(e.friend_number()), e.file_number());
        if let Ok(file_id) = file.file_id() {
            self.transfers
                .add(file_id, e.friend_number(), e.file_number(), e.file_size());
            self.friend_event(e.friend_number(), |pk| {
                ToxEvent::FileRecv(pk, file_id, e.kind(), e.file_size(), filename)
            });
        }
    }

    pub(super) fn file_chunk_request(&mut self, e: &EventFileChunkRequest) {
        if let Some(file_id) = self.file_id_of(e.friend_number(), e.file_number()) {
            self.friend_event(e.friend_number(), |pk| {
                ToxEvent::FileChunkRequest(pk, file_id, e.position(), e.length())
            });
        }
    }

    pub(super) fn file_recv_chunk(&mut self, e: &EventFileRecvChunk) {
        let Ok(pk) = self.tox.friend(e.friend_number()).public_key() else {
            return;
        };
        if let Some(file_id) = self.file_id_of(e.friend_number(), e.file_number()) {
            self.tx_io.tell(IOAction::WriteChunk(
                pk,
                file_id,
                e.position(),
                e.data().to_vec(),
            ));
            self.transfers
                .end_at(&file_id, e.position() + e.data().len() as u64);
        // Tox ends each transfer with an empty chunk, after the last byte
        // ended it here.
        } else if !e.data().is_empty() {
            log_error(
                self.tx,
                LogContext::Global,
                format!(
                    "Failed to get FileId for RecvChunk friend={} file={}",
                    e.friend_number().0,
                    e.file_number().0
                ),
            );
        }
    }

    pub(super) fn file_recv_control(&mut self, e: &EventFileRecvControl) {
        if let Some(file_id) = self.file_id_of(e.friend_number(), e.file_number()) {
            self.friend_event(e.friend_number(), |pk| {
                ToxEvent::FileRecvControl(pk, file_id, e.control())
            });
            if e.control() == FileControl::Cancel {
                self.transfers.remove(&file_id);
            }
        }
    }
}
