//! Files over account sync: the blobs toxxi and its devices fetch from each
//! other, and the files devices ask toxxi to send. See doc/account-sync.md.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use toxcore::tox::ToxConnection;
use toxcore::types::{FileId, MAX_FILENAME_LENGTH, PublicKey, ToxFileControl};

use super::event::BlobId;
use super::protocol::SessionMessage;
use crate::model::{
    FileTransferProgress, InternalMessageId, MessageContent, MessageStatus, Model, TransferStatus,
    WindowId,
};
use crate::msg::{Cmd, IOAction, ToxAction};
use crate::utils::{decode_hex, encode_hex};

pub fn blobs_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("blobs")
}

pub fn blob_path(dir: &Path, blob: &BlobId) -> PathBuf {
    dir.join(encode_hex(&blob.0))
}

/// Where a blob being received is kept until it has all come.
pub fn part_path(dir: &Path, blob: &BlobId) -> PathBuf {
    dir.join(format!("{}.part", encode_hex(&blob.0)))
}

/// A blob goes as a file whose ID is the blob's.
pub fn file_id(blob: &BlobId) -> FileId {
    FileId(blob.0)
}

/// The blobs toxxi holds, each a file named by its ID in hex.
#[derive(Debug, Default)]
pub struct Blobs {
    dir: PathBuf,
    held: HashSet<BlobId>,
}

impl Blobs {
    pub fn load(config_dir: &Path) -> Self {
        let dir = blobs_dir(config_dir);
        let held = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let id = decode_hex(entry.file_name().to_str()?)?;
                Some(BlobId(id.try_into().ok()?))
            })
            .collect();
        Self { dir, held }
    }

    pub fn path(&self, blob: &BlobId) -> PathBuf {
        blob_path(&self.dir, blob)
    }

    pub fn holds(&self, blob: &BlobId) -> bool {
        self.held.contains(blob)
    }

    pub fn insert(&mut self, blob: BlobId) {
        self.held.insert(blob);
    }

    fn forget(&mut self, blob: &BlobId) {
        self.held.remove(blob);
    }
}

/// A blob on its way between toxxi and a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobTransfer {
    pub device: PublicKey,
    pub incoming: bool,
    /// Known once the file has started.
    pub size: Option<u64>,
}

fn to_device(device: PublicKey, message: SessionMessage) -> Cmd {
    Cmd::Tox(ToxAction::SyncSend(device, message.encode()))
}

/// The most blobs sent to a device at once: a device asks for all it lacks,
/// and Tox takes no more than 256 transfers with a friend.
const MAX_BLOB_SENDS: usize = 8;

/// A device asks for `blob`. Only one transfer of a blob runs at a time, as
/// its file ID is the blob's, so others wait for it, as do those past the
/// most sent to the device at once.
pub fn wanted(model: &mut Model, device: PublicKey, blob: BlobId) -> Vec<Cmd> {
    if !model.blobs.holds(&blob) {
        return vec![to_device(device, SessionMessage::NoBlob(blob))];
    }
    let sending = model
        .session
        .blob_transfers
        .values()
        .filter(|t| t.device == device && !t.incoming)
        .count();
    if model.session.blob_transfers.contains_key(&blob) || sending >= MAX_BLOB_SENDS {
        model.session.blob_queue.push((device, blob));
        return Vec::new();
    }
    model.session.blob_transfers.insert(
        blob,
        BlobTransfer {
            device,
            incoming: false,
            size: None,
        },
    );
    vec![Cmd::IO(IOAction::SendBlob(device, blob))]
}

/// The file that `wanted` asked Tox for has started.
pub fn started(
    model: &mut Model,
    pk: PublicKey,
    file_id: FileId,
    path: String,
    size: u64,
) -> Option<Vec<Cmd>> {
    let transfer = model
        .session
        .blob_transfers
        .get_mut(&BlobId(file_id.0))
        .filter(|t| t.device == pk && !t.incoming)?;
    transfer.size = Some(size);
    Some(vec![Cmd::IO(IOAction::OpenFileForSending(
        pk, file_id, path,
    ))])
}

/// The blob `wanted` was to send is gone from disk.
pub fn missing(model: &mut Model, device: PublicKey, blob: BlobId) -> Vec<Cmd> {
    model.blobs.forget(&blob);
    let mut cmds = ended(model, blob);
    cmds.push(to_device(device, SessionMessage::NoBlob(blob)));
    cmds
}

/// Asks `device` for `blob`, unless it's on its way.
fn want(model: &mut Model, device: PublicKey, blob: BlobId) -> Vec<Cmd> {
    if model.session.blob_transfers.contains_key(&blob) {
        return Vec::new();
    }
    model.session.blob_transfers.insert(
        blob,
        BlobTransfer {
            device,
            incoming: true,
            size: None,
        },
    );
    vec![to_device(device, SessionMessage::WantBlob(blob))]
}

/// `pk` sends a blob, which is taken only if it was asked of them.
pub fn offered(model: &mut Model, pk: PublicKey, file_id: FileId, size: u64) -> Vec<Cmd> {
    let blob = BlobId(file_id.0);
    match model.session.blob_transfers.get_mut(&blob) {
        Some(t) if t.device == pk && t.incoming && t.size.is_none() => {
            t.size = Some(size);
            vec![Cmd::IO(IOAction::ReceiveBlob(pk, blob, size))]
        }
        _ => vec![Cmd::Tox(ToxAction::FileControl(
            pk,
            file_id,
            ToxFileControl::TOX_FILE_CONTROL_CANCEL,
        ))],
    }
}

/// The blob transfer `file_id` has reached `end`; `None` if it's no blob's.
pub fn progressed(model: &mut Model, pk: PublicKey, file_id: FileId, end: u64) -> Option<Vec<Cmd>> {
    let blob = BlobId(file_id.0);
    let transfer = *model.session.blob_transfers.get(&blob)?;
    if transfer.device != pk {
        return None;
    }
    if transfer.size.is_none_or(|size| end < size) {
        return Some(Vec::new());
    }
    Some(if transfer.incoming {
        model.session.blob_transfers.remove(&blob);
        vec![Cmd::IO(IOAction::StoreBlob(pk, blob))]
    } else {
        ended(model, blob)
    })
}

/// Ends the blob transfer `file_id` that `pk` cancelled or that failed here;
/// `None` if it's no blob's. A device that can't send a blob doesn't have it.
pub fn stopped(model: &mut Model, pk: PublicKey, file_id: FileId) -> Option<Vec<Cmd>> {
    let blob = BlobId(file_id.0);
    let transfer = *model.session.blob_transfers.get(&blob)?;
    if transfer.device != pk {
        return None;
    }
    let mut cmds = ended(model, blob);
    if transfer.incoming {
        cmds.extend(unavailable(model, pk, blob));
    }
    Some(cmds)
}

/// Closes a blob's transfer and starts the next one waiting for it.
fn ended(model: &mut Model, blob: BlobId) -> Vec<Cmd> {
    let Some(transfer) = model.session.blob_transfers.remove(&blob) else {
        return Vec::new();
    };
    let mut cmds = vec![Cmd::IO(IOAction::CloseFile(
        transfer.device,
        file_id(&blob),
    ))];
    // The next waiting for this blob, or for its device's room.
    if let Some(i) = model
        .session
        .blob_queue
        .iter()
        .position(|(device, b)| *b == blob || *device == transfer.device)
    {
        let (device, blob) = model.session.blob_queue.remove(i);
        cmds.extend(wanted(model, device, blob));
    }
    cmds
}

/// `device` doesn't have `blob`: the files it asked to send with it fail.
pub fn unavailable(model: &mut Model, device: PublicKey, blob: BlobId) -> Vec<Cmd> {
    if model
        .session
        .blob_transfers
        .get(&blob)
        .is_some_and(|t| t.device == device && t.incoming)
    {
        model.session.blob_transfers.remove(&blob);
    }
    let mut cmds = Vec::new();
    for file in pending(model) {
        if file.blob == blob && file.author == device {
            let window_id = WindowId::Friend(file.friend);
            if let Some(msg) =
                model.mark_message_status(window_id, file.internal_id, MessageStatus::Failed)
            {
                cmds.extend(model.record(window_id, &msg));
            }
        }
    }
    cmds
}

/// A blob from `device` has all come, and was kept if it's the one asked for.
pub fn stored(model: &mut Model, device: PublicKey, blob: BlobId, ok: bool) -> Vec<Cmd> {
    if !ok {
        return unavailable(model, device, blob);
    }
    model.blobs.insert(blob);
    send_pending(model)
}

/// A device's file waiting to be sent.
struct Pending {
    friend: PublicKey,
    internal_id: InternalMessageId,
    blob: BlobId,
    name: String,
    size: u64,
    author: PublicKey,
}

fn pending(model: &Model) -> Vec<Pending> {
    let mut files = Vec::new();
    for (&window_id, conv) in &model.domain.conversations {
        let WindowId::Friend(friend) = window_id else {
            continue;
        };
        for msg in &conv.messages {
            if let MessageContent::FileTransfer {
                file_id,
                name,
                size,
                is_incoming: false,
                blob: Some(blob),
                ..
            } = &msg.content
                && msg.is_self
                && msg.status == MessageStatus::Pending
                && !file_id.is_some_and(|id| model.domain.file_transfers.contains_key(&id))
                && let Some(event) = model
                    .message_events
                    .get(&(window_id, msg.internal_id))
                    .and_then(|recorded| model.events.get(&recorded.id))
            {
                files.push(Pending {
                    friend,
                    internal_id: msg.internal_id,
                    blob: *blob,
                    name: name.clone(),
                    size: *size,
                    author: event.author,
                });
            }
        }
    }
    files
}

/// Sends the files devices asked to send whose friends are online, and asks
/// devices for the blobs of their files that toxxi doesn't hold yet.
pub fn send_pending(model: &mut Model) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    for file in pending(model) {
        if file.name.len() > MAX_FILENAME_LENGTH {
            // Tox doesn't take it.
            let window_id = WindowId::Friend(file.friend);
            if let Some(msg) =
                model.mark_message_status(window_id, file.internal_id, MessageStatus::Failed)
            {
                cmds.extend(model.record(window_id, &msg));
            }
        } else if !model.blobs.holds(&file.blob) {
            if model.session.sync_sessions.contains(&file.author) {
                cmds.extend(want(model, file.author, file.blob));
            }
        } else if model
            .domain
            .friends
            .get(&file.friend)
            .is_some_and(|info| info.connection != ToxConnection::TOX_CONNECTION_NONE)
        {
            cmds.push(start(model, file));
        }
    }
    cmds
}

fn start(model: &mut Model, file: Pending) -> Cmd {
    let file_id = FileId(rand::random());
    if let Some(msg) = model
        .domain
        .conversations
        .get_mut(&WindowId::Friend(file.friend))
        .and_then(|conv| {
            conv.messages
                .iter_mut()
                .find(|msg| msg.internal_id == file.internal_id)
        })
        && let MessageContent::FileTransfer { file_id: id, .. } = &mut msg.content
    {
        *id = Some(file_id);
    }
    let path = model.blobs.path(&file.blob).to_string_lossy().into_owned();
    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: file.name.clone(),
            total_size: file.size,
            transferred: 0,
            is_receiving: false,
            status: TransferStatus::Active,
            speed: 0.0,
            last_update: model.time_provider.now(),
            last_transferred: 0,
            friend_pk: file.friend,
        },
    );
    Cmd::Tox(ToxAction::FileSend(
        file.friend,
        0,
        file.size,
        file.name,
        path,
        Some(file_id),
    ))
}

/// Toxcore drops a friend's transfers when they go offline. A device's file
/// starts over when they're back; a device's blobs are asked for again in its
/// next session. The rest failed.
pub fn offline(model: &mut Model, pk: PublicKey) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    if let Some(conv) = model.domain.conversations.get(&WindowId::Friend(pk)) {
        for msg in &conv.messages {
            if let MessageContent::FileTransfer {
                file_id: Some(file_id),
                blob: Some(_),
                is_incoming: false,
                ..
            } = &msg.content
                && msg.status == MessageStatus::Pending
                && model.domain.file_transfers.remove(file_id).is_some()
            {
                cmds.push(Cmd::IO(IOAction::CloseFile(pk, *file_id)));
            }
        }
    }
    let failed: Vec<FileId> = model
        .domain
        .file_transfers
        .iter()
        .filter(|(_, transfer)| transfer.friend_pk == pk)
        .map(|(file_id, _)| *file_id)
        .collect();
    for file_id in failed {
        model.domain.file_transfers.remove(&file_id);
        cmds.push(Cmd::IO(IOAction::CloseFile(pk, file_id)));
        if let Some(msg) = model.update_file_status(pk, file_id, MessageStatus::Failed) {
            cmds.extend(model.record(WindowId::Friend(pk), &msg));
        }
    }
    model.session.blob_queue.retain(|(device, _)| *device != pk);
    let blobs: Vec<BlobId> = model
        .session
        .blob_transfers
        .iter()
        .filter(|(_, t)| t.device == pk)
        .map(|(blob, _)| *blob)
        .collect();
    for blob in blobs {
        cmds.extend(ended(model, blob));
    }
    cmds
}
