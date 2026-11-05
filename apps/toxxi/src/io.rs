use crate::config;
use crate::msg::{IOAction, IOEvent, Msg, ToxAction};
use crate::sync::event::BlobId;
use crate::sync::files::{blob_path, blobs_dir, file_id, part_path};
use crate::utils::Tell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use toxcore::types::{FileControl, FileId, PublicKey};

/// Keeps a copy of the file at `path` as a blob: not a link, as the user's
/// file can change later.
fn keep_blob(dir: &Path, path: &Path) -> io::Result<BlobId> {
    let blob = BlobId::of(fs::File::open(path)?)?;
    let target = blob_path(dir, &blob);
    if !target.exists() {
        fs::create_dir_all(dir)?;
        let part = part_path(dir, &blob);
        fs::copy(path, &part)?;
        fs::rename(part, target)?;
    }
    Ok(blob)
}

/// Keeps a received blob if it has the ID we asked for.
fn store_blob(dir: &Path, blob: &BlobId) -> io::Result<bool> {
    let part = part_path(dir, blob);
    if BlobId::of(fs::File::open(&part)?)? != *blob {
        fs::remove_file(part)?;
        return Ok(false);
    }
    fs::rename(part, blob_path(dir, blob))?;
    Ok(true)
}

/// The event log writer's jobs, done in order.
enum LogJob {
    /// Events to keep, and the messages to send devices once they're kept.
    Append(Vec<Vec<u8>>, Vec<(PublicKey, Vec<u8>)>),
    /// Moves the log to the given name, to start a new one.
    SetAside(PathBuf),
}

/// Appends events to the log in its own thread, as waiting for the disk would
/// hold up file transfers. Then sends devices the messages that carry them.
fn spawn_event_writer(
    path: PathBuf,
    tx_msg: mpsc::Sender<Msg>,
    tx_tox: mpsc::Sender<ToxAction>,
) -> (mpsc::Sender<LogJob>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<LogJob>();
    let writer = std::thread::spawn(move || {
        // Events we failed to write go with the next batch.
        let (mut records, mut pushes) = (Vec::new(), Vec::new());
        while let Ok(job) = rx.recv() {
            match job {
                LogJob::Append(more, more_pushes) => {
                    records.extend(more);
                    pushes.extend(more_pushes);
                }
                LogJob::SetAside(to) => {
                    // Unwritten events belong to the old log: drop them.
                    records.clear();
                    pushes.clear();
                    if let Err(e) = std::fs::rename(&path, &to)
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                            "Failed to set the event log aside: {e}"
                        ))));
                    }
                    continue;
                }
            }
            match crate::sync::store::append_log(&path, &records) {
                Ok(()) => {
                    records.clear();
                    for (device, message) in pushes.drain(..) {
                        tx_tox.tell(ToxAction::SyncSend(device, message));
                    }
                }
                Err(e) => {
                    tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                        "Failed to save events: {}",
                        e
                    ))));
                }
            }
        }
    });
    (tx, writer)
}

/// Where we keep a download from `pk` until it's complete: a transfer only
/// resumes into what came of the one with its file ID.
fn download_part(downloads: &Path, pk: &PublicKey, file_id: &FileId) -> PathBuf {
    downloads.join(".partial").join(format!(
        "{}-{}",
        crate::utils::encode_hex(&pk.0),
        crate::utils::encode_hex(&file_id.0)
    ))
}

/// Opens the part at `path` and returns how many of `size` bytes it has.
fn open_part(path: &Path, size: u64) -> io::Result<(fs::File, u64)> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let mut have = file.metadata()?.len();
    // A part as big as the file would have been finished: it's another file's.
    if have >= size {
        file.set_len(0)?;
        have = 0;
    }
    Ok((file, have))
}

/// Returns `dir`'s file named `name`, or "name (2).ext" and so on while that
/// one is `taken`.
fn unused_path(dir: &Path, name: &str, taken: impl Fn(&Path) -> bool) -> PathBuf {
    let path = dir.join(name);
    if !taken(&path) {
        return path;
    }
    let name = Path::new(name);
    let stem = name
        .file_stem()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    let ext = name
        .extension()
        .map_or_else(String::new, |e| format!(".{}", e.to_string_lossy()));
    let mut n = 2;
    loop {
        let path = dir.join(format!("{stem} ({n}){ext}"));
        if !taken(&path) {
            return path;
        }
        n += 1;
    }
}

pub fn spawn_io_worker(
    tx_msg: mpsc::Sender<Msg>,
    tx_tox: mpsc::Sender<ToxAction>,
    rx_io: mpsc::Receiver<IOAction>,
    config_dir: PathBuf,
    downloads_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut active_files: HashMap<FileId, (File, PathBuf)> = HashMap::new();
        // The sizes and names of the downloads coming.
        let mut receiving: HashMap<FileId, (u64, String)> = HashMap::new();
        let rt = tokio::runtime::Handle::current();
        let blobs = blobs_dir(&config_dir);
        let (events, writer) = spawn_event_writer(
            config_dir.join(crate::sync::store::EVENTS_FILE),
            tx_msg.clone(),
            tx_tox.clone(),
        );
        // Written files are flushed before they're read again.
        let close = |rt: &tokio::runtime::Handle, file: Option<(File, PathBuf)>| {
            file.map(|(mut file, path)| {
                if let Err(e) = rt.block_on(file.flush()) {
                    tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                        "Failed to write {}: {e}",
                        path.display()
                    ))));
                }
                path
            })
        };

        while let Ok(action) = rx_io.recv() {
            match action {
                IOAction::SaveConfig(config) => {
                    if let Err(e) = config::save_config(&config_dir, &config) {
                        tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                            "Failed to save config: {}",
                            e
                        ))));
                    }
                }
                IOAction::OpenFileForSending(pk, file_id, path) => {
                    if let Ok(file) = rt.block_on(tokio::fs::File::open(&path)) {
                        active_files.insert(file_id, (file, path));
                    } else {
                        tx_msg.tell(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("Could not open file: {}", path.display()),
                        )));
                    }
                }
                IOAction::OpenFileForReceiving(pk, file_id, filename, size) => {
                    let name = Path::new(&filename)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file")
                        .to_owned();
                    let path = download_part(&downloads_dir, &pk, &file_id);
                    match open_part(&path, size) {
                        Ok((file, have)) => {
                            active_files.insert(file_id, (File::from_std(file), path));
                            receiving.insert(file_id, (size, name));
                            // Tox takes a seek only before the transfer starts.
                            if have > 0 {
                                tx_tox.tell(ToxAction::FileSeek(pk, file_id, have));
                            }
                            tx_tox.tell(ToxAction::FileControl(pk, file_id, FileControl::Resume));
                        }
                        Err(e) => {
                            tx_msg.tell(Msg::IO(IOEvent::FileError(
                                pk,
                                file_id,
                                format!("Could not open {:?}: {}", path, e),
                            )));
                        }
                    }
                }
                IOAction::ReadChunk(pk, file_id, position, length) => {
                    if let Some((file, _)) = active_files.get_mut(&file_id) {
                        let mut data = vec![0u8; length];
                        let res = rt.block_on(async {
                            file.seek(SeekFrom::Start(position)).await?;
                            file.read(&mut data).await
                        });

                        match res {
                            Ok(n) => {
                                data.truncate(n);
                                tx_tox.tell(ToxAction::FileSendChunk(pk, file_id, position, data));
                                tx_msg.tell(Msg::IO(IOEvent::FileChunkRead(
                                    pk, file_id, position, n,
                                )));
                            }
                            Err(e) => {
                                tx_msg.tell(Msg::IO(IOEvent::FileError(
                                    pk,
                                    file_id,
                                    format!("Read/Seek error: {}", e),
                                )));
                            }
                        }
                    } else {
                        tx_msg.tell(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("ReadChunk failed - FileId {} not found", file_id),
                        )));
                    }
                }
                IOAction::WriteChunk(pk, file_id, position, data) => {
                    if let Some((file, _)) = active_files.get_mut(&file_id) {
                        let len = data.len();
                        let res = rt.block_on(async {
                            file.seek(SeekFrom::Start(position)).await?;
                            file.write_all(&data).await
                        });

                        match res {
                            Ok(_) => {
                                tx_msg.tell(Msg::IO(IOEvent::FileChunkWritten(
                                    pk, file_id, position, len,
                                )));
                            }
                            Err(e) => {
                                tx_msg.tell(Msg::IO(IOEvent::FileError(
                                    pk,
                                    file_id,
                                    format!("Write/Seek error: {}", e),
                                )));
                            }
                        }
                    }
                }
                IOAction::CloseFile(_pk, file_id) => {
                    receiving.remove(&file_id);
                    close(&rt, active_files.remove(&file_id));
                }
                IOAction::CancelFile(_pk, file_id) => {
                    let path = close(&rt, active_files.remove(&file_id));
                    // Don't delete a file we were sending: it's the user's.
                    if receiving.remove(&file_id).is_some()
                        && let Some(part) = path
                        && let Err(e) = fs::remove_file(&part)
                    {
                        tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                            "Failed to delete {}: {e}",
                            part.display()
                        ))));
                    }
                }
                IOAction::FinishFile(pk, file_id) => {
                    let mut file = active_files.remove(&file_id);
                    let received = receiving.remove(&file_id);
                    if let (Some((file, path)), Some((size, _))) = (&mut file, &received)
                        && let Err(e) = rt.block_on(file.set_len(*size))
                    {
                        tx_msg.tell(Msg::IO(IOEvent::Error(format!(
                            "Failed to finish {}: {e}",
                            path.display()
                        ))));
                    }
                    let mut path = close(&rt, file);
                    // Move a finished download into the downloads, under a name
                    // no file there has.
                    if let (Some(part), Some((_, name))) = (&path, received) {
                        let target = unused_path(&downloads_dir, &name, Path::exists);
                        path = fs::rename(part, &target).map(|()| target).ok();
                    }
                    let (blobs, tx_msg) = (blobs.clone(), tx_msg.clone());
                    // Copying a large file would hold up other transfers.
                    std::thread::spawn(move || {
                        let blob = path.and_then(|path| keep_blob(&blobs, &path).ok());
                        tx_msg.tell(Msg::IO(IOEvent::FileFinished(pk, file_id, blob)));
                    });
                }
                IOAction::SendBlob(pk, blob, kind) => {
                    let path = blob_path(&blobs, &blob);
                    match fs::metadata(&path) {
                        Ok(meta) => {
                            tx_tox.tell(ToxAction::FileSend {
                                friend: pk,
                                kind,
                                size: meta.len(),
                                name: String::new(),
                                path,
                                resume: Some(file_id(&blob)),
                            });
                        }
                        Err(_) => {
                            tx_msg.tell(Msg::IO(IOEvent::BlobMissing(pk, blob)));
                        }
                    }
                }
                IOAction::ReceiveBlob(pk, blob, size) => {
                    let path = part_path(&blobs, &blob);
                    let opened = fs::create_dir_all(&blobs).and_then(|_| {
                        let file = fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create(true)
                            .truncate(false)
                            .open(&path)?;
                        // A part as big as the blob would have been kept.
                        let mut have = file.metadata()?.len();
                        if have >= size {
                            file.set_len(0)?;
                            have = 0;
                        }
                        Ok((file, have))
                    });
                    match opened {
                        Ok((file, have)) => {
                            let id = file_id(&blob);
                            active_files.insert(id, (File::from_std(file), path));
                            if have > 0 {
                                tx_tox.tell(ToxAction::FileSeek(pk, id, have));
                            }
                            tx_tox.tell(ToxAction::FileControl(pk, id, FileControl::Resume));
                        }
                        Err(e) => {
                            tx_msg.tell(Msg::IO(IOEvent::FileError(
                                pk,
                                file_id(&blob),
                                format!("Could not open {:?}: {}", path, e),
                            )));
                        }
                    }
                }
                IOAction::StoreBlob(pk, blob) => {
                    close(&rt, active_files.remove(&file_id(&blob)));
                    let ok = store_blob(&blobs, &blob).unwrap_or(false);
                    tx_msg.tell(Msg::IO(IOEvent::BlobStored(pk, blob, ok)));
                }
                IOAction::AppendEvents(records, pushes) => {
                    events.tell(LogJob::Append(records, pushes));
                }
                IOAction::SetAsideEvents(name) => {
                    events.tell(LogJob::SetAside(config_dir.join(name)));
                }
            }
        }
        // Write the events still waiting before toxxi ends.
        drop(events);
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a panic in the writer has printed its message"
        )]
        let _ = writer.join();
    })
}
