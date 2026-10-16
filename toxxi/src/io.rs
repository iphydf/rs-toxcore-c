use crate::config;
use crate::msg::{IOAction, IOEvent, Msg, ToxAction};
use crate::sync::event::BlobId;
use crate::sync::files::{blob_path, blobs_dir, file_id, part_path};
use crate::sync::protocol::BLOB_FILE_KIND;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use toxcore::types::{FileId, PublicKey, ToxFileControl};

/// Keeps a copy of the file at `path` as a blob: not a link, as the user's
/// file can change after.
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

/// Keeps a received blob if it has the ID it was asked for.
fn store_blob(dir: &Path, blob: &BlobId) -> io::Result<bool> {
    let part = part_path(dir, blob);
    if BlobId::of(fs::File::open(&part)?)? != *blob {
        fs::remove_file(part)?;
        return Ok(false);
    }
    fs::rename(part, blob_path(dir, blob))?;
    Ok(true)
}

/// Events to keep, and the messages to send devices once they're kept.
type EventBatch = (Vec<Vec<u8>>, Vec<(PublicKey, Vec<u8>)>);

/// Appends events to the log in their own thread, as waiting for them to
/// be on disk would hold up file transfers, and then sends devices what
/// carries them.
fn spawn_event_writer(
    path: PathBuf,
    tx_msg: mpsc::Sender<Msg>,
    tx_tox: mpsc::Sender<ToxAction>,
) -> (mpsc::Sender<EventBatch>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<EventBatch>();
    let writer = std::thread::spawn(move || {
        while let Ok((records, pushes)) = rx.recv() {
            match crate::sync::store::append_log(&path, &records) {
                Ok(()) => {
                    for (device, message) in pushes {
                        let _ = tx_tox.send(ToxAction::SyncSend(device, message));
                    }
                }
                Err(e) => {
                    let _ = tx_msg.send(Msg::IO(IOEvent::Error(format!(
                        "Failed to save events: {}",
                        e
                    ))));
                }
            }
        }
    });
    (tx, writer)
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
        // The sizes of the files coming, which may be written over longer ones.
        let mut receiving: HashMap<FileId, u64> = HashMap::new();
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
                let _ = rt.block_on(file.flush());
                path
            })
        };

        while let Ok(action) = rx_io.recv() {
            match action {
                IOAction::SaveConfig(Some(config)) => {
                    if let Err(e) = config::save_config(&config_dir, &config) {
                        let _ = tx_msg.send(Msg::IO(IOEvent::Error(format!(
                            "Failed to save config: {}",
                            e
                        ))));
                    }
                }
                IOAction::SaveState(Some(data)) => {
                    let path = config_dir.join("state.json");
                    let _ = std::fs::write(path, data);
                }
                IOAction::SaveConfig(None) | IOAction::SaveState(None) => {
                    // These should have been filled by AppContext
                }
                IOAction::OpenFileForSending(pk, file_id, path) => {
                    if let Ok(file) = rt.block_on(tokio::fs::File::open(&path)) {
                        active_files.insert(file_id, (file, PathBuf::from(path)));
                    } else {
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("Could not open file: {}", path),
                        )));
                    }
                }
                IOAction::OpenFileForReceiving(pk, file_id, filename, size) => {
                    let _ = std::fs::create_dir_all(&downloads_dir);
                    let path = Path::new(&filename);
                    let safe_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file");
                    let full_path = downloads_dir.join(safe_name);

                    let open_res = rt.block_on(async {
                        tokio::fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(false)
                            .open(&full_path)
                            .await
                    });

                    if let Ok(file) = open_res {
                        active_files.insert(file_id, (file, full_path));
                        receiving.insert(file_id, size);
                    } else {
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("Could not create/open file: {:?}", full_path),
                        )));
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
                                let _ = tx_tox
                                    .send(ToxAction::FileSendChunk(pk, file_id, position, data));
                                let _ = tx_msg.send(Msg::IO(IOEvent::FileChunkRead(
                                    pk, file_id, position, n,
                                )));
                            }
                            Err(e) => {
                                let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
                                    pk,
                                    file_id,
                                    format!("Read/Seek error: {}", e),
                                )));
                            }
                        }
                    } else {
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
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
                                let _ = tx_msg.send(Msg::IO(IOEvent::FileChunkWritten(
                                    pk, file_id, position, len,
                                )));
                            }
                            Err(e) => {
                                let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
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
                IOAction::FinishFile(pk, file_id) => {
                    let mut file = active_files.remove(&file_id);
                    if let (Some((file, _)), Some(size)) = (&mut file, receiving.remove(&file_id)) {
                        let _ = rt.block_on(file.set_len(size));
                    }
                    let path = close(&rt, file);
                    let (blobs, tx_msg) = (blobs.clone(), tx_msg.clone());
                    // Copying a large file would hold up other transfers.
                    std::thread::spawn(move || {
                        let blob = path.and_then(|path| keep_blob(&blobs, &path).ok());
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileFinished(pk, file_id, blob)));
                    });
                }
                IOAction::SendBlob(pk, blob) => {
                    let path = blob_path(&blobs, &blob);
                    match fs::metadata(&path) {
                        Ok(meta) => {
                            let _ = tx_tox.send(ToxAction::FileSend(
                                pk,
                                BLOB_FILE_KIND,
                                meta.len(),
                                String::new(),
                                path.to_string_lossy().into_owned(),
                                Some(file_id(&blob)),
                            ));
                        }
                        Err(_) => {
                            let _ = tx_msg.send(Msg::IO(IOEvent::BlobMissing(pk, blob)));
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
                                let _ = tx_tox.send(ToxAction::FileSeek(pk, id, have));
                            }
                            let _ = tx_tox.send(ToxAction::FileControl(
                                pk,
                                id,
                                ToxFileControl::TOX_FILE_CONTROL_RESUME,
                            ));
                        }
                        Err(e) => {
                            let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
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
                    let _ = tx_msg.send(Msg::IO(IOEvent::BlobStored(pk, blob, ok)));
                }
                IOAction::AppendEvents(records, pushes) => {
                    let _ = events.send((records, pushes));
                }
            }
        }
        // The events still waiting are kept before toxxi ends.
        drop(events);
        let _ = writer.join();
    })
}
