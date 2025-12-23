use crate::config;
use crate::model::WindowId;
use crate::msg::{IOAction, IOEvent, Msg, ToxAction};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use tokio::fs::{File, OpenOptions, write};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use toxcore::types::FileId;

pub fn spawn_io_worker(
    tx_msg: mpsc::Sender<Msg>,
    tx_tox: mpsc::Sender<ToxAction>,
    rx_io: mpsc::Receiver<IOAction>,
    config_dir: PathBuf,
    downloads_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut active_files: HashMap<FileId, File> = HashMap::new();
        let rt = tokio::runtime::Handle::current();

        while let Ok(action) = rx_io.recv() {
            match action {
                IOAction::SaveProfile => {
                    // Profile saving is handled in Tox worker on shutdown
                }
                IOAction::SaveConfig(Some(config)) => {
                    let dir = config_dir.clone();
                    let tx_msg = tx_msg.clone();
                    rt.spawn(async move {
                        if let Err(e) = config::save_config(&dir, &config) {
                            let _ = tx_msg.send(Msg::IO(IOEvent::Error(format!(
                                "Failed to save config: {}",
                                e
                            ))));
                        } else {
                            let _ = tx_msg.send(Msg::IO(IOEvent::ConfigSaved));
                        }
                    });
                }
                IOAction::SaveState(Some(data)) => {
                    let path = config_dir.join("state.json");
                    rt.spawn(async move {
                        let _ = write(path, data).await;
                    });
                }
                IOAction::SaveConfig(None) | IOAction::SaveState(None) => {
                    // These should have been filled by AppContext
                }
                IOAction::OpenFileForSending(pk, file_id, path) => {
                    if let Ok(file) = rt.block_on(File::open(&path)) {
                        active_files.insert(file_id, file);
                    } else {
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("Could not open file: {}", path),
                        )));
                    }
                }
                IOAction::OpenFileForReceiving(pk, file_id, filename, _size) => {
                    let _ = std::fs::create_dir_all(&downloads_dir);
                    let path = Path::new(&filename);
                    let safe_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file");
                    let full_path = downloads_dir.join(safe_name);

                    let open_res = rt.block_on(async {
                        OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(false)
                            .open(&full_path)
                            .await
                    });

                    if let Ok(file) = open_res {
                        active_files.insert(file_id, file);
                    } else {
                        let _ = tx_msg.send(Msg::IO(IOEvent::FileError(
                            pk,
                            file_id,
                            format!("Could not create/open file: {:?}", full_path),
                        )));
                    }
                }
                IOAction::ReadChunk(pk, file_id, position, length) => {
                    if let Some(file) = active_files.get_mut(&file_id) {
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
                    if let Some(file) = active_files.get_mut(&file_id) {
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
                IOAction::CloseFile(pk, file_id) => {
                    active_files.remove(&file_id);
                    let _ = tx_msg.send(Msg::IO(IOEvent::FileFinished(pk, file_id)));
                }
                IOAction::LogMessage(window_id, message) => {
                    let logs_dir = config_dir.join("logs");
                    let _ = std::fs::create_dir_all(&logs_dir);

                    let filename = match window_id {
                        WindowId::Friend(pk) => {
                            Some(format!("friend_{}.jsonl", crate::utils::encode_hex(&pk.0)))
                        }
                        WindowId::Group(id) => {
                            Some(format!("group_{}.jsonl", crate::utils::encode_hex(&id.0)))
                        }
                        WindowId::Conference(id) => {
                            Some(format!("conf_{}.jsonl", crate::utils::encode_hex(&id.0)))
                        }
                        _ => None,
                    };

                    if let Some(fname) = filename {
                        let path = logs_dir.join(fname);
                        rt.spawn(async move {
                            if let Ok(json) = serde_json::to_string(&message)
                                && let Ok(mut file) = OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(path)
                                    .await
                            {
                                let _ = file.write_all(json.as_bytes()).await;
                                let _ = file.write_all(b"\n").await;
                            }
                        });
                    }
                }
            }
        }
    })
}
