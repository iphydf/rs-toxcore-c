use super::friend_arg;
use crate::completion::complete_friends;
use crate::disk::Disk;
use crate::model::{LogFilters, MessageContent, Model, TransferStatus, WindowId};
use crate::msg::{Cmd, IOAction, ToxAction};
use std::path::PathBuf;
use toxcore::types::{FileControl, FileId, FileKind, LogLevel};

use super::CommandDef;

fn complete_path(disk: &dyn Disk, prefix: &str) -> Vec<String> {
    let (dir_part, file_prefix) = if let Some(last_slash) = prefix.rfind('/') {
        (&prefix[..=last_slash], &prefix[last_slash + 1..])
    } else {
        ("", prefix)
    };

    let dir_to_read = if dir_part.is_empty() {
        PathBuf::from(".")
    } else if let Some(stripped) = dir_part.strip_prefix("~/") {
        if let Some(user_dirs) = directories::UserDirs::new() {
            user_dirs.home_dir().join(stripped)
        } else {
            PathBuf::from(dir_part)
        }
    } else if dir_part == "~" {
        if let Some(user_dirs) = directories::UserDirs::new() {
            user_dirs.home_dir().to_path_buf()
        } else {
            PathBuf::from(".")
        }
    } else {
        PathBuf::from(dir_part)
    };

    let mut result: Vec<String> = disk
        .list(&dir_to_read)
        .into_iter()
        .filter(|(name, _)| name.starts_with(file_prefix))
        .map(|(name, is_dir)| {
            let mut full_path = format!("{}{}", dir_part, name);
            if is_dir {
                full_path.push('/');
            }
            full_path
        })
        .collect();
    result.sort();
    result
}

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "file",
        args: (
            Some("send [friend] <path> | accept ..."),
            "send [friend] <path> | accept <friend> <file_id> | pause <friend> <file_id> | resume <friend> <file_id> | cancel <friend> <file_id> | list",
        ),
        desc: (None, "Manage file transfers"),
        exec: |model, args| {
            if !args.is_empty() && args[0] == "list" {
                let window_id = WindowId::Files;
                if !model.ui.window_ids.contains(&window_id) {
                    model.ui.window_ids.push(window_id);
                }
                if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                    model.set_active_window(pos);
                }
                return vec![];
            }
            let (pk, sub, rest) = match (args, model.active_window_id()) {
                // In a friend's chat, `/file send <path>` sends to them.
                (["send", rest @ ..], WindowId::Friend(pk)) if rest.len() == 1 => {
                    (pk, "send", rest)
                }
                ([sub, friend, rest @ ..], _) if !rest.is_empty() => {
                    let Some(pk) = friend_arg(model, friend) else {
                        return vec![];
                    };
                    (pk, *sub, rest)
                }
                _ => return file_usage(model),
            };
            match sub {
                "send" => {
                    let raw_path = rest[0];
                    let path_buf = if raw_path == "~" {
                        directories::UserDirs::new()
                            .map(|d| d.home_dir().to_path_buf())
                            .unwrap_or_else(|| PathBuf::from(raw_path))
                    } else if let Some(stripped) = raw_path.strip_prefix("~/") {
                        directories::UserDirs::new()
                            .map(|d| d.home_dir().join(stripped))
                            .unwrap_or_else(|| PathBuf::from(raw_path))
                    } else {
                        PathBuf::from(raw_path)
                    };

                    let path = path_buf.as_path();

                    let mut resume_file_id = None;
                    if let Some(id) = rest.get(1) {
                        let Some(id) = crate::utils::parse_hex(id).map(FileId) else {
                            model.add_error_message(MessageContent::Text(format!(
                                "Not a file ID: {}",
                                id
                            )));
                            return vec![];
                        };
                        resume_file_id = Some(id);
                    }

                    if let Some(file_size) = model.disk.size(path) {
                        let filename = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "file".to_owned());

                        let status_msg = if let Some(fid) = resume_file_id {
                            format!(
                                "Resuming file send: {} ({} bytes, ID: {})",
                                filename, file_size, fid
                            )
                        } else {
                            format!("Sending file: {} ({} bytes)", filename, file_size)
                        };

                        model.add_status_message(MessageContent::Text(status_msg));
                        return vec![Cmd::Tox(ToxAction::FileSend {
                            friend: pk,
                            kind: FileKind::DATA,
                            size: file_size,
                            name: filename,
                            path: path_buf,
                            resume: resume_file_id,
                        })];
                    } else {
                        model.add_error_message(MessageContent::Text(format!(
                            "File not found: {}",
                            path.display()
                        )));
                        return vec![];
                    }
                }
                "accept" | "pause" | "resume" | "cancel" => {
                    let file_id_str = rest[0];
                    match crate::utils::decode_hex(file_id_str) {
                        Some(bytes) if bytes.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            let file_id = FileId(arr);

                            if sub == "accept" {
                                let (mut filename, size) = model
                                    .domain
                                    .file_transfers
                                    .get(&file_id)
                                    .map(|p| (p.filename.clone(), p.total_size))
                                    .unwrap_or_else(|| (format!("recv_{}", file_id_str), 0));

                                if rest.len() >= 2 {
                                    filename = rest[1..].join(" ");
                                }

                                model.add_status_message(MessageContent::Text(format!(
                                    "Accepting file {} as {}",
                                    file_id, filename
                                )));

                                if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                                    p.status = TransferStatus::Active;
                                }
                                return vec![Cmd::IO(IOAction::OpenFileForReceiving(
                                    pk, file_id, filename, size,
                                ))];
                            }

                            let control = match sub {
                                "pause" => {
                                    if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                                        p.status = TransferStatus::Paused;
                                    }
                                    FileControl::Pause
                                }
                                "resume" => {
                                    if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                                        p.status = TransferStatus::Active;
                                    }
                                    FileControl::Resume
                                }
                                "cancel" => {
                                    return crate::update::cancel_transfer(model, pk, file_id);
                                }
                                _ => unreachable!(),
                            };
                            return vec![Cmd::Tox(ToxAction::FileControl(pk, file_id, control))];
                        }
                        _ => {
                            model.add_error_message(MessageContent::Text(format!(
                                "Invalid File ID: {}",
                                file_id_str
                            )));
                        }
                    }
                }
                _ => {}
            }
            file_usage(model)
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                let subs = [
                    ("send", "Send a file"),
                    ("accept", "Accept a file transfer"),
                    ("pause", "Pause a transfer"),
                    ("resume", "Resume a transfer"),
                    ("cancel", "Cancel a transfer"),
                    ("list", "List active transfers"),
                ];
                return subs
                    .iter()
                    .filter(|(s, _)| s.starts_with(prefix))
                    .map(|(s, d)| (s.to_string(), d.to_string()))
                    .collect();
            }
            if args.len() == 2 {
                let prefix = args[1];
                return complete_friends(model, prefix);
            }
            if args.len() == 3 {
                if args[0] == "send" {
                    return complete_path(model.disk.as_ref(), args[2])
                        .into_iter()
                        .map(|p| (p, "File Path".to_string()))
                        .collect();
                } else {
                    let prefix = args[2];
                    let mut ids: Vec<_> = model
                        .domain
                        .file_transfers
                        .iter()
                        .map(|(id, p)| (id.to_string(), p.filename.clone()))
                        .collect();
                    ids.sort_by(|a, b| a.0.cmp(&b.0));
                    return ids
                        .into_iter()
                        .filter(|(s, _)| s.starts_with(prefix))
                        .collect();
                }
            }
            vec![]
        }),
    },
    CommandDef {
        name: "logs",
        args: (
            Some("[all | clear | ...]"),
            "[all | clear | pause | resume | level=... | ...]",
        ),
        desc: (None, "Open the Tox logs window with optional filters"),
        exec: |model, args| {
            if !args.is_empty() {
                if args[0] == "clear" {
                    model.domain.tox_logs.clear();
                    if let Some(state) = model.ui.window_state.get_mut(&WindowId::Logs) {
                        state.msg_list_state.scroll = 0;
                    }
                    model.add_status_message(MessageContent::Text("Tox logs cleared.".to_owned()));
                } else if args[0] == "all" {
                    model.ui.log_filters = LogFilters::default();
                    if let Some(state) = model.ui.window_state.get_mut(&WindowId::Logs) {
                        state.msg_list_state.scroll = 0;
                    }
                    model.add_status_message(MessageContent::Text(
                        "Log filters cleared (showing all logs).".to_owned(),
                    ));
                } else if args[0] == "pause" {
                    model.ui.log_filters.paused = true;
                    model
                        .add_status_message(MessageContent::Text("Tox logging paused.".to_owned()));
                } else if args[0] == "resume" {
                    model.ui.log_filters.paused = false;
                    model.add_status_message(MessageContent::Text(
                        "Tox logging resumed.".to_owned(),
                    ));
                } else {
                    let mut filters = model.ui.log_filters.clone();
                    for arg in args {
                        if let Some((key, val)) = arg.split_once('=') {
                            match key {
                                "level" | "levels" => {
                                    if val.is_empty() {
                                        filters.levels.clear();
                                    } else {
                                        let mut first = true;
                                        for l in val.split(',') {
                                            let (op, l_name) =
                                                if let Some(stripped) = l.strip_prefix('+') {
                                                    (Some('+'), stripped)
                                                } else if let Some(stripped) = l.strip_prefix('-') {
                                                    (Some('-'), stripped)
                                                } else {
                                                    (None, l)
                                                };

                                            let level = match l_name.to_lowercase().as_str() {
                                                "trace" => Some(LogLevel::Trace),
                                                "debug" => Some(LogLevel::Debug),
                                                "info" => Some(LogLevel::Info),
                                                "warn" | "warning" => Some(LogLevel::Warning),
                                                "error" => Some(LogLevel::Error),
                                                _ => None,
                                            };

                                            if let Some(lvl) = level {
                                                match op {
                                                    Some('+') => {
                                                        if !filters.levels.contains(&lvl) {
                                                            filters.levels.push(lvl);
                                                        }
                                                    }
                                                    Some('-') => {
                                                        if filters.levels.is_empty() {
                                                            let all = vec![
                                                                LogLevel::Trace,
                                                                LogLevel::Debug,
                                                                LogLevel::Info,
                                                                LogLevel::Warning,
                                                                LogLevel::Error,
                                                            ];
                                                            filters.levels = all
                                                                .into_iter()
                                                                .filter(|&a| a != lvl)
                                                                .collect();
                                                        } else {
                                                            filters.levels.retain(|&x| x != lvl);
                                                        }
                                                    }
                                                    _ => {
                                                        if first {
                                                            filters.levels.clear();
                                                        }
                                                        if !filters.levels.contains(&lvl) {
                                                            filters.levels.push(lvl);
                                                        }
                                                    }
                                                }
                                            }
                                            first = false;
                                        }
                                    }
                                }
                                "file" => {
                                    filters.file_pattern = if val.is_empty() {
                                        None
                                    } else {
                                        Some(val.to_owned())
                                    };
                                }
                                "func" => {
                                    filters.func_pattern = if val.is_empty() {
                                        None
                                    } else {
                                        Some(val.to_owned())
                                    };
                                }
                                "msg" => {
                                    filters.msg_pattern = if val.is_empty() {
                                        None
                                    } else {
                                        Some(val.to_owned())
                                    };
                                }
                                "paused" => {
                                    filters.paused = val == "true";
                                }
                                _ => {
                                    model.add_error_message(MessageContent::Text(format!(
                                        "Unknown log filter: {}",
                                        key
                                    )));
                                }
                            }
                        }
                    }
                    model.ui.log_filters = filters;
                    if let Some(state) = model.ui.window_state.get_mut(&WindowId::Logs) {
                        state.msg_list_state.scroll = 0;
                    }
                    model.add_status_message(MessageContent::Text(
                        "Log filters updated.".to_owned(),
                    ));
                }
            }

            let window_id = WindowId::Logs;
            if !model.ui.window_ids.contains(&window_id) {
                model.ui.window_ids.push(window_id);
            }
            if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                model.set_active_window(pos);
            }
            vec![]
        },
        complete: Some(|_model, args| {
            let last = args.last().unwrap_or(&"");
            if !last.contains('=') {
                let keys = [
                    ("level=", "Filter by log level"),
                    ("file=", "Filter by file name"),
                    ("func=", "Filter by function name"),
                    ("msg=", "Filter by message content"),
                    ("clear", "Clear logs"),
                    ("all", "Show all logs"),
                ];
                return keys
                    .iter()
                    .filter(|(k, _)| k.starts_with(last))
                    .map(|(k, d)| (k.to_string(), d.to_string()))
                    .collect();
            }
            if let Some(prefix) = last.strip_prefix("level=") {
                let levels = ["trace", "debug", "info", "warn", "error"];
                return levels
                    .iter()
                    .filter(|l| l.starts_with(prefix))
                    .map(|l| (format!("level={}", l), format!("Level {}", l)))
                    .collect();
            }
            vec![]
        }),
    },
];

fn file_usage(model: &mut Model) -> Vec<Cmd> {
    model.add_error_message(MessageContent::List(vec![
        "Usage: /file send [friend] <path> [resume_file_id]".to_owned(),
        "       /file accept <friend> <file_id> [path]".to_owned(),
        "       /file pause <friend> <file_id>".to_owned(),
        "       /file resume <friend> <file_id>".to_owned(),
        "       /file cancel <friend> <file_id>".to_owned(),
        "       /file list".to_owned(),
    ]));
    vec![]
}
