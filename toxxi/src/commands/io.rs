use crate::model::{ConsoleMessageType, LogFilters, MessageContent, TransferStatus, WindowId};
use crate::msg::{Cmd, IOAction, ToxAction};
use std::fs::metadata;
use std::path::PathBuf;
use toxcore::tox::FriendNumber;
use toxcore::types::{FileId, ToxFileControl, ToxLogLevel};

use super::CommandDef;

fn complete_path(prefix: &str) -> Vec<String> {
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

    if let Ok(entries) = std::fs::read_dir(dir_to_read) {
        let mut result: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with(file_prefix) {
                    let mut full_path = format!("{}{}", dir_part, name);
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        full_path.push('/');
                    }
                    Some(full_path)
                } else {
                    None
                }
            })
            .collect();
        result.sort();
        result
    } else {
        vec![]
    }
}

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "file",
        args: (
            Some("send <fid> <path> | accept ..."),
            "send <fid> <path> | accept <fid> <file_id> | pause <fid> <file_id> | resume <fid> <file_id> | cancel <fid> <file_id> | list",
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
            if args.len() >= 3 {
                let sub = args[0];
                if let Ok(fid) = args[1].parse::<u32>() {
                    let friend_number = FriendNumber(fid);
                    let friend_pk_opt = model.session.friend_numbers.get(&friend_number).cloned();

                    if friend_pk_opt.is_none() {
                        model.add_console_message(
                            ConsoleMessageType::Error,
                            format!("Friend {} not found in session.", fid),
                        );
                        return vec![];
                    }
                    let pk = friend_pk_opt.unwrap();

                    match sub {
                        "send" => {
                            let raw_path = args[2];
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
                            let final_path_str = path_buf.to_string_lossy().into_owned();

                            // Optional resume_file_id
                            let mut resume_file_id = None;
                            if args.len() >= 4 {
                                match crate::utils::decode_hex(args[3]) {
                                    Some(bytes) if bytes.len() == 32 => {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        resume_file_id = Some(FileId(arr));
                                    }
                                    Some(_) => {
                                        model.add_console_message(
                                            ConsoleMessageType::Error,
                                            format!("Invalid resume File ID length: {}", args[3]),
                                        );
                                        return vec![];
                                    }
                                    None => {
                                        model.add_console_message(
                                            ConsoleMessageType::Error,
                                            format!("Invalid resume File ID hex: {}", args[3]),
                                        );
                                        return vec![];
                                    }
                                }
                            }

                            if let Ok(m) = metadata(path) {
                                let file_size = m.len();
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

                                model.add_console_message(ConsoleMessageType::Status, status_msg);
                                return vec![Cmd::Tox(ToxAction::FileSend(
                                    pk,
                                    0,
                                    file_size,
                                    filename,
                                    final_path_str,
                                    resume_file_id,
                                ))];
                            } else {
                                model.add_console_message(
                                    ConsoleMessageType::Error,
                                    format!("File not found: {}", final_path_str),
                                );
                                return vec![];
                            }
                        }
                        "accept" | "pause" | "resume" | "cancel" => {
                            let file_id_str = args[2];
                            // Parse hex string to [u8; 32] -> FileId
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
                                            .unwrap_or_else(|| {
                                                (format!("recv_{}", file_id_str), 0)
                                            });

                                        if args.len() >= 4 {
                                            filename = args[3..].join(" ");
                                        }

                                        model.add_console_message(
                                            ConsoleMessageType::Status,
                                            format!("Accepting file {} as {}", file_id, filename),
                                        );

                                        if let Some(p) =
                                            model.domain.file_transfers.get_mut(&file_id)
                                        {
                                            p.status = TransferStatus::Active;
                                        }

                                        let mut cmds = Vec::new();

                                        // Check if file exists to determine resume offset
                                        let start_offset = if let Ok(m) = metadata(&filename) {
                                            m.len()
                                        } else {
                                            0
                                        };

                                        cmds.push(Cmd::IO(IOAction::OpenFileForReceiving(
                                            pk, file_id, filename, size,
                                        )));

                                        if start_offset > 0 {
                                            model.add_console_message(
                                                ConsoleMessageType::Status,
                                                format!(
                                                    "Resuming download from offset {}",
                                                    start_offset
                                                ),
                                            );
                                            cmds.push(Cmd::Tox(ToxAction::FileSeek(
                                                pk,
                                                file_id,
                                                start_offset,
                                            )));
                                        }

                                        cmds.push(Cmd::Tox(ToxAction::FileControl(
                                            pk,
                                            file_id,
                                            ToxFileControl::TOX_FILE_CONTROL_RESUME,
                                        )));

                                        return cmds;
                                    }

                                    let control = match sub {
                                        "pause" => {
                                            if let Some(p) =
                                                model.domain.file_transfers.get_mut(&file_id)
                                            {
                                                p.status = TransferStatus::Paused;
                                            }
                                            ToxFileControl::TOX_FILE_CONTROL_PAUSE
                                        }
                                        "resume" => {
                                            if let Some(p) =
                                                model.domain.file_transfers.get_mut(&file_id)
                                            {
                                                p.status = TransferStatus::Active;
                                            }
                                            ToxFileControl::TOX_FILE_CONTROL_RESUME
                                        }
                                        "cancel" => {
                                            if let Some(p) =
                                                model.domain.file_transfers.get_mut(&file_id)
                                            {
                                                p.status = TransferStatus::Canceled;
                                            }
                                            ToxFileControl::TOX_FILE_CONTROL_CANCEL
                                        }
                                        _ => unreachable!(),
                                    };
                                    return vec![Cmd::Tox(ToxAction::FileControl(
                                        pk, file_id, control,
                                    ))];
                                }
                                _ => {
                                    model.add_console_message(
                                        ConsoleMessageType::Error,
                                        format!("Invalid File ID: {}", file_id_str),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            model.add_error_message(MessageContent::List(vec![
                "Usage: /file send <friend_id> <path> [resume_file_id]".to_owned(),
                "       /file accept <friend_id> <file_id> [path]".to_owned(),
                "       /file pause <friend_id> <file_id>".to_owned(),
                "       /file resume <friend_id> <file_id>".to_owned(),
                "       /file cancel <friend_id> <file_id>".to_owned(),
                "       /file list".to_owned(),
            ]));
            vec![]
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
                let mut ids: Vec<_> = model
                    .session
                    .friend_numbers
                    .iter()
                    .map(|(fn_num, pk)| {
                        let name = model
                            .domain
                            .friends
                            .get(pk)
                            .map(|i| i.name.clone())
                            .unwrap_or_else(|| format!("Friend {}", fn_num.0));
                        (fn_num.0.to_string(), name)
                    })
                    .collect();
                ids.sort_by(|a, b| a.0.cmp(&b.0));
                return ids
                    .into_iter()
                    .filter(|(id, _)| id.starts_with(prefix))
                    .collect();
            }
            if args.len() == 3 {
                if args[0] == "send" {
                    return complete_path(args[2])
                        .into_iter()
                        .map(|p| (p, "File Path".to_string()))
                        .collect();
                } else {
                    let prefix = args[2];
                    // Provide FileId completion
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
                    model.add_console_message(
                        ConsoleMessageType::Status,
                        "Tox logs cleared.".to_owned(),
                    );
                } else if args[0] == "all" {
                    model.ui.log_filters = LogFilters::default();
                    if let Some(state) = model.ui.window_state.get_mut(&WindowId::Logs) {
                        state.msg_list_state.scroll = 0;
                    }
                    model.add_console_message(
                        ConsoleMessageType::Status,
                        "Log filters cleared (showing all logs).".to_owned(),
                    );
                } else if args[0] == "pause" {
                    model.ui.log_filters.paused = true;
                    model.add_console_message(
                        ConsoleMessageType::Status,
                        "Tox logging paused.".to_owned(),
                    );
                } else if args[0] == "resume" {
                    model.ui.log_filters.paused = false;
                    model.add_console_message(
                        ConsoleMessageType::Status,
                        "Tox logging resumed.".to_owned(),
                    );
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
                                                "trace" => Some(ToxLogLevel::TOX_LOG_LEVEL_TRACE),
                                                "debug" => Some(ToxLogLevel::TOX_LOG_LEVEL_DEBUG),
                                                "info" => Some(ToxLogLevel::TOX_LOG_LEVEL_INFO),
                                                "warn" | "warning" => {
                                                    Some(ToxLogLevel::TOX_LOG_LEVEL_WARNING)
                                                }
                                                "error" => Some(ToxLogLevel::TOX_LOG_LEVEL_ERROR),
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
                                                                ToxLogLevel::TOX_LOG_LEVEL_TRACE,
                                                                ToxLogLevel::TOX_LOG_LEVEL_DEBUG,
                                                                ToxLogLevel::TOX_LOG_LEVEL_INFO,
                                                                ToxLogLevel::TOX_LOG_LEVEL_WARNING,
                                                                ToxLogLevel::TOX_LOG_LEVEL_ERROR,
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
                                    model.add_console_message(
                                        ConsoleMessageType::Error,
                                        format!("Unknown log filter: {}", key),
                                    );
                                }
                            }
                        }
                    }
                    model.ui.log_filters = filters;
                    if let Some(state) = model.ui.window_state.get_mut(&WindowId::Logs) {
                        state.msg_list_state.scroll = 0;
                    }
                    model.add_console_message(
                        ConsoleMessageType::Status,
                        "Log filters updated.".to_owned(),
                    );
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
