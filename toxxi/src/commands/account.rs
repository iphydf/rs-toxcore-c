use crate::model::{ConsoleMessageType, WindowId};
use crate::msg::{Cmd, ToxAction};
use toxcore::tox::ToxUserStatus;

use super::CommandDef;

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "nick",
        args: (None, "[name]"),
        desc: (None, "Set or show your name"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_console_message(
                    ConsoleMessageType::Info,
                    format!("Your current name: {}", model.domain.self_name),
                );
                return vec![];
            }
            let name = args.join(" ");
            let active_id = model.active_window_id();
            if let WindowId::Group(chat_id) = active_id {
                model.add_console_message(
                    ConsoleMessageType::Status,
                    format!("Group nickname set to: {}", name),
                );
                vec![Cmd::Tox(ToxAction::SetGroupNickname(chat_id, name))]
            } else if matches!(active_id, WindowId::Console | WindowId::Files) {
                // Self name change
                model.domain.self_name = name.clone();
                model.add_console_message(
                    ConsoleMessageType::Status,
                    format!("Name set to: {}", name),
                );
                vec![Cmd::Tox(ToxAction::SetName(name))]
            } else {
                // For friends/conferences we probably can't change nick?
                // Original code: if Group -> SetGroupNickname. else -> SetName (global).
                // But original code checked if active_id is Group.
                // "if let WindowId::Group(_) = active_id { ... } else { ... }"
                // So if it's Friend, it changed global name.
                model.domain.self_name = name.clone();
                model.add_console_message(
                    ConsoleMessageType::Status,
                    format!("Name set to: {}", name),
                );
                vec![Cmd::Tox(ToxAction::SetName(name))]
            }
        },
        complete: None,
    },
    CommandDef {
        name: "status",
        args: (None, "[msg]"),
        desc: (None, "Set or show status message"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_console_message(
                    ConsoleMessageType::Info,
                    format!("Your current status: {}", model.domain.self_status_message),
                );
                return vec![];
            }
            let msg = args.join(" ");
            model.domain.self_status_message = msg.clone();
            model.add_console_message(ConsoleMessageType::Status, "Status updated".to_owned());
            vec![Cmd::Tox(ToxAction::SetStatusMessage(msg))]
        },
        complete: None,
    },
    CommandDef {
        name: "status_type",
        args: (None, "<online|away|busy>"),
        desc: (None, "Set status type"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_console_message(
                    ConsoleMessageType::Error,
                    "Usage: /status_type <online|away|busy>".to_owned(),
                );
                return vec![];
            }
            let status = match args[0].to_lowercase().as_str() {
                "online" => ToxUserStatus::TOX_USER_STATUS_NONE,
                "away" => ToxUserStatus::TOX_USER_STATUS_AWAY,
                "busy" => ToxUserStatus::TOX_USER_STATUS_BUSY,
                _ => {
                    model.add_console_message(
                        ConsoleMessageType::Error,
                        "Invalid status type. Options: online, away, busy".to_owned(),
                    );
                    return vec![];
                }
            };
            let status_name = match status {
                ToxUserStatus::TOX_USER_STATUS_NONE => "online",
                ToxUserStatus::TOX_USER_STATUS_AWAY => "away",
                ToxUserStatus::TOX_USER_STATUS_BUSY => "busy",
            };
            model.domain.self_status_type = status;
            model.add_console_message(
                ConsoleMessageType::Status,
                format!("Status type set to: {}", status_name),
            );
            vec![Cmd::Tox(ToxAction::SetStatusType(status))]
        },
        complete: Some(|_model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                let statuses = [
                    ("online", "Set status to online"),
                    ("away", "Set status to away"),
                    ("busy", "Set status to busy"),
                ];
                return statuses
                    .iter()
                    .filter(|(s, _)| s.starts_with(prefix))
                    .map(|(s, d)| (s.to_string(), d.to_string()))
                    .collect();
            }
            vec![]
        }),
    },
    CommandDef {
        name: "qr",
        args: (None, ""),
        desc: (None, "Show your Tox ID as a QR code"),
        exec: |model, _args| {
            model.ui.show_qr = true;
            vec![]
        },
        complete: None,
    },
];
