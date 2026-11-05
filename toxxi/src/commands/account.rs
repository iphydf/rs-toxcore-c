use crate::model::{MessageContent, Model, WindowId};
use crate::msg::{Cmd, ToxAction};
use crate::sync::pairing::VALID_FOR;
use toxcore::tox::{FriendNumber, ToxUserStatus};
use toxcore::types::PublicKey;

use super::CommandDef;

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "nick",
        args: (None, "[name]"),
        desc: (None, "Set or show your name"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_info_message(MessageContent::Text(format!(
                    "Your current name: {}",
                    model.domain.self_name
                )));
                return vec![];
            }
            let name = args.join(" ");
            let active_id = model.active_window_id();
            if let WindowId::Group(chat_id) = active_id {
                model.add_status_message(MessageContent::Text(format!(
                    "Group nickname set to: {}",
                    name
                )));
                if let Some(conv) = model.domain.conversations.get_mut(&active_id) {
                    conv.self_name = Some(name.clone());
                }
                vec![Cmd::Tox(ToxAction::SetGroupNickname(chat_id, name))]
            } else if matches!(active_id, WindowId::Console | WindowId::Files) {
                // Self name change
                model.domain.self_name = name.clone();
                model.add_status_message(MessageContent::Text(format!("Name set to: {}", name)));
                vec![Cmd::Tox(ToxAction::SetName(name))]
            } else {
                // In Tox, group-specific nicknames are only for Groups.
                // For other window types, we fall back to a global name change.
                model.domain.self_name = name.clone();
                model.add_status_message(MessageContent::Text(format!("Name set to: {}", name)));
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
                model.add_info_message(MessageContent::Text(format!(
                    "Your current status: {}",
                    model.domain.self_status_message
                )));
                return vec![];
            }
            let msg = args.join(" ");
            model.domain.self_status_message = msg.clone();
            model.add_status_message(MessageContent::Text("Status updated".to_owned()));
            vec![Cmd::Tox(ToxAction::SetStatusMessage(msg))]
        },
        complete: None,
    },
    CommandDef {
        name: "nospam",
        args: (None, "[new|<8 hex digits>]"),
        desc: (
            None,
            "Show or change the end of your Tox ID, so requests to the old one stop",
        ),
        exec: |model, args| {
            let id = &model.domain.tox_id.0;
            let current = u32::from_be_bytes([id[32], id[33], id[34], id[35]]);
            let nospam = match args.first().map(|arg| arg.to_lowercase()) {
                None => {
                    model.add_info_message(MessageContent::Text(format!(
                        "Nospam: {current:08X}. /nospam new changes it."
                    )));
                    return vec![];
                }
                Some(arg) if arg == "new" => rand::random(),
                Some(arg) => match u32::from_str_radix(&arg, 16) {
                    Ok(nospam) if arg.len() == 8 && arg.bytes().all(|b| b.is_ascii_hexdigit()) => {
                        nospam
                    }
                    _ => {
                        model.add_error_message(MessageContent::Text(
                            "Usage: /nospam [new|<8 hex digits>]".to_owned(),
                        ));
                        return vec![];
                    }
                },
            };
            model.add_status_message(MessageContent::Text(format!(
                "Nospam set to {:08X}: friend requests to your old Tox ID no longer arrive.",
                nospam
            )));
            vec![Cmd::Tox(ToxAction::SetNospam(nospam))]
        },
        complete: None,
    },
    CommandDef {
        name: "status_type",
        args: (None, "<online|away|busy>"),
        desc: (None, "Set status type"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text(
                    "Usage: /status_type <online|away|busy>".to_owned(),
                ));
                return vec![];
            }
            let status = match args[0].to_lowercase().as_str() {
                "online" => ToxUserStatus::TOX_USER_STATUS_NONE,
                "away" => ToxUserStatus::TOX_USER_STATUS_AWAY,
                "busy" => ToxUserStatus::TOX_USER_STATUS_BUSY,
                _ => {
                    model.add_error_message(MessageContent::Text(
                        "Invalid status type. Options: online, away, busy".to_owned(),
                    ));
                    return vec![];
                }
            };
            let status_name = match status {
                ToxUserStatus::TOX_USER_STATUS_NONE => "online",
                ToxUserStatus::TOX_USER_STATUS_AWAY => "away",
                ToxUserStatus::TOX_USER_STATUS_BUSY => "busy",
            };
            model.domain.self_status_type = status;
            model.add_status_message(MessageContent::Text(format!(
                "Status type set to: {}",
                status_name
            )));
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
            model.ui.qr = Some(model.domain.tox_id.to_string());
            vec![]
        },
        complete: None,
    },
    CommandDef {
        name: "device",
        args: (
            Some("pair | allow|remove <id> | list"),
            "pair | allow <friend_id> | remove <friend_id> | list",
        ),
        desc: (None, "Manage the devices that can sync this account"),
        exec: device,
        complete: None,
    },
];

fn device(model: &mut Model, args: &[&str]) -> Vec<Cmd> {
    let friend_name =
        |model: &Model, pk: &PublicKey| model.domain.friends.get(pk).map(|info| info.name.clone());
    match args {
        ["list"] => {
            if model.config.sync_devices.is_empty() {
                model.add_info_message(MessageContent::Text(
                    "No devices can sync this account.".to_owned(),
                ));
            }
            for pk in model.config.sync_devices.clone() {
                let name = friend_name(model, &pk).unwrap_or_else(|| "(not a friend)".to_owned());
                model.add_info_message(MessageContent::Text(format!("{} {}", name, pk)));
            }
            vec![]
        }
        ["pair"] => {
            let code = model.session.pairing.issue(model.time_provider.now());
            let link = code.link(&model.domain.tox_id);
            model.add_status_message(MessageContent::Text(format!(
                "Open this on the new device within {} minutes: {}",
                VALID_FOR.as_secs() / 60,
                link
            )));
            model.ui.qr = Some(link);
            vec![]
        }
        [action @ ("allow" | "remove"), id] => {
            let Some(pk) = id
                .parse::<u32>()
                .ok()
                .and_then(|n| model.session.friend_numbers.get(&FriendNumber(n)).copied())
            else {
                model.add_error_message(MessageContent::Text(format!("Friend {} not found.", id)));
                return vec![];
            };
            let allow = *action == "allow";
            let name = friend_name(model, &pk).unwrap_or_else(|| pk.to_string());
            model.add_status_message(MessageContent::Text(if allow {
                format!("{} can now sync this account.", name)
            } else {
                format!("{} can no longer sync this account.", name)
            }));
            crate::sync::set_device(model, pk, allow)
        }
        _ => {
            model.add_error_message(MessageContent::Text(
                "Usage: /device pair | allow <friend_id> | remove <friend_id> | list".to_owned(),
            ));
            vec![]
        }
    }
}
