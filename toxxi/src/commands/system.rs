use crate::model::{MessageContent, Model, WindowId};
use crate::msg::{AppCmd, Cmd, IOAction};

use super::CommandDef;

fn screenshot_exec(model: &mut Model, args: &[&str]) -> Vec<Cmd> {
    let mut path = None;
    let mut cols = None;
    let mut rows = None;

    match args.len() {
        0 => {}
        1 => {
            path = Some(args[0].to_string());
        }
        2 => {
            let c = args[0].parse::<u16>();
            let r = args[1].parse::<u16>();
            if let (Ok(c), Ok(r)) = (c, r) {
                cols = Some(c);
                rows = Some(r);
            } else {
                model.add_error_message(MessageContent::Text(
                    "Usage: /screenshot [filename] [cols rows]".to_owned(),
                ));
                return vec![];
            }
        }
        3 => {
            path = Some(args[0].to_string());
            cols = args[1].parse::<u16>().ok();
            rows = args[2].parse::<u16>().ok();
            if cols.is_none() || rows.is_none() {
                model.add_error_message(MessageContent::Text(
                    "Invalid dimensions. Usage: /screenshot [filename] [cols rows]".to_owned(),
                ));
                return vec![];
            }
        }
        _ => {
            model.add_error_message(MessageContent::Text(
                "Usage: /screenshot [filename] [cols rows]".to_owned(),
            ));
            return vec![];
        }
    }

    let mut final_path = path.unwrap_or_else(|| {
        format!(
            "screenshot-{}.svg",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        )
    });

    let has_valid_ext = final_path.ends_with(".svg")
        || final_path.ends_with(".png")
        || final_path.ends_with(".qoi");

    if !has_valid_ext {
        final_path.push_str(".svg");
    }

    vec![Cmd::App(AppCmd::Screenshot(final_path, cols, rows))]
}

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "quit",
        args: (None, ""),
        desc: (None, "Exit the application"),
        exec: |_model, _args| vec![Cmd::App(AppCmd::Quit)],
        complete: None,
    },
    CommandDef {
        name: "clear",
        args: (None, "[all | system]"),
        desc: (
            Some("Clear messages in window"),
            "Clear the current window's messages",
        ),
        exec: |model, args| {
            let active_id = model.active_window_id();
            let clear_all = !args.is_empty() && args[0] == "all";
            let clear_system = !args.is_empty() && args[0] == "system" || args.is_empty();

            if clear_all {
                match active_id {
                    WindowId::Console => model.domain.console_messages.clear(),
                    WindowId::Logs => {
                        for v in model.domain.tox_logs.values_mut() {
                            v.clear();
                        }
                    }
                    _ => {
                        if let Some(conv) = model.domain.conversations.get_mut(&active_id) {
                            conv.messages.clear();
                        }
                    }
                }
                if let Some(state) = model.ui.window_state.get_mut(&active_id) {
                    state.msg_list_state.scroll = 0;
                }
                model.invalidate_full_window_cache(active_id);
            } else if clear_system {
                match active_id {
                    WindowId::Console => {
                        // /clear system in console clears Info messages.
                        model
                            .domain
                            .console_messages
                            .retain(|m| m.msg_type != crate::model::ConsoleMessageType::Info);
                    }
                    _ => {
                        if let Some(conv) = model.domain.conversations.get_mut(&active_id) {
                            conv.messages.retain(|m| m.sender != "System");
                        }
                    }
                }
                model.invalidate_full_window_cache(active_id);
            } else {
                model.add_error_message(MessageContent::Text(
                    "Usage: /clear [all | system]".to_owned(),
                ));
            }
            vec![]
        },
        complete: Some(|_model, _args| {
            vec![
                ("all".to_owned(), "Clear all messages".to_owned()),
                ("system".to_owned(), "Clear system messages only".to_owned()),
            ]
        }),
    },
    CommandDef {
        name: "pop",
        args: (None, ""),
        desc: (
            None,
            "Remove the most recent system message from the current window",
        ),
        exec: |model, _args| {
            let active_id = model.active_window_id();
            let mut changed = false;
            match active_id {
                WindowId::Console => {
                    use crate::model::ConsoleMessageType;
                    if let Some(pos) = model.domain.console_messages.iter().rposition(|m| {
                        matches!(
                            m.msg_type,
                            ConsoleMessageType::Info
                                | ConsoleMessageType::Status
                                | ConsoleMessageType::Error
                        )
                    }) {
                        model.domain.console_messages.remove(pos);
                        changed = true;
                    }
                }
                _ => {
                    if let Some(conv) = model.domain.conversations.get_mut(&active_id)
                        && let Some(pos) = conv.messages.iter().rposition(|m| m.sender == "System")
                    {
                        conv.messages.remove(pos);
                        changed = true;
                    }
                }
            }
            if changed {
                model.invalidate_full_window_cache(active_id);
            }
            vec![]
        },
        complete: None,
    },
    CommandDef {
        name: "win",
        args: (None, "<index>"),
        desc: (None, "Switch to a window by index"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text("Usage: /win <index>".to_owned()));
                return vec![];
            }
            if let Ok(idx) = args[0].parse::<usize>() {
                if idx < model.ui.window_ids.len() {
                    model.set_active_window(idx);
                } else {
                    model.add_error_message(MessageContent::Text(format!(
                        "Invalid window index: {}",
                        idx
                    )));
                }
            } else {
                model.add_error_message(MessageContent::Text(
                    "Window index must be a number.".to_owned(),
                ));
            }
            vec![]
        },
        complete: Some(|model, _args| {
            model
                .ui
                .window_ids
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    let topic = if let Some(conv) = model.domain.conversations.get(w) {
                        conv.name.clone()
                    } else {
                        format!("{:?}", w)
                    };
                    (i.to_string(), topic)
                })
                .collect()
        }),
    },
    CommandDef {
        name: "reload",
        args: (None, ""),
        desc: (None, "Restart Tox core"),
        exec: |_model, _args| vec![Cmd::App(AppCmd::ReloadTox)],
        complete: None,
    },
    CommandDef {
        name: "timeout",
        args: (None, "<ms>"),
        desc: (None, "Exit the application after some time"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text("Usage: /timeout <ms>".to_owned()));
                return vec![];
            }
            if let Ok(ms) = args[0].parse::<u64>() {
                model.add_status_message(MessageContent::Text(format!(
                    "Application will quit in {} ms",
                    ms
                )));
                return vec![Cmd::App(AppCmd::SetTimeout(ms))];
            }
            model.add_error_message(MessageContent::Text(
                "Timeout must be a number of milliseconds.".to_owned(),
            ));
            vec![]
        },
        complete: None,
    },
    CommandDef {
        name: "screenshot",
        args: (None, "[filename] [cols rows]"),
        desc: (
            None,
            "Save a screenshot of the current terminal as SVG (optional size)",
        ),
        exec: screenshot_exec,
        complete: None,
    },
    CommandDef {
        name: "sc",
        args: (None, "[filename] [cols rows]"),
        desc: (None, "Alias for /screenshot"),
        exec: screenshot_exec,
        complete: None,
    },
    CommandDef {
        name: "set",
        args: (None, "[key] [val]"),
        desc: (None, "Change or view settings"),
        exec: |model, args| {
            if args.is_empty() {
                let items = vec![
                    "--- Settings ---".to_owned(),
                    format!("ipv6_enabled      = {}", model.config.ipv6_enabled),
                    format!("udp_enabled       = {}", model.config.udp_enabled),
                    format!("start_port        = {}", model.config.start_port),
                    format!("end_port          = {}", model.config.end_port),
                    format!("blocked_strings   = {:?}", model.config.blocked_strings),
                    format!(
                        "system_messages   = {:?}",
                        model.config.enabled_system_messages
                    ),
                    "----------------".to_owned(),
                ];
                model.add_info_message(MessageContent::List(items));
                return vec![];
            }

            let key = args[0];
            if args.len() == 1 {
                match key {
                    "ipv6" | "ipv6_enabled" => {
                        model.add_info_message(MessageContent::Text(format!(
                            "ipv6_enabled = {}",
                            model.config.ipv6_enabled
                        )));
                    }
                    "udp" | "udp_enabled" => {
                        model.add_info_message(MessageContent::Text(format!(
                            "udp_enabled = {}",
                            model.config.udp_enabled
                        )));
                    }
                    "system_messages" => {
                        model.add_info_message(MessageContent::Text(format!(
                            "system_messages = {:?}",
                            model.config.enabled_system_messages
                        )));
                    }
                    _ => {
                        model.add_error_message(MessageContent::Text(format!(
                            "Unknown setting: {}",
                            key
                        )));
                    }
                }
                return vec![];
            }

            let val = args[1];
            let old_config = model.config.clone();
            let mut changed = false;
            let mut settings_updated = false;
            let mut cmds = Vec::new();

            match key {
                "system_messages" => {
                    use crate::config::SystemMessageType;
                    let type_opt = match val.to_lowercase().as_str() {
                        "join" => Some(SystemMessageType::Join),
                        "leave" => Some(SystemMessageType::Leave),
                        "nick" | "nickchange" => Some(SystemMessageType::NickChange),
                        _ => None,
                    };

                    if let Some(t) = type_opt {
                        if model.config.enabled_system_messages.contains(&t) {
                            model.config.enabled_system_messages.retain(|&x| x != t);
                            model
                                .saved_config
                                .enabled_system_messages
                                .retain(|&x| x != t);
                            model.add_status_message(MessageContent::Text(format!(
                                "System message {:?} disabled",
                                t
                            )));
                        } else {
                            model.config.enabled_system_messages.push(t);
                            model.saved_config.enabled_system_messages.push(t);
                            model.add_status_message(MessageContent::Text(format!(
                                "System message {:?} enabled",
                                t
                            )));
                        }
                        settings_updated = true;
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid system message type. Options: Join, Leave, Nick".to_owned(),
                        ));
                    }
                }
                "ipv6" | "ipv6_enabled" => {
                    if let Ok(v) = val.parse::<bool>() {
                        model.config.ipv6_enabled = v;
                        model.saved_config.ipv6_enabled = v;
                        model.add_status_message(MessageContent::Text(format!(
                            "ipv6_enabled set to {}",
                            v
                        )));
                        changed = true;
                        settings_updated = true;
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid boolean value".to_owned(),
                        ));
                    }
                }
                "udp" | "udp_enabled" => {
                    if let Ok(v) = val.parse::<bool>() {
                        model.config.udp_enabled = v;
                        model.saved_config.udp_enabled = v;
                        model.add_status_message(MessageContent::Text(format!(
                            "udp_enabled set to {}",
                            v
                        )));
                        changed = true;
                        settings_updated = true;
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid boolean value".to_owned(),
                        ));
                    }
                }
                _ => {
                    model.add_error_message(MessageContent::Text(format!(
                        "Unknown setting: {}",
                        key
                    )));
                }
            }

            if settings_updated {
                cmds.push(Cmd::IO(IOAction::SaveConfig(None)));
            }

            if changed && model.config.requires_restart(&old_config) {
                model.add_status_message(MessageContent::Text(
                    "Settings changed. Restarting Tox core...".to_owned(),
                ));
                cmds.push(Cmd::App(AppCmd::ReloadTox));
            }
            cmds
        },
        complete: Some(|_model, args| {
            if args.len() <= 1 {
                let prefix = args.first().copied().unwrap_or("");
                let keys = [
                    ("ipv6_enabled", "Toggle IPv6 support"),
                    ("udp_enabled", "Toggle UDP support"),
                    ("system_messages", "Configure system message types"),
                ];
                return keys
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix))
                    .map(|(k, d)| (k.to_string(), d.to_string()))
                    .collect();
            }
            if args.len() == 2 {
                let key = args[0];
                let prefix = args[1];
                if key == "system_messages" {
                    let values = [
                        ("Join", "Toggle Join messages"),
                        ("Leave", "Toggle Leave messages"),
                        ("Nick", "Toggle Nick change messages"),
                    ];
                    return values
                        .iter()
                        .filter(|(v, _)| v.to_lowercase().starts_with(&prefix.to_lowercase()))
                        .map(|(v, d)| (v.to_string(), d.to_string()))
                        .collect();
                }
                if key == "ipv6_enabled" || key == "udp_enabled" {
                    let values = [("true", "Enable"), ("false", "Disable")];
                    return values
                        .iter()
                        .filter(|(v, _)| v.starts_with(prefix))
                        .map(|(v, d)| (v.to_string(), d.to_string()))
                        .collect();
                }
            }
            vec![]
        }),
    },
    CommandDef {
        name: "block",
        args: (None, "[add|remove|list] [string]"),
        desc: (None, "Manage blocked strings (case-insensitive)"),
        exec: |model, args| {
            if args.is_empty() || args[0] == "list" {
                let items = vec![
                    "--- Blocked Strings ---".to_owned(),
                    format!("{:?}", model.config.blocked_strings),
                    "-----------------------".to_owned(),
                ];
                model.add_info_message(MessageContent::List(items));
                return vec![];
            }

            let subcmd = args[0];
            let s = args[1..].join(" ");

            if s.is_empty() && (subcmd == "add" || subcmd == "remove") {
                model.add_error_message(MessageContent::Text(format!(
                    "Usage: /block {} <string>",
                    subcmd
                )));
                return vec![];
            }

            match subcmd {
                "add" => {
                    if !model.config.blocked_strings.contains(&s) {
                        model.config.blocked_strings.push(s.clone());
                        model.saved_config.blocked_strings.push(s.clone());
                        model.add_status_message(MessageContent::Text(format!(
                            "Blocked string added: '{}'",
                            s
                        )));
                        vec![Cmd::IO(IOAction::SaveConfig(None))]
                    } else {
                        model.add_info_message(MessageContent::Text(format!(
                            "String '{}' is already blocked",
                            s
                        )));
                        vec![]
                    }
                }
                "remove" | "del" | "rm" => {
                    let old_len = model.config.blocked_strings.len();
                    model.config.blocked_strings.retain(|x| x != &s);
                    model.saved_config.blocked_strings.retain(|x| x != &s);
                    if model.config.blocked_strings.len() < old_len {
                        model.add_status_message(MessageContent::Text(format!(
                            "Blocked string removed: '{}'",
                            s
                        )));
                        vec![Cmd::IO(IOAction::SaveConfig(None))]
                    } else {
                        model.add_error_message(MessageContent::Text(format!(
                            "String '{}' not found in blocked list",
                            s
                        )));
                        vec![]
                    }
                }
                _ => {
                    model.add_error_message(MessageContent::Text(format!(
                        "Unknown subcommand: {}",
                        subcmd
                    )));
                    vec![]
                }
            }
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let subcmds = [
                    ("add", "Add a blocked string"),
                    ("remove", "Remove a blocked string"),
                    ("list", "List all blocked strings"),
                ];
                let prefix = args.first().copied().unwrap_or("");
                return subcmds
                    .iter()
                    .filter(|(s, _)| s.starts_with(prefix))
                    .map(|(s, d)| (s.to_string(), d.to_string()))
                    .collect();
            }
            if args.len() >= 2 && (args[0] == "remove" || args[0] == "del" || args[0] == "rm") {
                let prefix = args[1..].join(" ");
                return model
                    .config
                    .blocked_strings
                    .iter()
                    .filter(|s| s.starts_with(&prefix))
                    .map(|s| (s.to_string(), "Blocked String".to_string()))
                    .collect();
            }
            vec![]
        }),
    },
];
