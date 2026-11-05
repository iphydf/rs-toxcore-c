use super::friend_arg;
use crate::completion::complete_friends;
use crate::model::{MessageContent, WindowId};
use crate::msg::{Cmd, ToxAction};
use crate::utils::parse_address;
use toxcore::tox::Connection;
use toxcore::types::MessageType;

use super::CommandDef;

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "query",
        args: (None, "<friend>"),
        desc: (None, "Open a chat window for a friend"),
        exec: |model, args| {
            let [friend] = args else {
                model.add_error_message(MessageContent::Text("Usage: /query <friend>".to_owned()));
                return vec![];
            };
            if let Some(pk) = friend_arg(model, friend) {
                let window_id = WindowId::Friend(pk);
                model.ensure_friend_window(pk);
                if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                    model.set_active_window(pos);
                }
            }
            vec![]
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                return complete_friends(model, prefix);
            }
            vec![]
        }),
    },
    CommandDef {
        name: "whois",
        args: (None, "[friend]"),
        desc: (
            None,
            "Show information about a friend, or the one in this chat",
        ),
        exec: |model, args| {
            let pk = match (args, model.active_window_id()) {
                ([], WindowId::Friend(pk)) => Some(pk),
                ([friend], _) => friend_arg(model, friend),
                _ => {
                    model.add_error_message(MessageContent::Text(
                        "Usage: /whois <friend>".to_owned(),
                    ));
                    None
                }
            };
            if let Some(pk) = pk
                && let Some(info) = model.domain.friends.get(&pk).cloned()
            {
                let conn_str = match info.connection {
                    Connection::None => "Offline",
                    Connection::Tcp => "Online (TCP)",
                    Connection::Udp => "Online (UDP)",
                };
                let list = vec![
                    format!("Friend {}", info.name),
                    format!("  Status: {}", info.status_message),
                    format!("  Conn:   {}", conn_str),
                    format!("  PK:     {}", crate::utils::encode_hex(&pk.0)),
                ];
                model.add_info_message(MessageContent::List(list));
            }
            vec![]
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                return complete_friends(model, prefix);
            }
            vec![]
        }),
    },
    CommandDef {
        name: "msg",
        args: (None, "<friend> <text>"),
        desc: (None, "Send a message"),
        exec: |model, args| {
            if args.len() < 2 {
                model.add_error_message(MessageContent::Text(
                    "Usage: /msg <friend> <message>".to_owned(),
                ));
                return vec![];
            }
            let Some(pk) = friend_arg(model, args[0]) else {
                return vec![];
            };
            // Send it from the friend's chat, as a line typed there.
            model.ensure_friend_window(pk);
            if let Some(pos) = model
                .ui
                .window_ids
                .iter()
                .position(|&w| w == WindowId::Friend(pk))
            {
                model.set_active_window(pos);
            }
            let prefix = format!("/msg {} ", args[0]);
            crate::update::send_line(model, &prefix, &args[1..].join(" "), MessageType::Normal)
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                return complete_friends(model, prefix);
            }
            vec![]
        }),
    },
    CommandDef {
        name: "me",
        args: (None, "<action>"),
        desc: (None, "Send an action message to the current window"),
        exec: |model, args| {
            if args.is_empty() {
                model
                    .add_error_message(MessageContent::Text("Usage: /me <action text>".to_owned()));
                return vec![];
            }
            crate::update::send_line(model, "/me ", &args.join(" "), MessageType::Action)
        },
        complete: None,
    },
    CommandDef {
        name: "friends",
        args: (None, ""),
        desc: (None, "List friends"),
        exec: |model, _args| {
            let mut list = vec!["--- Friend List ---".to_owned()];
            if model.domain.friends.is_empty() {
                list.push("No friends added yet.".to_owned());
            } else {
                let mut friends: Vec<_> = model.domain.friends.iter().collect();
                friends.sort_by(|a, b| a.1.name.cmp(&b.1.name).then_with(|| a.0.cmp(b.0)));

                for (pk, info) in friends {
                    let status_str = match info.connection {
                        Connection::None => "Offline",
                        Connection::Tcp => "TCP",
                        Connection::Udp => "UDP",
                    };
                    list.push(format!(
                        "[{}] {} ({}) - {}",
                        crate::utils::short_key(pk),
                        info.name,
                        status_str,
                        info.status_message
                    ));
                }
            }
            list.push("-------------------".to_owned());
            model.add_info_message(MessageContent::List(list));
            vec![]
        },
        complete: None,
    },
    CommandDef {
        name: "friend",
        args: (None, "add <tox_id> [msg] | remove <friend>"),
        desc: (None, "Manage friends"),
        exec: |model, args| {
            if args.len() >= 2 && args[0] == "add" {
                let tox_id = args[1];
                let address = match parse_address(tox_id) {
                    Ok(address) => address,
                    Err(problem) => {
                        model.add_error_message(MessageContent::Text(format!(
                            "Not a Tox ID: {problem}"
                        )));
                        return vec![];
                    }
                };
                let msg = if args.len() > 2 {
                    args[2..].join(" ")
                } else {
                    "Hello".to_owned()
                };
                model.add_status_message(MessageContent::Text(format!(
                    "Sent friend request to {} with message: {}",
                    tox_id, msg
                )));
                vec![Cmd::Tox(ToxAction::AddFriend(address, msg))]
            } else if args.len() >= 2 && args[0] == "remove" {
                let Some(pk) = friend_arg(model, args[1]) else {
                    return vec![];
                };
                model.add_status_message(MessageContent::Text(format!(
                    "Removed friend {} with public key: {}",
                    model.friend_name(&pk),
                    crate::utils::encode_hex(&pk.0)
                )));
                model.remove_friend(pk)
            } else {
                model.add_error_message(MessageContent::Text(
                    "Usage: /friend add <tox_id> [msg]".to_owned(),
                ));
                model.add_error_message(MessageContent::Text(
                    "       /friend remove <friend>".to_owned(),
                ));
                vec![]
            }
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
                let subs = [("add", "Add a new friend"), ("remove", "Remove a friend")];
                return subs
                    .iter()
                    .filter(|(s, _)| s.starts_with(prefix))
                    .map(|(s, d)| (s.to_string(), d.to_string()))
                    .collect();
            }
            if args.len() == 2 && args[0] == "remove" {
                let prefix = args[1];
                return complete_friends(model, prefix);
            }
            vec![]
        }),
    },
];
