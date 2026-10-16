use crate::model::{MessageContent, MessageStatus, WindowId};
use crate::msg::{Cmd, ToxAction};
use toxcore::tox::{FriendNumber, ToxConnection};
use toxcore::types::MessageType;

use super::CommandDef;

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "query",
        args: (None, "<id>"),
        desc: (None, "Open a chat window for a friend"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text(
                    "Usage: /query <friend_id>".to_owned(),
                ));
                return vec![];
            }
            if let Ok(fid) = args[0].parse::<u32>() {
                let friend_number = FriendNumber(fid);
                if let Some(pk) = model.session.friend_numbers.get(&friend_number).cloned() {
                    let window_id = WindowId::Friend(pk);
                    model.ensure_friend_window(pk);
                    if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                        model.set_active_window(pos);
                    }
                } else {
                    model.add_error_message(MessageContent::Text(format!(
                        "Friend {} not found in session.",
                        fid
                    )));
                }
            } else {
                model.add_error_message(MessageContent::Text(
                    "Friend id must be a number.".to_owned(),
                ));
            }
            vec![]
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
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
            vec![]
        }),
    },
    CommandDef {
        name: "whois",
        args: (None, "<friend_id>"),
        desc: (None, "Show information about a friend"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text(
                    "Usage: /whois <friend_id>".to_owned(),
                ));
                return vec![];
            }
            if let Ok(fid) = args[0].parse::<u32>() {
                let friend_number = FriendNumber(fid);
                if let Some(pk) = model.session.friend_numbers.get(&friend_number) {
                    if let Some(info) = model.domain.friends.get(pk).cloned() {
                        let conn_str = match info.connection {
                            ToxConnection::TOX_CONNECTION_NONE => "Offline",
                            ToxConnection::TOX_CONNECTION_TCP => "Online (TCP)",
                            ToxConnection::TOX_CONNECTION_UDP => "Online (UDP)",
                        };
                        let list = vec![
                            format!("Friend {}", fid),
                            format!("  Name:   {}", info.name),
                            format!("  Status: {}", info.status_message),
                            format!("  Conn:   {}", conn_str),
                            format!("  PK:     {}", crate::utils::encode_hex(&pk.0)),
                        ];
                        model.add_info_message(MessageContent::List(list));
                    }
                } else {
                    model.add_error_message(MessageContent::Text(format!(
                        "Friend {} not found.",
                        fid
                    )));
                }
            } else {
                model.add_error_message(MessageContent::Text(
                    "Friend id must be a number.".to_owned(),
                ));
            }
            vec![]
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
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
            vec![]
        }),
    },
    CommandDef {
        name: "msg",
        args: (None, "<friend_id> <text>"),
        desc: (None, "Send a message"),
        exec: |model, args| {
            if args.len() < 2 {
                model.add_error_message(MessageContent::Text(
                    "Usage: /msg <friend_number> <message>".to_owned(),
                ));
                return vec![];
            }
            if let Ok(id) = args[0].parse::<u32>() {
                let friend_number = FriendNumber(id);
                if let Some(pk) = model.session.friend_numbers.get(&friend_number).cloned() {
                    let msg_content = args[1..].join(" ");
                    let (internal_id, msg_obj) = model.add_outgoing_friend_message(
                        pk,
                        MessageType::TOX_MESSAGE_TYPE_NORMAL,
                        msg_content.clone(),
                    );
                    let window_id = WindowId::Friend(pk);
                    let mut cmds: Vec<Cmd> =
                        model.record(window_id, &msg_obj).into_iter().collect();
                    if let Some(msg) =
                        model.mark_message_status(window_id, internal_id, MessageStatus::Sending)
                    {
                        cmds.extend(model.record(window_id, &msg));
                    }
                    if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                        model.set_active_window(pos);
                    }
                    cmds.push(Cmd::Tox(ToxAction::SendMessage(
                        pk,
                        MessageType::TOX_MESSAGE_TYPE_NORMAL,
                        msg_content.into_bytes(),
                        internal_id,
                    )));
                    cmds
                } else {
                    model.add_error_message(MessageContent::Text(format!(
                        "Friend {} not found in session.",
                        id
                    )));
                    vec![]
                }
            } else {
                model.add_error_message(MessageContent::Text("Invalid friend number".to_owned()));
                vec![]
            }
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().unwrap_or(&"");
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
            let action = args.join(" ");
            let window_id = model.ui.window_ids[model.ui.active_window_index];
            if window_id == WindowId::Console {
                model.add_error_message(MessageContent::Text(
                    "Cannot send action messages in the console window.".to_owned(),
                ));
                return vec![];
            }

            let (internal_id, msg_obj) = model.add_outgoing_message(
                window_id,
                MessageType::TOX_MESSAGE_TYPE_ACTION,
                action.clone(),
            );

            let mut cmds: Vec<Cmd> = model.record(window_id, &msg_obj).into_iter().collect();
            if let Some(msg) =
                model.mark_message_status(window_id, internal_id, MessageStatus::Sending)
            {
                cmds.extend(model.record(window_id, &msg));
            }

            match window_id {
                WindowId::Friend(pk) => {
                    cmds.push(Cmd::Tox(ToxAction::SendMessage(
                        pk,
                        MessageType::TOX_MESSAGE_TYPE_ACTION,
                        action.into_bytes(),
                        internal_id,
                    )));
                }
                WindowId::Group(chat_id) => {
                    cmds.push(Cmd::Tox(ToxAction::SendGroupMessage(
                        chat_id,
                        MessageType::TOX_MESSAGE_TYPE_ACTION,
                        action.into_bytes(),
                        internal_id,
                    )));
                }
                WindowId::Conference(conf_id) => {
                    cmds.push(Cmd::Tox(ToxAction::SendConferenceMessage(
                        conf_id,
                        MessageType::TOX_MESSAGE_TYPE_ACTION,
                        action.into_bytes(),
                        internal_id,
                    )));
                }
                _ => {}
            }
            cmds
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
                // Use session mappings to show numbers
                let mut mapping: Vec<_> = model.session.friend_numbers.iter().collect();
                mapping.sort_by_key(|(k, _)| k.0);

                for (num, pk) in mapping {
                    if let Some(info) = model.domain.friends.get(pk) {
                        let status_str = match info.connection {
                            ToxConnection::TOX_CONNECTION_NONE => "Offline",
                            ToxConnection::TOX_CONNECTION_TCP => "TCP",
                            ToxConnection::TOX_CONNECTION_UDP => "UDP",
                        };
                        list.push(format!(
                            "[{}] {} ({}) - {}",
                            num.0, info.name, status_str, info.status_message
                        ));
                    }
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
        args: (None, "add <tox_id> [msg] | remove <id>"),
        desc: (None, "Manage friends"),
        exec: |model, args| {
            if args.len() >= 2 && args[0] == "add" {
                let tox_id = args[1];
                let msg = if args.len() > 2 {
                    args[2..].join(" ")
                } else {
                    "Hello".to_owned()
                };
                model.add_status_message(MessageContent::Text(format!(
                    "Sent friend request to {} with message: {}",
                    tox_id, msg
                )));
                vec![Cmd::Tox(ToxAction::AddFriend(tox_id.to_owned(), msg))]
            } else if args.len() >= 2 && args[0] == "remove" {
                if let Ok(id) = args[1].parse::<u32>() {
                    let friend_number = FriendNumber(id);

                    if let Some(pk) = model.session.friend_numbers.get(&friend_number).cloned() {
                        if let Some(info) = model.domain.friends.get(&pk) {
                            let pk_hex = crate::utils::encode_hex(&pk.0);
                            model.add_status_message(MessageContent::Text(format!(
                                "Removed friend {} ({}) with public key: {}",
                                info.name, id, pk_hex
                            )));
                            model.remove_friend(pk)
                        } else {
                            vec![]
                        }
                    } else {
                        model.add_error_message(MessageContent::Text(format!(
                            "Friend {} not found in session.",
                            id
                        )));
                        vec![]
                    }
                } else {
                    model.add_error_message(MessageContent::Text(
                        "Invalid friend number".to_owned(),
                    ));
                    vec![]
                }
            } else {
                model.add_error_message(MessageContent::Text(
                    "Usage: /friend add <tox_id> [msg]".to_owned(),
                ));
                model.add_error_message(MessageContent::Text(
                    "       /friend remove <id>".to_owned(),
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
            vec![]
        }),
    },
];
