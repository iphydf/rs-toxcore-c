use crate::model::{MessageContent, Model, PendingItem, WindowId};
use crate::msg::{Cmd, ToxAction};
use toxcore::tox::FriendNumber;

use super::CommandDef;

pub const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "close",
        args: (None, ""),
        desc: (
            Some("Close window (leave group/conf)"),
            "Close the current window (and leave if it's a group or conference)",
        ),
        exec: |model, _args| {
            let active_idx = model.ui.active_window_index;
            let window_id = model.ui.window_ids[active_idx];

            if window_id == WindowId::Console {
                model.add_error_message(MessageContent::Text(
                    "Cannot close the console window.".to_owned(),
                ));
                return vec![];
            }

            let cmds = model.close_window(window_id);

            model.add_status_message(MessageContent::Text("Window closed.".to_owned()));

            cmds
        },
        complete: None,
    },
    CommandDef {
        name: "group",
        args: (
            Some("create [name] | join ... | invite ..."),
            "create [name] | join <pk> [name] [pass] | invite <fid> | list",
        ),
        desc: (None, "Manage groups"),
        exec: |model, args| {
            match args {
                ["list", ..] => {
                    let mut list = vec!["--- Group List ---".to_owned()];
                    // Use session mappings to show numbers
                    let mut mapping: Vec<_> = model.session.group_numbers.iter().collect();
                    mapping.sort_by_key(|(k, _)| k.0);

                    for (num, chat_id) in mapping {
                        if let Some(conv) =
                            model.domain.conversations.get(&WindowId::Group(*chat_id))
                        {
                            list.push(format!("[{}] {}", num.0, conv.name));
                        }
                    }
                    list.push("------------------".to_owned());
                    model.add_info_message(MessageContent::List(list));
                    vec![]
                }
                ["create", name @ ..] => {
                    let name = if name.is_empty() {
                        "Group".to_owned()
                    } else {
                        name.join(" ")
                    };
                    model.add_status_message(MessageContent::Text(format!(
                        "Creating group: {}",
                        name
                    )));
                    vec![Cmd::Tox(ToxAction::CreateGroup(name))]
                }
                ["join", pk, rest @ ..] => {
                    let pk = (*pk).to_owned();
                    let name = rest.first().copied().unwrap_or("Group").to_owned();
                    let pass = rest.get(1).copied().unwrap_or("").to_owned();

                    model.add_status_message(MessageContent::Text(format!(
                        "Requested to join group {} ({})",
                        pk, name
                    )));
                    vec![Cmd::Tox(ToxAction::JoinGroup(pk, name, pass))]
                }
                ["invite", fid_str, ..] => {
                    if let Ok(fid) = fid_str.parse::<u32>() {
                        let friend_number = FriendNumber(fid);
                        let window_id = model.active_window_id();

                        if let WindowId::Group(chat_id) = window_id {
                            if let Some(pk) =
                                model.session.friend_numbers.get(&friend_number).cloned()
                            {
                                model.add_status_message(MessageContent::Text(format!(
                                    "Inviting friend {} to group",
                                    fid
                                )));
                                vec![Cmd::Tox(ToxAction::InviteFriendToGroup(chat_id, pk))]
                            } else {
                                model.add_error_message(MessageContent::Text(format!(
                                    "Friend {} not found in session.",
                                    fid
                                )));
                                vec![]
                            }
                        } else {
                            model.add_error_message(MessageContent::Text(
                                "You must be in a group window to invite someone.".to_owned(),
                            ));
                            vec![]
                        }
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid friend number".to_owned(),
                        ));
                        vec![]
                    }
                }
                _ => {
                    model.add_error_message(MessageContent::Text(
                        "Usage: /group join <pk> [name] [pass]".to_owned(),
                    ));
                    model.add_error_message(MessageContent::Text(
                        "       /group invite <friend_id>".to_owned(),
                    ));
                    vec![]
                }
            }
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().copied().unwrap_or("");
                let subs = [
                    ("create", "Create a new group"),
                    ("join", "Join a group by ID"),
                    ("invite", "Invite a friend to the group"),
                    ("list", "List all groups"),
                ];
                return subs
                    .iter()
                    .filter(|(s, _)| s.starts_with(prefix))
                    .map(|(s, d)| (s.to_string(), d.to_string()))
                    .collect();
            }
            if args.len() == 2 && args[0] == "invite" {
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
    CommandDef {
        name: "conference",
        args: (
            Some("create | join ... | invite ..."),
            "create | join <fid> <cookie> | invite <fid> | list",
        ),
        desc: (None, "Manage conferences"),
        exec: |model, args| {
            match args {
                ["list", ..] => {
                    let mut list = vec!["--- Conference List ---".to_owned()];
                    // Use session mappings
                    let mut mapping: Vec<_> = model.session.conference_numbers.iter().collect();
                    mapping.sort_by_key(|(k, _)| k.0);

                    for (num, cid) in mapping {
                        if let Some(conv) =
                            model.domain.conversations.get(&WindowId::Conference(*cid))
                        {
                            list.push(format!("[{}] {}", num.0, conv.name));
                        }
                    }
                    list.push("-----------------------".to_owned());
                    model.add_info_message(MessageContent::List(list));
                    vec![]
                }
                ["create", ..] => {
                    model.add_status_message(MessageContent::Text(
                        "Creating conference...".to_owned(),
                    ));
                    vec![Cmd::Tox(ToxAction::CreateConference)]
                }
                ["join", fid_str, cookie, ..] => {
                    if let Ok(fid) = fid_str.parse::<u32>() {
                        let friend_number = FriendNumber(fid);
                        if let Some(pk) = model.session.friend_numbers.get(&friend_number).cloned()
                        {
                            model.add_status_message(MessageContent::Text(format!(
                                "Joining conference via friend {} with cookie {}",
                                fid, cookie
                            )));
                            vec![Cmd::Tox(ToxAction::JoinConference(
                                pk,
                                (*cookie).to_owned(),
                                None,
                            ))]
                        } else {
                            model.add_error_message(MessageContent::Text(format!(
                                "Friend {} not found in session.",
                                fid
                            )));
                            vec![]
                        }
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid friend number".to_owned(),
                        ));
                        vec![]
                    }
                }
                ["invite", fid_str, ..] => {
                    if let Ok(fid) = fid_str.parse::<u32>() {
                        let friend_number = FriendNumber(fid);
                        let window_id = model.active_window_id();

                        if let WindowId::Conference(conf_id) = window_id {
                            if let Some(pk) =
                                model.session.friend_numbers.get(&friend_number).cloned()
                            {
                                model.add_status_message(MessageContent::Text(format!(
                                    "Inviting friend {} to conference",
                                    fid
                                )));
                                vec![Cmd::Tox(ToxAction::InviteFriendToConference(conf_id, pk))]
                            } else {
                                model.add_error_message(MessageContent::Text(format!(
                                    "Friend {} not found in session.",
                                    fid
                                )));
                                vec![]
                            }
                        } else {
                            model.add_error_message(MessageContent::Text(
                                "You must be in a conference window to invite someone.".to_owned(),
                            ));
                            vec![]
                        }
                    } else {
                        model.add_error_message(MessageContent::Text(
                            "Invalid friend number".to_owned(),
                        ));
                        vec![]
                    }
                }
                _ => {
                    model.add_error_message(MessageContent::Text(
                        "Usage: /conference join <friend_id> <cookie>".to_owned(),
                    ));
                    model.add_error_message(MessageContent::Text(
                        "       /conference invite <friend_id>".to_owned(),
                    ));
                    vec![]
                }
            }
        },
        complete: Some(|model, args| {
            if args.len() <= 1 {
                let prefix = args.first().copied().unwrap_or("");
                let subs = [
                    ("create", "Create a new conference"),
                    ("join", "Join a conference"),
                    ("invite", "Invite a friend"),
                    ("list", "List active conferences"),
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
            vec![]
        }),
    },
    CommandDef {
        name: "topic",
        args: (None, "<topic>"),
        desc: (None, "Set the topic of the current group or conference"),
        exec: |model, args| {
            if args.is_empty() {
                model.add_error_message(MessageContent::Text(
                    "Usage: /topic <new topic>".to_owned(),
                ));
                return vec![];
            }
            let topic = args.join(" ");
            let window_id = model.active_window_id();

            match window_id {
                WindowId::Group(chat_id) => {
                    model.add_status_message(MessageContent::Text(format!(
                        "Setting group topic to: {}",
                        topic
                    )));
                    vec![Cmd::Tox(ToxAction::SetGroupTopic(chat_id, topic))]
                }
                WindowId::Conference(conf_id) => {
                    model.add_status_message(MessageContent::Text(format!(
                        "Setting conference title to: {}",
                        topic
                    )));
                    vec![Cmd::Tox(ToxAction::SetConferenceTopic(conf_id, topic))]
                }
                _ => {
                    model.add_error_message(MessageContent::Text(
                        "You must be in a group or conference window to set the topic.".to_owned(),
                    ));
                    vec![]
                }
            }
        },
        complete: None,
    },
    CommandDef {
        name: "pending",
        args: (None, ""),
        desc: (None, "List pending friend requests and invites"),
        exec: |model, _args| {
            let mut list = vec!["--- Pending Items ---".to_owned()];
            if model.domain.pending_items.is_empty() {
                list.push("No pending items.".to_owned());
            } else {
                for (i, item) in model.domain.pending_items.iter().enumerate() {
                    let msg = match item {
                        PendingItem::FriendRequest { pk, message } => {
                            let pk_hex = crate::utils::encode_hex(&pk.0);
                            format!("[{}] Friend Request from {} : {}", i, pk_hex, message)
                        }
                        PendingItem::GroupInvite {
                            friend, group_name, ..
                        } => {
                            format!(
                                "[{}] Group Invite to '{}' from Friend {}",
                                i,
                                group_name,
                                crate::utils::encode_hex(&friend.0[0..4])
                            )
                        }
                        PendingItem::ConferenceInvite { friend, .. } => {
                            format!(
                                "[{}] Conference Invite from Friend {}",
                                i,
                                crate::utils::encode_hex(&friend.0[0..4])
                            )
                        }
                    };
                    list.push(msg);
                }
            }
            list.push("----------------------".to_owned());
            model.add_info_message(MessageContent::List(list));
            vec![]
        },
        complete: None,
    },
    CommandDef {
        name: "accept",
        args: (None, "[index] [password]"),
        desc: (
            None,
            "Accept a pending request or invite, with the group's password if it has one",
        ),
        exec: |model, args| {
            if model.domain.pending_items.is_empty() {
                model.add_error_message(MessageContent::Text("No pending items.".to_owned()));
                return vec![];
            }

            let index = if args.is_empty() {
                0
            } else if let Ok(idx) = args[0].parse::<usize>() {
                idx
            } else {
                model.add_error_message(MessageContent::Text("Invalid index.".to_owned()));
                return vec![];
            };

            if index >= model.domain.pending_items.len() {
                model.add_error_message(MessageContent::Text("Index out of bounds.".to_owned()));
                return vec![];
            }

            let item = model.domain.pending_items[index].clone();
            // A recorded invite stays pending here until it's joined, and a
            // request until its friend is added.
            let invite = model.invite_of(&item);
            if invite.is_none() && !matches!(item, PendingItem::FriendRequest { .. }) {
                model.domain.pending_items.remove(index);
            }
            match item {
                PendingItem::FriendRequest { pk, .. } => {
                    vec![Cmd::Tox(ToxAction::AcceptFriend(pk))]
                }
                PendingItem::GroupInvite {
                    friend,
                    invite_data,
                    group_name,
                    ..
                } => {
                    // Friend is a PublicKey. We can look up their info (like name) directly.
                    if let Some(info) = model.domain.friends.get(&friend) {
                        model.add_status_message(MessageContent::Text(format!(
                            "Accepting group invite for '{}' from {}",
                            group_name, info.name
                        )));
                    } else {
                        model.add_status_message(MessageContent::Text(format!(
                            "Accepting group invite for '{}' from {}",
                            group_name,
                            crate::utils::encode_hex(&friend.0[0..4])
                        )));
                    }

                    let password = args.get(1).map(|password| (*password).to_owned());
                    match invite {
                        Some(invite) => crate::sync::invites::answer(model, invite, true, password),
                        None => vec![Cmd::Tox(ToxAction::AcceptGroupInvite(
                            friend,
                            invite_data,
                            group_name,
                            password.unwrap_or_default(),
                            None,
                        ))],
                    }
                }
                PendingItem::ConferenceInvite { friend, cookie, .. } => {
                    if let Some(info) = model.domain.friends.get(&friend) {
                        model.add_status_message(MessageContent::Text(format!(
                            "Accepting conference invite from {}",
                            info.name
                        )));
                    }
                    match invite {
                        Some(invite) => crate::sync::invites::answer(model, invite, true, None),
                        None => vec![Cmd::Tox(ToxAction::JoinConference(friend, cookie, None))],
                    }
                }
            }
        },
        complete: Some(|model, _args| {
            (0..model.domain.pending_items.len())
                .map(|i| (i.to_string(), "Pending Item".to_string()))
                .collect()
        }),
    },
    CommandDef {
        name: "reject",
        args: (None, "[index]"),
        desc: (None, "Reject a pending request or invite"),
        exec: |model, args| {
            if model.domain.pending_items.is_empty() {
                model.add_error_message(MessageContent::Text("No pending items.".to_owned()));
                return vec![];
            }

            let index = if args.is_empty() {
                0
            } else if let Ok(idx) = args[0].parse::<usize>() {
                idx
            } else {
                model.add_error_message(MessageContent::Text("Invalid index.".to_owned()));
                return vec![];
            };

            if index >= model.domain.pending_items.len() {
                model.add_error_message(MessageContent::Text("Index out of bounds.".to_owned()));
                return vec![];
            }

            let item = model.domain.pending_items.remove(index);
            model.add_status_message(MessageContent::Text("Item rejected.".to_owned()));
            match model.invite_of(&item) {
                Some(invite) => crate::sync::invites::answer(model, invite, false, None),
                None => vec![],
            }
        },
        complete: Some(|model, _args| {
            (0..model.domain.pending_items.len())
                .map(|i| (i.to_string(), "Pending Item".to_string()))
                .collect()
        }),
    },
    CommandDef {
        name: "ignore",
        args: (None, "<name|peer_id>"),
        desc: (None, "Toggle ignore for a peer in the current group"),
        exec: |model, args| handle_ignore_command(model, args, true), // ignore
        complete: Some(complete_ignore_command),
    },
    CommandDef {
        name: "unignore",
        args: (None, "<name|peer_id>"),
        desc: (None, "Stop ignoring a peer in the current group"),
        exec: |model, args| handle_ignore_command(model, args, false), // unignore
        complete: Some(complete_ignore_command),
    },
];

fn handle_ignore_command(model: &mut Model, args: &[&str], ignore: bool) -> Vec<Cmd> {
    if args.is_empty() {
        let cmd = if ignore { "/ignore" } else { "/unignore" };
        model.add_error_message(MessageContent::Text(format!(
            "Usage: {} <name|public_key>",
            cmd
        )));
        return vec![];
    }

    let target = args.join(" ");
    let window_id = model.active_window_id();
    let WindowId::Group(chat_id) = window_id else {
        model.add_error_message(MessageContent::Text(
            "You must be in a group window to ignore someone.".to_owned(),
        ));
        return vec![];
    };

    let Some(conv) = model.domain.conversations.get_mut(&window_id) else {
        return vec![];
    };

    // Find peer by Name or Public Key (hex)
    let peer_info = conv
        .peers
        .iter_mut()
        .find(|p| p.name == target || crate::utils::encode_hex(&p.id.0.0) == target);

    let (pk, name, is_ignored) = if let Some(peer) = peer_info {
        let pk = peer.id.0;
        let new_state = ignore;

        if peer.is_ignored == new_state {
            let msg = if new_state {
                format!("Already ignoring {}", peer.name)
            } else {
                format!("Already not ignoring {}", peer.name)
            };
            model.add_info_message(MessageContent::Text(msg));
            return vec![];
        }

        peer.is_ignored = new_state;
        if peer.is_ignored {
            conv.ignored_peers.insert(pk);
        } else {
            conv.ignored_peers.remove(&pk);
        }
        (pk, peer.name.clone(), peer.is_ignored)
    } else {
        model.add_error_message(MessageContent::Text(format!("Peer not found: {}", target)));
        return vec![];
    };

    let status_msg = if is_ignored {
        format!("Now ignoring {}", name)
    } else {
        format!("Stopped ignoring {}", name)
    };
    model.add_status_message(MessageContent::Text(status_msg));
    vec![Cmd::Tox(ToxAction::SetGroupPeerIgnore(
        chat_id, pk, is_ignored,
    ))]
}

fn complete_ignore_command(model: &Model, args: &[&str]) -> Vec<(String, String)> {
    let window_id = model.active_window_id();
    let mut candidates = Vec::new();
    if let Some(conv) = model.domain.conversations.get(&window_id) {
        let prefix = args.join(" ");
        for peer in &conv.peers {
            if peer.name.starts_with(&prefix) {
                candidates.push((peer.name.clone(), "Peer".to_string()));
            }
            let pk_str = crate::utils::encode_hex(&peer.id.0.0);
            if pk_str.starts_with(&prefix) {
                candidates.push((pk_str, format!("Peer: {}", peer.name)));
            }
        }
    }
    candidates
}
