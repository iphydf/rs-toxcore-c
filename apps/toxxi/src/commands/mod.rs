use std::sync::LazyLock;

use crate::model::{MessageContent, Model};
use crate::msg::Cmd;
use crate::widgets::command_menu::Command;
use toxcore::types::PublicKey;

pub mod account;
pub mod chat;
pub mod io;
pub mod multi_user;
pub mod system;

/// The friend an argument names: by name, where no other friend has it, or by
/// the start of their key, as `/friends` shows it. Says so when it names no
/// one, or more than one.
pub fn friend_arg(model: &mut Model, arg: &str) -> Option<PublicKey> {
    let arg_lower = arg.to_lowercase();
    let mut found: Vec<(&str, PublicKey)> = model
        .domain
        .friends
        .iter()
        .filter(|(pk, info)| {
            info.name.to_lowercase() == arg_lower
                || crate::utils::encode_hex(&pk.0).starts_with(&arg_lower)
        })
        .map(|(pk, info)| (info.name.as_str(), *pk))
        .collect();
    found.sort();
    let error = match found.as_slice() {
        [(_, pk)] => return Some(*pk),
        [] => format!("No friend is called {arg} or has a key starting with it."),
        _ => {
            let friends: Vec<_> = found
                .iter()
                .map(|(name, pk)| format!("{} {}", crate::utils::short_key(pk), name))
                .collect();
            format!("{arg} could be: {}", friends.join(", "))
        }
    };
    model.add_error_message(MessageContent::Text(error));
    None
}

pub type CompletionFn = fn(&Model, &[&str]) -> Vec<(String, String)>;

#[derive(Clone, Copy)]
pub struct CommandDef {
    pub name: &'static str,
    pub args: (Option<&'static str>, &'static str), // (Short, Long)
    pub desc: (Option<&'static str>, &'static str), // (Short, Long)
    pub exec: fn(&mut Model, &[&str]) -> Vec<Cmd>,
    pub complete: Option<CompletionFn>,
}

impl CommandDef {
    pub fn to_widget_command(&self) -> Command {
        let (short_args, long_args) = self.args;
        let (short_desc, long_desc) = self.desc;

        let mut cmd = Command::new(self.name, long_desc).args(long_args);
        if let Some(sa) = short_args {
            cmd = cmd.short_args(sa);
        }
        if let Some(sd) = short_desc {
            cmd = cmd.short_description(sd);
        }
        cmd
    }
}

pub static COMMANDS: LazyLock<Vec<CommandDef>> = LazyLock::new(|| {
    let mut v = Vec::new();

    // The help command must be in the same list.
    v.push(CommandDef {
        name: "help",
        args: (None, ""),
        desc: (None, "Display this help message"),
        exec: |model, _args| {
            let mut help_items = vec!["Available commands:".to_owned()];
            for c in COMMANDS.iter() {
                let (_, long_args) = c.args;
                let (_, long_desc) = c.desc;
                if long_args.is_empty() {
                    help_items.push(format!("  /{} - {}", c.name, long_desc));
                } else {
                    help_items.push(format!("  /{} {} - {}", c.name, long_args, long_desc));
                }
            }
            model.add_info_message(MessageContent::List(help_items));
            vec![]
        },
        complete: Some(|_model, _args| vec![]),
    });

    v.extend_from_slice(account::COMMANDS);
    v.extend_from_slice(chat::COMMANDS);
    v.extend_from_slice(io::COMMANDS);
    v.extend_from_slice(multi_user::COMMANDS);
    v.extend_from_slice(system::COMMANDS);

    v.sort_by_key(|c| c.name);
    v
});
