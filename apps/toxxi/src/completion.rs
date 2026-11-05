use crate::commands::COMMANDS;
use crate::model::{Model, WindowId};
use crate::widgets::command_menu::find_fuzzy_indices;

pub fn complete_command_arguments(input: &str, model: &Model) -> Vec<(String, String)> {
    if !input.starts_with('/') {
        return vec![];
    }

    let parts: Vec<&str> = input.split_whitespace().collect();

    // The command menu completes command names: we only complete arguments.
    if parts.is_empty() || (parts.len() == 1 && !input.ends_with(' ')) {
        return vec![];
    }

    let cmd_name = parts[0].trim_start_matches('/');
    for c in COMMANDS.iter() {
        if c.name == cmd_name
            && let Some(complete_fn) = c.complete
        {
            let mut args: Vec<&str> = parts[1..].to_vec();
            if input.ends_with(' ') {
                args.push("");
            }
            return complete_fn(model, &args);
        }
    }

    vec![]
}

/// Returns the friends a typed argument may mean, by name or key, as their
/// short key (what the argument becomes) and their name.
pub fn complete_friends(model: &Model, prefix: &str) -> Vec<(String, String)> {
    let prefix_lower = prefix.to_lowercase();
    let mut friends: Vec<_> = model
        .domain
        .friends
        .iter()
        .filter(|(pk, info)| {
            prefix.is_empty()
                || crate::utils::encode_hex(&pk.0).starts_with(&prefix_lower)
                || !find_fuzzy_indices(&info.name, prefix).is_empty()
        })
        .map(|(pk, info)| (crate::utils::short_key(pk), info.name.clone()))
        .collect();
    friends.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    friends
}

pub fn complete_text(input: &str, model: &Model) -> Vec<String> {
    // Complete the last word typed.
    let last_word = input.split_whitespace().last().unwrap_or("");
    if last_word.is_empty() {
        return vec![];
    }

    let mut candidates = Vec::new();

    if !last_word.is_empty() {
        let is_single_alphanumeric =
            last_word.len() == 1 && last_word.chars().next().is_some_and(char::is_alphanumeric);

        let mut seen_emojis = std::collections::HashSet::new();
        for &(name, emoji) in crate::emojis::EMOJIS {
            if is_single_alphanumeric && !name.to_lowercase().starts_with(&last_word.to_lowercase())
            {
                continue;
            }

            if name.to_lowercase().starts_with(&last_word.to_lowercase())
                && !model.config.hidden_emojis.iter().any(|h| h == emoji)
                && seen_emojis.insert(emoji)
            {
                // A single letter or digit doesn't complete the emoji names that
                // start with it: there are far too many.
                if is_single_alphanumeric
                    && name.len() > 1
                    && name.chars().next().is_some_and(char::is_alphanumeric)
                {
                    seen_emojis.remove(emoji);
                    continue;
                }

                candidates.push(emoji.to_string());
            }
        }
    }

    // Only offer names of people in the chat.
    let friend_name = |pk| model.domain.friends.get(pk).map(|info| info.name.as_str());
    let names: Vec<&str> = match model.active_window_id() {
        WindowId::Friend(pk) => [friend_name(&pk), Some(model.domain.self_name.as_str())]
            .into_iter()
            .flatten()
            .collect(),
        window_id @ (WindowId::Group(_) | WindowId::Conference(_)) => model
            .domain
            .conversations
            .get(&window_id)
            .map(|conv| {
                let self_name = conv.self_name.as_ref().unwrap_or(&model.domain.self_name);
                std::iter::once(self_name.as_str())
                    .chain(conv.peers.iter().map(|peer| peer.name.as_str()))
                    .collect()
            })
            .unwrap_or_default(),
        WindowId::Console | WindowId::Logs | WindowId::Files => model
            .domain
            .friends
            .values()
            .map(|info| info.name.as_str())
            .collect(),
    };
    let word = last_word.to_lowercase();
    candidates.extend(
        names
            .into_iter()
            .filter(|name| name.to_lowercase().starts_with(&word))
            .map(str::to_owned),
    );

    candidates.sort_by(|a, b| {
        let prio_a = crate::emojis::get_emoji_priority(a);
        let prio_b = crate::emojis::get_emoji_priority(b);
        match (prio_a, prio_b) {
            (Some(pa), Some(pb)) => pa.cmp(&pb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.cmp(b),
        }
    });
    candidates.dedup();
    candidates
}

pub fn get_replacement(original_input: &str, candidate: &str) -> String {
    if original_input.starts_with('/') {
        let parts: Vec<&str> = original_input.split_whitespace().collect();

        // Completing the command itself
        if (parts.len() <= 1 && !original_input.ends_with(' ')) || original_input == "/" {
            return format!("{} ", candidate);
        }

        // Completing an argument
        if let Some(last_space_idx) = original_input.rfind(' ') {
            let (prefix, _) = original_input.split_at(last_space_idx + 1);
            return format!("{}{}", prefix, candidate);
        }
    }

    // Replace the last word.
    if let Some(last_space_idx) = original_input.rfind(' ') {
        let (prefix, _) = original_input.split_at(last_space_idx + 1);
        format!("{}{}", prefix, candidate)
    } else {
        if !original_input.starts_with('/') && !crate::emojis::is_emoji(candidate) {
            return format!("{}: ", candidate);
        }
        candidate.to_owned()
    }
}

pub fn get_start_position(input: &str) -> usize {
    if input.starts_with('/') {
        let parts: Vec<&str> = input.split_whitespace().collect();

        // Completing the command itself
        if (parts.len() <= 1 && !input.ends_with(' ')) || input == "/" {
            return 0;
        }

        // Completing an argument
        if let Some(last_space_idx) = input.rfind(' ') {
            return last_space_idx + 1;
        }
    }

    // Replace the last word.
    if let Some(last_space_idx) = input.rfind(' ') {
        last_space_idx + 1
    } else {
        0
    }
}
