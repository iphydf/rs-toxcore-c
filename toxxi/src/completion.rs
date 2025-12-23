use crate::commands::COMMANDS;
use crate::model::Model;

pub fn complete_command_arguments(input: &str, model: &Model) -> Vec<(String, String)> {
    if !input.starts_with('/') {
        return vec![];
    }

    let parts: Vec<&str> = input.split_whitespace().collect();

    // If we are completing the command name, we return empty as CommandMenu handles this.
    // We only return candidates if we are completing arguments (more than 1 part or space after command).
    if parts.is_empty() || (parts.len() == 1 && !input.ends_with(' ')) {
        return vec![];
    }

    // If we are completing arguments
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

pub fn complete_text(input: &str, model: &Model) -> Vec<String> {
    // Friend name completion or Emoji completion
    // We complete based on the last word typed to support "Hello Alice" -> "Hello Alice"
    let last_word = input.split_whitespace().last().unwrap_or("");
    if last_word.is_empty() {
        return vec![];
    }

    let mut candidates = Vec::new();

    if !last_word.is_empty() {
        let is_single_alphanumeric =
            last_word.len() == 1 && last_word.chars().next().unwrap().is_alphanumeric();

        for &(name, emoji) in crate::emojis::EMOJIS {
            if is_single_alphanumeric && !name.to_lowercase().starts_with(&last_word.to_lowercase())
            {
                continue;
            }

            if name.to_lowercase().starts_with(&last_word.to_lowercase()) {
                // If it's a single alphanumeric character, only suggest if it's an exact match
                // or if we're not in a "potential name" context (but here we don't know).
                // Better: if single alphanumeric, only suggest if it's NOT just a prefix of a longer emoji name
                // that starts with a letter, UNLESS it's a symbol.
                if is_single_alphanumeric
                    && name.len() > 1
                    && name.chars().next().unwrap().is_alphanumeric()
                {
                    continue;
                }

                candidates.push(emoji.to_string());
            }
        }
    }

    for friend in model.domain.friends.values() {
        if friend
            .name
            .to_lowercase()
            .starts_with(&last_word.to_lowercase())
        {
            candidates.push(friend.name.clone());
        }
    }

    let active_id = model.active_window_id();
    if let Some(conv) = model.domain.conversations.get(&active_id) {
        let self_name = conv.self_name.as_ref().unwrap_or(&model.domain.self_name);
        if self_name
            .to_lowercase()
            .starts_with(&last_word.to_lowercase())
        {
            candidates.push(self_name.clone());
        }

        for peer in &conv.peers {
            if peer
                .name
                .to_lowercase()
                .starts_with(&last_word.to_lowercase())
            {
                candidates.push(peer.name.clone());
            }
        }
    }

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

    // Word replacement (replaces the last word with the candidate)
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

    // Word replacement
    if let Some(last_space_idx) = input.rfind(' ') {
        last_space_idx + 1
    } else {
        0
    }
}
