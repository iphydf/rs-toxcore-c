use crate::plugin::Plugin;
use std::error::Error;
use toxcore::tox::Tox;
use toxcore::tox::events::Event;
use toxcore::types::{ConferenceNumber, GroupNumber};

pub struct Forwarder;

impl Plugin for Forwarder {
    fn name(&self) -> &str {
        "forwarder"
    }

    fn on_event(&mut self, bot: &Tox, event: &Event) -> Result<(), Box<dyn Error>> {
        match event {
            Event::GroupMessage(e) => {
                let group_number = e.group_number();
                let peer_id = e.peer_id();
                let message = e.message();
                let message_type = e.message_type();

                if message.starts_with(b"!") || message.starts_with(b"~") {
                    return Ok(());
                }

                let group = bot.group(group_number);
                let peer_name = group.peer_name(peer_id)?;
                let peer_name_str = String::from_utf8_lossy(&peer_name);

                let formatted = format!("<{}> {}", peer_name_str, String::from_utf8_lossy(message));

                // Forward to Conference 0 if it exists
                // In a more robust design, we'd have a mapping, but original bot uses 0.
                let conf = bot.conference(ConferenceNumber(0));
                let _ = conf.send_message(message_type, formatted.as_bytes());
            }
            Event::ConferenceMessage(e) => {
                let conference_number = e.conference_number();
                let peer_number = e.peer_number();
                let message = e.message();
                let message_type = e.message_type();

                let conf = bot.conference(conference_number);
                if conf.peer_number_is_ours(peer_number)? {
                    return Ok(());
                }

                if message.starts_with(b"!") || message.starts_with(b"~") {
                    return Ok(());
                }

                let peer_name = conf.peer_name(peer_number)?;
                let peer_name_str = String::from_utf8_lossy(&peer_name);

                let formatted = format!("<{}> {}", peer_name_str, String::from_utf8_lossy(message));

                // Forward to Group 0 if it exists
                let group = bot.group(GroupNumber(0));
                let _ = group.send_message(message_type, formatted.as_bytes());
            }
            _ => {}
        }
        Ok(())
    }
}
