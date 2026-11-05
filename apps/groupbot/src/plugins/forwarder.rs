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
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "the bot ignores other events"
        )]
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

                // TODO(iphydf): Map groups to conferences instead of using 0.
                let conf = bot.conference(ConferenceNumber(0));
                if let Err(e) = conf.send_message(message_type, formatted.as_bytes()) {
                    tracing::error!("Failed to forward to the conference: {}", e);
                }
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

                let group = bot.group(GroupNumber(0));
                if let Err(e) = group.send_message(message_type, formatted.as_bytes()) {
                    tracing::error!("Failed to forward to the group: {}", e);
                }
            }
            _ => {}
        }
        Ok(())
    }
}
