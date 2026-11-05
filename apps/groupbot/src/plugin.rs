use std::error::Error;
use toxcore::tox::Tox;
use toxcore::tox::events::Event;
use toxcore::types::{ConferenceNumber, FriendNumber, GroupNumber, PublicKey};

#[derive(Clone, Debug)]
pub enum CommandSource {
    Friend(FriendNumber),
    Group(GroupNumber),
    Conference(ConferenceNumber),
}

#[derive(Clone, Debug)]
pub struct CommandContext {
    pub source: CommandSource,
    pub sender_pk: PublicKey,
}

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;

    /// Handle any Tox event.
    fn on_event(&mut self, _bot: &Tox, _event: &Event) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Handle commands starting with `!`.
    fn on_command(
        &mut self,
        _bot: &Tox,
        _context: &CommandContext,
        _args: &[String],
    ) -> Result<Option<String>, Box<dyn Error>> {
        Ok(None)
    }
}
