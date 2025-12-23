use std::error::Error;
use toxcore::tox::Tox;
use toxcore::tox::events::Event;
use toxcore::types::{ConferenceNumber, FriendNumber, GroupNumber, MessageType, PublicKey};

use merkle_tox_core::dag::ConversationId;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum CommandSource {
    Friend(FriendNumber),
    Group(GroupNumber),
    Conference(ConferenceNumber),
    MerkleTox(ConversationId),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CommandContext {
    pub source: CommandSource,
    pub sender_pk: PublicKey,
    pub message_type: MessageType,
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
