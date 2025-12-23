use crate::plugin::{CommandContext, Plugin};
use std::error::Error;
use toxcore::tox::Tox;

pub struct Echo;

impl Plugin for Echo {
    fn name(&self) -> &str {
        "echo"
    }

    fn on_command(
        &mut self,
        _bot: &Tox,
        _context: &CommandContext,
        args: &[String],
    ) -> Result<Option<String>, Box<dyn Error>> {
        Ok(Some(format!("{:?}", args)))
    }
}
