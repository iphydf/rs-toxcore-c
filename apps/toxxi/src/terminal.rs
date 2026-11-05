use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, Stdout};

pub struct TerminalHandle {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalHandle {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalHandle {
    fn drop(&mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "we can't do anything if the terminal can't be restored"
        )]
        let _ = disable_raw_mode();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "we can't do anything if the terminal can't be restored"
        )]
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableBracketedPaste
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "we can't do anything if the terminal can't be restored"
        )]
        let _ = self.terminal.show_cursor();
    }
}
