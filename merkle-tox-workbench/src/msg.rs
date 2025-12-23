use crossterm::event::Event as CrosstermEvent;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Msg {
    Input(CrosstermEvent),
    Tick(Duration),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    Redraw,
    Quit,
}
