use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use std::time::{Duration, Instant};

use merkle_tox_workbench::model::{Args, Model};
use merkle_tox_workbench::msg::{Cmd, Msg};
use merkle_tox_workbench::ui;
use merkle_tox_workbench::update;

fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut model = Model::new(
        args.nodes,
        args.real_nodes,
        args.rate,
        args.step,
        args.seed,
        args.topology,
    );
    model.table_state.select(Some(0));

    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui::ui(f, &mut model))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            let event = event::read()?;
            let cmds = update::update(&mut model, Msg::Input(event));
            if cmds.contains(&Cmd::Quit) {
                break;
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let _ = update::update(&mut model, Msg::Tick(tick_rate));
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
