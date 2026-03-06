use std::io;
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use merkle_tox_bench::harness::SimulationHarness;
use merkle_tox_bench::headless;
use merkle_tox_bench::scenario::{self, Scenario};
use merkle_tox_bench::tui::{self, TuiState};

#[derive(Parser, Debug)]
#[command(
    name = "merkle-tox-bench",
    about = "Merkle-Tox network benchmark suite"
)]
struct Args {
    /// Run in headless mode (no TUI).
    #[arg(long)]
    headless: bool,

    /// Comma-separated list of scenario IDs to run (e.g., "1,2,6").
    #[arg(long)]
    scenarios: Option<String>,

    /// Save results as JSON baseline to this path.
    #[arg(long)]
    save: Option<String>,

    /// Load a baseline JSON for comparison.
    #[arg(long)]
    load: Option<String>,

    /// Output results as JSON to stdout.
    #[arg(long)]
    json: bool,

    /// RNG seed for determinism.
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let scenario_ids: Option<Vec<usize>> = args.scenarios.as_ref().map(|s| {
        s.split(',')
            .filter_map(|id| id.trim().parse().ok())
            .collect()
    });

    let scenarios = if let Some(ids) = &scenario_ids {
        scenario::scenarios_by_ids(ids)
    } else {
        scenario::all_scenarios()
    };

    if scenarios.is_empty() {
        eprintln!("No valid scenarios selected.");
        return Ok(());
    }

    if args.headless {
        run_headless_mode(&args, &scenarios)?;
    } else {
        run_tui_mode(&args, scenarios)?;
    }

    Ok(())
}

fn run_headless_mode(args: &Args, scenarios: &[Scenario]) -> io::Result<()> {
    let report = headless::run_headless(scenarios, args.seed);

    if args.json {
        headless::print_json(&report);
    } else {
        headless::print_summary(&report);
    }

    if let Some(save_path) = &args.save {
        headless::save_baseline(&report, save_path)?;
        eprintln!("Baseline saved to {}", save_path);
    }

    if let Some(load_path) = &args.load {
        match headless::load_baseline(load_path) {
            Ok(baseline) => headless::print_comparison(&report, &baseline),
            Err(e) => eprintln!("Failed to load baseline: {}", e),
        }
    }

    Ok(())
}

/// Tracks execution of scenario phases in the TUI event loop.
struct PhaseTracker {
    phase_idx: usize,
    phase_start: Duration,
    action_executed: bool,
}

impl PhaseTracker {
    fn new() -> Self {
        Self {
            phase_idx: 0,
            phase_start: Duration::ZERO,
            action_executed: false,
        }
    }
}

fn run_tui_mode(args: &Args, scenarios: Vec<Scenario>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut tui_state = TuiState::new(scenarios);
    let mut harness: Option<SimulationHarness> = None;
    let mut tracker: Option<PhaseTracker> = None;
    let seed = args.seed;
    let tick_rate = Duration::from_millis(16);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| {
            tui::render(f, &tui_state, harness.as_ref());
        })?;

        let timeout = if tui_state.running {
            tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::ZERO)
        } else {
            // Idle: block on input instead of busy-looping redraws.
            Duration::from_millis(500)
        };

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('j') | KeyCode::Right => {
                    if !tui_state.running {
                        tui_state.selected_scenario =
                            (tui_state.selected_scenario + 1) % tui_state.scenarios.len();
                        tui_state.finished = false;
                        harness = None;
                        tracker = None;
                    }
                }
                KeyCode::Char('k') | KeyCode::Left => {
                    if !tui_state.running {
                        tui_state.selected_scenario =
                            (tui_state.selected_scenario + tui_state.scenarios.len() - 1)
                                % tui_state.scenarios.len();
                        tui_state.finished = false;
                        harness = None;
                        tracker = None;
                    }
                }
                KeyCode::Enter => {
                    if !tui_state.running {
                        // Show "Setting up..." before the expensive harness creation.
                        tui_state.running = true;
                        tui_state.finished = false;
                        terminal.draw(|f| {
                            tui::render(f, &tui_state, None);
                        })?;

                        let scenario = tui_state.current_scenario().clone();
                        let h =
                            SimulationHarness::new(scenario.node_count, &scenario.network, seed);
                        harness = Some(h);
                        tracker = Some(PhaseTracker::new());
                    }
                }
                KeyCode::Char('n') => {
                    tui_state.running = false;
                    tui_state.finished = false;
                    harness = None;
                    tracker = None;
                    tui_state.selected_scenario =
                        (tui_state.selected_scenario + 1) % tui_state.scenarios.len();
                }
                KeyCode::Esc => {
                    // Stop current scenario
                    if tui_state.running {
                        tui_state.running = false;
                        tui_state.finished = true;
                        if let Some(h) = &harness {
                            tui_state.scenario_scores[tui_state.selected_scenario] =
                                Some(h.metrics.aggregated.score);
                        }
                    }
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();

            if tui_state.running
                && let (Some(h), Some(tr)) = (&mut harness, &mut tracker)
            {
                let scenario = tui_state.current_scenario().clone();
                let step = Duration::from_millis(10);

                for _ in 0..5 {
                    if !tr.action_executed
                        && let Some(phase) = scenario.phases.get(tr.phase_idx)
                    {
                        tr.phase_start = h.virtual_elapsed;
                        h.execute_action(&phase.action, &scenario);
                        tr.action_executed = true;
                    }

                    h.tick(step);

                    let phase_name = scenario
                        .phases
                        .get(tr.phase_idx)
                        .map(|p| p.name)
                        .unwrap_or("Done");

                    h.metrics.collect(
                        &h.nodes,
                        &h.conv_id,
                        h.virtual_elapsed,
                        phase_name,
                        tr.phase_idx,
                        scenario.timeout,
                    );

                    if let Some(phase) = scenario.phases.get(tr.phase_idx)
                        && h.virtual_elapsed - tr.phase_start >= phase.duration
                    {
                        tr.phase_idx += 1;
                        tr.action_executed = false;
                    }

                    let timed_out = h.virtual_elapsed >= scenario.timeout;
                    let all_done = h.metrics.aggregated.convergence_pct >= 99.9
                        && h.metrics.aggregated.all_blobs_complete
                        && tr.phase_idx >= scenario.phases.len().saturating_sub(1);
                    let phases_exhausted = tr.phase_idx >= scenario.phases.len();

                    if timed_out || all_done || phases_exhausted {
                        tui_state.running = false;
                        tui_state.finished = true;
                        tui_state.scenario_scores[tui_state.selected_scenario] =
                            Some(h.metrics.aggregated.score);
                        break;
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
