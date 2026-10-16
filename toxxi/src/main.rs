use clap::Parser;
use crossterm::event::{self};
use directories::ProjectDirs;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use toxxi::model::{self, ConsoleMessageType};
use toxxi::msg::{AppCmd, Cmd, IOEvent, Msg, SystemEvent, ToxEvent};
use toxxi::script::{ScriptController, ScriptRequest, ScriptResponse};
use toxxi::terminal::TerminalHandle;
use toxxi::ui::draw;
use toxxi::update::{handle_enter, shows, update};
use toxxi::{app, bootstrap, config, io, worker};

/// Toxxi - A Terminal Tox Client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable IPv6
    #[arg(long)]
    ipv6: Option<bool>,

    /// Enable UDP
    #[arg(long)]
    udp: Option<bool>,

    /// Start port range
    #[arg(long)]
    start_port: Option<u16>,

    /// End port range
    #[arg(long)]
    end_port: Option<u16>,

    /// Path to savedata file (optional)
    #[arg(short, long)]
    savedata: Option<String>,

    /// Path to Rhai script file for headless execution (optional)
    #[arg(long)]
    script: Option<String>,
}

struct Runtime {
    should_stop: Arc<AtomicBool>,
    tick_handle: tokio::task::JoinHandle<()>,
    input_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Runtime {
    fn new(tx: mpsc::Sender<Msg>, script_mode: bool) -> Self {
        let should_stop = Arc::new(AtomicBool::new(false));

        let should_stop_tick = should_stop.clone();
        let tx_tick = tx.clone();
        let tick_handle = tokio::spawn(async move {
            loop {
                if should_stop_tick.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(app::TICK_RATE).await;
                if tx_tick.send(Msg::System(SystemEvent::Tick)).is_err() {
                    break;
                }
            }
        });

        let mut input_handle = None;
        if !script_mode {
            let should_stop_input = should_stop.clone();
            let tx_input = tx.clone();
            input_handle = Some(tokio::spawn(async move {
                loop {
                    if should_stop_input.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(true) = event::poll(Duration::from_millis(100))
                        && let Ok(event) = event::read()
                        && tx_input.send(Msg::Input(event)).is_err()
                    {
                        break;
                    }
                }
            }));
        }

        Self {
            should_stop,
            tick_handle,
            input_handle,
        }
    }

    async fn shutdown(self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.input_handle {
            let _ = handle.await;
        }
        let _ = self.tick_handle.await;
    }
}

fn log_headless(msg: &Msg) {
    match msg {
        Msg::Tox(tox_event) => match tox_event {
            ToxEvent::Message(f, _t, m) => {
                println!("[MSG] Friend {}: {}", f.0, toxxi::text::of(m))
            }
            ToxEvent::ConnectionStatus(s) => println!("[CONN] Self: {:?}", s),
            ToxEvent::FriendStatus(f, s, _) => {
                println!("[STATUS] Friend {}: {:?}", f.0, s)
            }
            ToxEvent::GroupTopic(g, t, _) => println!("[TOPIC] Group {}: {}", g.0, t),
            ToxEvent::ConferenceTitle(c, t, _) => {
                println!("[TOPIC] Conference {}: {}", c.0, t)
            }
            ToxEvent::FileRecv(f, file, kind, size, filename) => {
                println!(
                    "[FILE] Recv from {}: {} (ID: {}, size: {}, kind: {})",
                    f.0, filename, file, size, kind
                )
            }
            _ => {}
        },
        Msg::IO(io_event) => match io_event {
            IOEvent::FileStarted(f, file, path, _) => {
                println!("[FILE] Started with {}: {} (ID: {})", f, path, file)
            }
            IOEvent::FileFinished(f, file, _) => {
                println!("[FILE] Finished with {}: ID {}", f, file)
            }
            _ => {}
        },
        Msg::System(SystemEvent::Log {
            severity,
            context: _,
            message,
        }) => println!("[LOG] [{:?}] {}", severity, message),
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let savedata_path: Option<PathBuf> = if let Some(path_str) = &args.savedata {
        Some(PathBuf::from(path_str))
    } else {
        ProjectDirs::from("", "", "toxxi").map(|proj_dirs| {
            let data_dir = proj_dirs.data_dir();
            let _ = fs::create_dir_all(data_dir);
            data_dir.join("savedata.tox")
        })
    };

    let config_dir = ProjectDirs::from("", "", "toxxi")
        .map(|proj_dirs| proj_dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let saved_config = config::load_config(&config_dir);
    let mut runtime_config = saved_config.clone();

    if let Some(v) = args.ipv6 {
        runtime_config.ipv6_enabled = v;
    }
    if let Some(v) = args.udp {
        runtime_config.udp_enabled = v;
    }
    if let Some(v) = args.start_port {
        runtime_config.start_port = v;
    }
    if let Some(v) = args.end_port {
        runtime_config.end_port = v;
    }

    let initial_state = worker::get_initial_state(&savedata_path)?;

    let (nodes, _bootstrap_logs) = bootstrap::setup_nodes(&config_dir).await;

    let (tx, rx) = mpsc::channel();
    let runtime = Runtime::new(tx.clone(), args.script.is_some());

    let (tx_tox_action, rx_tox_action) = mpsc::channel();
    let (tx_io, rx_io) = mpsc::channel();

    let mut model = model::load_or_initialize(
        &config_dir,
        model::ToxSelfInfo {
            tox_id: initial_state.tox_id,
            name: initial_state.name,
            status_msg: initial_state.status_message,
            status_type: initial_state.status_type,
        },
        initial_state.friends,
        initial_state.groups,
        initial_state.conferences,
        saved_config,
        runtime_config,
    );

    let tox_handle = worker::spawn_tox(
        tx.clone(),
        tx_io.clone(),
        rx_tox_action,
        savedata_path.clone(),
        &model.config,
        nodes.clone(),
        config_dir.clone(),
    );

    let downloads_dir = if let Some(dir) = &model.config.downloads_directory {
        PathBuf::from(dir)
    } else if let Some(user_dirs) = directories::UserDirs::new() {
        if let Some(dl) = user_dirs.download_dir() {
            dl.to_path_buf()
        } else {
            config_dir.join("downloads")
        }
    } else {
        config_dir.join("downloads")
    };

    let screenshots_dir = if let Some(user_dirs) = directories::UserDirs::new() {
        if let Some(pic) = user_dirs.picture_dir() {
            pic.to_path_buf()
        } else {
            config_dir.join("screenshots")
        }
    } else {
        config_dir.join("screenshots")
    };

    let _io_handle = io::spawn_io_worker(
        tx.clone(),
        tx_tox_action.clone(),
        rx_io,
        config_dir.clone(),
        downloads_dir.clone(),
    );

    let mut ctx = app::AppContext {
        tx_tox_action,
        tox_handle,
        savedata_path,
        config_dir,
        quit_at: None,
        tx_io,
        screenshots_dir,
    };

    let mut script_ctrl = args
        .script
        .map(|path| ScriptController::new(PathBuf::from(path), tx.clone()));

    let mut tui = if script_ctrl.is_none() {
        let handle = TerminalHandle::new()?;

        model.add_console_message(ConsoleMessageType::Info, "Welcome to Toxxi!".to_owned());
        model.add_console_message(
            ConsoleMessageType::Info,
            format!("Tox ID: {}", model.domain.tox_id),
        );
        if let Some(path) = &ctx.savedata_path {
            model.add_console_message(
                ConsoleMessageType::Info,
                format!("Profile path: {:?}", path),
            );
        }

        Some(handle)
    } else {
        println!("Starting in script mode...");
        println!("Tox ID: {}", model.domain.tox_id);
        None
    };

    while let Ok(first_msg) = rx.recv() {
        let mut batch = vec![first_msg];
        while let Ok(msg) = rx.try_recv() {
            batch.push(msg);
        }

        let mut should_break = false;
        let mut redraw = false;
        for msg in batch {
            redraw |= shows(&model, &msg);
            if tui.is_none() {
                log_headless(&msg);
            }

            if let Msg::System(SystemEvent::ScriptRequest(req)) = &msg
                && let Some(ctrl) = &mut script_ctrl
            {
                ctrl.pending_req = Some(req.clone());
                if let ScriptRequest::Command(cmd_str) = req {
                    let cmds = handle_enter(&mut model, cmd_str);
                    let res = ctx.execute(cmds, &mut model).await;
                    if res.should_quit {
                        should_break = true;
                    }
                    ctrl.pending_req = None;
                    let _ = ctrl.tx_script_res.send(ScriptResponse::Ok);
                }
                if should_break {
                    break;
                }
                continue;
            }

            if let Some(ctrl) = &mut script_ctrl {
                ctrl.check_fulfillment(&model, &msg);
            }

            let cmds = update(&mut model, msg);
            let res = ctx.execute(cmds, &mut model).await;
            if res.should_quit {
                should_break = true;
            }
            if res.needs_redraw
                && let Some(h) = &mut tui
            {
                h.terminal.clear()?;
            }

            if let Some((path_str, cols, rows)) = res.screenshot_params {
                let current_size = tui.as_ref().and_then(|h| h.terminal.size().ok());
                toxxi::screenshot::handle_screenshot(
                    &mut model,
                    &ctx.screenshots_dir,
                    path_str,
                    cols,
                    rows,
                    current_size,
                );
            }

            if should_break {
                break;
            }
        }

        if should_break {
            break;
        }

        if ctx.quit_at.is_some_and(|at| Instant::now() >= at) {
            let _ = ctx.execute(vec![Cmd::App(AppCmd::Quit)], &mut model).await;
            break;
        }

        if script_ctrl.as_ref().is_some_and(|ctrl| ctrl.is_finished()) {
            let _ = ctx.execute(vec![Cmd::App(AppCmd::Quit)], &mut model).await;
            break;
        }

        if redraw && let Some(h) = &mut tui {
            h.terminal.draw(|f| draw(f, &mut model))?;
        }
    }

    runtime.shutdown().await;

    // Final drain of messages to ensure we save the latest state
    ctx.drain(&rx, &mut model).await;

    model::save_state(&ctx.config_dir, &model)?;
    config::save_config(&ctx.config_dir, &model.saved_config)?;

    Ok(())
}
