use crate::config::{self, Config};
use crate::model::{self, ConsoleMessageType, Model};
use crate::msg::{AppCmd, Cmd, IOAction, Msg, SystemEvent, ToxAction};
use crate::ui::draw;
use crate::update::{shows, update};
use crate::utils::Tell;
use crate::{bootstrap, io, worker};
use ratatui::Terminal;
use ratatui::backend::Backend;
use std::error::Error;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const TICK_RATE: Duration = Duration::from_millis(200);

pub struct AppContext {
    pub tx_tox_action: mpsc::Sender<ToxAction>,
    pub tox_handle: JoinHandle<()>,
    pub savedata_path: Option<PathBuf>,
    pub config_dir: PathBuf,
    pub tx_io: mpsc::Sender<IOAction>,
    pub screenshots_dir: PathBuf,
}

#[derive(Default)]
pub struct ExecutionResult {
    pub should_quit: bool,
    pub needs_redraw: bool,
    pub screenshot_params: Option<(String, Option<u16>, Option<u16>)>,
}

impl AppContext {
    /// Handles the messages left once the app stops, waiting for files still
    /// being copied into blobs, whose ends are recorded then.
    pub async fn drain(&mut self, rx: &mpsc::Receiver<Msg>, model: &mut Model) {
        while let Some(msg) = if model.session.finishing.is_empty() {
            rx.try_recv().ok()
        } else {
            rx.recv().ok()
        } {
            let cmds = crate::update::update(model, msg);
            let _ = self.execute(cmds, model).await;
        }
        if model.session.account_dirty {
            let cmds = model.record_account();
            let _ = self.execute(cmds, model).await;
        }
    }

    pub async fn execute(&mut self, cmds: Vec<Cmd>, model: &mut Model) -> ExecutionResult {
        let cmds = effects(model, cmds);
        let mut result = ExecutionResult::default();
        for cmd in cmds {
            match cmd {
                Cmd::Tox(action) => {
                    self.tx_tox_action.tell(action);
                }
                Cmd::IO(action) => {
                    self.tx_io.tell(action);
                }
                Cmd::App(AppCmd::Quit) => {
                    self.tx_tox_action.tell(ToxAction::Shutdown);
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "a panic in the Tox thread has printed its message"
                    )]
                    let _ = (&mut self.tox_handle).await;
                    result.should_quit = true;
                }
                Cmd::App(AppCmd::ReloadTox) => {
                    self.tx_tox_action
                        .tell(ToxAction::Reload(Box::new(model.config.clone())));
                }
                Cmd::App(AppCmd::Redraw) => {
                    result.needs_redraw = true;
                }
                Cmd::App(AppCmd::SaveState) => {
                    let saved = model::save_state(&self.config_dir, model)
                        .and_then(|()| config::save_config(&self.config_dir, &model.saved_config));
                    if let Err(e) = saved {
                        model.add_console_message(
                            ConsoleMessageType::Error,
                            format!("Failed to save the state: {e}"),
                        );
                    }
                }
                Cmd::App(AppCmd::Screenshot(path, cols, rows)) => {
                    result.screenshot_params = Some((path, cols, rows));
                }
            }
        }
        result
    }
}

/// What `cmds` do on this profile: a linked profile's own Tox only syncs
/// with its home, which carries out the account's actions.
pub fn effects(model: &mut Model, cmds: Vec<Cmd>) -> Vec<Cmd> {
    match model.config.home {
        Some(home) => crate::sync::linked::redirect(model, home, cmds),
        None => cmds,
    }
}

pub struct Dirs {
    /// The profile, or none to run with a new one that isn't saved.
    pub savedata: Option<PathBuf>,
    /// Settings, state and the chat log.
    pub config: PathBuf,
    /// Where received files go unless the settings say otherwise.
    pub downloads: PathBuf,
    pub screenshots: PathBuf,
}

/// Runs toxxi on `terminal` until it quits, reading the input that comes to
/// `rx` through `tx`'s other ends. `adjust` changes the settings for this run
/// only; `observe` sees the model after each batch of messages.
pub async fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    dirs: Dirs,
    adjust: impl FnOnce(&mut Config),
    (tx, rx): (mpsc::Sender<Msg>, mpsc::Receiver<Msg>),
    mut observe: impl FnMut(&Model),
) -> Result<(), Box<dyn Error>>
where
    B::Error: 'static,
{
    let saved_config = config::load_config(&dirs.config);
    let mut runtime_config = saved_config.clone();
    adjust(&mut runtime_config);

    let initial_state = worker::get_initial_state(&dirs.savedata)?;
    let (nodes, _bootstrap_logs) = bootstrap::setup_nodes(&dirs.config).await;
    let ticks = tokio::spawn(tick(tx.clone()));

    let (tx_tox_action, rx_tox_action) = mpsc::channel();
    let (tx_io, rx_io) = mpsc::channel();

    let mut model = model::load_or_initialize(
        &dirs.config,
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
        dirs.savedata.clone(),
        &model.config,
        nodes,
        dirs.config.clone(),
    );

    let downloads = match &model.config.downloads_directory {
        Some(dir) => PathBuf::from(dir),
        None => dirs.downloads,
    };
    let _io_handle = io::spawn_io_worker(
        tx.clone(),
        tx_tox_action.clone(),
        rx_io,
        dirs.config.clone(),
        downloads,
    );

    let mut ctx = AppContext {
        tx_tox_action,
        tox_handle,
        savedata_path: dirs.savedata,
        config_dir: dirs.config,
        tx_io,
        screenshots_dir: dirs.screenshots,
    };

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
    terminal.draw(|f| draw(f, &mut model))?;
    observe(&model);

    'running: while let Ok(first_msg) = rx.recv() {
        let mut batch = vec![first_msg];
        while let Ok(msg) = rx.try_recv() {
            batch.push(msg);
        }

        let mut redraw = false;
        for msg in batch {
            redraw |= shows(&model, &msg);

            let cmds = update(&mut model, msg);
            let res = ctx.execute(cmds, &mut model).await;
            if res.needs_redraw {
                terminal.clear()?;
            }

            if let Some((path_str, cols, rows)) = res.screenshot_params {
                crate::screenshot::handle_screenshot(
                    &mut model,
                    &ctx.screenshots_dir,
                    path_str,
                    cols,
                    rows,
                    terminal.size().ok(),
                );
            }

            if res.should_quit {
                break 'running;
            }
        }

        if redraw {
            terminal.draw(|f| draw(f, &mut model))?;
        }
        observe(&model);
    }

    ticks.abort();

    // Save what the last messages changed.
    ctx.drain(&rx, &mut model).await;

    model::save_state(&ctx.config_dir, &model)?;
    config::save_config(&ctx.config_dir, &model.saved_config)?;

    Ok(())
}

async fn tick(tx: mpsc::Sender<Msg>) {
    loop {
        tokio::time::sleep(TICK_RATE).await;
        if tx.send(Msg::System(SystemEvent::Tick)).is_err() {
            break;
        }
    }
}
