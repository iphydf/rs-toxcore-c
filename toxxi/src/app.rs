use crate::model::{FullState, Model};
use crate::msg::{AppCmd, Cmd, IOAction, Msg, ToxAction};
use serde_json::to_string_pretty;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// How often toxxi ticks.
pub const TICK_RATE: Duration = Duration::from_millis(200);

pub struct AppContext {
    pub tx_tox_action: mpsc::Sender<ToxAction>,
    pub tox_handle: JoinHandle<()>,
    pub savedata_path: Option<PathBuf>,
    pub config_dir: PathBuf,
    pub quit_at: Option<Instant>,
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
    /// Takes the messages left once the app stops, waiting for the files
    /// being kept, whose ends are recorded once they are.
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
        let mut result = ExecutionResult::default();
        for cmd in cmds {
            match cmd {
                Cmd::Tox(action) => {
                    let _ = self.tx_tox_action.send(action);
                }
                Cmd::IO(action) => {
                    self.handle_io_action(action, model).await;
                }
                Cmd::App(AppCmd::Quit) => {
                    let _ = self.tx_tox_action.send(ToxAction::Shutdown);
                    let _ = (&mut self.tox_handle).await;
                    result.should_quit = true;
                }
                Cmd::App(AppCmd::ReloadTox) => {
                    let _ = self
                        .tx_tox_action
                        .send(ToxAction::Reload(Box::new(model.config.clone())));
                }
                Cmd::App(AppCmd::SetTimeout(ms)) => {
                    self.quit_at = Some(Instant::now() + Duration::from_millis(ms));
                }
                Cmd::App(AppCmd::Redraw) => {
                    result.needs_redraw = true;
                }
                Cmd::App(AppCmd::Screenshot(path, cols, rows)) => {
                    result.screenshot_params = Some((path, cols, rows));
                }
            }
        }
        result
    }

    async fn handle_io_action(&mut self, action: IOAction, model: &Model) {
        match action {
            IOAction::SaveConfig(opt_config) => {
                let config = opt_config.unwrap_or_else(|| model.saved_config.clone());
                let _ = self.tx_io.send(IOAction::SaveConfig(Some(config)));
            }
            IOAction::SaveState(opt_data) => {
                let data = if let Some(d) = opt_data {
                    d
                } else {
                    let state = FullState {
                        domain: model.domain.clone(),
                        active_window_index: model.ui.active_window_index,
                        window_ids: model.ui.window_ids.clone(),
                        window_state: model.ui.window_state.clone(),
                        input_history: model.ui.input_history.clone(),
                        log_filters: model.ui.log_filters.clone(),
                    };
                    to_string_pretty(&state).unwrap_or_default()
                };
                let _ = self.tx_io.send(IOAction::SaveState(Some(data)));
            }
            IOAction::OpenFileForSending(..)
            | IOAction::OpenFileForReceiving(..)
            | IOAction::ReadChunk(..)
            | IOAction::WriteChunk(..)
            | IOAction::CloseFile(..)
            | IOAction::FinishFile(..)
            | IOAction::SendBlob(..)
            | IOAction::ReceiveBlob(..)
            | IOAction::StoreBlob(..)
            | IOAction::AppendEvents(..) => {
                let _ = self.tx_io.send(action);
            }
        }
    }
}
