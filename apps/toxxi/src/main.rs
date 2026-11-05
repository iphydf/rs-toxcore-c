#![deny(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm
)]

use clap::Parser;
use crossterm::event;
use directories::{ProjectDirs, UserDirs};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use toxxi::utils::Tell;

use toxxi::app;
use toxxi::msg::{Msg, SystemEvent};
use toxxi::terminal::TerminalHandle;

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
}

/// Quits on SIGTERM and SIGHUP (the terminal closed), as /quit does, so we save
/// what isn't saved yet.
#[cfg(unix)]
async fn quit_on_signal(tx: mpsc::Sender<Msg>) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut hangup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = hangup.recv() => {}
    }
    tx.tell(Msg::System(SystemEvent::Quit));
}

#[cfg(not(unix))]
async fn quit_on_signal(_tx: mpsc::Sender<Msg>) {}

/// Passes the terminal's input on until `stop` is set.
fn read_input(tx: mpsc::Sender<Msg>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        if let Ok(true) = event::poll(Duration::from_millis(100))
            && let Ok(event) = event::read()
            && tx.send(Msg::Input(event)).is_err()
        {
            break;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let data_dir = ProjectDirs::from("", "", "toxxi").map(|dirs| dirs.data_dir().to_path_buf());
    if let Some(dir) = &data_dir
        && let Err(e) = toxxi::utils::private_dir(dir)
    {
        eprintln!("Can't make {} private: {e}", dir.display());
    }
    let config_dir = data_dir.clone().unwrap_or_else(|| PathBuf::from("."));
    let user_dirs = UserDirs::new();
    let dirs = app::Dirs {
        savedata: args
            .savedata
            .map(PathBuf::from)
            .or_else(|| data_dir.map(|dir| dir.join("savedata.tox"))),
        downloads: user_dirs
            .as_ref()
            .and_then(|dirs| dirs.download_dir())
            .map_or_else(|| config_dir.join("downloads"), PathBuf::from),
        screenshots: user_dirs
            .as_ref()
            .and_then(|dirs| dirs.picture_dir())
            .map_or_else(|| config_dir.join("screenshots"), PathBuf::from),
        config: config_dir,
    };

    let (tx, rx) = mpsc::channel();
    let stop_input = Arc::new(AtomicBool::new(false));
    let input = std::thread::spawn({
        let tx = tx.clone();
        let stop = stop_input.clone();
        move || read_input(tx, stop)
    });
    let signals = tokio::spawn(quit_on_signal(tx.clone()));

    let mut tui = TerminalHandle::new()?;
    let result = app::run(
        &mut tui.terminal,
        dirs,
        |config| {
            if let Some(v) = args.ipv6 {
                config.ipv6_enabled = v;
            }
            if let Some(v) = args.udp {
                config.udp_enabled = v;
            }
            if let Some(v) = args.start_port {
                config.start_port = v;
            }
            if let Some(v) = args.end_port {
                config.end_port = v;
            }
        },
        (tx, rx),
        |_| {},
    )
    .await;

    stop_input.store(true, Ordering::Relaxed);
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a panic in the input thread has printed its message"
    )]
    let _ = input.join();
    signals.abort();
    result
}
