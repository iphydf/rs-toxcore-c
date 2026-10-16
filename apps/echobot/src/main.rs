//! A Tox bot that sends friends back what they send it: messages, and the
//! audio and video of their calls. Clients can test calls against it, also
//! ones it places when asked with a `!` command.

use clap::Parser;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use toxcore::tox::events::Event;
use toxcore::tox::{Options, Tox, ToxSavedataType};
use toxcore::toxav::ToxAV;
use toxcore::toxav::bit_rate::{AUDIO_BIT_RATE, VIDEO_BIT_RATE, VideoBitRates};
use toxcore::toxav::events::{AvEvent, AvEvents};
use toxcore::types::{FriendNumber, MessageType, ToxavCallControl, ToxavFriendCallState};

const SAVE_INTERVAL: Duration = Duration::from_secs(600);

/// How long a friend waits between calls they ask for, and the longest they
/// can have one wait, as to lock their phone first.
const CALL_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_CALL_DELAY: u64 = 120;

const HELP: &str = "!call [seconds]: I call you, after that many seconds if given \
                    (up to 120). !video [seconds]: with video. !hangup: I end our \
                    call. Anything else I send back.";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    savefile: Option<String>,
    #[arg(long, default_value = "EchoBot")]
    nick: String,
    #[arg(long, default_value = "Echoes messages and calls")]
    status_message: String,
    #[arg(long, default_value = "https://nodes.tox.chat/json")]
    nodes_url: String,
    /// Bootstrap + TCP-relay node(s), each `HOST:PORT:HEXPK`, in place of
    /// the `--nodes-url` list. Repeatable.
    #[arg(long = "bootstrap-node", value_name = "HOST:PORT:HEXPK")]
    bootstrap_nodes: Vec<String>,
}

/// The calls the bot is in, sending video back while the friend sends it.
struct Calls<'a> {
    av: ToxAV<'a, AvEvents>,
    video_bit_rates: VideoBitRates,
    // When each friend last asked to be called.
    called: HashMap<FriendNumber, Instant>,
    // The calls asked for with a delay: when to place each, with its video
    // bit rate.
    pending: HashMap<FriendNumber, (Instant, u32)>,
}

impl<'a> Calls<'a> {
    fn new(tox: &'a Tox) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            av: ToxAV::new(tox, AvEvents::default())?,
            video_bit_rates: VideoBitRates::default(),
            called: HashMap::new(),
            pending: HashMap::new(),
        })
    }

    /// Does what a friend's command, `!` and a word in any case, asks, and
    /// says what came of it.
    fn command(&mut self, friend: FriendNumber, command: &str) -> String {
        let command = command.to_lowercase();
        let mut words = command.split_whitespace();
        match (words.next(), words.next().map(str::parse), words.next()) {
            (Some(name @ ("call" | "video")), delay, None) => {
                let delay = match delay {
                    None => 0,
                    Some(Ok(seconds)) if seconds <= MAX_CALL_DELAY => seconds,
                    Some(_) => return HELP.to_owned(),
                };
                if self
                    .called
                    .get(&friend)
                    .is_some_and(|at| at.elapsed() < CALL_COOLDOWN)
                {
                    return format!("Wait {} s between calls", CALL_COOLDOWN.as_secs());
                }
                self.called.insert(friend, Instant::now());
                let bit_rate = if name == "video" { VIDEO_BIT_RATE } else { 0 };
                if delay > 0 {
                    let at = Instant::now() + Duration::from_secs(delay);
                    self.pending.insert(friend, (at, bit_rate));
                    return format!("Calling you in {delay} s");
                }
                match self.place(friend, bit_rate) {
                    Ok(()) => "Calling you".to_owned(),
                    Err(e) => format!("Couldn't call you: {e}"),
                }
            }
            (Some("hangup"), None, None) => {
                let pending = self.pending.remove(&friend).is_some();
                match self
                    .av
                    .call_control(friend, ToxavCallControl::TOXAV_CALL_CONTROL_CANCEL)
                {
                    Ok(()) => {
                        self.video_bit_rates.forget(friend);
                        "Hung up".to_owned()
                    }
                    Err(_) if pending => "Won't call you".to_owned(),
                    Err(e) => format!("No call to end: {e}"),
                }
            }
            _ => HELP.to_owned(),
        }
    }

    fn place(&mut self, friend: FriendNumber, bit_rate: u32) -> toxcore::types::Result<()> {
        info!("Calling friend {} (video: {})", friend.0, bit_rate != 0);
        self.av.call(friend, AUDIO_BIT_RATE, bit_rate)?;
        self.video_bit_rates.started(friend, bit_rate);
        Ok(())
    }

    fn iteration_interval(&self) -> Duration {
        Duration::from_millis(self.av.iteration_interval().into())
    }

    fn iterate(&mut self) {
        let now = Instant::now();
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(&friend, &(_, bit_rate))| (friend, bit_rate))
            .collect();
        for (friend, bit_rate) in due {
            self.pending.remove(&friend);
            if let Err(e) = self.place(friend, bit_rate) {
                error!("Failed to call friend {}: {e}", friend.0);
            }
        }
        self.av.iterate();
        for event in std::mem::take(&mut self.av.handler_mut().0) {
            self.handle(event);
        }
        if let Err(e) = self.video_bit_rates.raise(&self.av) {
            warn!("Failed to raise a video bit rate: {e}");
        }
    }

    fn handle(&mut self, event: AvEvent) {
        match event {
            AvEvent::Call { friend, video } => {
                info!("Answering friend {}'s call (video: {video})", friend.0);
                let bit_rate = if video { VIDEO_BIT_RATE } else { 0 };
                match self.av.answer(friend, AUDIO_BIT_RATE, bit_rate) {
                    Ok(()) => self.video_bit_rates.started(friend, bit_rate),
                    Err(e) => error!("Failed to answer friend {}: {e}", friend.0),
                }
            }
            AvEvent::CallState { friend, state } => {
                let ended = [
                    ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_ERROR,
                    ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_FINISHED,
                ]
                .iter()
                .any(|flag| flag.is_in(state));
                let sending_video =
                    ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_SENDING_V.is_in(state);
                if ended {
                    let error = ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_ERROR.is_in(state);
                    info!("Friend {}'s call ended (error: {error})", friend.0);
                    self.video_bit_rates.forget(friend);
                } else if sending_video != self.video_bit_rates.sending(friend) {
                    let bit_rate = if sending_video { VIDEO_BIT_RATE } else { 0 };
                    self.set_video_bit_rate(friend, bit_rate);
                }
            }
            AvEvent::VideoBitRate { friend, bit_rate } => {
                debug!("Friend {} loses video at {bit_rate} kbit/s", friend.0);
                if let Err(e) = self.video_bit_rates.lost(&self.av, friend, bit_rate) {
                    warn!("Failed to lower friend {}'s video bit rate: {e}", friend.0);
                }
            }
            AvEvent::Audio {
                friend,
                pcm,
                channels,
                sampling_rate,
            } => {
                if let Err(e) = self
                    .av
                    .audio_send_frame(friend, &pcm, channels, sampling_rate)
                {
                    debug!("Failed to echo audio to friend {}: {e}", friend.0);
                }
            }
            AvEvent::Video { friend, frame } => {
                if !self.video_bit_rates.sending(friend) {
                    return;
                }
                if let Err(e) = self.av.video_send_frame(
                    friend,
                    frame.width,
                    frame.height,
                    &frame.y,
                    &frame.u,
                    &frame.v,
                ) {
                    debug!("Failed to echo video to friend {}: {e}", friend.0);
                }
            }
        }
    }

    fn set_video_bit_rate(&mut self, friend: FriendNumber, bit_rate: u32) {
        if let Err(e) = self.video_bit_rates.set(&self.av, friend, bit_rate) {
            warn!(
                "Failed to set friend {}'s video bit rate to {bit_rate}: {e}",
                friend.0
            );
        }
    }
}

fn save(tox: &Tox, path: &Path) {
    if let Err(e) = fs::write(path, tox.savedata()) {
        error!("Failed to save to {}: {e}", path.display());
    }
}

/// Accepts friend requests, echoes messages and does `!` commands.
fn handle(tox: &Tox, event: &Event, savefile: &Path, calls: &mut Calls) {
    match event {
        Event::FriendRequest(e) => {
            info!(
                "Accepting {}'s friend request",
                hex::encode(e.public_key().0)
            );
            match tox.friend_add_norequest(&e.public_key()) {
                Ok(_) => save(tox, savefile),
                Err(e) => error!("Failed to accept friend request: {e}"),
            }
        }
        Event::FriendMessage(e) => {
            let friend = tox.friend(e.friend_number());
            let sent = match std::str::from_utf8(e.message()) {
                Ok(text) if text.trim_start().starts_with('!') => {
                    let reply = calls.command(e.friend_number(), &text.trim_start()[1..]);
                    info!("Friend {} sent {text:?}: {reply}", e.friend_number().0);
                    friend.send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, reply.as_bytes())
                }
                _ => friend.send_message(e.message_type(), e.message()),
            };
            if let Err(err) = sent {
                error!(
                    "Failed to echo friend {}'s message: {err}",
                    e.friend_number().0
                );
            }
        }
        Event::SelfConnectionStatus(e) => info!("Connection: {:?}", e.connection_status()),
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let savefile = match (&args.savefile, std::env::var("BUILD_WORKSPACE_DIRECTORY")) {
        (Some(path), _) => PathBuf::from(path),
        (None, Ok(base)) => PathBuf::from(base).join("rs-toxcore-c/apps/echobot/echobot.tox"),
        (None, Err(_)) => return Err("--savefile is needed outside `bazel run`".into()),
    };

    let mut opts = Options::new()?;
    opts.set_experimental_owned_data(true);
    opts.set_experimental_disable_dns(true);
    opts.set_local_discovery_enabled(false);
    opts.set_udp_enabled(true);
    if savefile.exists() {
        opts.set_savedata_type(ToxSavedataType::TOX_SAVEDATA_TYPE_TOX_SAVE);
        opts.set_savedata_data(&fs::read(&savefile)?)?;
    }

    let tox = Tox::new(opts)?;
    if tox.name().is_empty() {
        tox.set_name(args.nick.as_bytes())?;
    }
    if tox.status_message().is_empty() {
        tox.set_status_message(args.status_message.as_bytes())?;
    }
    save(&tox, &savefile);
    info!("Bot ID: {}", hex::encode(tox.address().0));

    let bootstrap_nodes = if args.bootstrap_nodes.is_empty() {
        nodes::discover(&args.nodes_url, false, true).await
    } else {
        let specs = args
            .bootstrap_nodes
            .iter()
            .filter_map(|spec| {
                nodes::parse(spec)
                    .inspect_err(|e| error!("Ignoring --bootstrap-node {spec:?}: {e}"))
                    .ok()
            })
            .collect();
        nodes::resolve(specs, false).await
    };
    nodes::bootstrap(&tox, &bootstrap_nodes);

    let mut calls = Calls::new(&tox)?;
    let mut last_save = Instant::now();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let start = Instant::now();
        match tox.events() {
            Ok(events) => {
                for event in &events {
                    handle(&tox, &event, &savefile, &mut calls);
                }
            }
            Err(e) => error!("Failed to iterate: {e}"),
        }
        calls.iterate();

        if last_save.elapsed() > SAVE_INTERVAL {
            save(&tox, &savefile);
            last_save = Instant::now();
        }

        let interval = calls
            .iteration_interval()
            .min(Duration::from_millis(tox.iteration_interval().into()));
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(interval.saturating_sub(start.elapsed())) => {}
        }
    }

    info!("Shutting down");
    save(&tox, &savefile);
    Ok(())
}
