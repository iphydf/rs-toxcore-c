//! A Tox bot that sends friends back what they send it: messages, files, and
//! the audio and video of their calls, also in groups they invite it to.
//! Clients can test against it, also with `!` commands for what a friend
//! can't send itself: calls it places, files, bursts of messages and more.

use clap::Parser;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use toxcore::tox::events::Event;
use toxcore::tox::{Options, Tox, ToxSavedataType};
use toxcore::toxav::ToxAV;
use toxcore::toxav::bit_rate::{AUDIO_BIT_RATE, VIDEO_BIT_RATE, VideoBitRates};
use toxcore::toxav::events::{AvEvent, AvEvents};
use toxcore::types::{
    ConferenceNumber, FILE_ID_LENGTH, FileId, FileNumber, FriendNumber, GroupNumber,
    GroupPeerNumber, MAX_MESSAGE_LENGTH, MessageType, Tox_Err_File_Send_Chunk, ToxConferenceType,
    ToxConnection, ToxError, ToxFileControl, ToxGroupExitType, ToxGroupPrivacyState, ToxUserStatus,
    ToxavCallControl, ToxavFriendCallState,
};

const SAVE_INTERVAL: Duration = Duration::from_secs(600);

/// How long a friend waits between calls they ask for, and the longest they
/// can have one or a message wait, as to lock their phone first.
const CALL_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_DELAY: u64 = 120;

/// How long the bot shows typing before it echoes a message.
const TYPING_TIME: Duration = Duration::from_secs(1);

/// How long the bot remembers what it said in a group, not to echo it back,
/// so that two bots in a group don't echo each other forever.
const ECHO_MEMORY: Duration = Duration::from_secs(10);

const MAX_BURST: u32 = 100;
const LONG_LINES: u32 = 100;

/// `TOX_FILE_KIND_DATA` and `TOX_FILE_KIND_AVATAR`.
const DATA_KIND: u32 = 0;
const AVATAR_KIND: u32 = 1;

const MIB: u64 = 1024 * 1024;

/// The largest file the bot takes or makes, and the most it holds at once.
const MAX_FILE_SIZE: u64 = 100 * MIB;
const MAX_HELD: u64 = 1024 * MIB;

const AVATAR: &[u8] = include_bytes!("../echobot.png");

/// A `!` command, by any of its names in any case: what it takes and does,
/// for the help, and what it does with the words after its name, `None` if
/// they don't fit.
struct Command {
    names: &'static [&'static str],
    args: &'static str,
    does: fn() -> String,
    run: fn(&mut Bot, &Tox, &mut Calls, FriendNumber, &Request) -> Option<Vec<String>>,
}

/// A `!` command as a friend sent it.
struct Request<'r> {
    name: String,
    words: Vec<&'r str>,
    // What follows the name, as typed.
    rest: &'r str,
}

const COMMANDS: &[Command] = &[
    Command {
        names: &["call", "video"],
        args: " [seconds]",
        does: || format!("I call you, after that many seconds if given (up to {MAX_DELAY})"),
        run: |_, _, calls, friend, request| {
            let delay = match request.words[..] {
                [] => 0,
                [seconds] => seconds.parse().ok().filter(|&s| s <= MAX_DELAY)?,
                _ => return None,
            };
            Some(vec![calls.call(friend, request.name == "video", delay)])
        },
    },
    Command {
        names: &["hangup"],
        args: "",
        does: || "I end our call".to_owned(),
        run: |_, _, calls, friend, request| {
            request
                .words
                .is_empty()
                .then(|| vec![calls.hang_up(friend)])
        },
    },
    Command {
        names: &["file"],
        args: " <size>",
        does: || {
            format!(
                "I send you a file of random bytes, as !file 20M (up to {})",
                size_text(MAX_FILE_SIZE)
            )
        },
        run: |bot, tox, _, friend, request| match request.words[..] {
            [size] => {
                let size = parse_size(size).filter(|&size| size <= MAX_FILE_SIZE)?;
                Some(vec![
                    bot.make_file(tox, friend, size)
                        .unwrap_or_else(|e| format!("Couldn't make the file: {e}")),
                ])
            }
            _ => None,
        },
    },
    Command {
        names: &["long"],
        args: "",
        does: || "a message too long for one, in parts".to_owned(),
        run: |_, _, _, _, request| request.words.is_empty().then(long_message),
    },
    Command {
        names: &["burst"],
        args: " <count>",
        does: || format!("that many messages at once (up to {MAX_BURST})"),
        run: |_, _, _, _, request| match request.words[..] {
            [count] => {
                let count = count
                    .parse()
                    .ok()
                    .filter(|count| (1..=MAX_BURST).contains(count))?;
                Some((1..=count).map(|i| format!("{i} of {count}")).collect())
            }
            _ => None,
        },
    },
    Command {
        names: &["later"],
        args: " <seconds> <text>",
        does: || format!("I send you the text after that many seconds (up to {MAX_DELAY})"),
        run: |bot, _, _, friend, request| match request.words[..] {
            [seconds, _, ..] => {
                let seconds = seconds.parse().ok().filter(|&s| s <= MAX_DELAY)?;
                let text = request
                    .rest
                    .split_once(char::is_whitespace)
                    .map_or("", |(_, text)| text.trim_start());
                Some(vec![bot.later(friend, seconds, text)])
            }
            _ => None,
        },
    },
    Command {
        names: &["away", "busy", "online"],
        args: "",
        does: || "I change my status".to_owned(),
        run: |_, tox, _, _, request| {
            request.words.is_empty().then(|| {
                tox.set_status(match request.name.as_str() {
                    "away" => ToxUserStatus::TOX_USER_STATUS_AWAY,
                    "busy" => ToxUserStatus::TOX_USER_STATUS_BUSY,
                    _ => ToxUserStatus::TOX_USER_STATUS_NONE,
                });
                vec![format!("I'm {} now", request.name)]
            })
        },
    },
    Command {
        names: &["group", "conference"],
        args: "",
        does: || "I make one and invite you".to_owned(),
        run: |bot, tox, _, friend, request| {
            request
                .words
                .is_empty()
                .then(|| vec![bot.invite(tox, friend, &request.name)])
        },
    },
];

/// The commands, and what the bot does with anything else.
fn help() -> String {
    COMMANDS
        .iter()
        .map(|command| {
            let usage: Vec<String> = command
                .names
                .iter()
                .map(|name| format!("!{name}{}", command.args))
                .collect();
            format!("{}: {}", usage.join(", "), (command.does)())
        })
        .chain(std::iter::once(
            "Anything else I send back, files too, also in groups.".to_owned(),
        ))
        .collect::<Vec<_>>()
        .join("\n")
}

const FULL: &str = "I hold too many files now, try later";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    savefile: Option<String>,
    #[arg(long, default_value = "echobot-rs")]
    nick: String,
    #[arg(long, default_value = "Echoes messages and calls. Send !help for more")]
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

    /// Calls a friend who asked, after this many seconds, and says what came
    /// of it.
    fn call(&mut self, friend: FriendNumber, video: bool, delay: u64) -> String {
        if self
            .called
            .get(&friend)
            .is_some_and(|at| at.elapsed() < CALL_COOLDOWN)
        {
            return format!("Wait {} s between calls", CALL_COOLDOWN.as_secs());
        }
        self.called.insert(friend, Instant::now());
        let bit_rate = if video { VIDEO_BIT_RATE } else { 0 };
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

    /// Ends a friend's call, or the one they're waiting for.
    fn hang_up(&mut self, friend: FriendNumber) -> String {
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

/// A message to send when it's due: an echo, shown as typed first, or one
/// asked for with `!later`.
struct Due {
    at: Instant,
    friend: FriendNumber,
    kind: MessageType,
    message: Vec<u8>,
    typed: bool,
}

/// A file a friend sends the bot, written to disk as it comes. A friend
/// sending it again with the same ID, as after going offline, resumes it.
struct Receiving {
    path: PathBuf,
    file: fs::File,
    name: Vec<u8>,
}

/// A file the bot sends a friend, deleted once sent. If the friend goes
/// offline first, it's offered again with the same ID when they're back, so
/// that they can resume it.
struct Offer {
    path: PathBuf,
    id: FileId,
    name: Vec<u8>,
    size: u64,
}

/// What the bot sends under a file number.
enum Sending {
    Avatar,
    File(Offer, fs::File),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Chat {
    Conference(ConferenceNumber),
    Group(GroupNumber),
}

/// Everything but calls.
struct Bot {
    savefile: PathBuf,
    nick: String,
    // Where the files the bot takes and sends are.
    dir: PathBuf,
    online: HashSet<FriendNumber>,
    due: Vec<Due>,
    receiving: HashMap<(FriendNumber, FileNumber), Receiving>,
    sending: HashMap<(FriendNumber, FileNumber), Sending>,
    // How many ends toxcore reported for transfers under each number after
    // giving it to a new one: it frees a number as the transfer ends, before
    // the bot hears of the end.
    ended: HashMap<(FriendNumber, FileNumber), u32>,
    // Files whose sending stopped as their friend went offline.
    unsent: HashMap<FriendNumber, Vec<Offer>>,
    // Chunks toxcore had no room for, to send before any after them.
    deferred: VecDeque<(FriendNumber, FileNumber, u64, Vec<u8>)>,
    // What the bot said in each group lately, with when.
    said: HashMap<Chat, Vec<(Instant, Vec<u8>)>>,
    // Who else is in each group, to leave it when they've all gone.
    peers: HashMap<GroupNumber, HashSet<GroupPeerNumber>>,
    // The conferences where the bot has seen others.
    met: HashSet<ConferenceNumber>,
}

impl Bot {
    /// Written to a new file first, so that a crash can't leave half a save.
    fn save(&self, tox: &Tox) {
        let mut new = self.savefile.clone().into_os_string();
        new.push(".new");
        if let Err(e) =
            fs::write(&new, tox.savedata()).and_then(|()| fs::rename(&new, &self.savefile))
        {
            error!("Failed to save to {}: {e}", self.savefile.display());
        }
    }

    /// Accepts friend requests and invites, echoes messages and files, and
    /// does `!` commands.
    fn handle(&mut self, tox: &Tox, event: &Event, calls: &mut Calls) {
        let handled = match event {
            Event::FriendRequest(e) => {
                info!(
                    "Accepting {}'s friend request",
                    hex::encode(e.public_key().0)
                );
                tox.friend_add_norequest(&e.public_key())
                    .map(|_| self.save(tox))
                    .map_err(Into::into)
            }
            Event::FriendConnectionStatus(e) => {
                let online = e.connection_status() != ToxConnection::TOX_CONNECTION_NONE;
                self.connection(tox, e.friend_number(), online);
                Ok(())
            }
            Event::FriendMessage(e) => {
                let friend = e.friend_number();
                match std::str::from_utf8(e.message()) {
                    Ok(text) if text.trim_start().starts_with('!') => {
                        let replies = self.command(tox, calls, friend, &text.trim_start()[1..]);
                        info!("Friend {} sent {text:?}: {:?}", friend.0, replies.first());
                        replies.iter().try_for_each(|reply| {
                            tox.friend(friend)
                                .send_message(
                                    MessageType::TOX_MESSAGE_TYPE_NORMAL,
                                    reply.as_bytes(),
                                )
                                .map(|_| ())
                        })
                    }
                    _ => {
                        let _ = tox.friend(friend).set_typing(true);
                        self.due.push(Due {
                            at: Instant::now() + TYPING_TIME,
                            friend,
                            kind: e.message_type(),
                            message: e.message().to_vec(),
                            typed: true,
                        });
                        Ok(())
                    }
                }
                .map_err(Into::into)
            }
            Event::FileRecv(e) => self.receive(
                tox,
                e.friend_number(),
                e.file_number(),
                e.kind(),
                e.file_size(),
                e.filename(),
            ),
            Event::FileRecvChunk(e) => self.received(
                tox,
                e.friend_number(),
                e.file_number(),
                e.position(),
                e.data(),
            ),
            Event::FileChunkRequest(e) => self.requested(
                tox,
                e.friend_number(),
                e.file_number(),
                e.position(),
                e.length(),
            ),
            Event::FileRecvControl(e) => {
                if e.control() == ToxFileControl::TOX_FILE_CONTROL_CANCEL {
                    self.cancelled(e.friend_number(), e.file_number());
                }
                Ok(())
            }
            Event::ConferenceInvite(e) => {
                if e.conference_type() == ToxConferenceType::TOX_CONFERENCE_TYPE_TEXT {
                    info!("Joining friend {}'s conference", e.friend_number().0);
                    tox.conference_join(&tox.friend(e.friend_number()), e.cookie())
                        .map(|_| self.save(tox))
                        .map_err(Into::into)
                } else {
                    Ok(())
                }
            }
            Event::ConferenceMessage(e) => {
                let conference = tox.conference(e.conference_number());
                match conference.peer_number_is_ours(e.peer_number()) {
                    Ok(false)
                        if self.echoes(Chat::Conference(conference.number()), e.message()) =>
                    {
                        conference.send_message(e.message_type(), e.message())
                    }
                    _ => Ok(()),
                }
                .map_err(Into::into)
            }
            Event::ConferencePeerListChanged(e) => {
                let number = e.conference_number();
                let conference = tox.conference(number);
                match conference.peer_count() {
                    Ok(count) if count > 1 => {
                        self.met.insert(number);
                        Ok(())
                    }
                    Ok(_) if self.met.remove(&number) => {
                        info!("Leaving conference {}, as everyone else left", number.0);
                        self.said.remove(&Chat::Conference(number));
                        conference.delete().map(|()| self.save(tox))
                    }
                    other => other.map(|_| ()),
                }
                .map_err(Into::into)
            }
            Event::GroupInvite(e) => {
                info!("Joining friend {}'s group", e.friend_number().0);
                tox.group_invite_accept(
                    &tox.friend(e.friend_number()),
                    e.invite_data(),
                    self.nick.as_bytes(),
                    None,
                )
                .map(|_| self.save(tox))
                .map_err(Into::into)
            }
            Event::GroupMessage(e) => {
                let group = tox.group(e.group_number());
                if self.echoes(Chat::Group(e.group_number()), e.message()) {
                    group
                        .send_message(e.message_type(), e.message())
                        .map(|_| ())
                        .map_err(Into::into)
                } else {
                    Ok(())
                }
            }
            Event::GroupPeerJoin(e) => {
                self.peers
                    .entry(e.group_number())
                    .or_default()
                    .insert(e.peer_id());
                Ok(())
            }
            Event::GroupPeerExit(e) => {
                let number = e.group_number();
                let ours = e.exit_type() == ToxGroupExitType::TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED;
                let peers = self.peers.entry(number).or_default();
                peers.remove(&e.peer_id());
                if !ours && peers.is_empty() {
                    info!("Leaving group {}, as everyone else left", number.0);
                    self.peers.remove(&number);
                    self.said.remove(&Chat::Group(number));
                    tox.group(number)
                        .leave(None)
                        .map(|()| self.save(tox))
                        .map_err(Into::into)
                } else {
                    Ok(())
                }
            }
            Event::SelfConnectionStatus(e) => {
                info!("Connection: {:?}", e.connection_status());
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err(e) = handled {
            error!("Failed to handle an event: {e}");
        }
    }

    /// Does what a friend's command, `!` and a name in any case, asks, and
    /// gives its replies: the help if it's none of the commands.
    fn command(
        &mut self,
        tox: &Tox,
        calls: &mut Calls,
        friend: FriendNumber,
        request: &str,
    ) -> Vec<String> {
        let request = request.trim();
        let (name, rest) = request
            .split_once(char::is_whitespace)
            .map_or((request, ""), |(name, rest)| (name, rest.trim_start()));
        let request = Request {
            name: name.to_lowercase(),
            words: rest.split_whitespace().collect(),
            rest,
        };
        COMMANDS
            .iter()
            .find(|command| command.names.contains(&request.name.as_str()))
            .and_then(|command| (command.run)(self, tox, calls, friend, &request))
            .unwrap_or_else(|| vec![help()])
    }

    /// Sends a friend the text after this many seconds, and says so.
    fn later(&mut self, friend: FriendNumber, seconds: u64, text: &str) -> String {
        self.due.push(Due {
            at: Instant::now() + Duration::from_secs(seconds),
            friend,
            kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
            message: text.as_bytes().to_vec(),
            typed: false,
        });
        format!("Sending it in {seconds} s")
    }

    /// Makes a group or conference, as named, and invites the friend to it.
    fn invite(&self, tox: &Tox, friend: FriendNumber, kind: &str) -> String {
        let name = format!("{}'s {kind}", self.nick);
        let invited = if kind == "group" {
            tox.group_new(
                ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE,
                name.as_bytes(),
                self.nick.as_bytes(),
            )
            .and_then(|group| group.invite_friend(&tox.friend(friend)))
        } else {
            tox.conference_new().and_then(|conference| {
                conference.set_title(name.as_bytes())?;
                conference.invite(&tox.friend(friend))
            })
        };
        invited.map_or_else(
            |e| format!("Couldn't make a {kind}: {e}"),
            |()| format!("Invited you to my {kind}"),
        )
    }

    /// Sends the messages that are due, and stops typing to whoever has no
    /// more echoes coming.
    fn send_due(&mut self, tox: &Tox) {
        let now = Instant::now();
        let (mut due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.due)
            .into_iter()
            .partition(|d| d.at <= now);
        self.due = waiting;
        due.sort_by_key(|d| d.at);
        for d in due {
            let friend = tox.friend(d.friend);
            if let Err(e) = friend.send_message(d.kind, &d.message) {
                error!("Failed to send friend {} a message: {e}", d.friend.0);
            }
            if d.typed && !self.due.iter().any(|w| w.typed && w.friend == d.friend) {
                let _ = friend.set_typing(false);
            }
        }
    }

    /// Whether to echo a message in a group: not one the bot said there
    /// lately.
    fn echoes(&mut self, chat: Chat, message: &[u8]) -> bool {
        let said = self.said.entry(chat).or_default();
        said.retain(|(at, _)| at.elapsed() < ECHO_MEMORY);
        if said.iter().any(|(_, m)| m == message) {
            return false;
        }
        said.push((Instant::now(), message.to_vec()));
        true
    }

    /// Sends the avatar and the files that weren't sent to a friend who came
    /// online, and keeps those being sent to one who went offline.
    fn connection(&mut self, tox: &Tox, friend: FriendNumber, online: bool) {
        if online == self.online.contains(&friend) {
            return;
        }
        if online {
            self.online.insert(friend);
            let id = FileId(Tox::hash(AVATAR).0);
            match tox.file_send(
                &tox.friend(friend),
                AVATAR_KIND,
                AVATAR.len() as u64,
                Some(&id),
                b"",
            ) {
                Ok(file) => self.start((friend, file.number()), Sending::Avatar),
                Err(e) => warn!("Failed to send friend {} the avatar: {e}", friend.0),
            }
            for offer in self.unsent.remove(&friend).unwrap_or_default() {
                self.offer(tox, friend, offer);
            }
        } else {
            self.online.remove(&friend);
            self.receiving.retain(|(f, _), _| *f != friend);
            self.ended.retain(|(f, _), _| *f != friend);
            self.deferred.retain(|(f, ..)| *f != friend);
            let (stopped, rest) = std::mem::take(&mut self.sending)
                .into_iter()
                .partition::<HashMap<_, _>, _>(|((f, _), _)| *f == friend);
            self.sending = rest;
            self.unsent
                .entry(friend)
                .or_default()
                .extend(stopped.into_values().filter_map(|sending| match sending {
                    Sending::Avatar => None,
                    Sending::File(offer, _) => Some(offer),
                }));
        }
    }

    fn receive(
        &mut self,
        tox: &Tox,
        friend: FriendNumber,
        number: FileNumber,
        kind: u32,
        size: u64,
        name: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let file = tox.file(&tox.friend(friend), number);
        if kind != DATA_KIND {
            return Ok(file.control(ToxFileControl::TOX_FILE_CONTROL_CANCEL)?);
        }
        let refusal = if size > MAX_FILE_SIZE {
            Some(format!("I take files up to {}", size_text(MAX_FILE_SIZE)))
        } else if self.held() + size > MAX_HELD {
            Some(FULL.to_owned())
        } else {
            None
        };
        if let Some(refusal) = refusal {
            file.control(ToxFileControl::TOX_FILE_CONTROL_CANCEL)?;
            tox.friend(friend)
                .send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, refusal.as_bytes())?;
            return Ok(());
        }
        let path = self
            .path(tox, friend, &file.file_id()?)?
            .with_extension("part");
        let stored = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let have = stored.metadata()?.len();
        if have >= size {
            stored.set_len(0)?;
        } else if have > 0 {
            info!("Resuming friend {}'s file at {have}", friend.0);
            file.seek(have)?;
        }
        file.control(ToxFileControl::TOX_FILE_CONTROL_RESUME)?;
        self.receiving.insert(
            (friend, number),
            Receiving {
                path,
                file: stored,
                name: name.to_vec(),
            },
        );
        Ok(())
    }

    /// Writes a chunk, or sends the whole file back once it's all there.
    fn received(
        &mut self,
        tox: &Tox,
        friend: FriendNumber,
        number: FileNumber,
        position: u64,
        data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        if !data.is_empty() {
            return match self.receiving.get(&(friend, number)) {
                Some(receiving) => Ok(receiving.file.write_all_at(data, position)?),
                None => Ok(()),
            };
        }
        let Some(receiving) = self.receiving.remove(&(friend, number)) else {
            return Ok(());
        };
        let id = random_id()?;
        let path = self.path(tox, friend, &id)?;
        fs::rename(&receiving.path, &path)?;
        let size = receiving.file.metadata()?.len();
        info!("Sending friend {} their file back", friend.0);
        self.offer(
            tox,
            friend,
            Offer {
                path,
                id,
                name: receiving.name,
                size,
            },
        );
        Ok(())
    }

    fn requested(
        &mut self,
        tox: &Tox,
        friend: FriendNumber,
        number: FileNumber,
        position: u64,
        length: usize,
    ) -> Result<(), Box<dyn Error>> {
        let key = (friend, number);
        if length == 0 {
            return self.end(key);
        }
        let chunk = match self.sending.get(&key) {
            Some(Sending::Avatar) => {
                let from = usize::try_from(position)?;
                AVATAR[from..from + length].to_vec()
            }
            Some(Sending::File(_, stored)) => {
                let mut chunk = vec![0; length];
                stored.read_exact_at(&mut chunk, position)?;
                chunk
            }
            None => return Ok(()),
        };
        if self.deferred.iter().any(|(f, n, ..)| (*f, *n) == key) {
            self.deferred.push_back((friend, number, position, chunk));
            return Ok(());
        }
        match tox
            .file(&tox.friend(friend), number)
            .send_chunk(position, &chunk)
        {
            Err(ToxError::FileSendChunk(
                Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_SENDQ,
            )) => {
                self.deferred.push_back((friend, number, position, chunk));
                Ok(())
            }
            sent => Ok(sent?),
        }
    }

    /// Sends the chunks toxcore had no room for, while it has room.
    fn send_deferred(&mut self, tox: &Tox) {
        while let Some((friend, number, position, chunk)) = self.deferred.pop_front() {
            match tox
                .file(&tox.friend(friend), number)
                .send_chunk(position, &chunk)
            {
                Err(ToxError::FileSendChunk(
                    Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_SENDQ,
                )) => {
                    self.deferred.push_front((friend, number, position, chunk));
                    break;
                }
                Err(e) => warn!("Failed to send friend {} a chunk: {e}", friend.0),
                Ok(()) => {}
            }
        }
    }

    fn cancelled(&mut self, friend: FriendNumber, number: FileNumber) {
        let key = (friend, number);
        let ended = match self.receiving.remove(&key) {
            Some(receiving) => fs::remove_file(receiving.path).map_err(Into::into),
            None => self.end(key),
        };
        if let Err(e) = ended {
            warn!("Failed to delete a cancelled file: {e}");
        }
    }

    /// Sends under a number, which ended any transfer it was for before.
    fn start(&mut self, key: (FriendNumber, FileNumber), sending: Sending) {
        if let Some(before) = self.sending.insert(key, sending) {
            *self.ended.entry(key).or_default() += 1;
            if let Sending::File(offer, _) = before
                && let Err(e) = fs::remove_file(&offer.path)
            {
                warn!("Failed to delete {}: {e}", offer.path.display());
            }
        }
    }

    /// Forgets a transfer that ended, unless the end is of one before it.
    fn end(&mut self, key: (FriendNumber, FileNumber)) -> Result<(), Box<dyn Error>> {
        if let Some(earlier) = self.ended.get_mut(&key) {
            *earlier -= 1;
            if *earlier == 0 {
                self.ended.remove(&key);
            }
            return Ok(());
        }
        if let Some(Sending::File(offer, _)) = self.sending.remove(&key) {
            fs::remove_file(offer.path)?;
        }
        Ok(())
    }

    /// Sends a file of random bytes, and says so.
    fn make_file(
        &mut self,
        tox: &Tox,
        friend: FriendNumber,
        size: u64,
    ) -> Result<String, Box<dyn Error>> {
        if self.held() + size > MAX_HELD {
            return Ok(FULL.to_owned());
        }
        let name = format!("random-{}.bin", size_text(size));
        let id = random_id()?;
        let path = self.path(tox, friend, &id)?;
        io::copy(
            &mut fs::File::open("/dev/urandom")?.take(size),
            &mut fs::File::create(&path)?,
        )?;
        let reply = format!("Sending you {name}");
        self.offer(
            tox,
            friend,
            Offer {
                path,
                id,
                name: name.into_bytes(),
                size,
            },
        );
        Ok(reply)
    }

    /// Keeps the offer to send again when the friend comes back, if it fails.
    fn offer(&mut self, tox: &Tox, friend: FriendNumber, offer: Offer) {
        let stored = match fs::File::open(&offer.path) {
            Ok(stored) => stored,
            Err(e) => return error!("Failed to open {}: {e}", offer.path.display()),
        };
        match tox.file_send(
            &tox.friend(friend),
            DATA_KIND,
            offer.size,
            Some(&offer.id),
            &offer.name,
        ) {
            Ok(file) => self.start((friend, file.number()), Sending::File(offer, stored)),
            Err(e) => {
                warn!("Failed to send friend {} a file: {e}", friend.0);
                self.unsent.entry(friend).or_default().push(offer);
            }
        }
    }

    /// Where a friend's file with this ID is kept.
    fn path(
        &self,
        tox: &Tox,
        friend: FriendNumber,
        id: &FileId,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let key = tox.friend(friend).public_key()?;
        Ok(self
            .dir
            .join(format!("{}-{}", hex::encode(key.0), hex::encode(id.0))))
    }

    /// The bytes of all files kept now.
    fn held(&self) -> u64 {
        fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok()?.metadata().ok())
            .map(|metadata| metadata.len())
            .sum()
    }
}

fn random_id() -> io::Result<FileId> {
    let mut id = [0; FILE_ID_LENGTH];
    fs::File::open("/dev/urandom")?.read_exact(&mut id)?;
    Ok(FileId(id))
}

/// A size as `!file` takes it: bytes, or with K or M for KiB or MiB.
fn parse_size(word: &str) -> Option<u64> {
    let word = word.to_lowercase();
    let (digits, unit) = match (word.strip_suffix('k'), word.strip_suffix('m')) {
        (Some(digits), _) => (digits, 1024),
        (_, Some(digits)) => (digits, MIB),
        _ => (word.as_str(), 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

fn size_text(size: u64) -> String {
    match size {
        _ if size >= MIB && size.is_multiple_of(MIB) => format!("{}M", size / MIB),
        _ if size >= 1024 && size.is_multiple_of(1024) => format!("{}K", size / 1024),
        _ => size.to_string(),
    }
}

/// Lines too many for one message, split as clients split them: at the last
/// line break that fits.
fn long_message() -> Vec<String> {
    let mut parts = vec![String::new()];
    for n in 1..=LONG_LINES {
        let line = format!("Line {n} of {LONG_LINES}: äöü € 😀");
        let part = parts.last_mut().expect("parts start with one");
        if part.is_empty() {
            part.push_str(&line);
        } else if part.len() + 1 + line.len() <= MAX_MESSAGE_LENGTH {
            part.push('\n');
            part.push_str(&line);
        } else {
            parts.push(line);
        }
    }
    parts
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
    // The last run's files: their transfers are gone.
    let dir = savefile.with_extension("files");
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;

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
    // The arguments win over the save, so that renaming the bot renames it,
    // and it starts online.
    tox.set_name(args.nick.as_bytes())?;
    tox.set_status_message(args.status_message.as_bytes())?;
    tox.set_status(ToxUserStatus::TOX_USER_STATUS_NONE);
    let mut bot = Bot {
        savefile,
        nick: args.nick.clone(),
        dir,
        online: HashSet::new(),
        due: Vec::new(),
        receiving: HashMap::new(),
        sending: HashMap::new(),
        ended: HashMap::new(),
        deferred: VecDeque::new(),
        unsent: HashMap::new(),
        said: HashMap::new(),
        peers: HashMap::new(),
        met: HashSet::new(),
    };
    bot.save(&tox);
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
                    bot.handle(&tox, &event, &mut calls);
                }
            }
            Err(e) => error!("Failed to iterate: {e}"),
        }
        calls.iterate();
        bot.send_deferred(&tox);
        bot.send_due(&tox);

        if last_save.elapsed() > SAVE_INTERVAL {
            bot.save(&tox);
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
    bot.save(&tox);
    Ok(())
}
