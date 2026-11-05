use crate::config::Config;
use crate::msg::{Cmd, IOAction, ToxAction};
use crate::sync::account::AccountState;
use crate::sync::event::{BlobId, ChatId, ChatKind, Content, Event, EventId, GraphId};
use crate::sync::fact::Facts;
use crate::sync::files::{BlobTransfer, Blobs};
use crate::sync::history::{self, Recorded};
use crate::sync::pairing::Pairing;
use crate::sync::protocol::{Features, SessionMessage};
use crate::sync::session;
use crate::sync::store::{EVENTS_FILE, EventStore, read_log};
use crate::time::TimeProvider;
use crate::widgets::{
    ChatLayout, ChatMessage, CommandMenuState, EmojiGridState, EmojiPickerState, InputBoxState,
    MessageListState, QuickSwitcherState, SidebarItem,
};
use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use toxcore::tox::{
    ConferenceNumber, FriendNumber, GroupNumber, GroupPeerNumber, ToxConferenceType, ToxConnection,
    ToxUserStatus,
};
use toxcore::types::{
    Address, ConferenceId, FileId, GroupChatId, MessageType, PublicKey, ToxGroupPrivacyState,
    ToxGroupRole, ToxGroupVoiceState, ToxLogLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InternalMessageId(pub usize);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FriendInfo {
    pub name: String,
    pub public_key: Option<PublicKey>,
    pub status_message: String,
    pub connection: ToxConnection,
    #[serde(skip, default)]
    pub is_typing: bool,
}

fn unnamed_friend(pk: &PublicKey) -> String {
    format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
}

impl FriendInfo {
    /// A friend Tox has told nothing about yet.
    pub fn new(pk: PublicKey, connection: ToxConnection) -> Self {
        Self {
            name: unnamed_friend(&pk),
            public_key: Some(pk),
            status_message: String::new(),
            connection,
            is_typing: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    Incoming,
    Pending,
    Sending,
    Sent(u32),
    Received,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageContent {
    Text(String),
    List(Vec<String>),
    FileTransfer {
        file_id: Option<FileId>,
        name: String,
        size: u64,
        progress: f64,
        speed: String,
        is_incoming: bool,
        /// Its bytes, once the home holds them: a device's file to send, or
        /// one that ended well.
        #[serde(skip)]
        blob: Option<BlobId>,
    },
}

impl MessageContent {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            MessageContent::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn contains(&self, s: &str) -> bool {
        match self {
            MessageContent::Text(t) => t.contains(s),
            MessageContent::List(items) => items.iter().any(|item| item.contains(s)),
            MessageContent::FileTransfer { name, .. } => name.contains(s),
        }
    }
}

pub const SYSTEM_SENDER: &str = "System";

/// The Status window keeps the newest this many messages.
pub const MAX_CONSOLE_MESSAGES: usize = 1000;

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub internal_id: InternalMessageId,
    pub sender: String,
    pub sender_pk: Option<PublicKey>,
    pub is_self: bool,
    pub content: MessageContent,
    pub timestamp: DateTime<FixedOffset>,
    pub status: MessageStatus,
    pub message_type: MessageType,
    pub highlighted: bool,
    /// In a group, the member it is between the account and alone: whom it
    /// went to, or who sent it.
    pub privately: Option<PublicKey>,
}

impl Message {
    pub fn is_system(&self) -> bool {
        !self.is_self && self.sender_pk.is_none() && self.sender == SYSTEM_SENDER
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub PublicKey);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PeerInfo {
    pub id: PeerId,
    pub name: String,
    pub role: Option<ToxGroupRole>,
    pub status: ToxUserStatus,
    pub is_ignored: bool,
    pub seen_online: bool,
}

/// A group's settings as Tox last told them.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupSettings {
    pub privacy: ToxGroupPrivacyState,
    pub peer_limit: u16,
    /// Empty for none.
    pub password: String,
    pub topic_lock: bool,
    pub voice_state: ToxGroupVoiceState,
    /// Our key in the group, which is its own.
    pub self_pk: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Conversation {
    pub name: String,
    #[serde(skip, default)]
    pub messages: Vec<Message>,
    pub topic: Option<String>,
    pub peers: Vec<PeerInfo>,
    pub self_role: Option<ToxGroupRole>,
    pub self_name: Option<String>,
    pub ignored_peers: HashSet<PublicKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowId {
    Console,
    Friend(PublicKey),
    Group(GroupChatId),
    Conference(ConferenceId),
    Logs,
    Files,
}

impl From<ChatId> for WindowId {
    fn from(chat: ChatId) -> Self {
        match chat {
            ChatId::Group(id) => WindowId::Group(id),
            ChatId::Conference(id) => WindowId::Conference(id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsoleMessageType {
    Info,
    Status,
    Error,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ConsoleMessage {
    pub msg_type: ConsoleMessageType,
    pub content: MessageContent,
    pub timestamp: DateTime<FixedOffset>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ToxLogItem {
    pub level: ToxLogLevel,
    pub file: String,
    pub line: u32,
    pub func: String,
    pub message: String,
    pub timestamp: DateTime<FixedOffset>,
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct LogFilters {
    pub levels: Vec<ToxLogLevel>,
    pub file_pattern: Option<String>,
    pub func_pattern: Option<String>,
    pub msg_pattern: Option<String>,
    pub paused: bool,
}

impl LogFilters {
    pub fn matches(&self, item: &ToxLogItem) -> bool {
        if !self.levels.is_empty() && !self.levels.contains(&item.level) {
            return false;
        }
        if let Some(pattern) = &self.file_pattern
            && !item.file.contains(pattern)
        {
            return false;
        }
        if let Some(pattern) = &self.func_pattern
            && !item.func.contains(pattern)
        {
            return false;
        }
        if let Some(pattern) = &self.msg_pattern
            && !item.message.contains(pattern)
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum PendingItem {
    FriendRequest {
        pk: PublicKey,
        message: String,
    },
    GroupInvite {
        friend: PublicKey,
        invite_data: String,
        group_name: String,
    },
    ConferenceInvite {
        friend: PublicKey,
        conference_type: ToxConferenceType,
        cookie: String,
    },
}

impl PendingItem {
    /// An invite's friend, kind of chat, name and what Tox joins it with.
    pub fn invite(&self) -> Option<(PublicKey, ChatKind, String, Vec<u8>)> {
        match self {
            PendingItem::FriendRequest { .. } => None,
            PendingItem::GroupInvite {
                friend,
                invite_data,
                group_name,
            } => Some((
                *friend,
                ChatKind::Group,
                group_name.clone(),
                crate::utils::decode_hex(invite_data)?,
            )),
            PendingItem::ConferenceInvite { friend, cookie, .. } => Some((
                *friend,
                ChatKind::Conference,
                String::new(),
                crate::utils::decode_hex(cookie)?,
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct WindowUiState {
    #[serde(skip, default)]
    pub msg_list_state: MessageListState,
    pub unread_count: usize,
    pub show_peers: bool,
    #[serde(skip, default)]
    pub last_height: usize,
    #[serde(skip)]
    pub cached_messages: Option<Vec<ChatMessage>>,
    #[serde(skip)]
    pub layout: ChatLayout,
    #[serde(skip)]
    pub dirty_indices: HashSet<usize>,
}

impl Default for WindowUiState {
    fn default() -> Self {
        Self {
            msg_list_state: MessageListState::default(),
            unread_count: 0,
            show_peers: true,
            last_height: 0,
            cached_messages: None,
            layout: ChatLayout::default(),
            dirty_indices: HashSet::new(),
        }
    }
}

impl WindowUiState {
    pub fn invalidate_layout(&mut self) {
        self.layout.invalidate();
    }

    pub fn invalidate_full_cache(&mut self) {
        self.cached_messages = None;
        self.dirty_indices.clear();
        self.layout.invalidate();
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub enum TransferStatus {
    Active,
    Paused,
    Canceled,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FileTransferProgress {
    pub filename: String,
    pub total_size: u64,
    pub transferred: u64,
    pub is_receiving: bool,
    pub status: TransferStatus,
    #[serde(skip)]
    pub speed: f64,
    #[serde(skip, default = "Instant::now")]
    pub last_update: Instant,
    #[serde(skip)]
    pub last_transferred: u64,
    pub friend_pk: PublicKey,
}

impl FileTransferProgress {
    pub fn update_speed(&mut self, now: Instant, current_transferred: u64) {
        let duration = now.duration_since(self.last_update).as_secs_f64();
        if duration >= 0.5 {
            self.speed =
                (current_transferred.saturating_sub(self.last_transferred)) as f64 / duration;
            self.last_update = now;
            self.last_transferred = current_transferred;
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DomainState {
    pub tox_id: Address,
    pub self_name: String,
    pub self_status_message: String,
    pub self_status_type: ToxUserStatus,
    pub self_connection_status: ToxConnection,

    #[serde(with = "vectorize_map")]
    pub friends: HashMap<PublicKey, FriendInfo>,
    #[serde(with = "vectorize_map")]
    pub conversations: HashMap<WindowId, Conversation>,
    pub console_messages: Vec<ConsoleMessage>,
    #[serde(with = "vectorize_map")]
    pub tox_logs: HashMap<ToxLogLevel, VecDeque<ToxLogItem>>,
    pub pending_items: Vec<PendingItem>,

    pub next_internal_id: InternalMessageId,
    #[serde(with = "vectorize_map")]
    pub file_transfers: HashMap<FileId, FileTransferProgress>,
}

#[derive(Default)]
pub struct SessionState {
    pub friend_numbers: HashMap<FriendNumber, PublicKey>,
    pub group_numbers: HashMap<GroupNumber, GroupChatId>,
    pub conference_numbers: HashMap<ConferenceNumber, ConferenceId>,
    pub group_peer_numbers: HashMap<(GroupNumber, GroupPeerNumber), PublicKey>,
    pub group_settings: HashMap<GroupChatId, GroupSettings>,
    pub friend_statuses: HashMap<PublicKey, ToxUserStatus>,
    /// The live facts devices in session were last told.
    pub live: Facts,
    pub sync_sessions: HashSet<PublicKey>,
    /// Devices' events waiting for their parents.
    pub held: HashMap<EventId, crate::sync::Held>,
    /// Devices' events we didn't take this session, and those after them, so
    /// we don't ask for them again.
    pub dropped: HashMap<EventId, PublicKey>,
    // Friends sent our Hello since they came online.
    pub greeted: HashSet<PublicKey>,
    /// Friends whose Hello came while online, with what they speak.
    pub hellos: HashMap<PublicKey, Features>,
    pub pairing: Pairing,
    pub blob_transfers: HashMap<BlobId, BlobTransfer>,
    // Friends waiting for a blob that's on its way to another, with the kind
    // of file it goes as.
    pub blob_queue: Vec<(PublicKey, BlobId, u32)>,
    /// The avatars friends are sending.
    pub avatar_offers: HashMap<PublicKey, BlobId>,
    /// The account's avatar a device wished for, while its blob comes.
    pub avatar_wish: Option<BlobId>,
    /// The calls going on, by friend.
    pub calls: HashMap<PublicKey, crate::sync::calls::Call>,
    /// Invites whose chats are being joined.
    pub joining: HashSet<EventId>,
    /// The invites groups were joined from.
    pub group_invites: HashMap<GroupChatId, EventId>,
    /// Changes to the account wait for the next tick.
    pub account_dirty: bool,
    /// Windows messages came to since someone last acted in them: a toxxi
    /// left running reads nothing.
    pub unseen: HashSet<WindowId>,
    /// Files that have all come or gone, being kept as blobs.
    pub finishing: HashSet<FileId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InputMode {
    #[default]
    SingleLine,
    MultiLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UiMode {
    #[default]
    Chat,
    Navigation,
}

#[derive(Clone)]
pub struct UiState {
    pub active_window_index: usize,
    pub window_ids: Vec<WindowId>,
    pub window_state: HashMap<WindowId, WindowUiState>,

    pub input_state: InputBoxState,
    pub input_mode: InputMode,
    pub ui_mode: UiMode,
    pub input_blocked_indices: Vec<(usize, usize)>,
    pub input_history: Vec<String>,
    pub history_index: Option<usize>,
    pub saved_input_before_history: String,

    pub log_filters: LogFilters,
    pub completion: CompletionState,
    pub command_menu: Option<CommandMenuState>,
    pub quick_switcher: Option<QuickSwitcherState>,
    pub emoji_picker: Option<EmojiPickerState>,
    pub qr: Option<String>,
    pub last_typing_activity: Option<Instant>,
    pub is_typing_sent: bool,
    pub sidebar_cache: Option<Vec<SidebarItem>>,
}

#[derive(Clone)]
pub struct CompletionState {
    pub active: bool,
    pub candidates: Vec<String>,
    pub index: usize,
    pub original_input: String,
    pub emoji_grid_state: EmojiGridState,
}

pub struct Model {
    pub domain: DomainState,
    pub ui: UiState,
    pub session: SessionState,
    pub config: Config,
    pub saved_config: Config,
    pub tick_count: u64,
    pub time_provider: Arc<dyn TimeProvider>,
    pub events: EventStore,
    pub message_events: HashMap<(WindowId, InternalMessageId), Recorded>,
    pub account: AccountState,
    pub blobs: Blobs,
}

impl DomainState {
    pub fn self_public_key(&self) -> PublicKey {
        self.tox_id.public_key()
    }

    pub fn new(
        tox_id: Address,
        self_name: String,
        self_status_message: String,
        self_status_type: ToxUserStatus,
    ) -> Self {
        Self {
            tox_id,
            self_name,
            self_status_message,
            self_status_type,
            self_connection_status: ToxConnection::TOX_CONNECTION_NONE,
            friends: HashMap::new(),
            conversations: HashMap::new(),
            console_messages: Vec::new(),
            tox_logs: HashMap::new(),
            pending_items: Vec::new(),
            next_internal_id: InternalMessageId(1),
            file_transfers: HashMap::new(),
        }
    }
}

impl Default for UiState {
    fn default() -> Self {
        Self::new()
    }
}

impl UiState {
    pub fn new() -> Self {
        Self {
            active_window_index: 0,
            window_ids: vec![WindowId::Console],
            window_state: HashMap::new(),
            input_state: InputBoxState::new(),
            input_mode: InputMode::SingleLine,
            ui_mode: UiMode::Chat,
            input_blocked_indices: Vec::new(),
            input_history: Vec::new(),
            history_index: None,
            saved_input_before_history: String::new(),
            log_filters: LogFilters::default(),
            completion: CompletionState {
                active: false,
                candidates: Vec::new(),
                index: 0,
                original_input: String::new(),
                emoji_grid_state: EmojiGridState::default(),
            },
            command_menu: None,
            quick_switcher: None,
            emoji_picker: None,
            qr: None,
            last_typing_activity: None,
            is_typing_sent: false,
            sidebar_cache: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupReconcileInfo {
    pub number: GroupNumber,
    pub chat_id: GroupChatId,
    pub name: Option<String>,
    pub role: Option<ToxGroupRole>,
    pub self_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConferenceReconcileInfo {
    pub number: ConferenceNumber,
    pub id: ConferenceId,
    pub title: Option<String>,
}

impl Model {
    pub fn new(domain: DomainState, saved_config: Config, runtime_config: Config) -> Self {
        let timezone = runtime_config.timezone.clone();
        Self {
            domain,
            ui: UiState::new(),
            session: SessionState::default(),
            config: runtime_config,
            saved_config,
            tick_count: 0,
            time_provider: Arc::new(crate::time::RealTimeProvider::new(timezone.as_deref())),
            events: EventStore::default(),
            message_events: HashMap::new(),
            account: AccountState::default(),
            blobs: Blobs::default(),
        }
    }

    pub(crate) fn persist(&self, records: Vec<Vec<u8>>) -> Vec<Cmd> {
        self.persist_from(records, None)
    }

    /// As `persist`, for events from `device`, which has them already.
    pub(crate) fn persist_from(
        &self,
        records: Vec<Vec<u8>>,
        device: Option<PublicKey>,
    ) -> Vec<Cmd> {
        if records.is_empty() {
            return Vec::new();
        }
        let messages: Vec<Vec<u8>> = session::batches(records.iter().cloned())
            .iter()
            .map(SessionMessage::encode)
            .collect();
        let pushes = self
            .session
            .sync_sessions
            .iter()
            .filter(|session| Some(**session) != device)
            .flat_map(|session| messages.iter().map(|message| (*session, message.clone())))
            .collect();
        vec![Cmd::IO(IOAction::AppendEvents(records, pushes))]
    }

    pub fn record_account(&mut self) -> Vec<Cmd> {
        self.session.account_dirty = false;
        let (kept, live) = crate::sync::facts::split(self);
        let contents: Vec<Content> = crate::sync::facts::changes(self, &kept)
            .into_iter()
            .chain(self.friend_changes())
            .chain(self.request_changes())
            .chain(self.invite_changes())
            .chain(self.read_changes())
            .chain(self.device_changes())
            .collect();
        let mut cmds = self.record_in_account(contents);
        cmds.extend(crate::sync::facts::push(self, live));
        cmds
    }

    pub fn record_in_account(&mut self, contents: Vec<Content>) -> Vec<Cmd> {
        let author = self.domain.self_public_key();
        let graph = GraphId::account(&author);
        let time = self.time_provider.now_local().timestamp_millis();
        let mut records = Vec::new();
        for content in contents {
            let (id, bytes) = self.events.create(graph, author, time, content.clone());
            self.account.apply(id, &content);
            records.push(bytes);
        }
        self.persist(records)
    }

    fn friend_changes(&self) -> Vec<Content> {
        let mut contents = Vec::new();
        for pk in self.domain.friends.keys() {
            let known = self.account.friends.get(pk).cloned().unwrap_or_default();
            if !known.wanted {
                contents.push(Content::WantFriend {
                    pk: *pk,
                    request_message: None,
                    nospam: None,
                });
            }
        }
        for (pk, known) in &self.account.friends {
            if known.wanted && !self.domain.friends.contains_key(pk) {
                contents.push(Content::UnwantFriend { pk: *pk });
            }
        }
        contents
    }

    /// The devices allowed here that the account graph doesn't name, or names
    /// still, as the account's devices.
    pub fn device_changes(&self) -> Vec<Content> {
        let mut contents: Vec<Content> = self
            .config
            .sync_devices
            .iter()
            .filter(|pk| !self.account.devices.contains_key(pk))
            .map(|pk| Content::Device {
                pk: *pk,
                name: self
                    .domain
                    .friends
                    .get(pk)
                    .map(|info| info.name.clone())
                    .unwrap_or_default(),
            })
            .collect();
        contents.extend(
            self.account
                .devices
                .keys()
                .filter(|pk| !self.config.sync_devices.contains(pk))
                .map(|pk| Content::DeviceGone { pk: *pk }),
        );
        contents
    }

    fn request_changes(&self) -> Vec<Content> {
        let pending: HashMap<PublicKey, &String> = self
            .domain
            .pending_items
            .iter()
            .filter_map(|item| match item {
                PendingItem::FriendRequest { pk, message } => Some((*pk, message)),
                _ => None,
            })
            .filter(|(pk, _)| !self.domain.friends.contains_key(pk))
            .collect();
        let known = |pk: &PublicKey| {
            self.account
                .friends
                .get(pk)
                .and_then(|f| f.request.as_ref())
        };
        let mut contents: Vec<Content> = pending
            .iter()
            .filter(|(pk, message)| known(pk) != Some(**message))
            .map(|(pk, message)| Content::FriendRequest {
                pk: *pk,
                message: (*message).clone(),
            })
            .collect();
        // Declined: neither pending nor a friend any more.
        for (pk, friend) in &self.account.friends {
            if friend.request.is_some()
                && !pending.contains_key(pk)
                && !self.domain.friends.contains_key(pk)
            {
                contents.push(Content::UnwantFriend { pk: *pk });
            }
        }
        contents
    }

    /// The invite recorded for `item`, while it waits for an answer, is
    /// being joined, or couldn't be.
    pub fn invite_of(&self, item: &PendingItem) -> Option<EventId> {
        let (from, _, _, data) = item.invite()?;
        self.account
            .invites
            .iter()
            .find(|(_, invite)| invite.from == from && invite.invite == data && invite.is_open())
            .map(|(id, _)| *id)
    }

    /// Invites pending here that devices don't have.
    fn invite_changes(&self) -> Vec<Content> {
        let mut seen = HashSet::new();
        self.domain
            .pending_items
            .iter()
            .filter(|item| self.invite_of(item).is_none())
            .filter_map(PendingItem::invite)
            .filter(|(from, _, _, invite)| seen.insert((*from, invite.clone())))
            .map(|(from, kind, name, invite)| Content::ChatInvite {
                from,
                kind,
                name,
                invite,
            })
            .collect()
    }

    fn newest(&self, graph: &GraphId) -> Option<(u64, EventId)> {
        self.events
            .heads_of(graph)
            .iter()
            .filter_map(|id| self.events.get(id).map(|event| (event.rank, *id)))
            .max()
    }

    /// A chat is read up to a rank: concurrent events of the same rank are
    /// read together.
    fn read_rank(&self, graph: &GraphId) -> Option<u64> {
        self.account.read.get(graph).map(|(rank, _)| *rank)
    }

    /// Windows with nothing unread are read up to their newest event.
    fn read_changes(&self) -> Vec<Content> {
        let me = self.domain.self_public_key();
        self.domain
            .conversations
            .keys()
            .filter(|window_id| {
                !self.session.unseen.contains(window_id)
                    && self
                        .ui
                        .window_state
                        .get(window_id)
                        .is_none_or(|state| state.unread_count == 0)
            })
            .filter_map(|window_id| history::graph_of(&me, *window_id))
            .filter_map(|graph| {
                let (rank, event) = self.newest(&graph)?;
                (self.read_rank(&graph) < Some(rank)).then_some(Content::ReadUpTo {
                    graph,
                    event,
                    rank,
                })
            })
            .collect()
    }

    /// Takes in a read marker from another device. A window it has read
    /// to the end has nothing unread here either.
    pub fn read_elsewhere(&mut self, window_id: WindowId, id: EventId, content: &Content) {
        self.account.apply(id, content);
        let me = self.domain.self_public_key();
        if let Some(graph) = history::graph_of(&me, window_id)
            && self.read_rank(&graph) >= self.newest(&graph).map(|(rank, _)| rank)
            && let Some(state) = self.ui.window_state.get_mut(&window_id)
        {
            state.unread_count = 0;
            self.session.unseen.remove(&window_id);
            self.invalidate_sidebar_cache();
        }
    }

    pub fn record(&mut self, window_id: WindowId, msg: &Message) -> Vec<Cmd> {
        self.record_as(window_id, msg, None)
    }

    /// Records a message that came from Tox as `bytes`.
    pub fn record_received(
        &mut self,
        window_id: WindowId,
        msg: &Message,
        bytes: Vec<u8>,
    ) -> Vec<Cmd> {
        self.record_as(window_id, msg, Some(bytes))
    }

    /// The bytes a text message goes to Tox as: those it was recorded with.
    pub fn tox_bytes(&self, window_id: WindowId, msg: &Message) -> Option<Vec<u8>> {
        let recorded = self.message_events.get(&(window_id, msg.internal_id));
        match recorded.and_then(|recorded| self.events.get(&recorded.id)) {
            Some(Event {
                content: Content::Send { message, .. } | Content::SendPrivately { message, .. },
                ..
            }) => Some(message.clone()),
            _ => msg.content.as_text().map(|text| text.as_bytes().to_vec()),
        }
    }

    fn record_as(
        &mut self,
        window_id: WindowId,
        msg: &Message,
        bytes: Option<Vec<u8>>,
    ) -> Vec<Cmd> {
        let key = (window_id, msg.internal_id);
        let (recorded, records) = history::record(
            &mut self.events,
            self.domain.self_public_key(),
            self.time_provider.now_local().timestamp_millis(),
            window_id,
            msg,
            self.message_events.get(&key).copied(),
            bytes,
        );
        if let Some(recorded) = recorded {
            self.message_events.insert(key, recorded);
        }
        self.persist(records)
    }

    fn viewer(&self, window_id: WindowId) -> history::Viewer {
        history::Viewer {
            me: self.domain.self_public_key(),
            friend: match window_id {
                WindowId::Friend(pk) => Some(pk),
                _ => None,
            },
            offset: *self.time_provider.now_local().offset(),
            patterns: self.highlight_patterns(window_id),
        }
    }

    fn load_history(&mut self, window_id: WindowId) {
        let me = self.domain.self_public_key();
        let Some(graph) = history::graph_of(&me, window_id) else {
            return;
        };
        let events: Vec<_> = self
            .events
            .graph(&graph)
            .into_iter()
            .map(|(id, event)| (id, event.clone()))
            .collect();
        let viewer = self.viewer(window_id);
        let mut messages: Vec<Message> = Vec::new();
        let mut index: HashMap<EventId, usize> = HashMap::new();
        for (id, event) in events {
            let mut update = |target: &EventId, status: MessageStatus| {
                if let Some(&i) = index.get(target) {
                    messages[i].status = status;
                }
            };
            let message = match event.content {
                // Groups have no receipts; their messages are Received once sent.
                Content::Sent { intent } if viewer.friend.is_some() => {
                    update(&intent, MessageStatus::Sent(0));
                    None
                }
                Content::Sent { intent } | Content::Delivered { intent } => {
                    update(&intent, MessageStatus::Received);
                    None
                }
                Content::FileEnded { file, ok, blob } => {
                    if let Some(&i) = index.get(&file) {
                        let msg = &mut messages[i];
                        msg.status = match (ok, msg.is_self) {
                            (false, _) => MessageStatus::Failed,
                            (true, true) => MessageStatus::Sent(0),
                            (true, false) => MessageStatus::Received,
                        };
                        if let MessageContent::FileTransfer {
                            progress,
                            blob: held,
                            ..
                        } = &mut msg.content
                            && ok
                        {
                            *progress = 1.0;
                            *held = blob.or(*held);
                        }
                    }
                    None
                }
                content => {
                    history::message_of(&viewer, self.domain.next_internal_id, event.time, content)
                }
            };
            if let Some(message) = message {
                self.domain.next_internal_id.0 += 1;
                index.insert(id, messages.len());
                messages.push(message);
            }
        }

        for (id, i) in index {
            let msg = &messages[i];
            self.message_events.insert(
                (window_id, msg.internal_id),
                Recorded::new(id, window_id, msg),
            );
        }
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            conv.messages = messages;
        }
    }

    /// The conversation of this account that `graph` holds.
    pub fn window_of(&self, graph: &GraphId) -> Option<WindowId> {
        let me = self.domain.self_public_key();
        self.domain
            .friends
            .keys()
            .map(|pk| WindowId::Friend(*pk))
            .chain(self.domain.conversations.keys().copied())
            .find(|window_id| history::graph_of(&me, *window_id).as_ref() == Some(graph))
    }

    /// Shows a message one of the devices sent through this one, pending like
    /// any of ours, and returns it.
    pub fn add_device_message(&mut self, window_id: WindowId, id: EventId) -> Option<Message> {
        if !self.domain.conversations.contains_key(&window_id) {
            // The new window's history has it.
            self.ensure_window(window_id);
            let (&(_, internal_id), _) = self
                .message_events
                .iter()
                .find(|((window, _), recorded)| *window == window_id && recorded.id == id)?;
            return self.domain.conversations[&window_id]
                .messages
                .iter()
                .find(|msg| msg.internal_id == internal_id)
                .cloned();
        }
        let event = self.events.get(&id)?.clone();
        let msg = history::message_of(
            &self.viewer(window_id),
            self.domain.next_internal_id,
            event.time,
            event.content,
        )?;
        self.domain.next_internal_id.0 += 1;
        self.message_events.insert(
            (window_id, msg.internal_id),
            Recorded::new(id, window_id, &msg),
        );
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            conv.messages.push(msg.clone());
        }
        self.invalidate_window_cache(window_id);
        Some(msg)
    }

    pub fn with_time_provider(mut self, tp: Arc<dyn TimeProvider>) -> Self {
        self.time_provider = tp;
        self
    }

    pub fn invalidate_window_cache(&mut self, window_id: WindowId) {
        if let Some(state) = self.ui.window_state.get_mut(&window_id) {
            state.invalidate_layout();
        }
    }

    pub fn invalidate_full_window_cache(&mut self, window_id: WindowId) {
        if let Some(state) = self.ui.window_state.get_mut(&window_id) {
            state.invalidate_full_cache();
        }
    }

    pub fn invalidate_sidebar_cache(&mut self) {
        self.ui.sidebar_cache = None;
    }

    pub fn set_active_window(&mut self, index: usize) {
        if index < self.ui.window_ids.len() {
            self.ui.active_window_index = index;
            self.read_active();
            self.ui.is_typing_sent = false;
            self.ui.last_typing_activity = None;
            self.invalidate_sidebar_cache();
        }
    }

    /// Someone acts in the window shown, so has read it.
    pub fn read_active(&mut self) {
        let id = self.active_window_id();
        if let Some(state) = self.ui.window_state.get_mut(&id) {
            state.unread_count = 0;
        }
        self.session.unseen.remove(&id);
        self.invalidate_sidebar_cache();
    }

    pub fn active_window_id(&self) -> WindowId {
        self.ui.window_ids[self.ui.active_window_index]
    }

    fn friend_name(&self, pk: &PublicKey) -> String {
        self.domain
            .friends
            .get(pk)
            .map(|info| info.name.clone())
            .unwrap_or_else(|| unnamed_friend(pk))
    }

    pub fn window_name(&self, id: WindowId) -> String {
        if let Some(conv) = self.domain.conversations.get(&id) {
            return conv.name.clone();
        }
        match id {
            WindowId::Console => "Status".to_owned(),
            WindowId::Logs => "Logs".to_owned(),
            WindowId::Files => "Files".to_owned(),
            WindowId::Friend(pk) => self.friend_name(&pk),
            WindowId::Group(g) => format!("Group {}", crate::utils::encode_hex(&g.0[0..4])),
            WindowId::Conference(c) => {
                format!("Conference {}", crate::utils::encode_hex(&c.0[0..4]))
            }
        }
    }

    pub fn should_highlight(&self, window_id: WindowId, text: &str) -> bool {
        self.highlight_patterns(window_id)
            .iter()
            .any(|re| re.is_match(text))
    }

    fn highlight_patterns(&self, window_id: WindowId) -> Vec<Regex> {
        let mut highlights = self.config.highlight_strings.clone();
        highlights.push(self.domain.self_name.clone());

        if let WindowId::Group(chat_id) = window_id
            && let Some(conv) = self.domain.conversations.get(&WindowId::Group(chat_id))
            && let Some(self_name) = &conv.self_name
        {
            highlights.push(self_name.clone());
        }

        highlights
            .iter()
            .filter(|h| !h.is_empty())
            .filter_map(|h| {
                Regex::new(&format!(
                    r"(?i)(^|[\s@:.,!?])\b{}\b($|[\s:.,!?']|'s)",
                    regex::escape(h)
                ))
                .ok()
            })
            .collect()
    }

    fn push_console_message(&mut self, msg_type: ConsoleMessageType, content: MessageContent) {
        let console = &mut self.domain.console_messages;
        console.push(ConsoleMessage {
            msg_type,
            content,
            timestamp: self.time_provider.now_local(),
        });
        if console.len() > MAX_CONSOLE_MESSAGES {
            console.drain(..console.len() - MAX_CONSOLE_MESSAGES);
        }
    }

    pub fn add_console_message(&mut self, msg_type: ConsoleMessageType, content: String) {
        self.push_console_message(msg_type, MessageContent::Text(content));
        self.invalidate_window_cache(WindowId::Console);
        self.invalidate_sidebar_cache();
    }

    pub fn add_info_message(&mut self, content: MessageContent) {
        self.add_system_message(ConsoleMessageType::Info, content);
    }

    pub fn add_status_message(&mut self, content: MessageContent) {
        self.add_system_message(ConsoleMessageType::Status, content);
    }

    pub fn add_error_message(&mut self, content: MessageContent) {
        self.add_system_message(ConsoleMessageType::Error, content);
    }

    fn add_system_message(&mut self, msg_type: ConsoleMessageType, content: MessageContent) {
        let active_id = self.active_window_id();
        self.add_system_message_to(active_id, msg_type, content);
    }

    pub fn add_system_message_to(
        &mut self,
        window_id: WindowId,
        msg_type: ConsoleMessageType,
        content: MessageContent,
    ) -> Option<Message> {
        match window_id {
            WindowId::Console | WindowId::Logs | WindowId::Files => {
                self.push_console_message(msg_type, content);
                self.invalidate_window_cache(window_id);
                self.invalidate_sidebar_cache();
                None
            }
            _ => {
                let active_id = self.active_window_id();
                let highlighted = if let MessageContent::Text(text) = &content {
                    self.should_highlight(window_id, text)
                } else {
                    false
                };
                if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
                    let internal_id = self.domain.next_internal_id;
                    self.domain.next_internal_id.0 += 1;
                    let msg = Message {
                        internal_id,
                        sender: SYSTEM_SENDER.to_owned(),
                        sender_pk: None,
                        is_self: false,
                        content,
                        timestamp: self.time_provider.now_local(),
                        status: MessageStatus::Incoming,
                        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                        highlighted,
                        privately: None,
                    };
                    conv.messages.push(msg.clone());
                    if active_id != window_id {
                        let state = self.ui.window_state.entry(window_id).or_default();
                        state.unread_count += 1;
                    }
                    self.invalidate_window_cache(window_id);
                    self.invalidate_sidebar_cache();
                    Some(msg)
                } else {
                    None
                }
            }
        }
    }

    pub fn ensure_friend_window(&mut self, pk: PublicKey) {
        self.ensure_friend_conversation(pk);
        self.open_window(WindowId::Friend(pk));
    }

    fn ensure_friend_conversation(&mut self, pk: PublicKey) {
        let default_name = self.friend_name(&pk);
        self.ensure_conversation(WindowId::Friend(pk), default_name);
    }

    /// Closes a window, leaving it if it's a group or conference.
    pub fn close_window(&mut self, window_id: WindowId) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        match window_id {
            WindowId::Group(chat_id) => {
                cmds.push(Cmd::Tox(ToxAction::LeaveGroup(chat_id)));
            }
            WindowId::Conference(conf_id) => {
                cmds.push(Cmd::Tox(ToxAction::DeleteConference(conf_id)));
            }
            _ => {}
        }

        // Remove window and conversation
        self.ui.window_ids.retain(|id| *id != window_id);
        self.domain.conversations.remove(&window_id);
        self.message_events
            .retain(|(window, _), _| *window != window_id);
        self.ui.window_state.remove(&window_id);

        // Adjust active index
        if self.ui.active_window_index >= self.ui.window_ids.len() {
            self.ui.active_window_index = self.ui.window_ids.len().saturating_sub(1);
        }
        cmds
    }

    pub fn ensure_group_window(&mut self, chat_id: GroupChatId) {
        let name = if let Some((num, _)) = self
            .session
            .group_numbers
            .iter()
            .find(|(_, id)| *id == &chat_id)
        {
            format!("Group {}", num.0)
        } else {
            "Group".to_owned()
        };
        self.ensure_conversation_window(WindowId::Group(chat_id), name);
    }

    pub fn ensure_conference_window(&mut self, conference_id: ConferenceId) {
        let name = if let Some((num, _)) = self
            .session
            .conference_numbers
            .iter()
            .find(|(_, id)| *id == &conference_id)
        {
            format!("Conference {}", num.0)
        } else {
            "Conference".to_owned()
        };
        self.ensure_conversation_window(WindowId::Conference(conference_id), name);
    }

    fn ensure_conversation_window(&mut self, window_id: WindowId, default_name: String) {
        self.ensure_conversation(window_id, default_name);
        self.open_window(window_id);
    }

    fn open_window(&mut self, window_id: WindowId) {
        if !self.ui.window_ids.contains(&window_id) {
            self.ui.window_ids.push(window_id);
            self.invalidate_sidebar_cache();
        }
    }

    fn ensure_conversation(&mut self, window_id: WindowId, default_name: String) {
        if let Entry::Vacant(entry) = self.domain.conversations.entry(window_id) {
            entry.insert(Conversation {
                name: default_name,
                messages: Vec::new(),
                topic: None,
                peers: Vec::new(),
                self_role: None,
                self_name: None,
                ignored_peers: HashSet::new(),
            });
            self.load_history(window_id);
        }
        self.invalidate_sidebar_cache();
    }

    pub fn total_messages_for(&self, id: WindowId) -> usize {
        match id {
            WindowId::Console => self.domain.console_messages.len(),
            WindowId::Logs => self.domain.tox_logs.values().map(|v| v.len()).sum(),
            WindowId::Files => self.domain.file_transfers.len(),
            _ => self
                .domain
                .conversations
                .get(&id)
                .map(|c| c.messages.len())
                .unwrap_or(0),
        }
    }

    pub fn scroll_up(&mut self, amount: usize) {
        let id = self.active_window_id();
        let state = self.ui.window_state.entry(id).or_default();
        let max_scroll = state
            .msg_list_state
            .total_height
            .saturating_sub(state.last_height);
        state.msg_list_state.scroll = (state.msg_list_state.scroll + amount).min(max_scroll);
    }

    pub fn scroll_down(&mut self, amount: usize) {
        let id = self.active_window_id();
        let state = self.ui.window_state.entry(id).or_default();
        state.msg_list_state.scroll = state.msg_list_state.scroll.saturating_sub(amount);
    }

    pub fn add_outgoing_message(
        &mut self,
        window_id: WindowId,
        message_type: MessageType,
        content: String,
    ) -> (InternalMessageId, Message) {
        self.add_outgoing(window_id, message_type, content, None)
    }

    /// A message to one member of a group alone.
    pub fn add_outgoing_private_message(
        &mut self,
        chat_id: GroupChatId,
        to: PublicKey,
        message_type: MessageType,
        content: String,
    ) -> (InternalMessageId, Message) {
        self.add_outgoing(WindowId::Group(chat_id), message_type, content, Some(to))
    }

    fn add_outgoing(
        &mut self,
        window_id: WindowId,
        message_type: MessageType,
        content: String,
        privately: Option<PublicKey>,
    ) -> (InternalMessageId, Message) {
        self.ensure_window(window_id);

        let internal_id = self.domain.next_internal_id;
        self.domain.next_internal_id.0 += 1;

        let mut msg = Message {
            internal_id,
            sender: String::new(),
            sender_pk: Some(self.domain.self_public_key()),
            is_self: true,
            content: MessageContent::Text(content),
            timestamp: self.time_provider.now_local(),
            status: MessageStatus::Pending,
            message_type,
            highlighted: false,
            privately,
        };

        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            let sender = conv
                .self_name
                .clone()
                .unwrap_or_else(|| self.domain.self_name.clone());
            msg.sender = sender;
            conv.messages.push(msg.clone());
            self.invalidate_window_cache(window_id);
        } else {
            msg.sender = self.domain.self_name.clone();
        }

        (internal_id, msg)
    }

    pub fn add_outgoing_friend_message(
        &mut self,
        pk: PublicKey,
        message_type: MessageType,
        msg: String,
    ) -> (InternalMessageId, Message) {
        self.add_outgoing_message(WindowId::Friend(pk), message_type, msg)
    }

    pub fn add_friend_message(
        &mut self,
        pk: PublicKey,
        message_type: MessageType,
        msg: String,
    ) -> Option<Message> {
        let window_id = WindowId::Friend(pk);
        self.ensure_friend_window(pk);

        let sender = self.friend_name(&pk);
        let sender_pk = self
            .domain
            .friends
            .get(&pk)
            .map_or(Some(pk), |info| info.public_key);

        self.add_incoming_message(window_id, message_type, sender, msg, sender_pk, false)
    }

    pub fn add_group_message(
        &mut self,
        chat_id: GroupChatId,
        message_type: MessageType,
        sender: String,
        content: String,
        sender_pk: Option<PublicKey>,
    ) -> Option<Message> {
        self.ensure_group_window(chat_id);
        self.add_incoming_message(
            WindowId::Group(chat_id),
            message_type,
            sender,
            content,
            sender_pk,
            false,
        )
    }

    /// A message from one member of a group to the account alone.
    pub fn add_private_group_message(
        &mut self,
        chat_id: GroupChatId,
        message_type: MessageType,
        sender: String,
        content: String,
        from: PublicKey,
    ) -> Option<Message> {
        self.ensure_group_window(chat_id);
        self.add_incoming_message(
            WindowId::Group(chat_id),
            message_type,
            sender,
            content,
            Some(from),
            true,
        )
    }

    pub fn add_conference_message(
        &mut self,
        conference_id: ConferenceId,
        message_type: MessageType,
        sender: String,
        content: String,
        sender_pk: Option<PublicKey>,
    ) -> Option<Message> {
        self.ensure_conference_window(conference_id);
        self.add_incoming_message(
            WindowId::Conference(conference_id),
            message_type,
            sender,
            content,
            sender_pk,
            false,
        )
    }

    fn add_incoming_message(
        &mut self,
        window_id: WindowId,
        message_type: MessageType,
        sender: String,
        content: String,
        sender_pk: Option<PublicKey>,
        private: bool,
    ) -> Option<Message> {
        let active_id = self.active_window_id();
        let highlighted = self.should_highlight(window_id, &content);
        let me = self.domain.self_public_key();
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            let internal_id = self.domain.next_internal_id;
            self.domain.next_internal_id.0 += 1;
            let is_self = sender_pk.as_ref().map(|pk| *pk == me).unwrap_or(false);
            let msg = Message {
                internal_id,
                sender,
                sender_pk,
                is_self,
                content: MessageContent::Text(content),
                timestamp: self.time_provider.now_local(),
                status: MessageStatus::Incoming,
                message_type,
                highlighted,
                privately: sender_pk.filter(|_| private),
            };
            conv.messages.push(msg.clone());
            if active_id != window_id {
                let state = self.ui.window_state.entry(window_id).or_default();
                state.unread_count += 1;
            }
            if !is_self {
                self.session.unseen.insert(window_id);
            }
            self.invalidate_window_cache(window_id);
            self.invalidate_sidebar_cache();
            Some(msg)
        } else {
            None
        }
    }

    /// Forgets a friend and their window, and deletes them from Tox.
    pub fn remove_friend(&mut self, pk: PublicKey) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        if self.session.calls.contains_key(&pk) {
            cmds.push(Cmd::Tox(ToxAction::CallHangUp(pk)));
            cmds.extend(crate::sync::calls::ended(self, pk));
        }
        let window_id = WindowId::Friend(pk);
        self.domain.friends.remove(&pk);
        self.domain.conversations.remove(&window_id);
        self.message_events
            .retain(|(window, _), _| *window != window_id);
        self.session
            .friend_numbers
            .retain(|_, friend| *friend != pk);
        self.ui.window_ids.retain(|&w| w != window_id);
        if self.ui.active_window_index >= self.ui.window_ids.len() {
            self.ui.active_window_index = self.ui.window_ids.len().saturating_sub(1);
        }
        self.invalidate_sidebar_cache();
        cmds.push(Cmd::Tox(ToxAction::DeleteFriend(pk)));
        cmds
    }

    pub fn ensure_window(&mut self, window_id: WindowId) {
        match window_id {
            WindowId::Friend(pk) => self.ensure_friend_window(pk),
            WindowId::Group(g) => self.ensure_group_window(g),
            WindowId::Conference(c) => self.ensure_conference_window(c),
            WindowId::Console | WindowId::Logs | WindowId::Files => {
                if !self.ui.window_ids.contains(&window_id) {
                    self.ui.window_ids.push(window_id);
                }
            }
        }
    }

    pub fn add_file_transfer_message(
        &mut self,
        window_id: WindowId,
        is_self: bool,
        file_id: FileId,
        filename: String,
        size: u64,
        is_incoming: bool,
    ) -> Option<Message> {
        let me = self.domain.self_public_key();
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            let internal_id = self.domain.next_internal_id;
            self.domain.next_internal_id.0 += 1;

            let sender = if is_self {
                conv.self_name
                    .clone()
                    .unwrap_or_else(|| self.domain.self_name.clone())
            } else {
                match window_id {
                    WindowId::Friend(pk) => self
                        .domain
                        .friends
                        .get(&pk)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| unnamed_friend(&pk)),
                    _ => SYSTEM_SENDER.to_owned(),
                }
            };

            let msg = Message {
                internal_id,
                sender,
                sender_pk: if is_self {
                    Some(me)
                } else {
                    match window_id {
                        WindowId::Friend(pk) => Some(pk),
                        _ => None,
                    }
                },
                is_self,
                content: MessageContent::FileTransfer {
                    file_id: Some(file_id),
                    name: filename,
                    size,
                    progress: 0.0,
                    speed: "0 B/s".to_owned(),
                    is_incoming,
                    blob: None,
                },
                timestamp: self.time_provider.now_local(),
                status: if is_self {
                    MessageStatus::Pending
                } else {
                    MessageStatus::Incoming
                },
                message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                highlighted: false,
                privately: None,
            };

            conv.messages.push(msg.clone());
            self.invalidate_window_cache(window_id);
            Some(msg)
        } else {
            None
        }
    }

    pub fn add_tox_log(
        &mut self,
        level: ToxLogLevel,
        file: String,
        line: u32,
        func: String,
        message: String,
    ) {
        if self.ui.log_filters.paused {
            return;
        }
        let item = ToxLogItem {
            level,
            file,
            line,
            func,
            message,
            timestamp: self.time_provider.now_local(),
        };

        if self.ui.log_filters.matches(&item)
            && let Some(state) = self.ui.window_state.get_mut(&WindowId::Logs)
            && state.msg_list_state.scroll > 0
        {
            state.msg_list_state.scroll += 1;
        }

        let bucket = self.domain.tox_logs.entry(level).or_default();
        bucket.push_back(item);
        if bucket.len() > 200 {
            bucket.pop_front();
        }
        self.invalidate_window_cache(WindowId::Logs);
        self.invalidate_sidebar_cache();
    }

    pub fn scroll_top(&mut self) {
        let id = self.active_window_id();
        let state = self.ui.window_state.entry(id).or_default();
        state.msg_list_state.scroll = state
            .msg_list_state
            .total_height
            .saturating_sub(state.last_height);
    }

    pub fn scroll_bottom(&mut self) {
        let id = self.active_window_id();
        let state = self.ui.window_state.entry(id).or_default();
        state.msg_list_state.scroll_to_bottom();
    }

    pub fn update_file_progress(
        &mut self,
        pk: PublicKey,
        file: FileId,
        transferred: u64,
        total_size: u64,
        speed: String,
    ) {
        let window_id = WindowId::Friend(pk);
        let mut updated_idx = None;
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            for (i, msg) in conv.messages.iter_mut().enumerate().rev() {
                if let MessageContent::FileTransfer {
                    file_id: Some(fid),
                    progress,
                    speed: msg_speed,
                    ..
                } = &mut msg.content
                    && *fid == file
                {
                    if total_size > 0 {
                        *progress = transferred as f64 / total_size as f64;
                    }
                    *msg_speed = speed;
                    updated_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = updated_idx
            && let Some(state) = self.ui.window_state.get_mut(&window_id)
        {
            state.dirty_indices.insert(idx);
            state.invalidate_layout();
        }
    }

    /// The message of the file transfer `file` with `pk`.
    pub fn file_message(&mut self, pk: PublicKey, file: FileId) -> Option<&mut Message> {
        self.domain
            .conversations
            .get_mut(&WindowId::Friend(pk))?
            .messages
            .iter_mut()
            .rev()
            .find(|msg| {
                matches!(&msg.content, MessageContent::FileTransfer { file_id: Some(id), .. } if *id == file)
            })
    }

    pub fn update_file_status(
        &mut self,
        pk: PublicKey,
        file: FileId,
        status: MessageStatus,
    ) -> Option<Message> {
        let window_id = WindowId::Friend(pk);
        let mut updated_msg = None;
        let mut updated_idx = None;
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            for (i, msg) in conv.messages.iter_mut().enumerate().rev() {
                if let MessageContent::FileTransfer {
                    file_id: Some(fid), ..
                } = &msg.content
                    && *fid == file
                {
                    msg.status = status;
                    updated_msg = Some(msg.clone());
                    updated_idx = Some(i);
                    break;
                }
            }
        }
        if let Some(idx) = updated_idx
            && let Some(state) = self.ui.window_state.get_mut(&window_id)
        {
            state.dirty_indices.insert(idx);
            state.invalidate_layout();
        }
        updated_msg
    }

    pub fn mark_message_status(
        &mut self,
        window_id: WindowId,
        internal_id: InternalMessageId,
        status: MessageStatus,
    ) -> Option<Message> {
        let mut updated_msg = None;
        let mut updated_idx = None;
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            for (i, m) in conv.messages.iter_mut().enumerate().rev() {
                if m.internal_id == internal_id {
                    m.status = status;
                    updated_msg = Some(m.clone());
                    updated_idx = Some(i);
                    break;
                }
            }
        }
        if let Some(idx) = updated_idx
            && let Some(state) = self.ui.window_state.get_mut(&window_id)
        {
            state.dirty_indices.insert(idx);
            state.invalidate_layout();
        }
        updated_msg
    }

    pub fn reconcile(
        &mut self,
        friends: Vec<(FriendNumber, FriendInfo)>,
        groups: Vec<GroupReconcileInfo>,
        conferences: Vec<ConferenceReconcileInfo>,
    ) {
        // Clear session mappings
        self.session.friend_numbers.clear();
        self.session.group_numbers.clear();
        self.session.conference_numbers.clear();
        self.session.group_peer_numbers.clear();

        // 1. Populate friends and session mappings
        let mut new_friends_map = HashMap::new();
        for (num, info) in friends {
            if let Some(pk) = info.public_key {
                self.session.friend_numbers.insert(num, pk);
                new_friends_map.insert(pk, info);
            }
        }
        self.domain.friends = new_friends_map;

        // 2. Populate Groups and session mappings
        for info in groups {
            self.session.group_numbers.insert(info.number, info.chat_id);
            self.ensure_group_window(info.chat_id);

            if let Some(conv) = self
                .domain
                .conversations
                .get_mut(&WindowId::Group(info.chat_id))
            {
                if let Some(n) = info.name {
                    if !n.is_empty() {
                        conv.name = n;
                    } else if conv.name == "Group" {
                        conv.name = format!("Group {}", info.number.0);
                    }
                } else if conv.name == "Group" {
                    conv.name = format!("Group {}", info.number.0);
                }
                conv.self_role = info.role;
                conv.self_name = info.self_name;
            }
        }

        // 3. Populate Conferences and session mappings
        for info in conferences {
            self.session.conference_numbers.insert(info.number, info.id);
            self.ensure_conference_window(info.id);

            if let Some(conv) = self
                .domain
                .conversations
                .get_mut(&WindowId::Conference(info.id))
            {
                if let Some(t) = info.title {
                    if !t.is_empty() {
                        conv.name = t;
                    } else if conv.name == "Conference" {
                        conv.name = format!("Conference {}", info.number.0);
                    }
                } else if conv.name == "Conference" {
                    conv.name = format!("Conference {}", info.number.0);
                }
            }
        }

        // 4. Ensure Friend Conversations exist; their windows stay as the user left them
        let friend_pks: Vec<_> = self.domain.friends.keys().cloned().collect();
        for pk in friend_pks {
            self.ensure_friend_conversation(pk);
            // Sync name
            let info = self.domain.friends.get(&pk).unwrap(); // Safe unwrap
            if let Some(conv) = self.domain.conversations.get_mut(&WindowId::Friend(pk))
                && !info.name.is_empty()
                && info.name != conv.name
            {
                conv.name = info.name.clone();
            }
        }

        // 5. Cleanup old conversations (if needed)
        // Since we rebuild mappings, if a conversation exists in `domain.conversations` but not in new lists,
        // it persists (which is good for history). We don't delete them.

        // 6. Deduplicate peers and reset online status (ghosts from cache)
        for conv in self.domain.conversations.values_mut() {
            let mut seen = std::collections::HashSet::new();
            conv.peers.retain(|p| seen.insert(p.id));
            for peer in &mut conv.peers {
                peer.seen_online = false;
                peer.status = ToxUserStatus::TOX_USER_STATUS_NONE;
            }
        }

        self.invalidate_sidebar_cache();
    }
}

mod vectorize_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
    use std::collections::HashMap;
    use std::hash::Hash;

    pub fn serialize<K, V, S>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize,
        V: Serialize,
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for entry in map {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Eq + Hash,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let vec = Vec::<(K, V)>::deserialize(deserializer)?;
        Ok(vec.into_iter().collect())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FullState {
    pub domain: DomainState,
    pub active_window_index: usize,
    pub window_ids: Vec<WindowId>,
    #[serde(with = "vectorize_map")]
    pub window_state: HashMap<WindowId, WindowUiState>,
    pub input_history: Vec<String>,
    pub log_filters: LogFilters,
}

pub fn save_state(config_dir: &Path, model: &Model) -> io::Result<()> {
    let state_path = config_dir.join("state.json");
    let state = FullState {
        domain: model.domain.clone(),
        active_window_index: model.ui.active_window_index,
        window_ids: model.ui.window_ids.clone(),
        window_state: model.ui.window_state.clone(),
        input_history: model.ui.input_history.clone(),
        log_filters: model.ui.log_filters.clone(),
    };
    let data = serde_json::to_string_pretty(&state)?;
    fs::write(state_path, data)?;
    Ok(())
}

pub fn load_state(config_dir: &Path) -> Result<Option<FullState>, String> {
    let state_path = config_dir.join("state.json");
    if state_path.exists() {
        match fs::read_to_string(&state_path) {
            Ok(data) => match serde_json::from_str::<FullState>(&data) {
                Ok(state) => Ok(Some(state)),
                Err(e) => Err(format!("Failed to parse state file: {}", e)),
            },
            Err(e) => Err(format!("Failed to read state file: {}", e)),
        }
    } else {
        Ok(None)
    }
}

pub struct ToxSelfInfo {
    pub tox_id: Address,
    pub name: String,
    pub status_msg: String,
    pub status_type: ToxUserStatus,
}

pub fn initialize_model(
    self_info: ToxSelfInfo,
    friends: Vec<(FriendNumber, FriendInfo)>,
    groups: Vec<GroupReconcileInfo>,
    conferences: Vec<ConferenceReconcileInfo>,
    saved_config: Config,
    runtime_config: Config,
) -> Model {
    let domain = DomainState::new(
        self_info.tox_id,
        self_info.name,
        self_info.status_msg,
        self_info.status_type,
    );
    let mut m = Model::new(domain, saved_config, runtime_config);
    m.reconcile(friends, groups, conferences);
    // Without saved windows, open every friend's.
    let friend_pks: Vec<_> = m.domain.friends.keys().cloned().collect();
    for pk in friend_pks {
        m.ensure_friend_window(pk);
    }
    m
}

pub fn load_or_initialize(
    config_dir: &Path,
    self_info: ToxSelfInfo,
    friends: Vec<(FriendNumber, FriendInfo)>,
    groups: Vec<GroupReconcileInfo>,
    conferences: Vec<ConferenceReconcileInfo>,
    saved_config: Config,
    runtime_config: Config,
) -> Model {
    let mut load_error = None;
    match load_state(config_dir) {
        Ok(Some(state)) => {
            if state.domain.tox_id == self_info.tox_id {
                let mut m = Model::new(state.domain, saved_config, runtime_config);
                m.ui.window_ids = state.window_ids;
                m.ui.window_state = state.window_state;

                m.reconcile(friends, groups, conferences);

                m.set_active_window(state.active_window_index);
                m.ui.input_history = state.input_history;
                m.ui.log_filters = state.log_filters;

                load_history(&mut m, config_dir);
                return m;
            } else {
                load_error = Some(format!(
                    "Tox ID mismatch in state file. Expected {}, found {}",
                    self_info.tox_id, state.domain.tox_id
                ));
            }
        }
        Ok(None) => {}
        Err(e) => {
            load_error = Some(e);
        }
    }

    let mut m = initialize_model(
        self_info,
        friends,
        groups,
        conferences,
        saved_config,
        runtime_config,
    );

    if let Some(err) = load_error {
        m.add_console_message(ConsoleMessageType::Error, err);
    }

    load_history(&mut m, config_dir);
    m
}

fn load_history(m: &mut Model, config_dir: &Path) {
    m.blobs = Blobs::load(config_dir);
    let path = config_dir.join(EVENTS_FILE);
    match read_log(&path) {
        Ok(records) => {
            let bad = records
                .iter()
                .filter(|record| m.events.insert(record).is_err())
                .count();
            if bad > 0 {
                m.add_console_message(
                    ConsoleMessageType::Error,
                    format!("Skipped {} unreadable events in {}", bad, EVENTS_FILE),
                );
            }
        }
        Err(e) => m.add_console_message(
            ConsoleMessageType::Error,
            format!("Failed to read {}: {}", EVENTS_FILE, e),
        ),
    }
    let conversations: Vec<WindowId> = m.domain.conversations.keys().copied().collect();
    for window_id in conversations {
        m.load_history(window_id);
    }
    m.account = AccountState::of(&m.events, &GraphId::account(&m.domain.self_public_key()));
}
// end of file
