use crate::config::{Config, SystemMessageType};
use crate::disk::Disk;
use crate::msg::{Cmd, IOAction, ToxAction};
use crate::sync::account::AccountState;
use crate::sync::event::{BlobId, ChatId, ChatKind, Content, Event, EventId, GraphId};
use crate::sync::fact::Facts;
use crate::sync::files::{BlobTransfer, Blobs};
use crate::sync::history::{self, Recorded};
use crate::sync::pairing::Pairing;
use crate::sync::protocol::{Features, SessionMessage};
use crate::sync::replica::Replica;
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
    ConferenceNumber, ConferenceType, Connection, FriendMessageId, GroupNumber, GroupPeerNumber,
    UserStatus,
};
use toxcore::types::{
    Address, ConferenceId, FileId, FileKind, GroupChatId, GroupPrivacyState, GroupRole,
    GroupVoiceState, LogLevel, MessageType, PublicKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InternalMessageId(pub usize);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FriendInfo {
    pub name: String,
    pub public_key: Option<PublicKey>,
    pub status_message: String,
    pub connection: Connection,
    #[serde(skip, default)]
    pub is_typing: bool,
}

fn unnamed_friend(pk: &PublicKey) -> String {
    format!("Friend {}", crate::utils::short_key(pk))
}

impl FriendInfo {
    /// A friend Tox hasn't told us anything about yet.
    pub fn new(pk: PublicKey, connection: Connection) -> Self {
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
    /// Sent, with the ID its receipt will carry, or None if an earlier Tox
    /// sent it.
    Sent(Option<FriendMessageId>),
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
        /// The file's blob, once the home has it: a device's file to send, or
        /// a file that finished.
        #[serde(skip)]
        blob: Option<BlobId>,
    },
}

impl MessageContent {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            MessageContent::Text(t) => Some(t),
            MessageContent::List(_) | MessageContent::FileTransfer { .. } => None,
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
    /// In a group, the peer of a private message: who it went to, or who
    /// sent it.
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
    pub role: Option<GroupRole>,
    pub status: UserStatus,
    pub is_ignored: bool,
    pub seen_online: bool,
}

/// A group's settings, as Tox last reported them.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupSettings {
    pub privacy: GroupPrivacyState,
    pub peer_limit: u16,
    /// Empty for none.
    pub password: String,
    pub topic_lock: bool,
    pub voice_state: GroupVoiceState,
    /// Our key in the group, which differs from our Tox key.
    pub self_pk: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Conversation {
    pub name: String,
    #[serde(skip, default)]
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("all history stays in memory, which is fine for now")
    )]
    pub messages: Vec<Message>,
    pub topic: Option<String>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per peer toxcore has in the group"))]
    pub peers: Vec<PeerInfo>,
    pub self_role: Option<GroupRole>,
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
    pub level: LogLevel,
    pub file: String,
    pub line: u32,
    pub func: String,
    pub message: String,
    pub timestamp: DateTime<FixedOffset>,
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct LogFilters {
    pub levels: Vec<LogLevel>,
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

/// Strangers can send friend requests from as many keys as they like.
pub const MAX_PENDING_ITEMS: usize = 100;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum PendingItem {
    FriendRequest {
        pk: PublicKey,
        message: String,
    },
    GroupInvite {
        friend: PublicKey,
        #[serde(with = "crate::utils::hex_json")]
        invite_data: Vec<u8>,
        group_name: String,
    },
    ConferenceInvite {
        friend: PublicKey,
        conference_type: ConferenceType,
        #[serde(with = "crate::utils::hex_json")]
        cookie: Vec<u8>,
    },
}

impl PendingItem {
    /// Whether `other` asks the same: a request from the same key, or the
    /// same invite.
    fn same(&self, other: &PendingItem) -> bool {
        match (self, other) {
            (
                PendingItem::FriendRequest { pk: a, .. },
                PendingItem::FriendRequest { pk: b, .. },
            ) => a == b,
            _ => self == other,
        }
    }

    /// Returns the inviting friend, the kind of chat, its name and the data
    /// Tox joins it with.
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
                invite_data.clone(),
            )),
            PendingItem::ConferenceInvite { friend, cookie, .. } => {
                Some((*friend, ChatKind::Conference, String::new(), cookie.clone()))
            }
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
    #[cfg_attr(tokstyle, tokstyle::bounded("cleared at each render"))]
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
    pub self_status_type: UserStatus,
    pub self_connection_status: Connection,

    #[serde(with = "vectorize_map")]
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub friends: HashMap<PublicKey, FriendInfo>,
    #[serde(with = "vectorize_map")]
    #[cfg_attr(tokstyle, tokstyle::bounded("one per chat"))]
    pub conversations: HashMap<WindowId, Conversation>,
    pub console_messages: Vec<ConsoleMessage>,
    #[serde(with = "vectorize_map")]
    pub tox_logs: HashMap<LogLevel, VecDeque<ToxLogItem>>,
    pub pending_items: Vec<PendingItem>,

    pub next_internal_id: InternalMessageId,
    #[serde(with = "vectorize_map")]
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("one per transfer, which toxcore limits for each friend")
    )]
    pub file_transfers: HashMap<FileId, FileTransferProgress>,
}

#[derive(Default)]
pub struct SessionState {
    pub group_numbers: HashMap<GroupNumber, GroupChatId>,
    pub conference_numbers: HashMap<ConferenceNumber, ConferenceId>,
    pub group_peer_numbers: HashMap<(GroupNumber, GroupPeerNumber), PublicKey>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per group"))]
    pub group_settings: HashMap<GroupChatId, GroupSettings>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub friend_statuses: HashMap<PublicKey, UserStatus>,
    /// The live facts we last sent the devices in session.
    pub live: Facts,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per device"))]
    pub sync_sessions: HashSet<PublicKey>,
    /// Devices' events waiting for their parents.
    #[cfg_attr(tokstyle, tokstyle::bounded("only our devices send events"))]
    pub held: HashMap<EventId, crate::sync::Held>,
    /// Devices' events we didn't take this session, and those after them, so
    /// we don't ask for them again.
    #[cfg_attr(tokstyle, tokstyle::bounded("only our devices send events"))]
    pub dropped: HashMap<EventId, PublicKey>,
    /// Friends we sent our Hello since they came online.
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub greeted: HashSet<PublicKey>,
    /// Friends whose Hello came while they're online, with the features they
    /// support.
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub hellos: HashMap<PublicKey, Features>,
    pub pairing: Pairing,
    /// On a linked profile: its copy of the account, kept up with the home.
    pub replica: Option<Replica>,
    /// On a linked profile: its own Tox ID, which only the home knows.
    pub device: Option<Address>,
    /// On a linked profile: whether the home is online, so its live facts are
    /// current.
    pub home_online: bool,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("one per transfer, which toxcore limits for each friend")
    )]
    pub blob_transfers: HashMap<BlobId, BlobTransfer>,
    /// Friends waiting for a blob that's on its way to another friend, with
    /// the file kind to send it as.
    #[cfg_attr(tokstyle, tokstyle::bounded("only our devices ask for blobs"))]
    pub blob_queue: Vec<(PublicKey, BlobId, FileKind)>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub avatar_offers: HashMap<PublicKey, BlobId>,
    /// The avatar a device wants for the account, while its blob arrives.
    pub avatar_wish: Option<BlobId>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per friend"))]
    pub calls: HashMap<PublicKey, crate::sync::calls::Call>,
    /// Invites whose chats are being joined.
    #[cfg_attr(tokstyle, tokstyle::bounded("one per invite we accept"))]
    pub joining: HashSet<EventId>,
    /// The invites groups were joined from.
    #[cfg_attr(tokstyle, tokstyle::bounded("one per group"))]
    pub group_invites: HashMap<GroupChatId, EventId>,
    /// Account changes are recorded on the next tick.
    pub account_dirty: bool,
    /// Windows with messages since someone last acted in them: a toxxi left
    /// running doesn't read anything.
    #[cfg_attr(tokstyle, tokstyle::bounded("one per chat"))]
    pub unseen: HashSet<WindowId>,
    /// Files that are complete and being copied into blobs.
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("one per transfer, which toxcore limits for each friend")
    )]
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
    #[cfg_attr(tokstyle, tokstyle::bounded("one per chat"))]
    pub window_ids: Vec<WindowId>,
    #[cfg_attr(tokstyle, tokstyle::bounded("one per chat"))]
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
    pub typing_to: Option<PublicKey>,
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
    pub disk: Arc<dyn Disk>,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("all history stays in memory, which is fine for now")
    )]
    pub events: EventStore,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("all history stays in memory, which is fine for now")
    )]
    pub message_events: HashMap<(WindowId, InternalMessageId), Recorded>,
    #[cfg_attr(
        tokstyle,
        tokstyle::bounded("one per friend, chat, device or waiting request")
    )]
    pub account: AccountState,
    pub blobs: Blobs,
}

impl DomainState {
    /// Sorted as the Files window shows them, which its keys rely on.
    pub fn file_transfers_listed(&self) -> Vec<(&FileId, &FileTransferProgress)> {
        let mut transfers: Vec<_> = self.file_transfers.iter().collect();
        transfers.sort_by_key(|(file_id, _)| file_id.0);
        transfers
    }

    pub fn self_public_key(&self) -> PublicKey {
        self.tox_id.public_key()
    }

    pub fn new(
        tox_id: Address,
        self_name: String,
        self_status_message: String,
        self_status_type: UserStatus,
    ) -> Self {
        Self {
            tox_id,
            self_name,
            self_status_message,
            self_status_type,
            self_connection_status: Connection::None,
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
            typing_to: None,
            sidebar_cache: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupReconcileInfo {
    pub number: GroupNumber,
    pub chat_id: GroupChatId,
    pub name: Option<String>,
    pub role: Option<GroupRole>,
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
            disk: Arc::new(crate::disk::RealDisk),
            events: EventStore::default(),
            message_events: HashMap::new(),
            account: AccountState::default(),
            blobs: Blobs::default(),
        }
    }

    /// Who writes this profile's events: the account, or on a linked profile
    /// the device.
    pub fn author(&self) -> PublicKey {
        match (self.config.home, self.session.device) {
            (Some(_), Some(device)) => device.public_key(),
            _ => self.domain.self_public_key(),
        }
    }

    /// Where new events go: the devices in session, or on a linked profile
    /// the home.
    fn sync_peers(&self) -> Vec<PublicKey> {
        let home = self.config.home.filter(|_| {
            self.session.home_online
                && self
                    .session
                    .replica
                    .as_ref()
                    .is_some_and(Replica::in_session)
        });
        self.session
            .sync_sessions
            .iter()
            .copied()
            .chain(home)
            .collect()
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
            .sync_peers()
            .into_iter()
            .filter(|peer| Some(*peer) != device)
            .flat_map(|peer| messages.iter().map(move |message| (peer, message.clone())))
            .collect();
        vec![Cmd::IO(IOAction::AppendEvents(records, pushes))]
    }

    pub fn record_account(&mut self) -> Vec<Cmd> {
        self.session.account_dirty = false;
        // On a linked profile, the home records the account, except for what
        // was read here.
        if self.config.home.is_some() {
            let reads = self.read_changes();
            return self.record_in_account(reads);
        }
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
        let author = self.author();
        let graph = GraphId::account(&self.domain.self_public_key());
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

    /// Returns events for devices allowed here that the account doesn't list
    /// yet, and for devices it lists that are no longer allowed.
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
                PendingItem::GroupInvite { .. } | PendingItem::ConferenceInvite { .. } => None,
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

    /// Returns the bytes to send a text message as: those it was recorded with.
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
        self.record_content(window_id, msg, || history::created(window_id, msg, bytes))
    }

    /// Records `msg`, as `content` where it's new.
    fn record_content(
        &mut self,
        window_id: WindowId,
        msg: &Message,
        content: impl FnOnce() -> Option<Content>,
    ) -> Vec<Cmd> {
        let key = (window_id, msg.internal_id);
        let writing = history::Writing {
            account: self.domain.self_public_key(),
            author: self.author(),
            time: self.time_provider.now_local().timestamp_millis(),
        };
        let (recorded, records) = history::record(
            &mut self.events,
            &writing,
            window_id,
            msg,
            self.message_events.get(&key).copied(),
            content,
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
                WindowId::Console
                | WindowId::Group(_)
                | WindowId::Conference(_)
                | WindowId::Logs
                | WindowId::Files => None,
            },
            offset: *self.time_provider.now_local().offset(),
            patterns: self.highlight_patterns(window_id),
        }
    }

    /// Shows `window_id`'s history again with what came since, on a linked
    /// profile: what others wrote after the account's last read is unread,
    /// unless the window is shown.
    pub fn show_history(&mut self, window_id: WindowId) {
        self.load_history(window_id);
        let me = self.domain.self_public_key();
        let read = history::graph_of(&me, window_id).and_then(|graph| self.read_rank(&graph));
        let unread = match self.domain.conversations.get(&window_id) {
            Some(_) if self.active_window_id() == window_id => 0,
            Some(conv) => conv
                .messages
                .iter()
                .filter(|msg| !msg.is_self)
                .filter_map(|msg| self.message_events.get(&(window_id, msg.internal_id)))
                .filter_map(|recorded| self.events.get(&recorded.id))
                .filter(|event| Some(event.rank) > read)
                .count(),
            None => return,
        };
        self.ui
            .window_state
            .entry(window_id)
            .or_default()
            .unread_count = unread;
        self.invalidate_full_window_cache(window_id);
        self.invalidate_sidebar_cache();
    }

    /// Shows each group's and conference's history again, after the kinds of
    /// notices the config hides changed.
    pub fn show_notices_again(&mut self) {
        let chats: Vec<WindowId> = self
            .domain
            .conversations
            .keys()
            .copied()
            .filter(|id| matches!(id, WindowId::Group(_) | WindowId::Conference(_)))
            .collect();
        for window_id in chats {
            self.load_history(window_id);
            self.invalidate_full_window_cache(window_id);
        }
    }

    fn load_history(&mut self, window_id: WindowId) {
        let me = self.domain.self_public_key();
        let Some(graph) = history::graph_of(&me, window_id) else {
            return;
        };
        // Messages shown before keep their IDs: sends and receipts find them
        // by those.
        let mut known: HashMap<EventId, InternalMessageId> = HashMap::new();
        self.message_events
            .retain(|&(window, internal_id), recorded| {
                if window == window_id {
                    known.insert(recorded.id, internal_id);
                }
                window != window_id
            });
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
            let shown_before = known.get(&id).copied();
            let mut update = |target: &EventId, status: MessageStatus| {
                if let Some(&i) = index.get(target) {
                    messages[i].status = status;
                }
            };
            let message = match event.content {
                // Groups have no receipts; their messages are Received once sent.
                Content::Sent { intent } if viewer.friend.is_some() => {
                    update(&intent, MessageStatus::Sent(None));
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
                            (true, true) => MessageStatus::Sent(None),
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
                content @ (Content::Received { .. }
                | Content::Send { .. }
                | Content::Notice { .. }
                | Content::File { .. }
                | Content::FileAnswered { .. }
                | Content::Call { .. }
                | Content::CallEnded { .. }
                | Content::ReceivedPrivately { .. }
                | Content::SendPrivately { .. }
                | Content::PeerJoined { .. }
                | Content::PeerLeft { .. }
                | Content::PeerRenamed { .. }
                | Content::TopicSet { .. }
                | Content::TitleSet { .. }
                | Content::Moderated { .. }
                | Content::WantFriend { .. }
                | Content::UnwantFriend { .. }
                | Content::ReadUpTo { .. }
                | Content::FriendRequest { .. }
                | Content::MergeChat { .. }
                | Content::RelayBot { .. }
                | Content::Fact { .. }
                | Content::Want { .. }
                | Content::ChatInvite { .. }
                | Content::AnswerInvite { .. }
                | Content::InviteJoined { .. }
                | Content::Setting { .. }
                | Content::ClearSetting { .. }
                | Content::Device { .. }
                | Content::DeviceGone { .. }
                | Content::NewChat { .. }
                | Content::JoinChat { .. }
                | Content::InviteToChat { .. }
                | Content::ChatJoined { .. }
                | Content::Unknown { .. }) => {
                    if self.hides(&content) {
                        None
                    } else {
                        history::message_of(
                            &viewer,
                            shown_before.unwrap_or(self.domain.next_internal_id),
                            event.time,
                            content,
                        )
                    }
                }
            };
            if let Some(message) = message {
                if shown_before.is_none() {
                    self.domain.next_internal_id.0 += 1;
                }
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

    pub fn friend_name(&self, pk: &PublicKey) -> String {
        self.domain
            .friends
            .get(pk)
            .map(|info| info.name.clone())
            .unwrap_or_else(|| unnamed_friend(pk))
    }

    /// Sorts `windows` by name, ignoring case.
    pub fn by_name(&self, mut windows: Vec<WindowId>) -> Vec<WindowId> {
        windows.sort_by_cached_key(|window| {
            let id = match window {
                WindowId::Friend(pk) => pk.0,
                WindowId::Group(group) => group.0,
                WindowId::Conference(conference) => conference.0,
                WindowId::Console | WindowId::Logs | WindowId::Files => [0; 32],
            };
            (self.window_name(*window).to_lowercase(), id)
        });
        windows
    }

    /// The chat's name, or Tox's number for it until Tox gives a name.
    pub fn window_name(&self, id: WindowId) -> String {
        if let Some(conv) = self.domain.conversations.get(&id)
            && !conv.name.is_empty()
        {
            return conv.name.clone();
        }
        let numbered = |what: &str, number: Option<u32>, id: &[u8]| match number {
            Some(number) => format!("{what} {number}"),
            None => format!("{what} {}", crate::utils::encode_hex(&id[0..4])),
        };
        match id {
            WindowId::Console => "Status".to_owned(),
            WindowId::Logs => "Logs".to_owned(),
            WindowId::Files => "Files".to_owned(),
            WindowId::Friend(pk) => self.friend_name(&pk),
            WindowId::Group(g) => numbered(
                "Group",
                self.session
                    .group_numbers
                    .iter()
                    .find_map(|(number, id)| (*id == g).then_some(number.0)),
                &g.0,
            ),
            WindowId::Conference(c) => numbered(
                "Conference",
                self.session
                    .conference_numbers
                    .iter()
                    .find_map(|(number, id)| (*id == c).then_some(number.0)),
                &c.0,
            ),
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
            WindowId::Friend(_) | WindowId::Group(_) | WindowId::Conference(_) => {
                if !self.domain.conversations.contains_key(&window_id) {
                    return None;
                }
                let highlighted = if let MessageContent::Text(text) = &content {
                    self.should_highlight(window_id, text)
                } else {
                    false
                };
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
                    message_type: MessageType::Normal,
                    highlighted,
                    privately: None,
                };
                self.show(window_id, msg.clone());
                Some(msg)
            }
        }
    }

    fn show(&mut self, window_id: WindowId, msg: Message) {
        let active_id = self.active_window_id();
        let Some(conv) = self.domain.conversations.get_mut(&window_id) else {
            return;
        };
        conv.messages.push(msg);
        if active_id != window_id {
            let state = self.ui.window_state.entry(window_id).or_default();
            state.unread_count += 1;
        }
        self.invalidate_window_cache(window_id);
        self.invalidate_sidebar_cache();
    }

    /// Records `content`, something that happened in the chat, for the
    /// devices, and shows it here unless the config hides its kind.
    pub fn add_notice(&mut self, window_id: WindowId, content: Content) -> Vec<Cmd> {
        if !self.domain.conversations.contains_key(&window_id) {
            return Vec::new();
        }
        let time = self.time_provider.now_local().timestamp_millis();
        let Some(msg) = history::message_of(
            &self.viewer(window_id),
            self.domain.next_internal_id,
            time,
            content.clone(),
        ) else {
            return Vec::new();
        };
        self.domain.next_internal_id.0 += 1;
        if !self.hides(&content) {
            self.show(window_id, msg.clone());
        }
        self.record_content(window_id, &msg, || Some(content))
    }

    fn hides(&self, content: &Content) -> bool {
        SystemMessageType::of(content)
            .is_some_and(|kind| !self.config.enabled_system_messages.contains(&kind))
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
            WindowId::Console | WindowId::Friend(_) | WindowId::Logs | WindowId::Files => {}
        }

        self.retain_windows(|id| *id != window_id);
        self.domain.conversations.remove(&window_id);
        self.message_events
            .retain(|(window, _), _| *window != window_id);
        self.ui.window_state.remove(&window_id);
        cmds
    }

    /// Closes the windows not kept. The window shown stays shown if it's
    /// kept, or the one after it is shown.
    pub fn retain_windows(&mut self, keep: impl FnMut(&WindowId) -> bool) {
        let active = self.active_window_id();
        self.ui.window_ids.retain(keep);
        self.ui.active_window_index = self
            .ui
            .window_ids
            .iter()
            .position(|w| *w == active)
            .unwrap_or_else(|| {
                self.ui
                    .active_window_index
                    .min(self.ui.window_ids.len().saturating_sub(1))
            });
        self.invalidate_sidebar_cache();
    }

    /// Its name stays empty until Tox gives one.
    pub fn ensure_group_window(&mut self, chat_id: GroupChatId) {
        self.ensure_conversation_window(WindowId::Group(chat_id), String::new());
    }

    /// Its name stays empty until Tox gives one.
    pub fn ensure_conference_window(&mut self, conference_id: ConferenceId) {
        self.ensure_conversation_window(WindowId::Conference(conference_id), String::new());
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
            WindowId::Friend(_) | WindowId::Group(_) | WindowId::Conference(_) => self
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

    /// Returns true if the last render showed the window's oldest line.
    pub fn at_top(&self, id: WindowId) -> bool {
        self.ui.window_state.get(&id).is_some_and(|state| {
            state.msg_list_state.scroll
                >= state
                    .msg_list_state
                    .total_height
                    .saturating_sub(state.last_height)
        })
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

    /// A private message to one peer in a group.
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

        let msg = Message {
            internal_id,
            sender: self.own_name(window_id),
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
            conv.messages.push(msg.clone());
            self.invalidate_window_cache(window_id);
        }

        (internal_id, msg)
    }

    /// Our name in a chat: the one we set there, else our profile's.
    pub fn own_name(&self, window_id: WindowId) -> String {
        self.domain
            .conversations
            .get(&window_id)
            .and_then(|conv| conv.self_name.clone())
            .unwrap_or_else(|| self.domain.self_name.clone())
    }

    /// A member's name from the chat's member list. Every line about them
    /// takes it from here.
    pub fn member_name(&self, window_id: WindowId, pk: PublicKey) -> Option<String> {
        if pk == self.domain.self_public_key() {
            return Some(self.own_name(window_id));
        }
        self.domain
            .conversations
            .get(&window_id)?
            .peers
            .iter()
            .find(|peer| peer.id == PeerId(pk))
            .map(|peer| peer.name.clone())
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

    /// A private message from a peer in a group.
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
        // Tox ends their transfers without sending events.
        self.domain.file_transfers.retain(|file_id, transfer| {
            let theirs = transfer.friend_pk == pk;
            if theirs {
                cmds.push(Cmd::IO(IOAction::CancelFile(pk, *file_id)));
            }
            !theirs
        });
        let window_id = WindowId::Friend(pk);
        self.domain.friends.remove(&pk);
        self.domain.conversations.remove(&window_id);
        self.message_events
            .retain(|(window, _), _| *window != window_id);
        self.retain_windows(|&w| w != window_id);
        cmds.push(Cmd::Tox(ToxAction::DeleteFriend(pk)));
        cmds
    }

    /// Adds a request or invite to answer, replacing the same one from before.
    /// Returns false if too many are waiting already.
    pub fn add_pending(&mut self, item: PendingItem) -> bool {
        let pending = &mut self.domain.pending_items;
        if let Some(old) = pending.iter_mut().find(|old| old.same(&item)) {
            *old = item;
        } else if pending.len() >= MAX_PENDING_ITEMS {
            return false;
        } else {
            pending.push(item);
        }
        true
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
                    WindowId::Console
                    | WindowId::Group(_)
                    | WindowId::Conference(_)
                    | WindowId::Logs
                    | WindowId::Files => SYSTEM_SENDER.to_owned(),
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
                        WindowId::Console
                        | WindowId::Group(_)
                        | WindowId::Conference(_)
                        | WindowId::Logs
                        | WindowId::Files => None,
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
                message_type: MessageType::Normal,
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
        level: LogLevel,
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
        friends: Vec<FriendInfo>,
        groups: Vec<GroupReconcileInfo>,
        conferences: Vec<ConferenceReconcileInfo>,
    ) {
        self.session.group_numbers.clear();
        self.session.conference_numbers.clear();
        self.session.group_peer_numbers.clear();

        let mut new_friends_map = HashMap::new();
        for info in friends {
            if let Some(pk) = info.public_key {
                new_friends_map.insert(pk, info);
            }
        }
        self.domain.friends = new_friends_map;

        for info in groups {
            self.session.group_numbers.insert(info.number, info.chat_id);
            self.ensure_group_window(info.chat_id);

            if let Some(conv) = self
                .domain
                .conversations
                .get_mut(&WindowId::Group(info.chat_id))
            {
                if let Some(n) = info.name.filter(|n| !n.is_empty()) {
                    conv.name = n;
                }
                conv.self_role = info.role;
                conv.self_name = info.self_name;
            }
        }

        for info in conferences {
            self.session.conference_numbers.insert(info.number, info.id);
            self.ensure_conference_window(info.id);

            if let Some(conv) = self
                .domain
                .conversations
                .get_mut(&WindowId::Conference(info.id))
                && let Some(t) = info.title.filter(|t| !t.is_empty())
            {
                conv.name = t;
            }
        }

        // Friends' windows stay as the user left them.
        let friend_pks: Vec<_> = self.domain.friends.keys().cloned().collect();
        for pk in friend_pks {
            self.ensure_friend_conversation(pk);
            let Some(info) = self.domain.friends.get(&pk) else {
                continue;
            };
            if let Some(conv) = self.domain.conversations.get_mut(&WindowId::Friend(pk))
                && !info.name.is_empty()
                && info.name != conv.name
            {
                conv.name = info.name.clone();
            }
        }

        // Conversations Tox no longer lists stay, for their history.

        // Peers from the saved state may be duplicated, and aren't online yet.
        for conv in self.domain.conversations.values_mut() {
            let mut seen = std::collections::HashSet::new();
            conv.peers.retain(|p| seen.insert(p.id));
            for peer in &mut conv.peers {
                peer.seen_online = false;
                peer.status = UserStatus::None;
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
    crate::utils::write_atomically(&state_path, data.as_bytes())
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
    pub status_type: UserStatus,
}

pub fn initialize_model(
    self_info: ToxSelfInfo,
    friends: Vec<FriendInfo>,
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
    friends: Vec<FriendInfo>,
    groups: Vec<GroupReconcileInfo>,
    conferences: Vec<ConferenceReconcileInfo>,
    saved_config: Config,
    runtime_config: Config,
) -> Model {
    // A linked profile's Tox is only its device key, whose one friend is the
    // home: the account is the home's.
    let device = self_info.tox_id;
    let home = saved_config.home;
    let (self_info, friends) = match home {
        Some(home) => (
            ToxSelfInfo {
                tox_id: Address::from_public_key(home, 0),
                ..self_info
            },
            Vec::new(),
        ),
        None => (self_info, friends),
    };
    let mut m = load_or_initialize_account(
        config_dir,
        self_info,
        friends,
        groups,
        conferences,
        saved_config,
        runtime_config,
    );
    if let Some(home) = home {
        crate::sync::linked::started(&mut m, device, home);
    }
    m
}

fn load_or_initialize_account(
    config_dir: &Path,
    self_info: ToxSelfInfo,
    friends: Vec<FriendInfo>,
    groups: Vec<GroupReconcileInfo>,
    conferences: Vec<ConferenceReconcileInfo>,
    saved_config: Config,
    runtime_config: Config,
) -> Model {
    let mut load_error = None;
    match load_state(config_dir) {
        Ok(Some(state)) => {
            if state.domain.tox_id.public_key() == self_info.tox_id.public_key() {
                let mut m = Model::new(state.domain, saved_config, runtime_config);
                m.domain.tox_id = self_info.tox_id;
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
