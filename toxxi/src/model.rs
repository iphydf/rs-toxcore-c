use crate::config::Config;
use crate::time::TimeProvider;
use crate::widgets::{
    ChatLayout, ChatMessage, CommandMenuState, EmojiGridState, EmojiPickerState, InputBoxState,
    MessageListState, QuickSwitcherState, SidebarItem,
};
use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde::{Deserialize, Serialize};
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
    Address, GroupChatId, ConferenceId, FileId, MessageType, PublicKey, ToxGroupRole, ToxLogLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InternalMessageId(pub usize);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FriendInfo {
    pub name: String,
    pub public_key: Option<PublicKey>,
    pub status_message: String,
    pub connection: ToxConnection,
    pub last_sent_message_id: Option<u32>,
    pub last_read_receipt: Option<u32>,
    #[serde(skip, default)]
    pub is_typing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    },
    GameInvite {
        game_type: String,
        challenger: String,
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
            MessageContent::GameInvite { game_type, .. } => game_type.contains(s),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsoleMessageType {
    Info,
    Log,
    Status,
    Debug,
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
    Completed,
    Failed,
    Canceled,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FileTransferProgress {
    pub filename: String,
    pub total_size: u64,
    pub transferred: u64,
    pub is_receiving: bool,
    pub status: TransferStatus,
    pub file_kind: u32,
    pub file_path: Option<String>,
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
    pub self_public_key: PublicKey,
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
    pub show_qr: bool,
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
}

impl DomainState {
    pub fn new(
        tox_id: Address,
        self_public_key: PublicKey,
        self_name: String,
        self_status_message: String,
        self_status_type: ToxUserStatus,
    ) -> Self {
        Self {
            tox_id,
            self_public_key,
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
            show_qr: false,
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
        }
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
            let id = self.ui.window_ids[index];
            if let Some(state) = self.ui.window_state.get_mut(&id) {
                state.unread_count = 0;
            }
            self.ui.is_typing_sent = false;
            self.ui.last_typing_activity = None;
            self.invalidate_sidebar_cache();
        }
    }

    pub fn active_window_id(&self) -> WindowId {
        self.ui.window_ids[self.ui.active_window_index]
    }

    pub fn should_highlight(&self, window_id: WindowId, text: &str) -> bool {
        let mut highlights = self.config.highlight_strings.clone();
        highlights.push(self.domain.self_name.clone());

        if let WindowId::Group(chat_id) = window_id
            && let Some(conv) = self.domain.conversations.get(&WindowId::Group(chat_id))
            && let Some(self_name) = &conv.self_name
        {
            highlights.push(self_name.clone());
        }

        for h in highlights {
            if h.is_empty() {
                continue;
            }

            let pattern = format!(
                r"(?i)(^|[\s@:.,!?])\b{}\b($|[\s:.,!?']|'s)",
                regex::escape(&h)
            );

            if let Ok(re) = Regex::new(&pattern)
                && re.is_match(text)
            {
                return true;
            }
        }

        false
    }

    pub fn add_console_message(&mut self, msg_type: ConsoleMessageType, content: String) {
        self.domain.console_messages.push(ConsoleMessage {
            msg_type,
            content: MessageContent::Text(content),
            timestamp: self.time_provider.now_local(),
        });
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
                self.domain.console_messages.push(ConsoleMessage {
                    msg_type,
                    content,
                    timestamp: self.time_provider.now_local(),
                });
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
                        sender: "System".to_owned(),
                        sender_pk: None,
                        is_self: false,
                        content,
                        timestamp: self.time_provider.now_local(),
                        status: MessageStatus::Incoming,
                        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                        highlighted,
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
        let window_id = WindowId::Friend(pk);
        let default_name = if let Some(info) = self.domain.friends.get(&pk) {
            info.name.clone()
        } else {
            // Can't show Friend Number anymore without lookup, but we have PK
            format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
        };
        self.ensure_conversation(window_id, default_name);
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
        self.domain
            .conversations
            .entry(window_id)
            .or_insert_with(|| Conversation {
                name: default_name,
                messages: Vec::new(),
                topic: None,
                peers: Vec::new(),
                self_role: None,
                self_name: None,
                ignored_peers: HashSet::new(),
            });
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
        self.ensure_window(window_id);

        let internal_id = self.domain.next_internal_id;
        self.domain.next_internal_id.0 += 1;

        let mut msg = Message {
            internal_id,
            sender: String::new(),
            sender_pk: Some(self.domain.self_public_key),
            is_self: true,
            content: MessageContent::Text(content),
            timestamp: self.time_provider.now_local(),
            status: MessageStatus::Pending,
            message_type,
            highlighted: false,
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

        let (sender, sender_pk) = if let Some(info) = self.domain.friends.get(&pk) {
            (info.name.clone(), info.public_key)
        } else {
            (
                format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4])),
                Some(pk),
            )
        };

        self.add_incoming_message(window_id, message_type, sender, msg, sender_pk)
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
        )
    }

    fn add_incoming_message(
        &mut self,
        window_id: WindowId,
        message_type: MessageType,
        sender: String,
        content: String,
        sender_pk: Option<PublicKey>,
    ) -> Option<Message> {
        let active_id = self.active_window_id();
        let highlighted = self.should_highlight(window_id, &content);
        if let Some(conv) = self.domain.conversations.get_mut(&window_id) {
            let internal_id = self.domain.next_internal_id;
            self.domain.next_internal_id.0 += 1;
            let is_self = sender_pk
                .as_ref()
                .map(|pk| pk == &self.domain.self_public_key)
                .unwrap_or(false);
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

    pub fn active_window_topic(&self) -> String {
        let id = self.active_window_id();
        match id {
            WindowId::Console => format!("Tox ID: {}", self.domain.tox_id),
            WindowId::Logs => "Tox Logs".to_owned(),
            WindowId::Files => "File Manager".to_owned(),
            _ => {
                if let Some(conv) = self.domain.conversations.get(&id) {
                    if let Some(t) = &conv.topic {
                        t.clone()
                    } else {
                        conv.name.clone()
                    }
                } else {
                    "Conversation".to_owned()
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
                        .unwrap_or_else(|| {
                            format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
                        }),
                    _ => "System".to_owned(),
                }
            };

            let msg = Message {
                internal_id,
                sender,
                sender_pk: if is_self {
                    Some(self.domain.self_public_key)
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
                },
                timestamp: self.time_provider.now_local(),
                status: if is_self {
                    MessageStatus::Pending
                } else {
                    MessageStatus::Incoming
                },
                message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                highlighted: false,
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

    pub fn all_tox_logs(&self) -> Vec<ToxLogItem> {
        let mut all: Vec<_> = self
            .domain
            .tox_logs
            .values()
            .flatten()
            .filter(|log| self.ui.log_filters.matches(log))
            .cloned()
            .collect();
        all.sort_by_key(|l| l.timestamp);
        all
    }

    pub fn all_tox_logs_unfiltered(&self) -> Vec<ToxLogItem> {
        let mut all: Vec<_> = self.domain.tox_logs.values().flatten().cloned().collect();
        all.sort_by_key(|l| l.timestamp);
        all
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
        for (num, mut info) in friends {
            if let Some(pk) = info.public_key {
                self.session.friend_numbers.insert(num, pk);

                // Merge with existing info if present (persistence)
                if let Some(old_info) = self.domain.friends.get(&pk) {
                    info.last_sent_message_id = old_info.last_sent_message_id;
                    info.last_read_receipt = old_info.last_read_receipt;
                }
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
                        conv.name = t.clone();
                        conv.topic = Some(t);
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
    pub public_key: PublicKey,
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
        self_info.public_key,
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

                // Load logs for restored conversations
                let conversations: Vec<WindowId> = m.domain.conversations.keys().cloned().collect();
                for window_id in conversations {
                    let messages = load_conversation_logs(config_dir, window_id);
                    if let Some(conv) = m.domain.conversations.get_mut(&window_id) {
                        conv.messages = messages;
                    }
                }

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

    // Load logs for existing conversations
    let conversations: Vec<WindowId> = m.domain.conversations.keys().cloned().collect();
    for window_id in conversations {
        let messages = load_conversation_logs(config_dir, window_id);
        if let Some(conv) = m.domain.conversations.get_mut(&window_id) {
            conv.messages = messages;
        }
    }

    m
}

fn load_conversation_logs(config_dir: &Path, window_id: WindowId) -> Vec<Message> {
    let logs_dir = config_dir.join("logs");
    let filename = match window_id {
        WindowId::Friend(pk) => Some(format!("friend_{}.jsonl", crate::utils::encode_hex(&pk.0))),
        WindowId::Group(id) => Some(format!("group_{}.jsonl", crate::utils::encode_hex(&id.0))),
        WindowId::Conference(id) => Some(format!("conf_{}.jsonl", crate::utils::encode_hex(&id.0))),
        _ => None,
    };

    if let Some(fname) = filename {
        let path = logs_dir.join(fname);
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut messages = HashMap::new();
            for line in content.lines() {
                // Handle corrupted lines where multiple JSON objects are smashed together
                // e.g. {"status":"Received"...}{"status":"Received"...}
                let segments: Vec<&str> = if line.contains("}{") {
                    line.split("}{").collect()
                } else {
                    vec![line]
                };

                for (i, segment) in segments.iter().enumerate() {
                    let mut s = segment.to_string();
                    if segments.len() > 1 {
                        if i == 0 {
                            s.push('}');
                        } else if i == segments.len() - 1 {
                            s.insert(0, '{');
                        } else {
                            s.insert(0, '{');
                            s.push('}');
                        }
                    }

                    if let Ok(msg) = serde_json::from_str::<Message>(&s) {
                        messages.insert((msg.timestamp, msg.internal_id), msg);
                    }
                }
            }
            let mut result: Vec<Message> = messages.into_values().collect();
            result.sort_by_key(|m| m.timestamp);
            return result;
        }
    }
    Vec::new()
}

// end of file
