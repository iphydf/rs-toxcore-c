use crate::model::{GroupSettings, InternalMessageId, WindowId};
use crate::sync::event::{BlobId, ChatId, ChatKind, EventId};
use crate::sync::fact::Privacy;
use crossterm::event::Event as CrosstermEvent;
use std::path::PathBuf;
use toxcore::tox::{
    Address, ConferenceNumber, ConferencePeerNumber, ConferenceType, Connection, FriendMessageId,
    GroupNumber, GroupPeerNumber, UserStatus,
};
use toxcore::types::{
    ConferenceId, DhtId, FileControl, FileId, FileKind, GroupChatId, GroupJoinFail, GroupModEvent,
    GroupPrivacyState, GroupRole, GroupVoiceState, LogLevel, MessageType, PublicKey,
};

/// Who made the change, if Tox says.
pub type Setter = Option<PublicKey>;

#[derive(Debug, Clone)]
pub enum Msg {
    Tox(ToxEvent),
    Input(CrosstermEvent),
    IO(IOEvent),
    System(SystemEvent),
}

/// Tox events, with friends by key: Tox's friend numbers stay in the worker.
#[derive(Debug, Clone)]
pub enum ToxEvent {
    Message(PublicKey, MessageType, Vec<u8>),
    GroupMessage(
        GroupNumber,
        GroupPeerNumber,
        MessageType,
        Vec<u8>,
        Option<PublicKey>,
    ),
    GroupPrivateMessage(
        GroupNumber,
        GroupPeerNumber,
        MessageType,
        Vec<u8>,
        PublicKey,
    ),
    ConferenceMessage(
        ConferenceNumber,
        ConferencePeerNumber,
        MessageType,
        Vec<u8>,
        Option<PublicKey>,
    ),
    ConnectionStatus(Connection),
    /// A new Tox started, at startup or after a reload.
    Started,
    Address(Address),
    DhtId(DhtId),
    FriendStatus(PublicKey, Connection),
    FriendName(PublicKey, String),
    FriendStatusMessage(PublicKey, String),
    FriendTyping(PublicKey, bool),
    FriendUserStatus(PublicKey, UserStatus),
    ReadReceipt(PublicKey, FriendMessageId),
    SyncMessage(PublicKey, Vec<u8>),
    CallRinging {
        friend: PublicKey,
        video: bool,
    },
    /// A friend's call is connected to a device.
    CallConnected(PublicKey),
    CallEnded(PublicKey),
    MessageSent(PublicKey, FriendMessageId, InternalMessageId),
    GroupMessageSent(GroupNumber, InternalMessageId),
    ConferenceMessageSent(ConferenceNumber, InternalMessageId),
    MessageSendFailed(WindowId, InternalMessageId, SendFailure),
    FriendRequest(PublicKey, String),
    GroupInvite {
        friend: PublicKey,
        invite: Vec<u8>,
        name: String,
    },
    ConferenceInvite {
        friend: PublicKey,
        kind: ConferenceType,
        cookie: Vec<u8>,
    },
    GroupCreated(GroupNumber, GroupChatId, Option<String>),
    ConferenceCreated(ConferenceNumber, ConferenceId),
    /// The result of joining an invite's chat: the chat, or None if Tox
    /// refused.
    InviteJoined(EventId, Option<ChatId>),
    /// The chat Tox made for a device's `NewChat` or `JoinChat`, or None if it
    /// refused.
    ChatMade(EventId, Option<ChatId>),
    GroupTopic(GroupNumber, String, Setter),
    GroupName(GroupNumber, String),
    ConferenceTitle(ConferenceNumber, String, Setter),
    GroupSelfJoin(GroupNumber),
    GroupJoinFail(GroupNumber, GroupJoinFail),
    GroupSelfRole(GroupNumber, GroupRole),
    GroupSettings(GroupNumber, GroupSettings),
    GroupPeerJoin(GroupNumber, GroupPeerNumber, String, GroupRole, PublicKey),
    GroupPeerLeave(GroupNumber, GroupPeerNumber),
    GroupPeerName(GroupNumber, GroupPeerNumber, String, GroupRole, PublicKey),
    GroupPeerStatus(GroupNumber, GroupPeerNumber, UserStatus),
    GroupModeration {
        group: GroupNumber,
        source: GroupPeerNumber,
        target: GroupPeerNumber,
        event: GroupModEvent,
    },
    ConferencePeerJoin(ConferenceNumber, ConferencePeerNumber, String, PublicKey),
    ConferencePeerLeave(ConferenceNumber, ConferencePeerNumber, PublicKey),
    ConferencePeerName(ConferenceNumber, ConferencePeerNumber, String, PublicKey),
    FileRecv(PublicKey, FileId, FileKind, u64, String),
    FileChunkRequest(PublicKey, FileId, u64, usize),
    FileRecvControl(PublicKey, FileId, FileControl),
    FileChunkSent(PublicKey, FileId, u64, usize),
    Log {
        level: LogLevel,
        file: String,
        line: u32,
        func: String,
        message: String,
    },
}

/// Why a message wasn't sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// The chat is offline or Tox's queue is full: we try again later.
    Later,
    /// Tox will never take it: the chat is gone or the message is invalid.
    Never,
}

#[derive(Debug, Clone)]
pub enum IOEvent {
    FileStarted(PublicKey, FileId, PathBuf, u64),
    FileChunkRead(PublicKey, FileId, u64, usize),
    FileChunkWritten(PublicKey, FileId, u64, usize),
    /// With the file's blob, unless it couldn't be read.
    FileFinished(PublicKey, FileId, Option<BlobId>),
    FileError(PublicKey, FileId, String),
    BlobMissing(PublicKey, BlobId),
    /// Whether a device's blob was kept: it must have the ID we asked for.
    BlobStored(PublicKey, BlobId, bool),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogContext {
    Global,
    Friend(PublicKey),
    Group(GroupChatId),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SystemEvent {
    Tick,
    /// A signal to stop: toxxi quits as with /quit.
    Quit,
    /// Shows a chat, e.g. one a notification is about.
    Show(crate::model::WindowId),
    /// toxxi may soon be killed without warning (e.g. an app in the
    /// background): save everything now.
    Save,
    Log {
        severity: LogSeverity,
        context: LogContext,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    Tox(ToxAction),
    IO(IOAction),
    App(AppCmd),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppCmd {
    Quit,
    ReloadTox,
    Redraw,
    /// Saves the state and the config.
    SaveState,
    Screenshot(String, Option<u16>, Option<u16>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum IOAction {
    SaveConfig(crate::config::Config),
    OpenFileForSending(PublicKey, FileId, PathBuf),
    OpenFileForReceiving(PublicKey, FileId, String, u64), // Filename, Size
    WriteChunk(PublicKey, FileId, u64, Vec<u8>),
    ReadChunk(PublicKey, FileId, u64, usize),
    CloseFile(PublicKey, FileId),
    /// Closes the file of a transfer either side cancelled. The partial file
    /// of a download is deleted (it can't be resumed).
    CancelFile(PublicKey, FileId),
    /// Closes a complete file and keeps a copy as a blob.
    FinishFile(PublicKey, FileId),
    /// Sends a blob as a file, or says it's missing.
    SendBlob(PublicKey, BlobId, FileKind),
    /// Receives a blob of the given size, resuming after the part we have.
    ReceiveBlob(PublicKey, BlobId, u64),
    StoreBlob(PublicKey, BlobId),
    /// Keeps events, then sends devices the messages that carry them, so a
    /// device never has one of ours that a crash lost here.
    AppendEvents(Vec<Vec<u8>>, Vec<(PublicKey, Vec<u8>)>),
    /// Moves the event log to the file named, starting an empty one.
    SetAsideEvents(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupSetting {
    Privacy(GroupPrivacyState),
    PeerLimit(u16),
    /// Empty for none.
    Password(String),
    TopicLock(bool),
    VoiceState(GroupVoiceState),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToxAction {
    SendMessage(PublicKey, MessageType, Vec<u8>, InternalMessageId),
    SendGroupMessage(GroupChatId, MessageType, Vec<u8>, InternalMessageId),
    /// A new end of our Tox ID: friend requests to the old one don't arrive.
    SetNospam(u32),
    SendGroupPrivateMessage(
        GroupChatId,
        PublicKey,
        MessageType,
        Vec<u8>,
        InternalMessageId,
    ),
    SendConferenceMessage(ConferenceId, MessageType, Vec<u8>, InternalMessageId),
    AddFriend(Address, String), // Request message
    AcceptFriend(PublicKey),
    DeleteFriend(PublicKey),
    CreateGroup(String),
    CreateConference,
    LeaveGroup(GroupChatId),
    DeleteConference(ConferenceId),
    JoinGroup(GroupChatId, Option<String>),
    AcceptGroupInvite {
        friend: PublicKey,
        invite: Vec<u8>,
        password: Option<String>,
        /// The account's invite, to record how joining went.
        recorded: Option<EventId>,
    },
    JoinConference {
        friend: PublicKey,
        cookie: Vec<u8>,
        /// The account's invite, to record how joining went.
        recorded: Option<EventId>,
    },
    InviteFriendToGroup(GroupChatId, PublicKey),
    InviteFriendToConference(ConferenceId, PublicKey),
    /// A device's `NewChat`: a group of that privacy, or a conference, by name.
    MakeChat(EventId, ChatKind, Privacy, String),
    /// A device's `JoinChat`: a public group by its chat ID, with a password.
    JoinChatById(EventId, GroupChatId, Option<String>),
    SetGroupPeerIgnore(GroupChatId, PublicKey, bool),
    SetStatusMessage(String),
    SetStatusType(UserStatus),
    SetTyping(PublicKey, bool),
    SetName(String),
    /// This Tox's own name, which a linked profile's home shows for the
    /// device. Unlike `SetName`, it doesn't rename the account.
    SetDeviceName(String),
    SetGroupNickname(GroupChatId, String),
    SetGroupTopic(GroupChatId, String),
    SetGroupSetting(GroupChatId, GroupSetting),
    /// A new role for the peer, or none to kick them.
    ModerateGroupPeer(GroupChatId, PublicKey, Option<GroupRole>),
    SetConferenceTopic(ConferenceId, String),
    Bootstrap(String, u16, DhtId),
    FileSend {
        friend: PublicKey,
        kind: FileKind,
        size: u64,
        /// The name the friend sees.
        name: String,
        path: PathBuf,
        /// The ID of the transfer it resumes, if any.
        resume: Option<FileId>,
    },
    FileControl(PublicKey, FileId, FileControl),
    FileSendChunk(PublicKey, FileId, u64, Vec<u8>),
    FileSeek(PublicKey, FileId, u64),
    SyncSend(PublicKey, Vec<u8>),
    /// Answers or places the friend's call, and calls the device once it's
    /// connected, to pass their audio and video between them.
    CallConnect {
        friend: PublicKey,
        device: PublicKey,
        video: bool,
    },
    CallHangUp(PublicKey),
    Reload(Box<crate::config::Config>),
    Save,
    Shutdown,
}

impl ToxAction {
    /// Whether the action changes what Tox saves. The worker saves the profile
    /// right after one that does, so that a crash can't lose it.
    pub fn changes_savedata(&self) -> bool {
        match self {
            Self::SetNospam(..)
            | Self::AddFriend(..)
            | Self::AcceptFriend(..)
            | Self::DeleteFriend(..)
            | Self::CreateGroup(..)
            | Self::CreateConference
            | Self::LeaveGroup(..)
            | Self::DeleteConference(..)
            | Self::JoinGroup(..)
            | Self::AcceptGroupInvite { .. }
            | Self::JoinConference { .. }
            | Self::MakeChat(..)
            | Self::JoinChatById(..)
            | Self::SetStatusMessage(..)
            | Self::SetStatusType(..)
            | Self::SetName(..)
            | Self::SetDeviceName(..)
            | Self::SetGroupNickname(..)
            | Self::SetGroupTopic(..)
            | Self::SetGroupSetting(..)
            | Self::ModerateGroupPeer(..)
            | Self::SetConferenceTopic(..)
            | Self::Save => true,
            // Tox doesn't keep whom we ignore in a group.
            Self::SetGroupPeerIgnore(..)
            | Self::SendMessage(..)
            | Self::SendGroupMessage(..)
            | Self::SendGroupPrivateMessage(..)
            | Self::SendConferenceMessage(..)
            | Self::InviteFriendToGroup(..)
            | Self::InviteFriendToConference(..)
            | Self::SetTyping(..)
            | Self::Bootstrap(..)
            | Self::FileSend { .. }
            | Self::FileControl(..)
            | Self::FileSendChunk(..)
            | Self::FileSeek(..)
            | Self::SyncSend(..)
            | Self::CallConnect { .. }
            | Self::CallHangUp(..)
            | Self::Reload(..)
            | Self::Shutdown => false,
        }
    }
}
