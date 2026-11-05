use crate::model::{GroupSettings, InternalMessageId, WindowId};
use crate::sync::event::{BlobId, ChatId, ChatKind, EventId};
use crate::sync::fact::Privacy;
use crossterm::event::Event as CrosstermEvent;
use toxcore::tox::{
    Address, ConferenceNumber, ConferencePeerNumber, FriendMessageId, FriendNumber, GroupNumber,
    GroupPeerNumber, ToxConferenceType, ToxConnection, ToxUserStatus,
};
use toxcore::types::{
    ConferenceId, DhtId, FileId, GroupChatId, MessageType, PublicKey, ToxFileControl,
    ToxGroupJoinFail, ToxGroupModEvent, ToxGroupPrivacyState, ToxGroupRole, ToxGroupVoiceState,
    ToxLogLevel,
};

#[derive(Debug, Clone)]
pub enum Msg {
    /// Events originating from the Tox worker
    Tox(ToxEvent),
    /// Events originating from the User (Keyboard/Mouse)
    Input(CrosstermEvent),
    /// Events originating from the I/O worker (File transfers, disk persistence)
    IO(IOEvent),
    /// System-level events (Ticks, Logs)
    System(SystemEvent),
}

#[derive(Debug, Clone)]
pub enum ToxEvent {
    Message(FriendNumber, MessageType, Vec<u8>),
    GroupMessage(GroupNumber, MessageType, String, Vec<u8>, Option<PublicKey>),
    /// To us alone, from the member with the key.
    GroupPrivateMessage(GroupNumber, MessageType, String, Vec<u8>, PublicKey),
    ConferenceMessage(
        ConferenceNumber,
        MessageType,
        String,
        Vec<u8>,
        Option<PublicKey>,
    ),
    ConnectionStatus(ToxConnection),
    /// A new Tox runs, as at the start and after a reload.
    Started,
    Address(Address),
    DhtId(DhtId),
    FriendStatus(FriendNumber, ToxConnection, Option<PublicKey>),
    FriendName(FriendNumber, String),
    FriendStatusMessage(FriendNumber, String),
    FriendTyping(FriendNumber, bool),
    FriendUserStatus(FriendNumber, ToxUserStatus),
    ReadReceipt(FriendNumber, FriendMessageId),
    SyncMessage(FriendNumber, Vec<u8>),
    /// A friend calls the account, with video or not.
    CallRinging(PublicKey, bool),
    /// A friend's call is connected to a device.
    CallConnected(PublicKey),
    CallEnded(PublicKey),
    MessageSent(FriendNumber, FriendMessageId, InternalMessageId),
    GroupMessageSent(GroupNumber, InternalMessageId),
    ConferenceMessageSent(ConferenceNumber, InternalMessageId),
    MessageSendFailed(WindowId, InternalMessageId),
    FriendRequest(PublicKey, String),
    GroupInvite(FriendNumber, String, String),
    ConferenceInvite(FriendNumber, ToxConferenceType, String),
    GroupCreated(GroupNumber, GroupChatId, Option<String>),
    ConferenceCreated(ConferenceNumber, ConferenceId),
    /// How joining an invite's chat went: the chat, or none where Tox
    /// refused.
    InviteJoined(EventId, Option<ChatId>),
    /// What Tox made of a device's `NewChat` or `JoinChat`.
    ChatMade(EventId, Option<ChatId>),
    /// The topic, and the name of who changed it to that, where known.
    GroupTopic(GroupNumber, String, Option<String>),
    GroupName(GroupNumber, String),
    /// The title, and the name of who changed it to that, where known.
    ConferenceTitle(ConferenceNumber, String, Option<String>),
    GroupSelfJoin(GroupNumber),
    /// Tox couldn't join the group after all.
    GroupJoinFail(GroupNumber, ToxGroupJoinFail),
    GroupSelfRole(GroupNumber, ToxGroupRole),
    GroupSettings(GroupNumber, GroupSettings),
    GroupPeerJoin(
        GroupNumber,
        GroupPeerNumber,
        String,
        ToxGroupRole,
        PublicKey,
    ),
    GroupPeerLeave(GroupNumber, GroupPeerNumber),
    GroupPeerName(
        GroupNumber,
        GroupPeerNumber,
        String,
        ToxGroupRole,
        PublicKey,
    ),
    GroupPeerStatus(GroupNumber, GroupPeerNumber, ToxUserStatus),
    GroupModeration(
        GroupNumber,
        GroupPeerNumber,
        GroupPeerNumber,
        ToxGroupModEvent,
    ),
    ConferencePeerJoin(ConferenceNumber, ConferencePeerNumber, String, PublicKey),
    ConferencePeerLeave(ConferenceNumber, ConferencePeerNumber, PublicKey),
    ConferencePeerName(ConferenceNumber, ConferencePeerNumber, String, PublicKey),
    FileRecv(FriendNumber, FileId, u32, u64, String),
    FileChunkRequest(FriendNumber, FileId, u64, usize),
    FileRecvControl(FriendNumber, FileId, ToxFileControl),
    FileChunkSent(FriendNumber, FileId, u64, usize),
    Log(ToxLogLevel, String, u32, String, String),
}

#[derive(Debug, Clone)]
pub enum IOEvent {
    FileStarted(PublicKey, FileId, String, u64),
    FileChunkRead(PublicKey, FileId, u64, usize),
    FileChunkWritten(PublicKey, FileId, u64, usize),
    /// With the file's blob, now held, unless it couldn't be read.
    FileFinished(PublicKey, FileId, Option<BlobId>),
    FileError(PublicKey, FileId, String),
    BlobMissing(PublicKey, BlobId),
    /// Whether a blob from a device was kept, having the ID it was asked for.
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
    Log {
        severity: LogSeverity,
        context: LogContext,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    /// Send an action to the Tox worker
    Tox(ToxAction),
    /// Send a request to the I/O worker
    IO(IOAction),
    /// Internal application commands
    App(AppCmd),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppCmd {
    Quit,
    ReloadTox,
    Redraw,
    Screenshot(String, Option<u16>, Option<u16>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum IOAction {
    SaveConfig(Option<crate::config::Config>),
    SaveState(Option<String>),                            // JSON data
    OpenFileForSending(PublicKey, FileId, String),        // FullPath
    OpenFileForReceiving(PublicKey, FileId, String, u64), // Filename, Size
    WriteChunk(PublicKey, FileId, u64, Vec<u8>),
    ReadChunk(PublicKey, FileId, u64, usize),
    CloseFile(PublicKey, FileId),
    /// Closes a file that has all come or gone, and keeps it as a blob.
    FinishFile(PublicKey, FileId),
    /// Sends a blob as a file, or tells it's missing.
    SendBlob(PublicKey, BlobId, u32),
    /// Receives a blob of the given size, after the part already here.
    ReceiveBlob(PublicKey, BlobId, u64),
    StoreBlob(PublicKey, BlobId),
    /// Keeps events, then sends devices the messages that carry them, so a
    /// device never has one of ours that a crash lost here.
    AppendEvents(Vec<Vec<u8>>, Vec<(PublicKey, Vec<u8>)>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupSetting {
    Privacy(ToxGroupPrivacyState),
    PeerLimit(u16),
    /// Empty for none.
    Password(String),
    TopicLock(bool),
    VoiceState(ToxGroupVoiceState),
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
    AddFriend(String, String), // Address (hex), Message
    AcceptFriend(PublicKey),   // Public Key
    DeleteFriend(PublicKey),
    CreateGroup(String), // Group Name
    CreateConference,
    LeaveGroup(GroupChatId),
    DeleteConference(ConferenceId),
    JoinGroup(String, String, String), // PK (hex), Group Name, Password
    // Friend, Invite Data (hex), Group Name, Password, the recorded invite
    AcceptGroupInvite(PublicKey, String, String, String, Option<EventId>),
    JoinConference(PublicKey, String, Option<EventId>), // Friend, Cookie (hex), the recorded invite
    InviteFriendToGroup(GroupChatId, PublicKey),
    InviteFriendToConference(ConferenceId, PublicKey),
    /// A device's `NewChat`: a group of that privacy, or a conference, by name.
    MakeChat(EventId, ChatKind, Privacy, String),
    /// A device's `JoinChat`: a public group by its chat ID, with a password.
    JoinChatById(EventId, GroupChatId, Option<String>),
    SetGroupPeerIgnore(GroupChatId, PublicKey, bool),
    SetStatusMessage(String),
    SetStatusType(ToxUserStatus),
    SetTyping(PublicKey, bool),
    SetName(String),
    SetGroupNickname(GroupChatId, String),
    SetGroupTopic(GroupChatId, String),
    SetGroupSetting(GroupChatId, GroupSetting),
    /// A new role for the peer, or none to kick them.
    ModerateGroupPeer(GroupChatId, PublicKey, Option<ToxGroupRole>),
    SetConferenceTopic(ConferenceId, String),
    Bootstrap(String, u16, DhtId),
    FileSend(PublicKey, u32, u64, String, String, Option<FileId>), // Friend, Kind, Size, Filename, FullPath, ResumeID
    FileControl(PublicKey, FileId, ToxFileControl),
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
    Shutdown,
}
