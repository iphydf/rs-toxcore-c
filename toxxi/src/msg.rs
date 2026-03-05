use crate::model::{InternalMessageId, WindowId};
use crate::script::ScriptRequest;
use crossterm::event::Event as CrosstermEvent;
use toxcore::tox::{
    Address, ConferenceNumber, ConferencePeerNumber, FriendMessageId, FriendNumber, GroupNumber,
    GroupPeerNumber, ToxConferenceType, ToxConnection, ToxUserStatus,
};
use toxcore::types::{
    GroupChatId, ConferenceId, DhtId, FileId, MessageType, PublicKey, ToxFileControl, ToxGroupModEvent,
    ToxGroupRole, ToxLogLevel,
};

#[derive(Debug, Clone)]
pub enum Msg {
    /// Events originating from the Tox worker
    Tox(ToxEvent),
    /// Events originating from the User (Keyboard/Mouse)
    Input(CrosstermEvent),
    /// Events originating from the I/O worker (File transfers, disk persistence)
    IO(IOEvent),
    /// System-level events (Ticks, Scripting)
    System(SystemEvent),
}

#[derive(Debug, Clone)]
pub enum ToxEvent {
    Message(FriendNumber, MessageType, String),
    GroupMessage(GroupNumber, MessageType, String, String, Option<PublicKey>),
    ConferenceMessage(
        ConferenceNumber,
        MessageType,
        String,
        String,
        Option<PublicKey>,
    ),
    ConnectionStatus(ToxConnection),
    Address(Address),
    DhtId(DhtId),
    FriendStatus(FriendNumber, ToxConnection, Option<PublicKey>),
    FriendName(FriendNumber, String),
    FriendStatusMessage(FriendNumber, String),
    FriendTyping(FriendNumber, bool),
    ReadReceipt(FriendNumber, FriendMessageId),
    MessageSent(FriendNumber, FriendMessageId, InternalMessageId),
    GroupMessageSent(GroupNumber, InternalMessageId),
    ConferenceMessageSent(ConferenceNumber, InternalMessageId),
    MessageSendFailed(WindowId, InternalMessageId),
    FriendRequest(PublicKey, String),
    GroupInvite(FriendNumber, String, String),
    ConferenceInvite(FriendNumber, ToxConferenceType, String),
    GroupCreated(GroupNumber, GroupChatId, Option<String>),
    ConferenceCreated(ConferenceNumber, ConferenceId),
    GroupTopic(GroupNumber, String),
    GroupName(GroupNumber, String),
    ConferenceTitle(ConferenceNumber, String),
    GroupSelfJoin(GroupNumber),
    GroupSelfRole(GroupNumber, ToxGroupRole),
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
    FileRecvChunk(FriendNumber, FileId, u64, Vec<u8>),
    FileRecvControl(FriendNumber, FileId, ToxFileControl),
    FileChunkSent(FriendNumber, FileId, u64, usize),
    Log(ToxLogLevel, String, u32, String, String),
}

#[derive(Debug, Clone)]
pub enum IOEvent {
    FileStarted(PublicKey, FileId, String, u64),
    FileChunkRead(PublicKey, FileId, u64, usize),
    FileChunkWritten(PublicKey, FileId, u64, usize),
    FileFinished(PublicKey, FileId),
    FileError(PublicKey, FileId, String),
    ProfileSaved,
    ConfigSaved,
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
    ScriptRequest(ScriptRequest),
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
    SetTimeout(u64),
    Redraw,
    Screenshot(String, Option<u16>, Option<u16>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum IOAction {
    SaveProfile,
    SaveConfig(Option<crate::config::Config>),
    SaveState(Option<String>),                            // JSON data
    OpenFileForSending(PublicKey, FileId, String),        // FullPath
    OpenFileForReceiving(PublicKey, FileId, String, u64), // Filename, Size
    WriteChunk(PublicKey, FileId, u64, Vec<u8>),
    ReadChunk(PublicKey, FileId, u64, usize),
    CloseFile(PublicKey, FileId),
    LogMessage(WindowId, crate::model::Message),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToxAction {
    SendMessage(PublicKey, MessageType, String, InternalMessageId),
    SendGroupMessage(GroupChatId, MessageType, String, InternalMessageId),
    SendConferenceMessage(ConferenceId, MessageType, String, InternalMessageId),
    AddFriend(String, String), // Address (hex), Message
    AcceptFriend(PublicKey),   // Public Key
    DeleteFriend(PublicKey),
    CreateGroup(String), // Group Name
    CreateConference,
    LeaveGroup(GroupChatId),
    DeleteConference(ConferenceId),
    JoinGroup(String, String, String), // PK (hex), Group Name, Password
    AcceptGroupInvite(PublicKey, String, String, String), // Friend, Invite Data (hex), Group Name, Password
    JoinConference(PublicKey, String),                    // Friend, Cookie (hex)
    InviteFriendToGroup(GroupChatId, PublicKey),
    InviteFriendToConference(ConferenceId, PublicKey),
    SetGroupPeerIgnore(GroupChatId, PublicKey, bool),
    SetStatusMessage(String),
    SetStatusType(ToxUserStatus),
    SetTyping(PublicKey, bool),
    SetName(String),
    SetGroupNickname(GroupChatId, String),
    SetGroupTopic(GroupChatId, String),
    SetConferenceTopic(ConferenceId, String),
    Bootstrap(String, u16, DhtId),
    FileSend(PublicKey, u32, u64, String, String, Option<FileId>), // Friend, Kind, Size, Filename, FullPath, ResumeID
    FileControl(PublicKey, FileId, ToxFileControl),
    FileSendChunk(PublicKey, FileId, u64, Vec<u8>),
    FileSeek(PublicKey, FileId, u64),
    Reload(Box<crate::config::Config>),
    Shutdown,
}
