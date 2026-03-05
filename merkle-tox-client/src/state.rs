use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, NodeHash, PhysicalDevicePk, SignedPreKey,
};
use std::collections::{HashMap, HashSet};

/// Application-level events emitted by the client for UI/app consumption.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    MessageReceived {
        conversation_id: ConversationId,
        hash: NodeHash,
        author_pk: LogicalIdentityPk,
        timestamp: i64,
        content: Content,
    },
    MessageRedacted {
        conversation_id: ConversationId,
        target_hash: NodeHash,
    },
    ReactionAdded {
        conversation_id: ConversationId,
        target_hash: NodeHash,
        emoji: String,
        reactor_pk: LogicalIdentityPk,
    },
    TitleChanged {
        conversation_id: ConversationId,
        title: String,
    },
    TopicChanged {
        conversation_id: ConversationId,
        topic: String,
    },
    MemberJoined {
        conversation_id: ConversationId,
        member_pk: LogicalIdentityPk,
        role: MemberRole,
    },
    DeviceAuthorized {
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
    },
    DeviceRevoked {
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
    },
    NodeInvalidated {
        conversation_id: ConversationId,
        hash: NodeHash,
    },
    SpeculativeMessage {
        conversation_id: ConversationId,
        hash: NodeHash,
        author_pk: LogicalIdentityPk,
        content: Content,
    },
    IdentityPendingMessage {
        conversation_id: ConversationId,
        hash: NodeHash,
        author_pk: LogicalIdentityPk,
        content: Content,
    },
    EquivocationDetected {
        conversation_id: ConversationId,
        device_pk: PhysicalDevicePk,
        seq: u64,
        existing_hash: NodeHash,
        conflicting_hash: NodeHash,
    },
    BlobAvailable {
        hash: NodeHash,
    },
    PeerConnected {
        peer_pk: PhysicalDevicePk,
    },
    PeerDisconnected {
        peer_pk: PhysicalDevicePk,
    },
    HistorySnapshotNeeded {
        conversation_id: ConversationId,
    },
}

/// The current materialized state of a conversation.
#[derive(Debug, Clone)]
pub struct ChatState {
    pub conversation_id: ConversationId,
    pub title: String,
    pub topic: String,
    /// Author PK -> Member information
    pub members: HashMap<LogicalIdentityPk, MemberInfo>,
    /// Set of all authorized device PKs in the conversation
    pub authorized_devices: HashSet<PhysicalDevicePk>,
    /// Latest announcement per device: Device PK -> (PreKeys, LastResortKey).
    /// Mirrors the wire-side cap on `ControlAction::Announcement.pre_keys`.
    pub announcements: HashMap<
        PhysicalDevicePk,
        (
            tox_proto::BoundedVec<
                SignedPreKey,
                { tox_proto::constants::MAX_HANDSHAKES_PER_ANNOUNCEMENT as usize },
            >,
            SignedPreKey,
        ),
    >,
    /// Recent messages in the conversation
    pub messages: Vec<ChatMessage>,
    /// Messages received speculatively (not yet fully verified)
    pub speculative_messages: Vec<ChatMessage>,
    /// Messages from identity-pending conversations
    pub identity_pending_messages: Vec<ChatMessage>,
    /// The hashes of the current DAG heads
    pub heads: Vec<NodeHash>,
    /// The topological rank of the highest verified node processed
    pub max_verified_rank: u64,
}

impl Default for ChatState {
    fn default() -> Self {
        Self {
            conversation_id: ConversationId::from([0u8; 32]),
            title: String::new(),
            topic: String::new(),
            members: HashMap::new(),
            authorized_devices: HashSet::new(),
            announcements: HashMap::new(),
            messages: Vec::new(),
            speculative_messages: Vec::new(),
            identity_pending_messages: Vec::new(),
            heads: Vec::new(),
            max_verified_rank: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub hash: NodeHash,
    pub author_pk: LogicalIdentityPk,
    pub timestamp: i64,
    pub content: Content,
    /// Reactions to this message: Emoji -> Set of User PKs
    pub reactions: HashMap<String, HashSet<LogicalIdentityPk>>,
    pub is_redacted: bool,
}

#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub public_key: LogicalIdentityPk,
    pub role: MemberRole,
    pub joined_at: i64,
    /// Device PKs belonging to this member
    pub devices: HashSet<PhysicalDevicePk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberRole {
    Admin,
    Member,
}
