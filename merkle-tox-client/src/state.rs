use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, NodeHash, PhysicalDevicePk, SignedPreKey,
};
use std::collections::{HashMap, HashSet};

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
    /// Latest announcement per device: Device PK -> (PreKeys, LastResortKey)
    pub announcements: HashMap<PhysicalDevicePk, (Vec<SignedPreKey>, SignedPreKey)>,
    /// Recent messages in the conversation
    pub messages: Vec<ChatMessage>,
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
