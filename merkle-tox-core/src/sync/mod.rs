use crate::cas::BlobInfo;
use crate::dag::{
    ChainKey, ConversationId, KConv, NodeHash, NodeLookup, NodeType, PhysicalDevicePk,
};
use crate::error::MerkleToxResult;
use std::time::Duration;
use tox_proto::ToxProto;
pub use tox_reconcile::{SyncRange, Tier};

/// Advertises current DAG tips to peer.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct SyncHeads {
    /// Conversation ID (Genesis Hash).
    pub conversation_id: ConversationId,
    /// Current DAG heads.
    pub heads: Vec<NodeHash>,
    /// Flags indicating local capabilities (e.g., seeding blobs).
    pub flags: u64,
    /// Hash of earliest known admin head (for 500-hop trust bridging).
    pub anchor_hash: Option<NodeHash>,
}

/// Request for batch of nodes by hash.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct FetchBatchReq {
    pub conversation_id: ConversationId,
    pub hashes: Vec<NodeHash>,
}

pub const FLAG_CAS_INVENTORY: u64 = 0x01;

pub const SHARD_SIZE: u64 = 1000;

/// Trait for interacting with local DAG storage.
pub trait NodeStore: NodeLookup + Send + Sync {
    /// Returns current heads of local DAG for conversation.
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash>;

    /// Updates heads for conversation.
    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()>;

    /// Returns current heads of Admin track for conversation.
    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash>;

    /// Updates Admin heads for conversation.
    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()>;

    /// Checks if node exists in local store.
    fn has_node(&self, hash: &NodeHash) -> bool;

    /// Checks if node is verified.
    fn is_verified(&self, hash: &NodeHash) -> bool;

    /// Retrieves node by hash.
    fn get_node(&self, hash: &NodeHash) -> Option<crate::dag::MerkleNode>;

    /// Retrieves wire node by hash.
    fn get_wire_node(&self, hash: &NodeHash) -> Option<crate::dag::WireNode>;

    /// Persists node to store.
    fn put_node(
        &self,
        conversation_id: &ConversationId,
        node: crate::dag::MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()>;

    /// Persists wire node to store.
    fn put_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        node: crate::dag::WireNode,
    ) -> MerkleToxResult<()>;

    /// Removes wire node from store.
    fn remove_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()>;

    /// Returns all nodes with speculative status for conversation.
    fn get_speculative_nodes(
        &self,
        conversation_id: &ConversationId,
    ) -> Vec<crate::dag::MerkleNode>;

    /// Updates verification status of node.
    fn mark_verified(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()>;

    /// Returns last sequence number used by device in conversation.
    fn get_last_sequence_number(
        &self,
        conversation_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64;

    /// Returns diagnostic counts of verified and speculative nodes.
    fn get_node_counts(&self, conversation_id: &ConversationId) -> (usize, usize);

    /// Returns all verified nodes of specific type for conversation, ordered by rank.
    fn get_verified_nodes_by_type(
        &self,
        conversation_id: &ConversationId,
        node_type: NodeType,
    ) -> MerkleToxResult<Vec<crate::dag::MerkleNode>>;

    /// Returns all node hashes in specific range for conversation.
    fn get_node_hashes_in_range(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>>;

    /// Returns hashes of unpacked wire nodes.
    fn get_opaque_node_hashes(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<NodeHash>>;

    /// Returns total store size in bytes.
    fn size_bytes(&self) -> u64;

    // Key management

    /// Persists conversation key for specific epoch.
    fn put_conversation_key(
        &self,
        conversation_id: &ConversationId,
        epoch: u64,
        k_conv: KConv,
    ) -> MerkleToxResult<()>;

    /// Retrieves all persisted keys for conversation.
    fn get_conversation_keys(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<(u64, KConv)>>;

    /// Updates metadata for current epoch (message count, rotation time).
    fn update_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
        message_count: u32,
        last_rotation_time: i64,
    ) -> MerkleToxResult<()>;

    /// Retrieves metadata for current epoch.
    fn get_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Option<(u32, i64)>>;

    /// Persists ratchet chain key for specific node and epoch.
    fn put_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
        chain_key: ChainKey,
        epoch_id: u64,
    ) -> MerkleToxResult<()>;

    /// Retrieves ratchet chain key and epoch ID for specific node.
    fn get_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<Option<(ChainKey, u64)>>;

    /// Deletes ratchet chain key for specific node.
    fn remove_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<()>;
}

/// Trait for persisting large binary assets.
pub trait BlobStore: Send + Sync {
    /// Checks if blob is present in store.
    fn has_blob(&self, hash: &NodeHash) -> bool;

    /// Retrieves metadata for blob.
    fn get_blob_info(&self, hash: &NodeHash) -> Option<BlobInfo>;

    /// Updates or inserts blob metadata.
    fn put_blob_info(&self, info: BlobInfo) -> MerkleToxResult<()>;

    /// Writes data chunk to blob, optionally verifying with proof.
    /// conversation_id allows store to localize small blobs for performance.
    fn put_chunk(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        offset: u64,
        data: &[u8],
        proof: Option<&[u8]>,
    ) -> MerkleToxResult<()>;

    /// Reads data chunk from blob.
    fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> MerkleToxResult<Vec<u8>>;

    /// Reads data chunk with corresponding Bao proof.
    fn get_chunk_with_proof(
        &self,
        hash: &NodeHash,
        offset: u64,
        length: u32,
    ) -> MerkleToxResult<(Vec<u8>, Vec<u8>)>;
}

/// Trait for persisting reconciliation sketches (e.g., IBLTs).
pub trait ReconciliationStore: Send + Sync {
    /// Persists serialized sketch for specific range.
    fn put_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
        sketch: &[u8],
    ) -> MerkleToxResult<()>;

    /// Retrieves serialized sketch for specific range.
    fn get_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Option<Vec<u8>>>;
}

/// Trait for persisting protocol-wide metadata.
pub trait GlobalStore: Send + Sync {
    /// Retrieves persisted consensus clock offset.
    fn get_global_offset(&self) -> Option<i64>;

    /// Persists consensus clock offset.
    fn set_global_offset(&self, offset: i64) -> MerkleToxResult<()>;
}

/// Trait combining all store types for convenience.
pub trait FullStore: NodeStore + BlobStore + GlobalStore + ReconciliationStore {}
impl<T: NodeStore + BlobStore + GlobalStore + ReconciliationStore> FullStore for T {}

pub const POW_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(60);
pub const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(60);
pub const GOSSIP_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_RECON_DIFFICULTY: u32 = 12; // ~4096 hashes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodingResult {
    Success {
        missing_locally: Vec<NodeHash>,
        missing_remotely: Vec<NodeHash>,
    },
    Failed,
}
