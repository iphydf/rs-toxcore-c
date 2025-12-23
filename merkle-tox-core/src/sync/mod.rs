use crate::cas::BlobInfo;
use crate::dag::{
    ChainKey, ConversationId, KConv, NodeHash, NodeLookup, NodeType, PhysicalDevicePk,
};
use crate::error::MerkleToxResult;
use std::time::Duration;
use tox_proto::ToxProto;
pub use tox_reconcile::{SyncRange, Tier};

/// Advertises current DAG tips to a peer.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct SyncHeads {
    /// The Conversation ID (Genesis Hash).
    pub conversation_id: ConversationId,
    /// List of current DAG heads.
    pub heads: Vec<NodeHash>,
    /// Flags indicating local capabilities (e.g., seeding blobs).
    pub flags: u64,
}

/// Request for a batch of nodes by hash.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct FetchBatchReq {
    pub conversation_id: ConversationId,
    pub hashes: Vec<NodeHash>,
}

pub const FLAG_CAS_INVENTORY: u64 = 0x01;

pub const SHARD_SIZE: u64 = 1000;

/// A trait for interacting with the local DAG storage.
pub trait NodeStore: NodeLookup + Send + Sync {
    /// Returns the current heads of the local DAG for a conversation.
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash>;

    /// Updates the heads for a conversation.
    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()>;

    /// Returns the current heads of the Admin track for a conversation.
    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash>;

    /// Updates the Admin heads for a conversation.
    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()>;

    /// Checks if a node exists in the local store.
    fn has_node(&self, hash: &NodeHash) -> bool;

    /// Checks if a node is verified.
    fn is_verified(&self, hash: &NodeHash) -> bool;

    /// Retrieves a node by its hash.
    fn get_node(&self, hash: &NodeHash) -> Option<crate::dag::MerkleNode>;

    /// Retrieves a wire node by its hash.
    fn get_wire_node(&self, hash: &NodeHash) -> Option<crate::dag::WireNode>;

    /// Persists a node to the store.
    fn put_node(
        &self,
        conversation_id: &ConversationId,
        node: crate::dag::MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()>;

    /// Persists a wire node to the store.
    fn put_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        node: crate::dag::WireNode,
    ) -> MerkleToxResult<()>;

    /// Removes a wire node from the store.
    fn remove_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()>;

    /// Returns all nodes with speculative status for a conversation.
    fn get_speculative_nodes(
        &self,
        conversation_id: &ConversationId,
    ) -> Vec<crate::dag::MerkleNode>;

    /// Updates the verification status of a node.
    fn mark_verified(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()>;

    /// Returns the last sequence number used by a specific device in a conversation.
    fn get_last_sequence_number(
        &self,
        conversation_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64;

    /// Returns diagnostic counts of verified and speculative nodes.
    fn get_node_counts(&self, conversation_id: &ConversationId) -> (usize, usize);

    /// Returns all verified nodes of a specific type for a conversation, ordered by rank.
    fn get_verified_nodes_by_type(
        &self,
        conversation_id: &ConversationId,
        node_type: NodeType,
    ) -> MerkleToxResult<Vec<crate::dag::MerkleNode>>;

    /// Returns all node hashes in a specific range for a conversation.
    fn get_node_hashes_in_range(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>>;

    /// Returns all hashes of wire nodes that have not been unpacked yet.
    fn get_opaque_node_hashes(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<NodeHash>>;

    /// Returns the total size of the store in bytes.
    fn size_bytes(&self) -> u64;

    // Key management

    /// Persists a conversation key for a specific epoch.
    fn put_conversation_key(
        &self,
        conversation_id: &ConversationId,
        epoch: u64,
        k_conv: KConv,
    ) -> MerkleToxResult<()>;

    /// Retrieves all persisted keys for a conversation.
    fn get_conversation_keys(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<(u64, KConv)>>;

    /// Updates metadata for the current epoch (message count, rotation time).
    fn update_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
        message_count: u32,
        last_rotation_time: i64,
    ) -> MerkleToxResult<()>;

    /// Retrieves metadata for the current epoch.
    fn get_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Option<(u32, i64)>>;

    /// Persists a ratchet chain key for a specific node.
    fn put_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
        chain_key: ChainKey,
    ) -> MerkleToxResult<()>;

    /// Retrieves a ratchet chain key for a specific node.
    fn get_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<Option<ChainKey>>;

    /// Deletes a ratchet chain key for a specific node.
    fn remove_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<()>;
}

/// A trait for persisting large binary assets.
pub trait BlobStore: Send + Sync {
    /// Checks if a blob is present in the store.
    fn has_blob(&self, hash: &NodeHash) -> bool;

    /// Retrieves metadata for a blob.
    fn get_blob_info(&self, hash: &NodeHash) -> Option<BlobInfo>;

    /// Updates or inserts blob metadata.
    fn put_blob_info(&self, info: BlobInfo) -> MerkleToxResult<()>;

    /// Writes a chunk of data to a blob, optionally verifying it with a proof.
    /// The conversation_id allows the store to localize small blobs for performance.
    fn put_chunk(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        offset: u64,
        data: &[u8],
        proof: Option<&[u8]>,
    ) -> MerkleToxResult<()>;

    /// Reads a chunk of data from a blob.
    fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> MerkleToxResult<Vec<u8>>;

    /// Reads a chunk of data with its corresponding Bao proof.
    fn get_chunk_with_proof(
        &self,
        hash: &NodeHash,
        offset: u64,
        length: u32,
    ) -> MerkleToxResult<(Vec<u8>, Vec<u8>)>;
}

/// A trait for persisting reconciliation sketches (e.g., IBLTs).
pub trait ReconciliationStore: Send + Sync {
    /// Persists a serialized sketch for a specific range.
    fn put_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
        sketch: &[u8],
    ) -> MerkleToxResult<()>;

    /// Retrieves a serialized sketch for a specific range.
    fn get_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Option<Vec<u8>>>;
}

/// A trait for persisting protocol-wide metadata.
pub trait GlobalStore: Send + Sync {
    /// Retrieves the persisted consensus clock offset.
    fn get_global_offset(&self) -> Option<i64>;

    /// Persists the consensus clock offset.
    fn set_global_offset(&self, offset: i64) -> MerkleToxResult<()>;
}

/// A trait that combines all store types for convenience.
pub trait FullStore: NodeStore + BlobStore + GlobalStore + ReconciliationStore {}
impl<T: NodeStore + BlobStore + GlobalStore + ReconciliationStore> FullStore for T {}

pub const POW_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_RECON_DIFFICULTY: u32 = 12; // ~4096 hashes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodingResult {
    Success {
        missing_locally: Vec<NodeHash>,
        missing_remotely: Vec<NodeHash>,
    },
    Failed,
}
