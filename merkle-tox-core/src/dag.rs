use crate::error::MerkleToxError;
use bitflags::bitflags;
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::io::Cursor;
pub use tox_proto::{
    ChainKey, ConversationId, Ed25519Signature, EncryptionKey, EphemeralSigningPk,
    EphemeralSigningSk, EphemeralX25519Pk, EphemeralX25519Sk, HeaderKey, KConv, LogicalIdentityPk,
    LogicalIdentitySk, MacKey, MessageKey, NodeHash, NodeMac, PhysicalDeviceDhSk, PhysicalDevicePk,
    PhysicalDeviceSk, PowNonce, SenderKey, ShardHash, SharedSecretKey, ToxDeserialize, ToxProto,
    ToxSerialize,
};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ToxProto)]
    #[tox(bits = "u32")]
    pub struct Permissions: u32 {
        const NONE    = 0x00;
        const ADMIN   = 0x01;
        const MESSAGE = 0x02;
        const SYNC    = 0x04;
        const ALL     = Self::ADMIN.bits() | Self::MESSAGE.bits() | Self::SYNC.bits();
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ToxProto)]
    #[tox(bits = "u32")]
    pub struct WireFlags: u32 {
        const NONE       = 0x00;
        const COMPRESSED = 0x01;
        const ENCRYPTED  = 0x02;
    }
}

/// A hash is exactly 32 bytes (Blake3).
pub type Hash = [u8; 32];

/// A Public Key is 32 bytes (Ed25519/X25519).
pub type PublicKey = [u8; 32];

/// A signature is 64 bytes (Ed25519).
pub type Signature = [u8; 64];

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum NodeAuth {
    /// For content nodes: Ed25519-Sig(EphemeralSigning_SK, NodeData).
    EphemeralSignature(Ed25519Signature),
    /// For administrative nodes: Ed25519-Sig(Sender_SK, NodeData).
    Signature(Ed25519Signature),
}

impl NodeAuth {}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum EmojiSource {
    Unicode(String),
    Custom { hash: [u8; 32], shortcode: String },
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct MemberInfo {
    pub public_key: LogicalIdentityPk,
    pub role: u8,
    pub joined_at: i64,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct DelegationCertificate {
    /// Protocol version at time of signing. Prevents replay across versions.
    pub version: u32,
    /// Conversation this certificate is scoped to. Prevents cross-conversation replay.
    pub conversation_id: ConversationId,
    pub device_pk: PhysicalDevicePk,
    pub permissions: Permissions,
    pub expires_at: i64,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct InviteAction {
    pub invitee_pk: LogicalIdentityPk,
    pub role: u8,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct SignedPreKey {
    pub public_key: EphemeralX25519Pk,
    pub signature: Ed25519Signature,
    pub expires_at: i64,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct WrappedKey {
    pub recipient_pk: PhysicalDevicePk,
    pub opk_id: NodeHash,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct SnapshotData {
    pub basis_hash: NodeHash,
    pub members: Vec<MemberInfo>,
    pub last_seq_numbers: Vec<(PhysicalDevicePk, u64)>,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum ControlAction {
    Genesis {
        title: String,
        creator_pk: LogicalIdentityPk,
        permissions: Permissions,
        flags: u64,
        created_at: i64,
        /// PoW nonce for v2 formula (nonce inside action).
        /// When non-zero, PoW validation uses v2: `blake3(creator_pk || serialize(genesis_action))`.
        pow_nonce: u64,
    },
    SetTitle(String),
    SetTopic(String),
    Invite(InviteAction),
    Leave(LogicalIdentityPk),
    AuthorizeDevice {
        cert: DelegationCertificate,
    },
    RevokeDevice {
        target_device_pk: PhysicalDevicePk,
        reason: String,
    },
    Announcement {
        pre_keys: Vec<SignedPreKey>,
        last_resort_key: SignedPreKey,
    },
    HandshakePulse,
    Snapshot(SnapshotData),
    AnchorSnapshot {
        data: SnapshotData,
        cert: DelegationCertificate,
    },
    SoftAnchor {
        basis_hash: NodeHash,
        cert: DelegationCertificate,
    },
}

#[derive(Debug, Clone, ToxProto, PartialEq)]
pub enum Content {
    // 0: Custom (was Other)
    Custom {
        tag_id: u32,
        data: Vec<u8>,
    },
    // 1: KeyWrap
    KeyWrap {
        generation: u64,
        anchor_hash: NodeHash,
        ephemeral_pk: EphemeralX25519Pk,
        wrapped_keys: Vec<WrappedKey>,
    },
    // 2: SenderKeyDistribution
    SenderKeyDistribution {
        ephemeral_pk: EphemeralX25519Pk,
        wrapped_keys: Vec<WrappedKey>,
        ephemeral_signing_pk: EphemeralSigningPk,
        disclosed_keys: Vec<EphemeralSigningSk>,
    },
    // 3: HistoryExport
    HistoryExport {
        blob_hash: NodeHash,
        blob_size: u64,
        bao_root: Option<[u8; 32]>,
        ephemeral_pk: EphemeralX25519Pk,
        wrapped_keys: Vec<WrappedKey>,
    },
    // 4: Control
    Control(ControlAction),
    // 5: Text
    Text(String),
    // 6: Blob
    Blob {
        hash: NodeHash,
        name: String,
        mime_type: String,
        size: u64,
        metadata: Vec<u8>,
    },
    // 7: Location
    Location {
        latitude: f64,
        longitude: f64,
        title: Option<String>,
    },
    // 8: Edit
    Edit {
        target_hash: NodeHash,
        new_text: String,
    },
    // 9: Reaction
    Reaction {
        target_hash: NodeHash,
        emoji: EmojiSource,
    },
    // 10: Redaction
    Redaction {
        target_hash: NodeHash,
        reason: String,
    },
    // 11: LegacyBridge
    LegacyBridge {
        source_pk: PhysicalDevicePk,
        text: String,
        message_type: u8,
        dedup_id: NodeHash,
    },
    // 12: Unknown. Forward compatibility catch-all for unrecognized content types.
    // Passes validation but triggers no side effects.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

impl Content {
    /// Returns the node type classification for this content.
    /// Admin = Genesis, AuthorizeDevice, RevokeDevice, Snapshot, AnchorSnapshot, KeyWrap, SoftAnchor.
    /// Content = everything else.
    pub fn node_type(&self) -> NodeType {
        match self {
            Content::KeyWrap { .. }
            | Content::Control(
                ControlAction::Genesis { .. }
                | ControlAction::AuthorizeDevice { .. }
                | ControlAction::RevokeDevice { .. }
                | ControlAction::Snapshot(_)
                | ControlAction::AnchorSnapshot { .. }
                | ControlAction::SoftAnchor { .. },
            ) => NodeType::Admin,
            _ => NodeType::Content,
        }
    }
}

/// Logical representation of Merkle node.
#[derive(Debug, Clone, ToxProto, PartialEq)]
pub struct MerkleNode {
    pub parents: Vec<NodeHash>,
    pub author_pk: LogicalIdentityPk,
    pub sender_pk: PhysicalDevicePk,
    pub sequence_number: u64,
    pub topological_rank: u64,
    pub network_timestamp: i64,
    pub content: Content,
    pub metadata: Vec<u8>,
    pub authentication: NodeAuth,
    /// PoW nonce for Genesis nodes. External to serialized content so
    /// node hash remains stable regardless of mining effort.
    #[tox(skip)]
    pub pow_nonce: u64,
}

/// Wire format for Merkle node, used for Content nodes to obfuscate metadata.
#[derive(Debug, Clone, ToxProto, PartialEq)]
pub struct WireNode {
    pub parents: Vec<NodeHash>,
    pub sender_hint: [u8; 4],
    pub encrypted_routing: Vec<u8>,
    pub payload_data: Vec<u8>,
    pub topological_rank: u64,
    pub flags: WireFlags,
    pub authentication: NodeAuth,
}

impl WireNode {
    /// Serializes wire-format fields 1 to 6 with domain separator for signing.
    ///
    /// Used for encrypt-then-sign: content nodes signed post-encryption
    /// against actual wire bytes.
    pub fn serialize_for_auth(&self) -> Vec<u8> {
        let wire_auth = WireAuthData {
            parents: self.parents.clone(),
            sender_hint: self.sender_hint,
            encrypted_routing: self.encrypted_routing.clone(),
            payload_data: self.payload_data.clone(),
            topological_rank: self.topological_rank,
            flags: self.flags,
        };
        let serialized =
            tox_proto::serialize(&wire_auth).expect("Failed to serialize wire auth data");
        let separator: &[u8] = if self.flags.contains(WireFlags::ENCRYPTED) {
            b"merkle-tox v1 content-sig"
        } else {
            b"merkle-tox v1 admin-sig"
        };
        let mut bytes = Vec::with_capacity(separator.len() + serialized.len());
        bytes.extend_from_slice(separator);
        bytes.extend_from_slice(&serialized);
        bytes
    }
}

pub trait NodeLookup {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType>;
    fn get_rank(&self, hash: &NodeHash) -> Option<u64>;
    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64>;
    fn contains_node(&self, hash: &NodeHash) -> bool;
    fn has_children(&self, hash: &NodeHash) -> bool;
    /// Returns number of consecutive SoftAnchor ancestors ending at `hash`.
    /// 0 for non-SoftAnchor admin nodes, None if hash doesn't exist.
    fn get_soft_anchor_chain_length(&self, hash: &NodeHash) -> Option<u64>;
}

pub const POW_DIFFICULTY: u32 = 20; // Spec: BASELINE_POW_DIFFICULTY = 20 bits
pub const MAX_SOFT_ANCHOR_CHAIN: u64 = 3;

pub const MAX_PARENTS: usize = 16;
pub const MAX_ANCESTRY_HOPS: u64 = 500;
pub const MAX_METADATA_SIZE: usize = 32 * 1024; // 32KB

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Node has too many parents: {actual} (max {max})")]
    MaxParentsExceeded { actual: usize, max: usize },
    #[error("Metadata too large: {actual} bytes (max {max})")]
    MaxMetadataExceeded { actual: usize, max: usize },
    #[error("Too many speculative nodes")]
    TooManySpeculativeNodes,
    #[error("Too many verified nodes for this device")]
    TooManyVerifiedNodes,
    #[error("Genesis node does not satisfy Proof-of-Work requirement")]
    PoWInvalid,
    #[error("Cannot perform operation on an empty DAG")]
    EmptyDag,
    #[error("Invalid wire payload size: {actual} (expected at least {expected_min})")]
    InvalidWirePayloadSize { actual: usize, expected_min: usize },
    #[error("Node has exceeded the ancestry trust cap: {actual} (max {max})")]
    AncestryCapExceeded { actual: u64, max: u64 },
    #[error("Topological rank violation: actual {actual}, expected {expected}")]
    TopologicalRankViolation { actual: u64, expected: u64 },
    #[error("Missing parents: {0:?}")]
    MissingParents(Vec<NodeHash>),
    #[error("Invalid admin signature")]
    InvalidAdminSignature,
    #[error("Genesis node with MAC must not have parents")]
    GenesisMacWithParents,
    #[error("Admin node cannot have a Content parent")]
    AdminCannotHaveContentParent,
    #[error("Content node should use MAC")]
    ContentNodeShouldUseMac,
    #[error("Admin node should use Signature")]
    AdminNodeShouldUseSignature,
    #[error("Duplicate parent hash detected: {0:?}")]
    DuplicateParent(NodeHash),
    #[error("Invalid sequence number: {actual} (expected greater than {last})")]
    InvalidSequenceNumber { actual: u64, last: u64 },
    #[error("Invalid padding: {0}")]
    InvalidPadding(String),
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("MAC mismatch")]
    MacMismatch,
    #[error("Message too large: {actual} bytes (max {max})")]
    MaxMessageSizeExceeded { actual: usize, max: usize },
    #[error("SoftAnchor must have exactly one parent (the basis_hash)")]
    SoftAnchorInvalidParent,
    #[error("SoftAnchor chaining cap exceeded: {actual} (max {max})")]
    SoftAnchorChainingCapExceeded { actual: u64, max: u64 },
    #[error("Edit target must reference a Text node")]
    InvalidEditTarget,
    #[error("Edit author must match target author")]
    EditAuthorMismatch,
    #[error("Redaction permission denied: not original author and lacks ADMIN")]
    RedactionPermissionDenied,
    #[error("Reaction target must reference a content node")]
    InvalidReactionTarget,
    #[error("LegacyBridge dedup_id does not match derivation")]
    InvalidLegacyBridgeDedup,
}

/// Wire-format fields 1 to 6 of WireNode, used as signature input.
/// Signatures cover wire encoding (encrypt-then-sign) rather than
/// plaintext MerkleNode fields.
#[derive(ToxSerialize)]
struct WireAuthData {
    parents: Vec<NodeHash>,
    sender_hint: [u8; 4],
    encrypted_routing: Vec<u8>,
    payload_data: Vec<u8>,
    topological_rank: u64,
    flags: WireFlags,
}

/// Counts leading zero bits of a 32-byte hash.
fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut leading_zeros = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros();
            break;
        }
    }
    leading_zeros
}

/// Validates Genesis Proof-of-Work (v1 formula).
///
/// PoW input is `creator_pk || node_hash || nonce` where `node_hash` is
/// Blake3 hash of serialized MerkleNode (excluding `pow_nonce`
/// due to `#[tox(skip)]`).
pub fn validate_pow(creator_pk: &[u8; 32], node_hash: &NodeHash, nonce: u64) -> bool {
    let mut input = Vec::with_capacity(72);
    input.extend_from_slice(creator_pk);
    input.extend_from_slice(node_hash.as_bytes());
    input.extend_from_slice(&nonce.to_le_bytes());
    let hash = blake3::hash(&input);
    count_leading_zeros(hash.as_bytes()) >= POW_DIFFICULTY
}

/// Validates Genesis Proof-of-Work (v2 formula).
///
/// PoW input is `creator_pk || serialize(genesis_action)` where `genesis_action`
/// includes the `pow_nonce` field. The nonce is mined by incrementing
/// `genesis_action.pow_nonce` until the hash has sufficient leading zeros.
pub fn validate_pow_v2(creator_pk: &[u8; 32], genesis_action: &ControlAction) -> bool {
    let action_bytes =
        tox_proto::serialize(genesis_action).expect("Failed to serialize genesis action");
    let mut input = Vec::with_capacity(32 + action_bytes.len());
    input.extend_from_slice(creator_pk);
    input.extend_from_slice(&action_bytes);
    let hash = blake3::hash(&input);
    count_leading_zeros(hash.as_bytes()) >= POW_DIFFICULTY
}

impl MerkleNode {
    /// Validates Proof-of-Work for Genesis node.
    ///
    /// Tries v2 (nonce inside action) first when `genesis.pow_nonce != 0`,
    /// then falls back to v1 (external `self.pow_nonce`).
    pub fn validate_pow(&self) -> bool {
        if let Content::Control(
            action @ ControlAction::Genesis {
                creator_pk,
                pow_nonce,
                ..
            },
        ) = &self.content
        {
            // EXCEPTION: 1-on-1 Genesis nodes use EphemeralSignature (MAC-derived pseudo-sig)
            // and don't require PoW.
            if matches!(self.authentication, NodeAuth::EphemeralSignature(_)) {
                return true;
            }

            // v2: nonce inside genesis action
            if *pow_nonce != 0 && validate_pow_v2(creator_pk.as_bytes(), action) {
                return true;
            }

            // v1 fallback: external nonce
            let node_hash = self.hash();
            validate_pow(creator_pk.as_bytes(), &node_hash, self.pow_nonce)
        } else {
            true // Non-genesis nodes don't need PoW
        }
    }

    pub fn hash(&self) -> NodeHash {
        let data = tox_proto::serialize(self).expect("Failed to serialize node");
        NodeHash::from(*blake3::hash(&data).as_bytes())
    }

    /// Serializes node data for authentication (Signature or EphemeralSignature).
    ///
    /// Produces wire-format bytes (encrypt-then-sign): signature input is
    /// ToxProto encoding of `WireAuthData` (WireNode fields 1 to 6) prepended
    /// with domain separator.
    ///
    /// For exception nodes (admin, KeyWrap, SKD, HistoryExport), wire
    /// encoding is deterministic and computed from MerkleNode alone
    /// (no encryption randomness). Content nodes should use
    /// `WireNode::serialize_for_auth()` on actual encrypted wire node
    /// instead.
    pub fn serialize_for_auth(&self) -> Vec<u8> {
        // Build payload: [timestamp(8B) || serialize(content) || metadata]
        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(&self.network_timestamp.to_be_bytes());
        let content_data =
            tox_proto::serialize(&self.content).expect("Failed to serialize content");
        payload_data.extend_from_slice(&content_data);
        payload_data.extend_from_slice(&self.metadata);
        // ISO 7816-4 padding (no compression for auth bytes)
        apply_padding(&mut payload_data);

        // Cleartext routing: [sender_pk(32B) || seq_number(8B BE)]
        let mut routing = Vec::with_capacity(40);
        routing.extend_from_slice(self.sender_pk.as_bytes());
        routing.extend_from_slice(&self.sequence_number.to_be_bytes());

        let wire_auth = WireAuthData {
            parents: self.parents.clone(),
            sender_hint: [0, 0, 0, 0],
            encrypted_routing: routing,
            payload_data,
            topological_rank: self.topological_rank,
            flags: WireFlags::NONE,
        };

        let serialized =
            tox_proto::serialize(&wire_auth).expect("Failed to serialize wire auth data");
        let separator: &[u8] = match self.node_type() {
            NodeType::Admin => b"merkle-tox v1 admin-sig",
            NodeType::Content => b"merkle-tox v1 content-sig",
        };
        let mut bytes = Vec::with_capacity(separator.len() + serialized.len());
        bytes.extend_from_slice(separator);
        bytes.extend_from_slice(&serialized);
        bytes
    }

    pub fn node_type(&self) -> NodeType {
        self.content.node_type()
    }

    /// Returns true if node is "exception" type using cleartext
    /// wire encoding (no per-message encryption). Admin nodes,
    /// all Control actions, and SenderKeyDistribution are exception nodes.
    /// Control actions are device-signed and cleartext regardless of
    /// node_type() classification (which only affects chain isolation
    /// and domain separators).
    pub fn is_exception_node(&self) -> bool {
        self.node_type() == NodeType::Admin
            || matches!(
                self.content,
                Content::Control(_) | Content::SenderKeyDistribution { .. }
            )
    }

    /// Whether this node skips per-message ratchet advancement.
    /// Exception nodes skip because they are cleartext. HistoryExport also
    /// skips because it uses room-wide export keys, not the per-sender ratchet.
    pub fn skips_ratchet(&self) -> bool {
        self.is_exception_node() || matches!(self.content, Content::HistoryExport { .. })
    }

    /// Verifies the signature of an Admin node.
    pub fn verify_admin_signature(&self) -> bool {
        if let NodeAuth::Signature(sig) = &self.authentication {
            let Ok(verifying_key) = VerifyingKey::from_bytes(self.sender_pk.as_bytes()) else {
                return false;
            };
            let signature = DalekSignature::from_bytes(sig.as_ref());
            let auth_data = self.serialize_for_auth();

            verifying_key.verify(&auth_data, &signature).is_ok()
        } else {
            // EXCEPTION: 1-on-1 Genesis nodes use MAC.
            // Authenticity is checked in handle_node via MAC verification.
            if let Content::Control(ControlAction::Genesis { .. }) = &self.content {
                self.parents.is_empty()
            } else {
                false
            }
        }
    }

    /// Validates the node against the protocol rules.
    pub fn validate<L: NodeLookup + ?Sized>(
        &self,
        _conversation_id: &ConversationId,
        lookup: &L,
    ) -> Result<(), ValidationError> {
        // 0. Hard Limits
        if self.parents.len() > MAX_PARENTS {
            return Err(ValidationError::MaxParentsExceeded {
                actual: self.parents.len(),
                max: MAX_PARENTS,
            });
        }

        // Parent uniqueness check
        let mut unique_parents = HashSet::new();
        for p in &self.parents {
            if !unique_parents.insert(p) {
                return Err(ValidationError::DuplicateParent(*p));
            }
        }

        if self.metadata.len() > MAX_METADATA_SIZE {
            return Err(ValidationError::MaxMetadataExceeded {
                actual: self.metadata.len(),
                max: MAX_METADATA_SIZE,
            });
        }

        // Message size check: metadata + serialized content must not exceed MAX_MESSAGE_SIZE.
        let content_size = tox_proto::serialize(&self.content)
            .map(|v| v.len())
            .unwrap_or(0);
        let total_size = self.metadata.len() + content_size;
        if total_size > tox_proto::constants::MAX_MESSAGE_SIZE {
            return Err(ValidationError::MaxMessageSizeExceeded {
                actual: total_size,
                max: tox_proto::constants::MAX_MESSAGE_SIZE,
            });
        }

        let node_type = self.node_type();

        // SenderKeyDistribution: epoch 0 uses Signature, epoch n>0 uses EphemeralSignature (DARE §2).
        let is_skd = matches!(self.content, Content::SenderKeyDistribution { .. });
        // All Control actions use device Signature (they're administrative
        // actions that need accountability, not deniability).
        let is_control = matches!(self.content, Content::Control(_));
        // Combined flag: Content nodes that allow device Signature.
        let allows_device_sig = is_skd || (is_control && node_type == NodeType::Content);

        // 1. Authentication Rule: Admin nodes (including KeyWrap) MUST use Signature.
        //    SKD and Announcement/HandshakePulse accept both Signature and EphemeralSignature.
        //    Other content nodes MUST use EphemeralSignature.
        match (&self.authentication, node_type, allows_device_sig) {
            (NodeAuth::Signature(_), NodeType::Admin, _) => {}
            (NodeAuth::EphemeralSignature(_), NodeType::Content, false) => {}
            // SKD and pre-setup nodes allow both Signature and EphemeralSignature
            (NodeAuth::Signature(_), NodeType::Content, true) => {}
            (NodeAuth::EphemeralSignature(_), NodeType::Content, true) => {}
            (NodeAuth::Signature(_), NodeType::Content, false) => {
                return Err(ValidationError::ContentNodeShouldUseMac);
            }
            (NodeAuth::EphemeralSignature(_), NodeType::Admin, _) => {
                // EXCEPTION: 1-on-1 Genesis nodes use EphemeralSignature (MAC-derived pseudo-sig).
                if let Content::Control(ControlAction::Genesis { .. }) = &self.content {
                    if !self.parents.is_empty() {
                        return Err(ValidationError::GenesisMacWithParents);
                    }
                } else {
                    return Err(ValidationError::AdminNodeShouldUseSignature);
                }
            }
        }

        // 2. Admin Authenticity: applies to Admin nodes and any device-signed
        //    Content exception (SKD epoch 0, Announcement, HandshakePulse).
        let is_device_signed = matches!(self.authentication, NodeAuth::Signature(_));
        let is_device_signed_content = allows_device_sig && is_device_signed;
        if node_type == NodeType::Admin || is_device_signed_content {
            // 0. PoW check for Genesis
            if !self.validate_pow() {
                return Err(ValidationError::PoWInvalid);
            }

            // 1. Signature check
            if !self.verify_admin_signature() {
                return Err(ValidationError::InvalidAdminSignature);
            }
        }

        // 3. Cycle detection / Monotonicity: topological_rank MUST be max(parent_ranks) + 1.
        let mut max_parent_rank = 0;
        let mut missing = Vec::new();
        for parent_hash in &self.parents {
            if let Some(parent_rank) = lookup.get_rank(parent_hash) {
                if parent_rank >= max_parent_rank {
                    max_parent_rank = parent_rank;
                }
            } else {
                missing.push(*parent_hash);
            }
        }

        if !missing.is_empty() {
            return Err(ValidationError::MissingParents(missing));
        }

        let expected_rank = if self.parents.is_empty() {
            0
        } else {
            max_parent_rank + 1
        };

        if self.topological_rank != expected_rank {
            return Err(ValidationError::TopologicalRankViolation {
                actual: self.topological_rank,
                expected: expected_rank,
            });
        }

        // 4. Chain Isolation: Admin nodes MUST ONLY reference other Admin nodes
        //    as parents (merkle-tox-dag.md §3.2). SoftAnchor is exempt because
        //    its basis_hash can reference any node type.
        let is_soft_anchor = matches!(
            self.content,
            Content::Control(ControlAction::SoftAnchor { .. })
        );
        if node_type == NodeType::Admin && !is_soft_anchor {
            for parent_hash in &self.parents {
                match lookup.get_node_type(parent_hash) {
                    Some(NodeType::Admin) => {}
                    Some(NodeType::Content) => {
                        return Err(ValidationError::AdminCannotHaveContentParent);
                    }
                    None => {
                        return Err(ValidationError::MissingParents(vec![*parent_hash]));
                    }
                }
            }
        }

        // 4b. SoftAnchor-specific constraints
        if let Content::Control(ControlAction::SoftAnchor { basis_hash, .. }) = &self.content {
            // Single-parent: MUST have exactly basis_hash as sole parent
            if self.parents.len() != 1 || self.parents[0] != *basis_hash {
                return Err(ValidationError::SoftAnchorInvalidParent);
            }
            // Chaining cap: max 3 consecutive SoftAnchors
            if let Some(chain_len) = lookup.get_soft_anchor_chain_length(basis_hash) {
                let new_chain_len = chain_len + 1;
                if new_chain_len > MAX_SOFT_ANCHOR_CHAIN {
                    return Err(ValidationError::SoftAnchorChainingCapExceeded {
                        actual: new_chain_len,
                        max: MAX_SOFT_ANCHOR_CHAIN,
                    });
                }
            }
        }

        // 5. Ancestry Trust Cap: Content nodes must be within MAX_ANCESTRY_HOPS of an Admin node.
        if node_type == NodeType::Content && !self.parents.is_empty() {
            let mut min_distance = u64::MAX;
            for parent_hash in &self.parents {
                if let Some(dist) = lookup.get_admin_distance(parent_hash) {
                    min_distance = min_distance.min(dist);
                } else {
                    return Err(ValidationError::MissingParents(vec![*parent_hash]));
                }
            }

            if min_distance >= MAX_ANCESTRY_HOPS {
                return Err(ValidationError::AncestryCapExceeded {
                    actual: min_distance + 1,
                    max: MAX_ANCESTRY_HOPS,
                });
            }
        }

        Ok(())
    }

    /// Converts logical MerkleNode to wire representation.
    ///
    /// Content nodes use per-message encryption: payload encrypted with K_msg,
    /// routing encrypted with K_header AEAD, and 4-byte sender_hint for fast
    /// sender identification.
    ///
    /// Exception nodes (Admin, KeyWrap, SKD) use cleartext.
    /// HistoryExport uses room-wide export keys (k_header_export, k_payload_export).
    pub fn pack_wire(
        &self,
        keys: &crate::crypto::PackKeys,
        use_compression: bool,
    ) -> Result<WireNode, MerkleToxError> {
        // Build the payload: [timestamp || content || metadata]
        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(&self.network_timestamp.to_be_bytes());
        let content_data = tox_proto::serialize(&self.content)?;
        payload_data.extend_from_slice(&content_data);
        payload_data.extend_from_slice(&self.metadata);

        let mut flags = WireFlags::NONE;
        if use_compression
            && let Ok(compressed) = zstd::encode_all(&payload_data[..], 3)
            && compressed.len() < payload_data.len()
        {
            payload_data = compressed;
            flags |= WireFlags::COMPRESSED;
        }

        apply_padding(&mut payload_data);

        match keys {
            crate::crypto::PackKeys::Exception => {
                // Exception nodes: cleartext routing and payload
                let mut routing = Vec::new();
                routing.extend_from_slice(self.sender_pk.as_bytes());
                routing.extend_from_slice(&self.sequence_number.to_be_bytes());

                Ok(WireNode {
                    parents: self.parents.clone(),
                    sender_hint: [0, 0, 0, 0],
                    encrypted_routing: routing,
                    payload_data,
                    topological_rank: self.topological_rank,
                    flags,
                    authentication: self.authentication.clone(),
                })
            }
            crate::crypto::PackKeys::Content(ck) => {
                // 1. Encrypt payload with K_msg directly (ChaCha20, stream cipher)
                use chacha20::ChaCha20;
                use chacha20::cipher::{KeyIvInit, StreamCipher as _};
                let mut cipher =
                    ChaCha20::new(ck.k_msg.as_bytes().into(), (&ck.payload_nonce).into());
                cipher.apply_keystream(&mut payload_data);

                // Prepend payload nonce
                let mut encrypted_payload = Vec::with_capacity(12 + payload_data.len());
                encrypted_payload.extend_from_slice(&ck.payload_nonce);
                encrypted_payload.extend_from_slice(&payload_data);

                // 2. Compute payload_hash = Blake3(encrypted_payload) for AEAD AAD
                let payload_hash = *blake3::hash(&encrypted_payload).as_bytes();

                // 3. Encrypt routing with K_header AEAD
                let aead_ct = crate::crypto::encrypt_routing_aead(
                    &ck.k_header,
                    &ck.routing_nonce,
                    self.sequence_number,
                    &payload_hash,
                );

                // Prepend routing nonce → 12 + 24 = 36 bytes total
                let mut encrypted_routing = Vec::with_capacity(12 + aead_ct.len());
                encrypted_routing.extend_from_slice(&ck.routing_nonce);
                encrypted_routing.extend_from_slice(&aead_ct);

                // 4. Compute sender_hint
                let sender_hint = crate::crypto::compute_sender_hint(&ck.k_msg);

                flags |= WireFlags::ENCRYPTED;

                Ok(WireNode {
                    parents: self.parents.clone(),
                    sender_hint,
                    encrypted_routing,
                    payload_data: encrypted_payload,
                    topological_rank: self.topological_rank,
                    flags,
                    authentication: self.authentication.clone(),
                })
            }
        }
    }

    /// Try to decrypt routing with candidate K_header.
    /// Returns sequence number on success, None on AEAD tag mismatch.
    pub fn try_decrypt_routing(wire: &WireNode, k_header: &HeaderKey) -> Option<u64> {
        if wire.encrypted_routing.len() != 36 {
            return None;
        }
        let routing_nonce: [u8; 12] = wire.encrypted_routing[0..12].try_into().ok()?;
        let aead_ct = &wire.encrypted_routing[12..];
        let payload_hash = *blake3::hash(&wire.payload_data).as_bytes();
        crate::crypto::decrypt_routing_aead(k_header, &routing_nonce, aead_ct, &payload_hash)
    }

    /// Decrypt payload once sender is identified. Returns MerkleNode.
    pub fn unpack_wire_content(
        wire: &WireNode,
        sender_pk: PhysicalDevicePk,
        author_pk: LogicalIdentityPk,
        sequence_number: u64,
        k_msg: &MessageKey,
    ) -> Result<Self, MerkleToxError> {
        if wire.payload_data.len() < 12 {
            return Err(MerkleToxError::Validation(
                ValidationError::InvalidWirePayloadSize {
                    actual: wire.payload_data.len(),
                    expected_min: 12,
                },
            ));
        }

        let payload_nonce: [u8; 12] = wire.payload_data[0..12].try_into().unwrap();
        let mut payload_data = wire.payload_data[12..].to_vec();

        // Decrypt payload with K_msg directly
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher as _};
        let mut cipher = ChaCha20::new(k_msg.as_bytes().into(), (&payload_nonce).into());
        cipher.apply_keystream(&mut payload_data);

        Self::decode_payload(wire, sender_pk, author_pk, sequence_number, payload_data)
    }

    /// Unpack exception nodes (cleartext routing/payload).
    pub fn unpack_wire_exception(wire: &WireNode) -> Result<Self, MerkleToxError> {
        let routing = &wire.encrypted_routing;

        if routing.len() < 40 {
            return Err(MerkleToxError::Validation(
                ValidationError::InvalidWirePayloadSize {
                    actual: routing.len(),
                    expected_min: 40,
                },
            ));
        }

        let sender_pk_bytes: [u8; 32] = routing[0..32].try_into().unwrap();
        let sender_pk = PhysicalDevicePk::from(sender_pk_bytes);
        let sequence_number = u64::from_be_bytes(routing[32..40].try_into().unwrap());

        // For exception nodes, author_pk is resolved from the sender_pk (best effort).
        // The caller should resolve the logical identity separately.
        let author_pk = LogicalIdentityPk::from(*sender_pk.as_bytes());

        Self::decode_payload(
            wire,
            sender_pk,
            author_pk,
            sequence_number,
            wire.payload_data.clone(),
        )
    }

    /// Common payload decoding: remove padding, decompress, deserialize.
    fn decode_payload(
        wire: &WireNode,
        sender_pk: PhysicalDevicePk,
        author_pk: LogicalIdentityPk,
        sequence_number: u64,
        mut payload_data: Vec<u8>,
    ) -> Result<Self, MerkleToxError> {
        if let Err(e) = remove_padding(&mut payload_data) {
            tracing::debug!("Padding removal failed: {}", e);
            return Err(MerkleToxError::Validation(ValidationError::InvalidPadding(
                format!("Invalid padding: {}", e),
            )));
        }

        if wire.flags.contains(WireFlags::COMPRESSED) {
            payload_data = zstd::decode_all(&payload_data[..]).map_err(|e| {
                tracing::debug!("Decompression failed: {}", e);
                MerkleToxError::Validation(ValidationError::DecompressionFailed(format!(
                    "Decompression failed: {}",
                    e
                )))
            })?;
        }

        if payload_data.len() < 8 {
            tracing::debug!("Invalid wire payload size: {}", payload_data.len());
            return Err(MerkleToxError::Validation(
                ValidationError::InvalidWirePayloadSize {
                    actual: payload_data.len(),
                    expected_min: 8,
                },
            ));
        }

        let network_timestamp = i64::from_be_bytes(payload_data[0..8].try_into().unwrap());

        let mut cursor = Cursor::new(&payload_data[8..]);
        let content: Content =
            match Content::deserialize(&mut cursor, &tox_proto::ToxContext::empty()) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("Content deserialization failed: {}", e);
                    return Err(e.into());
                }
            };

        let consumed = cursor.position() as usize;
        let metadata = payload_data[8 + consumed..].to_vec();

        Ok(MerkleNode {
            parents: wire.parents.clone(),
            author_pk,
            sender_pk,
            sequence_number,
            topological_rank: wire.topological_rank,
            network_timestamp,
            content,
            metadata,
            authentication: wire.authentication.clone(),
            pow_nonce: 0,
        })
    }
}

pub fn apply_padding(data: &mut Vec<u8>) {
    // ISO/IEC 7816-4 padding: 0x80 followed by 0x00s
    data.push(0x80);
    let target_len = data.len().next_power_of_two();
    let target_len = std::cmp::max(target_len, tox_proto::constants::MIN_PADDING_BIN);
    data.resize(target_len, 0x00);
}

pub fn remove_padding(data: &mut Vec<u8>) -> Result<(), String> {
    if let Some(pos) = data.iter().rposition(|&x| x != 0x00) {
        if data[pos] == 0x80 {
            data.truncate(pos);
            Ok(())
        } else {
            Err("Last non-zero byte is not 0x80".to_string())
        }
    } else {
        Err("No non-zero bytes found (invalid padding)".to_string())
    }
}

/// Computes effective timestamp per spec §3 (clock.md).
/// `T_eff(N) = max(N.network_timestamp, max(T_eff(parents)))`
/// Presentation-layer only; not persisted.
pub fn effective_timestamp(node: &MerkleNode, store: &dyn crate::sync::NodeStore) -> i64 {
    let mut t_eff = node.network_timestamp;
    for parent_hash in &node.parents {
        if let Some(parent) = store.get_node(parent_hash) {
            let parent_t_eff = effective_timestamp(&parent, store);
            t_eff = t_eff.max(parent_t_eff);
        }
    }
    t_eff
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Admin,
    Content,
}
