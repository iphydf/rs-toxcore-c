use crate::crypto::ConversationKeys;
use crate::error::MerkleToxError;
use bitflags::bitflags;
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::io::Cursor;
pub use tox_proto::{
    ChainKey, ConversationId, Ed25519Signature, EncryptionKey, EphemeralX25519Pk,
    EphemeralX25519Sk, KConv, LogicalIdentityPk, LogicalIdentitySk, MacKey, MessageKey, NodeHash,
    NodeMac, PhysicalDeviceDhSk, PhysicalDevicePk, PhysicalDeviceSk, PowNonce, ShardHash,
    SharedSecretKey, ToxDeserialize, ToxProto, ToxSerialize,
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
    /// For content nodes: Blake3-MAC(K_mac, NodeData).
    Mac(NodeMac),
    /// For administrative nodes: Ed25519-Sig(Sender_SK, NodeData).
    Signature(Ed25519Signature),
}

impl NodeAuth {
    pub fn mac(&self) -> Option<&NodeMac> {
        match self {
            NodeAuth::Mac(mac) => Some(mac),
            _ => None,
        }
    }
}

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
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum ControlAction {
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
    Snapshot {
        basis_hash: NodeHash,
        members: Vec<MemberInfo>,
        last_seq_numbers: Vec<(PhysicalDevicePk, u64)>,
    },
    Rekey {
        new_epoch: u64,
    },
    Genesis {
        title: String,
        creator_pk: LogicalIdentityPk,
        permissions: Permissions,
        flags: u64,
        created_at: i64,
        pow_nonce: u64,
    },
}

#[derive(Debug, Clone, ToxProto, PartialEq)]
pub enum Content {
    Text(String),
    Blob {
        hash: NodeHash,
        name: String,
        mime_type: String,
        size: u64,
        metadata: Vec<u8>,
    },
    Reaction {
        target_hash: NodeHash,
        emoji: EmojiSource,
    },
    Location {
        latitude: f64,
        longitude: f64,
        title: Option<String>,
    },
    Control(ControlAction),
    Redaction {
        target_hash: NodeHash,
        reason: String,
    },
    Other {
        tag_id: u32,
        data: Vec<u8>,
    },
    KeyWrap {
        epoch: u64,
        wrapped_keys: Vec<WrappedKey>,
        /// The Alice's ephemeral PK used for X3DH.
        ephemeral_pk: Option<EphemeralX25519Pk>,
        /// The Bob's signed pre-key PK Alice used for X3DH.
        pre_key_pk: Option<EphemeralX25519Pk>,
    },
    RatchetSnapshot {
        epoch: u64,
        ciphertext: Vec<u8>,
    },
}

/// The logical representation of a Merkle node.
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
}

/// The wire format for a Merkle node, used for Content nodes to obfuscate metadata.
#[derive(Debug, Clone, ToxProto, PartialEq)]
pub struct WireNode {
    pub parents: Vec<NodeHash>,
    pub author_pk: LogicalIdentityPk,
    pub encrypted_payload: Vec<u8>,
    pub topological_rank: u64,
    pub network_timestamp: i64,
    pub flags: WireFlags,
    pub authentication: NodeAuth,
}

pub trait NodeLookup {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType>;
    fn get_rank(&self, hash: &NodeHash) -> Option<u64>;
    fn contains_node(&self, hash: &NodeHash) -> bool;
    fn has_children(&self, hash: &NodeHash) -> bool;
}

pub const POW_DIFFICULTY: u32 = 12; // Adjusted as per design update

pub const MAX_PARENTS: usize = 16;
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
}

#[derive(ToxSerialize)]
struct AuthData<'a> {
    conversation_id: &'a ConversationId,
    parents: &'a Vec<NodeHash>,
    author_pk: &'a LogicalIdentityPk,
    sender_pk: &'a PhysicalDevicePk,
    sequence_number: u64,
    topological_rank: u64,
    network_timestamp: i64,
    content: &'a Content,
    metadata: &'a Vec<u8>,
}

impl MerkleNode {
    /// Validates the Proof-of-Work for a Genesis node.
    pub fn validate_pow(&self) -> bool {
        if let Content::Control(ControlAction::Genesis { .. }) = &self.content {
            // EXCEPTION: 1-on-1 Genesis nodes use MAC and don't require PoW.
            if matches!(self.authentication, NodeAuth::Mac(_)) {
                return true;
            }

            let hash = self.hash();
            let mut leading_zeros = 0;
            for &byte in hash.as_bytes().iter() {
                if byte == 0 {
                    leading_zeros += 8;
                } else {
                    leading_zeros += byte.leading_zeros();
                    break;
                }
            }
            leading_zeros >= POW_DIFFICULTY
        } else {
            true // Non-genesis nodes don't need PoW
        }
    }

    pub fn hash(&self) -> NodeHash {
        let data = tox_proto::serialize(self).expect("Failed to serialize node");
        NodeHash::from(*blake3::hash(&data).as_bytes())
    }

    /// Serializes the node data for authentication (MAC or Signature).
    /// This excludes the authentication field itself.
    pub fn serialize_for_auth(&self, conversation_id: &ConversationId) -> Vec<u8> {
        let empty_conv_id = ConversationId::from([0u8; 32]);
        let auth_conv_id = if matches!(
            self.content,
            Content::Control(ControlAction::Genesis { .. })
        ) {
            tracing::debug!("Serializing Genesis node for auth, using empty conv ID");
            &empty_conv_id
        } else {
            tracing::debug!(
                "Serializing non-Genesis node for auth, using conv ID: {}",
                hex::encode(conversation_id.as_bytes())
            );
            conversation_id
        };

        tracing::debug!("AuthData fields:");
        tracing::debug!("  conv_id: {}", hex::encode(auth_conv_id.as_bytes()));
        tracing::debug!("  parents: {:?}", self.parents);
        tracing::debug!("  author_pk: {}", hex::encode(self.author_pk.as_bytes()));
        tracing::debug!("  sender_pk: {}", hex::encode(self.sender_pk.as_bytes()));
        tracing::debug!("  seq_num: {}", self.sequence_number);
        tracing::debug!("  rank: {}", self.topological_rank);
        tracing::debug!("  timestamp: {}", self.network_timestamp);
        tracing::debug!("  content: {:?}", self.content);
        tracing::debug!("  metadata len: {}", self.metadata.len());

        let data = AuthData {
            conversation_id: auth_conv_id,
            parents: &self.parents,
            author_pk: &self.author_pk,
            sender_pk: &self.sender_pk,
            sequence_number: self.sequence_number,
            topological_rank: self.topological_rank,
            network_timestamp: self.network_timestamp,
            content: &self.content,
            metadata: &self.metadata,
        };

        let bytes = tox_proto::serialize(&data).expect("Failed to serialize auth data");
        tracing::debug!("serialize_for_auth bytes: {}", hex::encode(&bytes));
        bytes
    }

    pub fn node_type(&self) -> NodeType {
        match &self.content {
            Content::Control(_) => NodeType::Admin,
            _ => NodeType::Content,
        }
    }

    /// Verifies the signature of an Admin node.
    pub fn verify_admin_signature(&self, conversation_id: &ConversationId) -> bool {
        if let NodeAuth::Signature(sig) = &self.authentication {
            let Ok(verifying_key) = VerifyingKey::from_bytes(self.sender_pk.as_bytes()) else {
                return false;
            };
            let signature = DalekSignature::from_bytes(sig.as_ref());
            let auth_data = self.serialize_for_auth(conversation_id);

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
        conversation_id: &ConversationId,
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

        let node_type = self.node_type();

        // 1. Authentication Rule: Admin nodes MUST use Signature. Content nodes MUST use MAC.
        match (&self.authentication, node_type) {
            (NodeAuth::Signature(_), NodeType::Admin) => {}
            (NodeAuth::Mac(_), NodeType::Content) => {}
            (NodeAuth::Signature(_), NodeType::Content) => {
                return Err(ValidationError::ContentNodeShouldUseMac);
            }
            (NodeAuth::Mac(_), NodeType::Admin) => {
                // EXCEPTION: 1-on-1 Genesis nodes use MAC.
                if let Content::Control(ControlAction::Genesis { .. }) = &self.content {
                    if !self.parents.is_empty() {
                        return Err(ValidationError::GenesisMacWithParents);
                    }
                } else {
                    return Err(ValidationError::AdminNodeShouldUseSignature);
                }
            }
        }

        // 2. Admin Authenticity
        if node_type == NodeType::Admin {
            // 0. PoW check for Genesis
            if !self.validate_pow() {
                return Err(ValidationError::PoWInvalid);
            }

            // 1. Signature check
            if !self.verify_admin_signature(conversation_id) {
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

        // 4. Chain Isolation: Admin nodes MUST ONLY reference other Admin nodes as parents.
        if node_type == NodeType::Admin {
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

        Ok(())
    }

    /// Converts the logical MerkleNode to its wire representation.
    /// Content nodes have their sensitive metadata (sender_pk, sequence_number, content, metadata) encrypted.
    pub fn pack_wire(
        &self,
        keys: &ConversationKeys,
        use_compression: bool,
    ) -> Result<WireNode, MerkleToxError> {
        let node_type = self.node_type();
        let is_key_wrap = matches!(self.content, Content::KeyWrap { .. });

        let mut payload = Vec::new();
        payload.extend_from_slice(self.sender_pk.as_bytes());
        payload.extend_from_slice(&self.sequence_number.to_be_bytes());
        let content_data = tox_proto::serialize(&self.content)?;
        payload.extend_from_slice(&content_data);
        payload.extend_from_slice(&self.metadata);

        let mut flags = WireFlags::NONE;
        if use_compression
            && let Ok(compressed) = zstd::encode_all(&payload[..], 3)
            && compressed.len() < payload.len()
        {
            payload = compressed;
            flags |= WireFlags::COMPRESSED;
        }

        apply_padding(&mut payload);

        if node_type == NodeType::Admin || is_key_wrap {
            Ok(WireNode {
                parents: self.parents.clone(),
                author_pk: self.author_pk,
                encrypted_payload: payload,
                topological_rank: self.topological_rank,
                network_timestamp: self.network_timestamp,
                flags,
                authentication: self.authentication.clone(),
            })
        } else {
            let mut nonce = [0u8; 12];
            if let Some(mac) = self.authentication.mac() {
                nonce.copy_from_slice(&mac.as_bytes()[0..12]);
            }

            tracing::debug!(
                "Encrypting wire node with k_enc prefix: {}",
                hex::encode(&keys.k_enc.as_bytes()[..8])
            );
            keys.encrypt(&nonce, &mut payload);
            flags |= WireFlags::ENCRYPTED;

            Ok(WireNode {
                parents: self.parents.clone(),
                author_pk: self.author_pk,
                encrypted_payload: payload,
                topological_rank: self.topological_rank,
                network_timestamp: self.network_timestamp,
                flags,
                authentication: self.authentication.clone(),
            })
        }
    }

    /// Reconstructs a logical MerkleNode from its wire representation.
    pub fn unpack_wire(
        wire: &WireNode,
        keys: &ConversationKeys,
        conversation_id: &ConversationId,
    ) -> Result<Self, MerkleToxError> {
        let mut payload = wire.encrypted_payload.clone();
        let is_admin = matches!(wire.authentication, NodeAuth::Signature(_));

        if wire.flags.contains(WireFlags::ENCRYPTED) {
            let mut nonce = [0u8; 12];
            if let Some(mac) = wire.authentication.mac() {
                nonce.copy_from_slice(&mac.as_bytes()[0..12]);
            }
            tracing::debug!(
                "Decrypting wire node with k_enc prefix: {}",
                hex::encode(&keys.k_enc.as_bytes()[..8])
            );
            keys.decrypt(&nonce, &mut payload);
        }

        if let Err(e) = remove_padding(&mut payload) {
            tracing::debug!("Padding removal failed: {}", e);
            return Err(MerkleToxError::Validation(ValidationError::InvalidPadding(
                format!("Invalid padding: {}", e),
            )));
        }

        if wire.flags.contains(WireFlags::COMPRESSED) {
            payload = zstd::decode_all(&payload[..]).map_err(|e| {
                tracing::debug!("Decompression failed: {}", e);
                MerkleToxError::Validation(ValidationError::DecompressionFailed(format!(
                    "Decompression failed: {}",
                    e
                )))
            })?;
        }

        if payload.len() < 32 + 8 {
            tracing::debug!("Invalid wire payload size: {}", payload.len());
            return Err(MerkleToxError::Validation(
                ValidationError::InvalidWirePayloadSize {
                    actual: payload.len(),
                    expected_min: 32 + 8,
                },
            ));
        }

        let sender_pk_bytes: [u8; 32] = payload[0..32].try_into().unwrap();
        let sender_pk = PhysicalDevicePk::from(sender_pk_bytes);
        let sequence_number = u64::from_be_bytes(payload[32..40].try_into().unwrap());

        // Use a Cursor to track how many bytes are consumed by Content deserialization.
        let mut cursor = Cursor::new(&payload[40..]);
        let content: Content =
            match Content::deserialize(&mut cursor, &tox_proto::ToxContext::empty()) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("Content deserialization failed: {}", e);
                    return Err(e.into());
                }
            };

        let consumed = cursor.position() as usize;
        let metadata = payload[40 + consumed..].to_vec();

        tracing::debug!("Unpacked node fields:");
        tracing::debug!("  sender_pk: {}", hex::encode(sender_pk.as_bytes()));
        tracing::debug!("  seq_num: {}", sequence_number);
        tracing::debug!("  content: {:?}", content);
        tracing::debug!("  metadata len: {}", metadata.len());

        let node = MerkleNode {
            parents: wire.parents.clone(),
            author_pk: wire.author_pk,
            sender_pk,
            sequence_number,
            topological_rank: wire.topological_rank,
            network_timestamp: wire.network_timestamp,
            content,
            metadata,
            authentication: wire.authentication.clone(),
        };

        // Verify MAC for non-admin nodes
        if !is_admin
            && let Some(mac) = node.authentication.mac()
            && !keys.verify_mac(&node.serialize_for_auth(conversation_id), mac)
        {
            return Err(MerkleToxError::Validation(ValidationError::MacMismatch));
        }

        Ok(node)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Admin,
    Content,
}
