use crate::crypto::ConversationKeys;
use crate::dag::{
    Content, ControlAction, Ed25519Signature, LogicalIdentityPk, MerkleNode, NodeAuth, Permissions,
    PhysicalDevicePk,
};
use ed25519_dalek::Signer;

pub struct NodeBuilder;

impl NodeBuilder {
    /// Creates a deterministic 1-on-1 Genesis node.
    pub fn new_1on1_genesis(
        pk_a: LogicalIdentityPk,
        pk_b: LogicalIdentityPk,
        keys: &ConversationKeys,
    ) -> MerkleNode {
        let mut pks = [pk_a, pk_b];
        pks.sort_unstable();

        let mut node = MerkleNode {
            parents: tox_proto::BoundedVec::new(),
            author_pk: LogicalIdentityPk::from([0u8; 32]), // Not used for 1-on-1 genesis
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: 1,
            topological_rank: 0,
            network_timestamp: 0,
            content: Content::Control(ControlAction::Genesis {
                title: "Private Chat".to_string(),
                creator_pk: pks[0],
                permissions: Permissions::ALL,
                flags: 0,
                created_at: 0,
                pow_nonce: 0,
            }),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])), // Placeholder
            pow_nonce: 0,
        };

        // 1-on-1 Genesis nodes use a MAC-derived pseudo-signature for authentication.
        // MAC bytes are embedded in the first 32 bytes of the 64-byte signature field.
        let auth_data = node.serialize_for_auth();
        let mac = keys.calculate_mac(&auth_data);
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(mac.as_bytes());
        node.authentication = NodeAuth::EphemeralSignature(Ed25519Signature::from(sig_bytes));

        node
    }

    /// Creates a Group Genesis node and solves the Proof-of-Work.
    pub fn new_group_genesis(
        title: String,
        creator_pk: LogicalIdentityPk,
        flags: u64,
        timestamp: i64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MerkleNode {
        let mut node = MerkleNode {
            parents: tox_proto::BoundedVec::new(),
            author_pk: creator_pk,
            sender_pk: creator_pk.to_physical(),
            sequence_number: 1,
            topological_rank: 0,
            network_timestamp: timestamp,
            content: Content::Control(ControlAction::Genesis {
                title,
                creator_pk,
                permissions: Permissions::ALL,
                flags,
                created_at: timestamp,
                pow_nonce: 0,
            }),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])), // Placeholder
            pow_nonce: 0,
        };

        // Solve PoW v2: nonce inside genesis action.
        // Iterate pow_nonce inside the action; sign after mining.
        let mut nonce = 0u64;
        loop {
            if let Content::Control(ControlAction::Genesis { pow_nonce, .. }) = &mut node.content {
                *pow_nonce = nonce;
            }
            if let Content::Control(ref action) = node.content
                && crate::dag::validate_pow_v2(creator_pk.as_bytes(), action)
            {
                break;
            }
            nonce += 1;
        }

        // Sign after mining: signature covers the mined action
        let auth_data = node.serialize_for_auth();
        let sig = signing_key.sign(&auth_data).to_bytes();
        node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));

        node
    }
}
