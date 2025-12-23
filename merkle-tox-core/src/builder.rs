use crate::crypto::ConversationKeys;
use crate::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode,
    NodeAuth, NodeMac, Permissions, PhysicalDevicePk,
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
            parents: vec![],
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
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])), // Placeholder
        };

        // 1-on-1 Genesis nodes use MAC and don't require PoW.
        let auth_data = node.serialize_for_auth(&ConversationId::from([0u8; 32]));
        node.authentication = NodeAuth::Mac(keys.calculate_mac(&auth_data));

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
            parents: vec![],
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
            metadata: vec![],
            authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])), // Placeholder
        };

        // Solve PoW
        let mut nonce = 0u64;
        loop {
            if let Content::Control(ControlAction::Genesis {
                ref mut pow_nonce, ..
            }) = node.content
            {
                *pow_nonce = nonce;
            }

            // Signature depends on pow_nonce
            let auth_data = node.serialize_for_auth(&ConversationId::from([0u8; 32]));
            let sig = signing_key.sign(&auth_data).to_bytes();
            node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));

            if node.validate_pow() {
                break;
            }
            nonce += 1;
        }

        node
    }
}
