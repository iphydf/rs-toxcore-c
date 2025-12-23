use crate::dag::{
    Content, ControlAction, ConversationId, DelegationCertificate, Ed25519Signature, KConv,
    LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac, Permissions, PhysicalDevicePk,
};
use crate::identity::sign_delegation;
use ed25519_dalek::{Signer, SigningKey};

/// A helper structure representing a logical user identity with a master key and an authorized device key.
pub struct TestIdentity {
    pub master_sk: SigningKey,
    pub master_pk: LogicalIdentityPk,
    pub device_sk: SigningKey,
    pub device_pk: PhysicalDevicePk,
}

impl Default for TestIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl TestIdentity {
    pub fn new() -> Self {
        let master_sk = random_signing_key();
        let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());
        let device_sk = random_signing_key();
        let device_pk = PhysicalDevicePk::from(device_sk.verifying_key().to_bytes());

        Self {
            master_sk,
            master_pk,
            device_sk,
            device_pk,
        }
    }

    /// Creates an authorization certificate for the device signed by the master key.
    pub fn make_device_cert(&self, perms: Permissions, expires: i64) -> DelegationCertificate {
        make_cert(&self.master_sk, self.device_pk, perms, expires)
    }

    /// Authorizes the device in the given engine.
    pub fn authorize_in_engine(
        &self,
        engine: &mut crate::engine::MerkleToxEngine,
        conversation_id: ConversationId,
        perms: Permissions,
        expires: i64,
    ) {
        let cert = self.make_device_cert(perms, expires);
        engine
            .identity_manager
            .authorize_device(
                conversation_id,
                self.master_pk,
                &cert,
                engine.clock.network_time_ms(),
                0,
            )
            .unwrap();
    }
}

/// A helper to manage a test conversation room with multiple participants.
pub struct TestRoom {
    pub conv_id: ConversationId,
    pub k_conv: [u8; 32],
    pub keys: crate::crypto::ConversationKeys,
    pub identities: Vec<TestIdentity>,
    pub genesis_node: Option<MerkleNode>,
}

impl TestRoom {
    pub fn new(identities_count: usize) -> Self {
        let mut k_conv = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k_conv);
        let keys = crate::crypto::ConversationKeys::derive(&KConv::from(k_conv));
        let mut identities = Vec::new();
        for _ in 0..identities_count {
            identities.push(TestIdentity::new());
        }

        // 1-on-1 Genesis for the first two
        let (conv_id, genesis_node) = if identities_count >= 2 {
            let node = crate::builder::NodeBuilder::new_1on1_genesis(
                identities[0].master_pk,
                identities[1].master_pk,
                &keys,
            );
            (ConversationId::from(node.hash()), Some(node))
        } else {
            let mut id = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
            (ConversationId::from(id), None)
        };

        Self {
            conv_id,
            k_conv,
            keys,
            identities,
            genesis_node,
        }
    }

    /// Sets up all identities in the engine and store.
    pub fn setup_engine(
        &self,
        engine: &mut crate::engine::MerkleToxEngine,
        store: &dyn crate::sync::NodeStore,
    ) {
        store
            .put_conversation_key(&self.conv_id, 0, KConv::from(self.k_conv))
            .unwrap();

        if let Some(genesis) = &self.genesis_node {
            store
                .put_node(&self.conv_id, genesis.clone(), true)
                .unwrap();
            store
                .set_heads(&self.conv_id, vec![genesis.hash()])
                .unwrap();
            store
                .set_admin_heads(&self.conv_id, vec![genesis.hash()])
                .unwrap();
        }

        for id in &self.identities {
            engine
                .identity_manager
                .add_member(self.conv_id, id.master_pk, 1, 0);
            id.authorize_in_engine(engine, self.conv_id, Permissions::ALL, i64::MAX);
        }

        engine.load_conversation_state(self.conv_id, store).unwrap();
    }
}

/// Helper to create a delegation certificate signed by an issuer.
pub fn make_cert(
    issuer: &SigningKey,
    device_pk: PhysicalDevicePk,
    perms: Permissions,
    expires: i64,
) -> DelegationCertificate {
    sign_delegation(issuer, device_pk, perms, expires)
}

/// Signs an administrative node using the provided signing key.
pub fn sign_admin_node(node: &mut MerkleNode, conversation_id: &ConversationId, sk: &SigningKey) {
    node.sender_pk = PhysicalDevicePk::from(sk.verifying_key().to_bytes());
    let sig = sk
        .sign(&node.serialize_for_auth(conversation_id))
        .to_bytes();
    node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));
}

/// Calculates and sets the MAC for a content node using the provided conversation keys.
pub fn sign_content_node(
    node: &mut MerkleNode,
    conversation_id: &ConversationId,
    keys: &crate::crypto::ConversationKeys,
) {
    let auth_data = node.serialize_for_auth(conversation_id);
    let mac = keys.calculate_mac(&auth_data);
    node.authentication = NodeAuth::Mac(mac);
}

/// Helper to create and sign a content node with full control over authorship.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_content_node(
    conversation_id: &ConversationId,
    keys: &crate::crypto::ConversationKeys,
    author_pk: LogicalIdentityPk,
    sender_pk: PhysicalDevicePk,
    parents: Vec<NodeHash>,
    content: Content,
    topological_rank: u64,
    sequence_number: u64,
    network_timestamp: i64,
) -> MerkleNode {
    let mut node = test_node();
    node.author_pk = author_pk;
    node.sender_pk = sender_pk;
    node.parents = parents;
    node.content = content;
    node.topological_rank = topological_rank;
    node.sequence_number = sequence_number;
    node.network_timestamp = network_timestamp;
    sign_content_node(&mut node, conversation_id, keys);
    node
}

/// The most common case: An authorized device sending a text message.
#[allow(clippy::too_many_arguments)]
pub fn create_msg(
    conversation_id: &ConversationId,
    keys: &crate::crypto::ConversationKeys,
    identity: &TestIdentity,
    parents: Vec<NodeHash>,
    text: &str,
    rank: u64,
    seq: u64,
    timestamp: i64,
) -> MerkleNode {
    create_signed_content_node(
        conversation_id,
        keys,
        identity.master_pk,
        identity.device_pk,
        parents,
        Content::Text(text.to_string()),
        rank,
        seq,
        timestamp,
    )
}

/// Helper to create and sign an administrative node.
#[allow(clippy::too_many_arguments)]
pub fn create_admin_node(
    conversation_id: &ConversationId,
    author_pk: LogicalIdentityPk,
    signing_key: &SigningKey,
    parents: Vec<NodeHash>,
    action: ControlAction,
    rank: u64,
    seq: u64,
    timestamp: i64,
) -> MerkleNode {
    let mut node = test_node();
    node.author_pk = author_pk;
    node.parents = parents;
    node.content = Content::Control(action);
    node.topological_rank = rank;
    node.sequence_number = seq;
    node.network_timestamp = timestamp;
    sign_admin_node(&mut node, conversation_id, signing_key);
    node
}

/// Generates a random Ed25519 signing key.
pub fn random_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    SigningKey::from_bytes(&bytes)
}

/// Creates a base test node with default values.
pub fn test_node() -> MerkleNode {
    MerkleNode {
        parents: Vec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text("dummy".to_string()),
        metadata: Vec::new(),
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    }
}

/// Creates a dummy Merkle node with the given parents.
pub fn create_dummy_node(parents: Vec<NodeHash>) -> MerkleNode {
    let mut node = test_node();
    node.parents = parents;
    node.content = Content::Text("dummy".to_string());
    node
}
