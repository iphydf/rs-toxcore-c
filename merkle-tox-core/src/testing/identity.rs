use crate::dag::{
    Content, ControlAction, ConversationId, DelegationCertificate, Ed25519Signature, KConv,
    LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, Permissions, PhysicalDevicePk,
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
    /// Uses a zero conversation_id (suitable for tests that don't check scoping).
    pub fn make_device_cert(&self, perms: Permissions, expires: i64) -> DelegationCertificate {
        make_cert(&self.master_sk, self.device_pk, perms, expires)
    }

    /// Creates an authorization certificate scoped to a specific conversation.
    pub fn make_device_cert_for(
        &self,
        perms: Permissions,
        expires: i64,
        conversation_id: ConversationId,
    ) -> DelegationCertificate {
        make_cert_for(
            &self.master_sk,
            self.device_pk,
            perms,
            expires,
            conversation_id,
        )
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
        let ctx = crate::identity::CausalContext {
            evaluating_node_hash: crate::dag::NodeHash::from([0u8; 32]),
            admin_ancestor_hashes: std::collections::HashSet::new(),
        };
        engine
            .identity_manager
            .authorize_device(
                &ctx,
                conversation_id,
                self.master_pk,
                &cert,
                engine.clock.network_time_ms(),
                0,
                crate::dag::NodeHash::from([0u8; 32]),
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

            let cert = id.make_device_cert(Permissions::ALL, i64::MAX);
            let auth_node = crate::testing::create_admin_node(
                &self.conv_id,
                id.master_pk,
                &id.master_sk,
                if let Some(genesis) = &self.genesis_node {
                    vec![genesis.hash()]
                } else {
                    vec![]
                },
                crate::dag::ControlAction::AuthorizeDevice { cert },
                1,
                1,
                0,
            );

            let effects = engine
                .handle_node(self.conv_id, auth_node, store, None)
                .unwrap();
            crate::testing::apply_effects(effects, store);
        }

        engine.load_conversation_state(self.conv_id, store).unwrap();

        // Register deterministic test ephemeral signing keys for all identities
        // so the engine can verify content nodes created by test helpers.
        for id in &self.identities {
            register_test_ephemeral_key(engine, &self.keys, &id.device_pk);
        }
    }
}

/// Helper to create a delegation certificate signed by an issuer.
/// Uses a zero conversation_id (suitable for tests that don't check scoping).
pub fn make_cert(
    issuer: &SigningKey,
    device_pk: PhysicalDevicePk,
    perms: Permissions,
    expires: i64,
) -> DelegationCertificate {
    sign_delegation(
        issuer,
        device_pk,
        perms,
        expires,
        ConversationId::from([0u8; 32]),
    )
}

/// Helper to create a delegation certificate scoped to a specific conversation.
pub fn make_cert_for(
    issuer: &SigningKey,
    device_pk: PhysicalDevicePk,
    perms: Permissions,
    expires: i64,
    conversation_id: ConversationId,
) -> DelegationCertificate {
    sign_delegation(issuer, device_pk, perms, expires, conversation_id)
}

/// Signs an administrative node using the provided signing key.
pub fn sign_admin_node(node: &mut MerkleNode, _conversation_id: &ConversationId, sk: &SigningKey) {
    node.sender_pk = PhysicalDevicePk::from(sk.verifying_key().to_bytes());
    let sig = sk.sign(&node.serialize_for_auth()).to_bytes();
    node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));
}

/// Signs a content node with an ephemeral Ed25519 key.
///
/// In production, each epoch has its own ephemeral signing key distributed via
/// SenderKeyDistribution. In tests, callers provide a signing key (or use
/// `sign_content_node_random` which generates one).
pub fn sign_content_node_with_key(
    node: &mut MerkleNode,
    _conversation_id: &ConversationId,
    eph_sk: &SigningKey,
) {
    let auth_data = node.serialize_for_auth();
    let sig = eph_sk.sign(&auth_data).to_bytes();
    node.authentication = NodeAuth::EphemeralSignature(Ed25519Signature::from(sig));
}

/// Signs a content node with a deterministic ephemeral key derived from the
/// conversation keys and sender. Useful for tests that don't need to control
/// the ephemeral key directly.
pub fn sign_content_node(
    node: &mut MerkleNode,
    conversation_id: &ConversationId,
    keys: &crate::crypto::ConversationKeys,
) {
    // Derive a deterministic ephemeral key from k_conv + sender_pk so that
    // the verifying key can be reconstructed by the test.
    let seed = blake3::derive_key(
        "merkle-tox v1 test-ephemeral",
        &[
            keys.k_conv.as_bytes().as_slice(),
            node.sender_pk.as_bytes().as_slice(),
        ]
        .concat(),
    );
    let eph_sk = SigningKey::from_bytes(&seed);
    sign_content_node_with_key(node, conversation_id, &eph_sk);
}

/// Returns the deterministic ephemeral signing key for a given sender in test contexts.
/// Matches the key used by `sign_content_node`.
pub fn test_ephemeral_signing_key(
    keys: &crate::crypto::ConversationKeys,
    sender_pk: &PhysicalDevicePk,
) -> SigningKey {
    let seed = blake3::derive_key(
        "merkle-tox v1 test-ephemeral",
        &[
            keys.k_conv.as_bytes().as_slice(),
            sender_pk.as_bytes().as_slice(),
        ]
        .concat(),
    );
    SigningKey::from_bytes(&seed)
}

/// Registers the deterministic test ephemeral signing key for a sender on the engine.
/// This must be called on the *receiving* engine so it can verify content nodes
/// created by `create_msg()` / `create_signed_content_node()` / `sign_content_node()`.
pub fn register_test_ephemeral_key(
    engine: &mut crate::engine::MerkleToxEngine,
    keys: &crate::crypto::ConversationKeys,
    sender_pk: &PhysicalDevicePk,
) {
    let eph_sk = test_ephemeral_signing_key(keys, sender_pk);
    let eph_vk = crate::dag::EphemeralSigningPk::from(eph_sk.verifying_key().to_bytes());
    engine
        .peer_ephemeral_signing_keys
        .insert((*sender_pk, 0), eph_vk);
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

/// Creates PackKeys::Content for a test content node.
/// Derives k_msg from the ratchet init for the sender, using the sequence counter.
/// Uses deterministic nonces derived from node data for reproducibility.
pub fn test_pack_content_keys(
    keys: &crate::crypto::ConversationKeys,
    sender_pk: &PhysicalDevicePk,
    sequence_number: u64,
) -> crate::crypto::PackContentKeys {
    let chain_key = crate::crypto::ratchet_init_sender(&keys.k_conv, sender_pk);
    let sender_key = crate::dag::SenderKey::from(*chain_key.as_bytes());
    let counter = sequence_number & 0xFFFFFFFF;

    // Step the ratchet forward to the right position
    let mut ck = chain_key;
    for _ in 1..counter {
        ck = crate::crypto::ratchet_step(&ck);
    }

    let k_msg = crate::crypto::ratchet_message_key(&ck);
    let _k_next = crate::crypto::ratchet_step(&ck);
    let k_header = crate::crypto::derive_k_header_epoch(&keys.k_conv, &sender_key);

    // Deterministic nonces for test reproducibility
    let routing_nonce_full = blake3::derive_key(
        "merkle-tox v1 test-routing-nonce",
        &[
            keys.k_conv.as_bytes().as_slice(),
            sender_pk.as_bytes().as_slice(),
            &sequence_number.to_be_bytes(),
        ]
        .concat(),
    );
    let payload_nonce_full = blake3::derive_key(
        "merkle-tox v1 test-payload-nonce",
        &[
            keys.k_conv.as_bytes().as_slice(),
            sender_pk.as_bytes().as_slice(),
            &sequence_number.to_be_bytes(),
        ]
        .concat(),
    );

    let mut routing_nonce = [0u8; 12];
    routing_nonce.copy_from_slice(&routing_nonce_full[..12]);
    let mut payload_nonce = [0u8; 12];
    payload_nonce.copy_from_slice(&payload_nonce_full[..12]);

    crate::crypto::PackContentKeys {
        k_msg,
        k_header,
        routing_nonce,
        payload_nonce,
    }
}

/// Transfers ephemeral signing keys from one engine to another.
/// Copies all of `from_engine`'s self-ephemeral signing keys into `to_engine`'s
/// peer_ephemeral_signing_keys, keyed by `from_engine.self_pk`.
/// Used in tests where `author_node()` generates random ephemeral keys and the
/// receiving engine needs to verify the signatures without going through SKD.
pub fn transfer_ephemeral_keys(
    from_engine: &crate::engine::MerkleToxEngine,
    to_engine: &mut crate::engine::MerkleToxEngine,
) {
    for (epoch, sk) in &from_engine.self_ephemeral_signing_keys {
        let vk = crate::dag::EphemeralSigningPk::from(sk.verifying_key().to_bytes());
        to_engine
            .peer_ephemeral_signing_keys
            .insert((from_engine.self_pk, *epoch), vk);
    }
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
        authentication: NodeAuth::EphemeralSignature(crate::dag::Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    }
}

/// Creates a dummy Merkle node with the given parents.
pub fn create_dummy_node(parents: Vec<NodeHash>) -> MerkleNode {
    let mut node = test_node();
    node.parents = parents;
    node.content = Content::Text("dummy".to_string());
    node
}
