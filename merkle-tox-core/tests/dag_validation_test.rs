use ed25519_dalek::{Signer, SigningKey};
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, EphemeralX25519Pk, LogicalIdentityPk,
    MAX_METADATA_SIZE, MAX_PARENTS, MerkleNode, NodeAuth, NodeHash, NodeMac, PhysicalDevicePk,
    SignedPreKey,
};
use merkle_tox_core::testing::{InMemoryStore, sign_admin_node, test_node};

#[test]
fn test_validate_max_parents() {
    let mut node = test_node();
    node.parents = vec![NodeHash::from([0u8; 32]); MAX_PARENTS + 1];
    node.topological_rank = 1; // Needs to be > 0 if it has parents, but it will fail earlier anyway
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::MaxParentsExceeded { .. })
    ));
}

#[test]
fn test_validate_max_metadata() {
    let mut node = test_node();
    node.metadata = vec![0u8; MAX_METADATA_SIZE + 1];
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::MaxMetadataExceeded { .. })
    ));
}

#[test]
fn test_validate_first_node_rank() {
    let mut node = test_node();
    node.parents = vec![];
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Correct: First node has rank 0
    node.topological_rank = 0;
    assert!(node.validate(&conv_id, &lookup).is_ok());

    // Incorrect: First node has rank 1
    node.topological_rank = 1;
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: 1,
                expected: 0
            }
        )
    ));
}

#[test]
fn test_validate_rank_violation() {
    let parent_hash = NodeHash::from([1u8; 32]);
    let mut node = test_node();
    node.parents = vec![parent_hash];
    node.topological_rank = 10;
    let conv_id = ConversationId::from([0xAAu8; 32]);

    let lookup = InMemoryStore::new();
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(parent_hash, (test_node(), true));
    // We need to set the rank of the parent in the store
    if let Some((n, _)) = lookup.nodes.write().unwrap().get_mut(&parent_hash) {
        n.topological_rank = 10;
    }
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: 10,
                expected: 11
            }
        )
    ));

    if let Some((n, _)) = lookup.nodes.write().unwrap().get_mut(&parent_hash) {
        n.topological_rank = 11;
    }
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: 10,
                expected: 12
            }
        )
    ));

    if let Some((n, _)) = lookup.nodes.write().unwrap().get_mut(&parent_hash) {
        n.topological_rank = 9;
    }
    assert!(node.validate(&conv_id, &lookup).is_ok());
}

#[test]
fn test_validate_admin_isolation() {
    let content_parent = NodeHash::from([1u8; 32]);
    let admin_parent = NodeHash::from([2u8; 32]);
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let conv_id = ConversationId::from([0xAAu8; 32]);

    let lookup = InMemoryStore::new();
    let mut c_node = test_node();
    c_node.topological_rank = 1;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(content_parent, (c_node, true));

    let mut a_node = test_node();
    a_node.topological_rank = 1;
    a_node.content = Content::Control(ControlAction::SetTitle("Parent Admin".to_string()));
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(admin_parent, (a_node, true));

    let mut node = test_node();
    node.content = Content::Control(ControlAction::SetTitle("Admin".to_string()));
    sign_admin_node(&mut node, &conv_id, &sk);
    node.topological_rank = 2;

    // Admin node with Content parent -> Fail
    node.parents = vec![content_parent];
    node.topological_rank = 2;
    sign_admin_node(&mut node, &conv_id, &sk); // Re-sign because parents changed
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::AdminCannotHaveContentParent)
    ));

    // Admin node with Admin parent -> Ok
    node.parents = vec![admin_parent];
    node.topological_rank = 2;
    sign_admin_node(&mut node, &conv_id, &sk);
    assert!(node.validate(&conv_id, &lookup).is_ok());

    // Content node with Admin parent -> Ok
    let mut content_node = test_node();
    content_node.parents = vec![admin_parent];
    content_node.topological_rank = 2;
    assert!(content_node.validate(&conv_id, &lookup).is_ok());
}

#[test]
fn test_validate_mixed_parents() {
    let content_parent = NodeHash::from([1u8; 32]);
    let admin_parent = NodeHash::from([2u8; 32]);
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    let mut c_node = test_node();
    c_node.topological_rank = 1;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(content_parent, (c_node, true));

    let mut a_node = test_node();
    a_node.topological_rank = 1;
    a_node.content = Content::Control(ControlAction::SetTitle("Parent Admin".to_string()));
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(admin_parent, (a_node, true));

    // Content node with BOTH Admin and Content parents -> Ok
    let mut node = test_node();
    node.parents = vec![content_parent, admin_parent];
    node.topological_rank = 2;
    assert!(node.validate(&conv_id, &lookup).is_ok());
}

#[test]
fn test_validate_content_parent_to_admin_v1_rule() {
    let content_parent = NodeHash::from([1u8; 32]);
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    let mut c_node = test_node();
    c_node.topological_rank = 1;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(content_parent, (c_node, true));

    // Admin node (Announcement)
    let mut admin_node = MerkleNode {
        parents: vec![content_parent],
        author_pk: LogicalIdentityPk::from(sk.verifying_key().to_bytes()),
        sender_pk: PhysicalDevicePk::from(sk.verifying_key().to_bytes()),
        sequence_number: 1,
        topological_rank: 2,
        network_timestamp: 1000,
        content: Content::Control(ControlAction::Announcement {
            pre_keys: vec![],
            last_resort_key: SignedPreKey {
                public_key: EphemeralX25519Pk::from([0u8; 32]),
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: 0,
            },
        }),
        metadata: vec![],
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
    };

    sign_admin_node(&mut admin_node, &conv_id, &sk);

    // Should FAIL because an Admin node cannot have a Content parent
    let res = admin_node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::AdminCannotHaveContentParent)
    ));
}

#[test]
fn test_validate_auth_mismatch() {
    let lookup = InMemoryStore::new();
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Content node with Signature -> Fail
    let mut node = test_node();
    node.sender_pk = PhysicalDevicePk::from(sk.verifying_key().to_bytes());
    let sig = sk.sign(&node.serialize_for_auth(&conv_id)).to_bytes();
    node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::ContentNodeShouldUseMac)
    ));

    // Admin node with MAC -> Fail
    let mut admin_node = test_node();
    admin_node.content = Content::Control(ControlAction::SetTitle("Admin".to_string()));
    admin_node.authentication = NodeAuth::Mac(NodeMac::from([0u8; 32]));
    let res = admin_node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::AdminNodeShouldUseSignature)
    ));
}

#[test]
fn test_validate_cycle_detection() {
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Node references itself as parent.
    let mut node = test_node();
    let hash = node.hash();
    node.parents = vec![hash];
    node.topological_rank = 1;

    // We simulate that the node is already known to the store.
    let mut n_in_store = test_node();
    n_in_store.topological_rank = 1;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(hash, (n_in_store, true));

    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: 1,
                expected: 2
            }
        )
    ));
}

#[test]
fn test_validate_indirect_cycle() {
    let hash2 = NodeHash::from([2u8; 32]);
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Node1(rank 10) -> Node2(rank 9) -> Node1(rank 10) ... wait.
    // The validator checks topological_rank > parent_rank.
    // In a DAG, rank must strictly increase.

    let mut n2 = test_node();
    n2.topological_rank = 10;
    lookup.nodes.write().unwrap().insert(hash2, (n2, true)); // Parent has rank 10

    let mut node = test_node();
    node.parents = vec![hash2];
    node.topological_rank = 10; // Rank NOT greater than parent

    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: 10,
                expected: 11
            }
        )
    ));
}

#[test]
fn test_validate_missing_parent() {
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let mut node = test_node();
    let missing_hash = NodeHash::from([0xEEu8; 32]);
    node.parents = vec![missing_hash];
    let res = node.validate(&conv_id, &lookup);
    assert!(
        matches!(res, Err(merkle_tox_core::dag::ValidationError::MissingParents(hashes)) if hashes == vec![missing_hash])
    );
}

#[test]
fn test_validate_duplicate_parents() {
    let parent_hash = NodeHash::from([1u8; 32]);
    let mut node = test_node();
    node.parents = vec![parent_hash, parent_hash];
    node.topological_rank = 1;

    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let mut p_node = test_node();
    p_node.topological_rank = 0;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(parent_hash, (p_node, true));

    let res = node.validate(&conv_id, &lookup);
    assert!(
        matches!(res, Err(merkle_tox_core::dag::ValidationError::DuplicateParent(h)) if h == parent_hash)
    );
}

#[test]
fn test_validate_extreme_rank_difference() {
    let parent_hash = NodeHash::from([1u8; 32]);
    let mut node = test_node();
    node.parents = vec![parent_hash];

    // Parent has rank 1
    let lookup = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let mut p_node = test_node();
    p_node.topological_rank = 1;
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(parent_hash, (p_node, true));

    // Child attempts to claim rank u64::MAX
    node.topological_rank = u64::MAX;

    let res = node.validate(&conv_id, &lookup);
    // Protocol Rule: rank MUST be max(parent_ranks) + 1.
    // If enforcement is correct, this should fail.
    assert!(matches!(
        res,
        Err(
            merkle_tox_core::dag::ValidationError::TopologicalRankViolation {
                actual: u64::MAX,
                expected: 2
            }
        )
    ));
}

// end of file
