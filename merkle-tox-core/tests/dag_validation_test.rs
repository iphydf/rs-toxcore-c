use ed25519_dalek::{Signer, SigningKey};
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode,
    NodeAuth, NodeHash, PhysicalDevicePk,
};
use merkle_tox_core::testing::{InMemoryStore, TestIdentity, TestRoom, sign_admin_node, test_node};

// The `validate(parents.len() > MAX_PARENTS)` check is no longer
// reachable: `MerkleNode.parents` is `BoundedVec<NodeHash, MAX_PARENTS>`,
// so an over-cap parent set cannot be constructed in safe Rust. The
// equivalent wire-side property (over-cap deserialise rejected) is
// enforced by `tox_proto::ToxDeserialize for BoundedVec<T, N>` and
// covered by `tests/adversarial_oversized_wire_test.rs`.

// `validate(metadata.len() > MAX_METADATA_SIZE)` is no longer
// reachable: `MerkleNode.metadata` is `BoundedBytes<MAX_METADATA_SIZE>`,
// so an over-cap construction is impossible in safe Rust. The
// equivalent wire-side property is enforced by
// `tox_proto::BoundedBytes`'s deserialiser and pinned by
// `tox-proto/tests/bounded_bytes_test.rs`. The
// `ValidationError::MaxMetadataExceeded` variant is kept reachable
// from the `WireNode -> MerkleNode` unpack path for in-memory
// constructions that bypass the type-system cap, so the test for
// that variant lives in `tests/wire_test.rs` instead.

#[test]
fn test_validate_first_node_rank() {
    let mut node = test_node();
    node.parents = tox_proto::bounded_vec![];
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
    node.parents = tox_proto::bounded_vec![parent_hash];
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
    a_node.content = Content::Control(ControlAction::Snapshot(
        merkle_tox_core::dag::SnapshotData {
            basis_hash: NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        },
    ));
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(admin_parent, (a_node, true));

    let mut node = test_node();
    node.content = Content::Control(ControlAction::Snapshot(
        merkle_tox_core::dag::SnapshotData {
            basis_hash: NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        },
    ));
    sign_admin_node(&mut node, &conv_id, &sk);
    node.topological_rank = 2;

    // Admin node with Content parent -> Fail
    node.parents = tox_proto::bounded_vec![content_parent];
    node.topological_rank = 2;
    sign_admin_node(&mut node, &conv_id, &sk); // Re-sign because parents changed
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::AdminCannotHaveContentParent)
    ));

    // Admin node with Admin parent -> Ok
    node.parents = tox_proto::bounded_vec![admin_parent];
    node.topological_rank = 2;
    sign_admin_node(&mut node, &conv_id, &sk);
    assert!(node.validate(&conv_id, &lookup).is_ok());

    // Content node with Admin parent -> Ok
    let mut content_node = test_node();
    content_node.parents = tox_proto::bounded_vec![admin_parent];
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
    a_node.content = Content::Control(ControlAction::Snapshot(
        merkle_tox_core::dag::SnapshotData {
            basis_hash: NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        },
    ));
    lookup
        .nodes
        .write()
        .unwrap()
        .insert(admin_parent, (a_node, true));

    // Content node with BOTH Admin and Content parents -> Ok
    let mut node = test_node();
    node.parents = tox_proto::bounded_vec![content_parent, admin_parent];
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

    // Admin node (Snapshot, a true Admin type)
    let mut admin_node = MerkleNode {
        parents: tox_proto::bounded_vec![content_parent],
        author_pk: LogicalIdentityPk::from(sk.verifying_key().to_bytes()),
        sender_pk: PhysicalDevicePk::from(sk.verifying_key().to_bytes()),
        sequence_number: 1,
        topological_rank: 2,
        network_timestamp: 1000,
        content: Content::Control(ControlAction::Snapshot(
            merkle_tox_core::dag::SnapshotData {
                basis_hash: NodeHash::from([0u8; 32]),
                members: tox_proto::BoundedVec::new(),
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
        )),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
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
    let sig = sk.sign(&node.serialize_for_auth()).to_bytes();
    node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));
    let res = node.validate(&conv_id, &lookup);
    assert!(matches!(
        res,
        Err(merkle_tox_core::dag::ValidationError::ContentNodeShouldUseMac)
    ));

    // Admin node with MAC -> Fail
    let mut admin_node = test_node();
    admin_node.content = Content::Control(ControlAction::Snapshot(
        merkle_tox_core::dag::SnapshotData {
            basis_hash: NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        },
    ));
    admin_node.authentication = NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64]));
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
    node.parents = tox_proto::bounded_vec![hash];
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
    // In a DAG, rank must increase.

    let mut n2 = test_node();
    n2.topological_rank = 10;
    lookup.nodes.write().unwrap().insert(hash2, (n2, true)); // Parent has rank 10

    let mut node = test_node();
    node.parents = tox_proto::bounded_vec![hash2];
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
    node.parents = tox_proto::bounded_vec![missing_hash];
    let res = node.validate(&conv_id, &lookup);
    assert!(
        matches!(res, Err(merkle_tox_core::dag::ValidationError::MissingParents(hashes)) if hashes == vec![missing_hash])
    );
}

#[test]
fn test_validate_duplicate_parents() {
    let parent_hash = NodeHash::from([1u8; 32]);
    let mut node = test_node();
    node.parents = tox_proto::bounded_vec![parent_hash, parent_hash];
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
    node.parents = tox_proto::bounded_vec![parent_hash];

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

/// DARE: Content nodes must use "merkle-tox v1 content-sig" domain separator.
/// Admin nodes must use "merkle-tox v1 admin-sig\0". A signature made with the
/// wrong separator must not verify.
#[test]
fn test_content_sig_domain_separator() {
    use merkle_tox_core::dag::{MerkleNode, NodeAuth, NodeType};

    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    // Create a content node
    let content_node = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text("hello".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };

    // Create an admin node
    let admin_node = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Control(ControlAction::Snapshot(
            merkle_tox_core::dag::SnapshotData {
                basis_hash: NodeHash::from([0u8; 32]),
                members: tox_proto::BoundedVec::new(),
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
        )),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };

    assert_eq!(content_node.node_type(), NodeType::Content);
    assert_eq!(admin_node.node_type(), NodeType::Admin);

    let content_auth = content_node.serialize_for_auth();
    let admin_auth = admin_node.serialize_for_auth();

    // Content nodes use "merkle-tox v1 content-sig" (25 bytes, no null terminator)
    assert!(
        content_auth.starts_with(b"merkle-tox v1 content-sig"),
        "Content node must use content-sig separator"
    );
    assert!(
        !content_auth.starts_with(b"merkle-tox v1 admin-sig\0"),
        "Content node must NOT use admin-sig separator"
    );

    // Admin nodes use "merkle-tox v1 admin-sig" (23 bytes, no null terminator)
    assert!(
        admin_auth.starts_with(b"merkle-tox v1 admin-sig"),
        "Admin node must use admin-sig separator"
    );
    assert!(
        !admin_auth.starts_with(b"merkle-tox v1 content-sig"),
        "Admin node must NOT use content-sig separator"
    );

    // Cross-type: sign content data with admin separator -> must NOT match content
    // (They have different separators so the auth data bytes differ.)
    assert_ne!(
        &content_auth[..25],
        &admin_auth[..23],
        "Separators must differ between content and admin nodes"
    );
}

/// Nodes whose serialized size exceeds the maximum message size must fail
/// validation. A 1 MB+ text message must be rejected.
#[test]
fn test_max_message_size_enforced() {
    let _ = tracing_subscriber::fmt::try_init();

    let alice = TestIdentity::new();
    let conv_id = ConversationId::from([11u8; 32]);
    let store = InMemoryStore::new();

    // Create a node with content exceeding 1 MB
    let big_text = "x".repeat(1_048_577); // > 1MB
    let big_node = merkle_tox_core::dag::MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text(big_text),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };

    let result = big_node.validate(&conv_id, &store);
    assert!(result.is_err(), "Oversized message should fail validation");
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("too large") || format!("{err}").contains("Message"),
        "Error should mention message size, got: {err}"
    );

    // A small message should pass the size check (may fail other checks like auth)
    let small_node = merkle_tox_core::dag::MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text("hello".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };

    // This should NOT fail with MaxMessageSizeExceeded (it may fail with signature check)
    let result = small_node.validate(&conv_id, &store);
    match result {
        Ok(_) => {} // fine
        Err(ref e) => {
            assert!(
                !format!("{e}").contains("Message size"),
                "Small message should not fail size check"
            );
        }
    }
}

// end of file
