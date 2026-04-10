use merkle_tox_core::crypto::{ConversationKeys, PackKeys};
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, HeaderKey, KConv, LogicalIdentityPk, MerkleNode,
    NodeHash, PhysicalDevicePk,
};
use merkle_tox_core::testing::{
    create_admin_node, create_signed_content_node, test_ephemeral_signing_key,
    test_pack_content_keys,
};

#[test]
fn test_wire_node_roundtrip() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);
    let author_pk = LogicalIdentityPk::from([2u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        author_pk,
        sender_pk,
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Secret message".to_string()),
        10,
        1,
        1600000000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let wire = node
        .pack_wire(&PackKeys::Content(ck), false)
        .expect("Failed to pack");

    // Check that sensitive fields are not easily visible in the encrypted payload
    assert!(
        !wire
            .encrypted_routing
            .windows(32)
            .any(|w| w == node.sender_pk.as_bytes())
    );

    // Decrypt using unpack_wire_content with known sender
    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let seq =
        MerkleNode::try_decrypt_routing(&wire, &ck2.k_header).expect("Routing AEAD should succeed");
    let unpacked = MerkleNode::unpack_wire_content(&wire, sender_pk, author_pk, seq, &ck2.k_msg)
        .expect("Failed to unpack");

    assert_eq!(node.author_pk, unpacked.author_pk);
    assert_eq!(node.sender_pk, unpacked.sender_pk);
    assert_eq!(node.sequence_number, unpacked.sequence_number);
    assert_eq!(node.content, unpacked.content);
}

#[test]
fn test_wire_node_compression_roundtrip() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);
    let author_pk = LogicalIdentityPk::from([2u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        author_pk,
        sender_pk,
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Very compressible text. ".repeat(100)),
        10,
        1,
        1600000000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let wire = node
        .pack_wire(&PackKeys::Content(ck), true)
        .expect("Failed to pack");
    assert!(
        wire.flags
            .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
    );

    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let seq = MerkleNode::try_decrypt_routing(&wire, &ck2.k_header).unwrap();
    let unpacked =
        MerkleNode::unpack_wire_content(&wire, sender_pk, author_pk, seq, &ck2.k_msg).unwrap();
    assert_eq!(node.content, unpacked.content);
}

#[test]
fn test_wire_node_compression_padding_uniformity() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Very compressible text. ".repeat(100)),
        10,
        1,
        1600000000,
    );

    // Use exception packing for padding uniformity test (simpler, same padding logic)
    let wire = node
        .pack_wire(&PackKeys::Exception, true)
        .expect("Failed to pack");
    assert!(
        wire.flags
            .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
    );

    // Payload size should be a power of 2, even when compressed.
    let payload_len = wire.payload_data.len();
    assert!(
        payload_len.is_power_of_two(),
        "Compressed payload size {} is not power of two",
        payload_len
    );
}

#[test]
fn test_admin_wire_node_no_encryption() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_admin_node(
        &conv_id,
        LogicalIdentityPk::from([2u8; 32]),
        &sk,
        vec![NodeHash::from([1u8; 32])],
        ControlAction::SetTitle("New Room".to_string()),
        10,
        1,
        1600000000,
    );

    let wire = node
        .pack_wire(&PackKeys::Exception, false)
        .expect("Failed to pack");

    // Admin nodes should have sender_pk visible in clear in the routing (exception = cleartext)
    assert_eq!(&wire.encrypted_routing[0..32], node.sender_pk.as_bytes());

    let unpacked = MerkleNode::unpack_wire_exception(&wire).expect("Failed to unpack");
    assert_eq!(node.content, unpacked.content);
}

#[test]
fn test_wire_malleability() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);
    let author_pk = LogicalIdentityPk::from([2u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        author_pk,
        sender_pk,
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Important message".to_string()),
        10,
        1,
        1600000000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let mut wire = node
        .pack_wire(&PackKeys::Content(ck), false)
        .expect("Failed to pack");

    // Flip a bit in the encrypted routing. With AEAD, this should cause
    // decryption to fail entirely (Poly1305 tag mismatch).
    wire.encrypted_routing[15] ^= 0x01;

    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let result = MerkleNode::try_decrypt_routing(&wire, &ck2.k_header);
    assert!(
        result.is_none(),
        "AEAD routing decryption should fail for tampered wire"
    );
}

#[test]
fn test_nonce_safety_concurrent_parents() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let parent_hash = NodeHash::from([0xEEu8; 32]);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([1u8; 32]);

    // Two nodes with the same parent but different content and sequence numbers
    let node1 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![parent_hash],
        Content::Text("Message A".to_string()),
        10,
        1,
        1000,
    );

    let node2 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![parent_hash],
        Content::Text("Message B".to_string()),
        10,
        2,
        1000,
    );

    let ck1 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 2);
    let wire1 = node1
        .pack_wire(&PackKeys::Content(ck1), false)
        .expect("Failed to pack");
    let wire2 = node2
        .pack_wire(&PackKeys::Content(ck2), false)
        .expect("Failed to pack");

    // Routing nonces should be different (deterministic test nonces differ by seq)
    assert_ne!(
        wire1.encrypted_routing, wire2.encrypted_routing,
        "Encrypted routing should be different for different messages"
    );
}

#[test]
fn test_nonce_uniqueness_identical_content() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([1u8; 32]);

    // Two nodes with identical content but different sequence numbers
    let node1 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Same content".to_string()),
        10,
        1,
        1000,
    );

    let node2 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Same content".to_string()),
        11,
        2,
        1000,
    );

    let ck1 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 2);
    let wire1 = node1.pack_wire(&PackKeys::Content(ck1), false).unwrap();
    let wire2 = node2.pack_wire(&PackKeys::Content(ck2), false).unwrap();

    // Different sequence numbers → different k_msg → different sender_hints
    assert_ne!(wire1.sender_hint, wire2.sender_hint);

    // Different nonces → different encrypted routing
    assert_ne!(wire1.encrypted_routing, wire2.encrypted_routing);
}

#[test]
fn test_pow_sensitivity() {
    use merkle_tox_core::builder::NodeBuilder;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let node = NodeBuilder::new_group_genesis(
        "Secret Group".to_string(),
        LogicalIdentityPk::from([1u8; 32]),
        0,
        1000,
        &sk,
    );
    assert!(node.validate_pow());

    // Change a single character in the title
    if let Content::Control(merkle_tox_core::dag::ControlAction::Genesis {
        mut title,
        creator_pk,
        permissions,
        flags,
        created_at,
        pow_nonce,
    }) = node.content
    {
        title.push('!');
        let corrupted_node = MerkleNode {
            content: Content::Control(merkle_tox_core::dag::ControlAction::Genesis {
                title,
                creator_pk,
                permissions,
                flags,
                created_at,
                pow_nonce,
            }),
            ..node
        };
        assert!(
            !corrupted_node.validate_pow(),
            "PoW should be invalid after title change"
        );
    }
}

#[test]
fn test_wire_node_padding_boundaries() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);
    let author_pk = LogicalIdentityPk::from([2u8; 32]);

    // Test with different payload sizes to hit different power-of-2 boundaries
    // Use exception packing so we can verify padding directly
    for size in [10, 64, 127, 128, 250, 500] {
        let node = create_signed_content_node(
            &conv_id,
            &keys,
            author_pk,
            sender_pk,
            vec![],
            Content::Text("A".repeat(size)),
            0,
            1,
            1000,
        );

        let wire = node
            .pack_wire(&PackKeys::Exception, false)
            .expect("Failed to pack");

        let payload_len = wire.payload_data.len();
        assert!(
            payload_len.is_power_of_two(),
            "Size {} is not power of two",
            payload_len
        );
        assert!(payload_len >= tox_proto::constants::MIN_PADDING_BIN);

        let unpacked = MerkleNode::unpack_wire_exception(&wire).expect("Failed to unpack");
        assert_eq!(node.content, unpacked.content);
    }
}

#[test]
fn test_wire_node_malformed_padding() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Standard message".to_string()),
        0,
        1,
        1000,
    );

    // Use exception packing so we can manipulate padding directly
    let mut wire = node
        .pack_wire(&PackKeys::Exception, false)
        .expect("Failed to pack");

    // Find the 0x80 byte and replace it with 0x00 (cleartext payload for exception)
    let payload = &mut wire.payload_data;
    if let Some(pos) = payload.iter().rposition(|&x| x == 0x80) {
        payload[pos] = 0x00;
    }

    let res = MerkleNode::unpack_wire_exception(&wire);
    assert!(
        matches!(
            res,
            Err(merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::InvalidPadding(_)
            ))
        ),
        "Unpack should fail with InvalidPadding error when 0x80 byte is missing"
    );
}

#[test]
fn test_wire_node_padding_edge_cases() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    // Case 1: Metadata ends with 0x80
    let mut node_80 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Message with special metadata".to_string()),
        0,
        1,
        1000,
    );
    node_80.metadata = tox_proto::BoundedBytes::try_from_vec(vec![0x80]).expect("under cap");
    merkle_tox_core::testing::sign_content_node(&mut node_80, &conv_id, &keys);
    let wire_80 = node_80.pack_wire(&PackKeys::Exception, false).unwrap();
    let unpacked_80 = MerkleNode::unpack_wire_exception(&wire_80).unwrap();
    assert_eq!(node_80.metadata, unpacked_80.metadata);

    // Case 2: Metadata ends with 0x00
    let mut node_00 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Message with zero metadata".to_string()),
        0,
        1,
        1000,
    );
    node_00.metadata = tox_proto::BoundedBytes::try_from_vec(vec![0x00]).expect("under cap");
    merkle_tox_core::testing::sign_content_node(&mut node_00, &conv_id, &keys);
    let wire_00 = node_00.pack_wire(&PackKeys::Exception, false).unwrap();
    let unpacked_00 = MerkleNode::unpack_wire_exception(&wire_00).unwrap();
    assert_eq!(node_00.metadata, unpacked_00.metadata);

    // Case 3: Metadata ends with many 0x00s
    let mut node_many_00 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Message with many zeroes".to_string()),
        0,
        1,
        1000,
    );
    node_many_00.metadata = tox_proto::BoundedBytes::try_from_vec(vec![0u8; 10]).expect("under cap");
    merkle_tox_core::testing::sign_content_node(&mut node_many_00, &conv_id, &keys);
    let wire_many_00 = node_many_00.pack_wire(&PackKeys::Exception, false).unwrap();
    let unpacked_many_00 = MerkleNode::unpack_wire_exception(&wire_many_00).unwrap();
    assert_eq!(node_many_00.metadata, unpacked_many_00.metadata);
}

#[test]
fn test_wire_mac_verification_failure() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Authentic message".to_string()),
        0,
        1,
        1000,
    );

    // Scenario 1: Modify the authenticated data (content) and check signature fails
    let eph_sk = test_ephemeral_signing_key(&keys, &node.sender_pk);
    let eph_vk = eph_sk.verifying_key();
    let mut corrupted_node = node.clone();
    corrupted_node.content = Content::Text("Tampered message".to_string());
    let sig_bytes = match &corrupted_node.authentication {
        merkle_tox_core::dag::NodeAuth::EphemeralSignature(s) => s,
        _ => panic!("Expected EphemeralSignature"),
    };
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_ref());
    assert!(
        ed25519_dalek::Verifier::verify(&eph_vk, &corrupted_node.serialize_for_auth(), &sig)
            .is_err(),
        "Signature verification should fail for tampered content"
    );

    // Scenario 2: Tamper with AEAD-encrypted routing → decryption must fail
    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let mut wire = node
        .pack_wire(&PackKeys::Content(ck), false)
        .expect("Failed to pack");
    wire.encrypted_routing[20] ^= 0x01;

    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    assert!(
        MerkleNode::try_decrypt_routing(&wire, &ck2.k_header).is_none(),
        "AEAD should reject tampered routing"
    );
}

#[test]
fn test_sender_hint_derivation() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    let ck1 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let ck2 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);

    // Same keys → same hint
    let hint1 = merkle_tox_core::crypto::compute_sender_hint(&ck1.k_msg);
    let hint2 = merkle_tox_core::crypto::compute_sender_hint(&ck2.k_msg);
    assert_eq!(hint1, hint2);

    // Different seq → different hint
    let ck3 = test_pack_content_keys(&keys, &conv_id, &sender_pk, 2);
    let hint3 = merkle_tox_core::crypto::compute_sender_hint(&ck3.k_msg);
    assert_ne!(hint1, hint3);
}

#[test]
fn test_routing_aead_rejects_wrong_key() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Test".to_string()),
        0,
        1,
        1000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let wire = node.pack_wire(&PackKeys::Content(ck), false).unwrap();

    // Try decrypting with a wrong key
    let wrong_key = HeaderKey::from([0xFFu8; 32]);
    assert!(
        MerkleNode::try_decrypt_routing(&wire, &wrong_key).is_none(),
        "AEAD should reject wrong key"
    );
}

/// Defense-in-depth: a wire packet encrypted in conversation A must not be
/// decryptable under conversation B's key derivation, even when k_conv, the
/// sender, and the sequence number are identical.
///
/// The threat this guards against is a shared-k_conv compromise: if a bug
/// (or persistence mixup, or KeyWrap misrouting) ever causes two rooms to
/// hold the same k_conv, the wire AEAD should still fail cross-room rather
/// than fail-open. Binding `conversation_id` into the KDF for the header
/// key and the ratchet chain key provides that defense.
#[test]
fn test_routing_aead_binds_conversation_id() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let sender_pk = PhysicalDevicePk::from([3u8; 32]);
    let author_pk = LogicalIdentityPk::from([2u8; 32]);
    let conv_id_a = ConversationId::from([0xAAu8; 32]);
    let conv_id_b = ConversationId::from([0xBBu8; 32]);

    // Alice packs a wire node scoped to conversation A.
    let node = create_signed_content_node(
        &conv_id_a,
        &keys,
        author_pk,
        sender_pk,
        vec![NodeHash::from([1u8; 32])],
        Content::Text("secret for A only".to_string()),
        10,
        1,
        1_600_000_000,
    );
    let ck_a = test_pack_content_keys(&keys, &conv_id_a, &sender_pk, 1);
    let wire = node.pack_wire(&PackKeys::Content(ck_a), false).unwrap();

    // Attacker, knowing the (accidentally) shared k_conv, derives keys as
    // conversation B would and tries to decrypt.
    let ck_b = test_pack_content_keys(&keys, &conv_id_b, &sender_pk, 1);
    let routing = MerkleNode::try_decrypt_routing(&wire, &ck_b.k_header);

    assert!(
        routing.is_none(),
        "wire packet encrypted in conv A must not decrypt with conv B's header key \
         (conv_id must be mixed into derive_k_header_epoch)",
    );
}

#[test]
fn test_exception_node_cleartext() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_admin_node(
        &conv_id,
        LogicalIdentityPk::from([2u8; 32]),
        &sk,
        vec![],
        ControlAction::SetTitle("Room".to_string()),
        0,
        1,
        1000,
    );

    assert!(node.is_exception_node());
    let wire = node.pack_wire(&PackKeys::Exception, false).unwrap();
    assert!(
        !wire
            .flags
            .contains(merkle_tox_core::dag::WireFlags::ENCRYPTED)
    );
    assert_eq!(wire.sender_hint, [0, 0, 0, 0]);

    let unpacked = MerkleNode::unpack_wire_exception(&wire).unwrap();
    assert_eq!(node.content, unpacked.content);
    assert_eq!(node.sender_pk, unpacked.sender_pk);
}

// end of file
