use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeHash,
    PhysicalDevicePk,
};
use merkle_tox_core::testing::{create_admin_node, create_signed_content_node};

#[test]
fn test_wire_node_roundtrip() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Secret message".to_string()),
        10,
        1,
        1600000000,
    );

    let wire = node.pack_wire(&keys, false).expect("Failed to pack");

    // Check that sensitive fields are not easily visible in the encrypted payload
    assert!(
        !wire
            .encrypted_payload
            .windows(32)
            .any(|w| w == node.sender_pk.as_bytes())
    );

    let unpacked = MerkleNode::unpack_wire(&wire, &keys, &conv_id).expect("Failed to unpack");

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

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Very compressible text. ".repeat(100)),
        10,
        1,
        1600000000,
    );

    let wire = node.pack_wire(&keys, true).expect("Failed to pack");
    assert!(
        wire.flags
            .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
    );

    let unpacked = MerkleNode::unpack_wire(&wire, &keys, &conv_id).expect("Failed to unpack");
    assert_eq!(node.content, unpacked.content);
}

#[test]
fn test_wire_node_compression_padding_uniformity() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Very compressible text. ".repeat(100)),
        10,
        1,
        1600000000,
    );

    let wire = node.pack_wire(&keys, true).expect("Failed to pack");
    assert!(
        wire.flags
            .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
    );

    // Encrypted payload size should be a power of 2, even when compressed.
    let payload_len = wire.encrypted_payload.len();
    assert!(
        payload_len.is_power_of_two(),
        "Compressed payload size {} is not power of two",
        payload_len
    );
}

#[test]
fn test_admin_wire_node_no_encryption() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
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

    let wire = node.pack_wire(&keys, false).expect("Failed to pack");

    // Admin nodes should have sender_pk visible in clear in the payload (by our pack logic)
    assert_eq!(&wire.encrypted_payload[0..32], node.sender_pk.as_bytes());

    let unpacked = MerkleNode::unpack_wire(&wire, &keys, &conv_id).expect("Failed to unpack");
    assert_eq!(node.content, unpacked.content);
}

#[test]
fn test_wire_malleability() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![NodeHash::from([1u8; 32])],
        Content::Text("Important message".to_string()),
        10,
        1,
        1600000000,
    );

    let mut wire = node.pack_wire(&keys, false).expect("Failed to pack");

    // Flip a bit in the encrypted payload. We pick index 10, which is
    // guaranteed to be within the 'sender_pk' field.
    wire.encrypted_payload[10] ^= 0x01;

    // Unpacking MUST fail because the MAC will not match the corrupted ciphertext.
    let unpacked_res = MerkleNode::unpack_wire(&wire, &keys, &conv_id);
    assert!(
        unpacked_res.is_err(),
        "Unpacking tampered wire should fail due to MAC mismatch"
    );
}

#[test]
fn test_nonce_safety_concurrent_parents() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let parent_hash = NodeHash::from([0xEEu8; 32]);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    // Two nodes with the same parent but different content
    let node1 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        PhysicalDevicePk::from([1u8; 32]),
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
        PhysicalDevicePk::from([1u8; 32]),
        vec![parent_hash],
        Content::Text("Message B".to_string()),
        10,
        2,
        1000,
    );

    let wire1 = node1.pack_wire(&keys, false).expect("Failed to pack");
    let wire2 = node2.pack_wire(&keys, false).expect("Failed to pack");

    // If nonces were derived from parent_hash, they would be identical.
    // We check that the first few bytes of encrypted payload (which contain sender_pk, which is same for both)
    // are different in the wires.
    assert_ne!(
        wire1.encrypted_payload[0..32],
        wire2.encrypted_payload[0..32],
        "Ciphertexts should be different for same prefix if nonces are unique"
    );
}

#[test]
fn test_nonce_uniqueness_identical_content() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    // Two nodes with EVERYTHING identical except they differ in their sequence number.
    // This will result in different MACs, and thus different nonces for WireNode obfuscation.

    let node1 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        PhysicalDevicePk::from([1u8; 32]),
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
        PhysicalDevicePk::from([1u8; 32]),
        vec![],
        Content::Text("Same content".to_string()),
        11, // Different sequence number -> different MAC
        2,
        1000,
    );

    let wire1 = node1.pack_wire(&keys, false).unwrap();
    let wire2 = node2.pack_wire(&keys, false).unwrap();

    assert_ne!(wire1.authentication.mac(), wire2.authentication.mac());

    // Nonces are derived from MACs.
    // We check that the first 12 bytes of encrypted payload (containing sender_pk) are different.
    assert_ne!(
        wire1.encrypted_payload[0..12],
        wire2.encrypted_payload[0..12]
    );
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

    // Test with different payload sizes to hit different power-of-2 boundaries
    for size in [10, 64, 127, 128, 250, 500] {
        let node = create_signed_content_node(
            &conv_id,
            &keys,
            LogicalIdentityPk::from([2u8; 32]),
            PhysicalDevicePk::from([3u8; 32]),
            vec![],
            Content::Text("A".repeat(size)),
            0,
            1,
            1000,
        );

        let wire = node.pack_wire(&keys, false).expect("Failed to pack");

        // Encrypted payload size (before compression) should be a power of 2
        // Note: our current pack_wire applies padding THEN encrypts.
        // So the ciphertext size is the padded size.
        let payload_len = wire.encrypted_payload.len();
        assert!(
            payload_len.is_power_of_two(),
            "Size {} is not power of two",
            payload_len
        );
        assert!(payload_len >= tox_proto::constants::MIN_PADDING_BIN);

        let unpacked = MerkleNode::unpack_wire(&wire, &keys, &conv_id).expect("Failed to unpack");
        assert_eq!(node.content, unpacked.content);
    }
}

#[test]
fn test_wire_node_malformed_padding() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![],
        Content::Text("Standard message".to_string()),
        0,
        1,
        1000,
    );

    let mut wire = node.pack_wire(&keys, false).expect("Failed to pack");

    // Decrypt, mess up the padding, re-encrypt
    let mac = wire.authentication.mac().unwrap();

    let mut payload = wire.encrypted_payload.clone();
    keys.decrypt_payload_with_mac(mac, &mut payload);

    // Find the 0x80 byte and replace it with 0x00
    if let Some(pos) = payload.iter().rposition(|&x| x == 0x80) {
        payload[pos] = 0x00;
    }

    keys.encrypt_payload_with_mac(mac, &mut payload);
    wire.encrypted_payload = payload;

    let res = MerkleNode::unpack_wire(&wire, &keys, &conv_id);
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

    // Case 1: Metadata ends with 0x80
    let mut node_80 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![],
        Content::Text("Message with special metadata".to_string()),
        0,
        1,
        1000,
    );
    node_80.metadata = vec![0x80];
    merkle_tox_core::testing::sign_content_node(&mut node_80, &conv_id, &keys);
    let wire_80 = node_80.pack_wire(&keys, false).unwrap();
    let unpacked_80 = MerkleNode::unpack_wire(&wire_80, &keys, &conv_id).unwrap();
    assert_eq!(node_80.metadata, unpacked_80.metadata);

    // Case 2: Metadata ends with 0x00
    let mut node_00 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![],
        Content::Text("Message with zero metadata".to_string()),
        0,
        1,
        1000,
    );
    node_00.metadata = vec![0x00];
    merkle_tox_core::testing::sign_content_node(&mut node_00, &conv_id, &keys);
    let wire_00 = node_00.pack_wire(&keys, false).unwrap();
    let unpacked_00 = MerkleNode::unpack_wire(&wire_00, &keys, &conv_id).unwrap();
    assert_eq!(node_00.metadata, unpacked_00.metadata);

    // Case 3: Metadata ends with many 0x00s
    let mut node_many_00 = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![],
        Content::Text("Message with many zeroes".to_string()),
        0,
        1,
        1000,
    );
    node_many_00.metadata = vec![0u8; 10];
    merkle_tox_core::testing::sign_content_node(&mut node_many_00, &conv_id, &keys);
    let wire_many_00 = node_many_00.pack_wire(&keys, false).unwrap();
    let unpacked_many_00 = MerkleNode::unpack_wire(&wire_many_00, &keys, &conv_id).unwrap();
    assert_eq!(node_many_00.metadata, unpacked_many_00.metadata);
}

#[test]
fn test_wire_mac_verification_failure() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        vec![],
        Content::Text("Authentic message".to_string()),
        0,
        1,
        1000,
    );

    let wire = node.pack_wire(&keys, false).expect("Failed to pack");

    // Scenario 1: Modify the authenticated data (content)
    let mut corrupted_node = node.clone();
    corrupted_node.content = Content::Text("Tampered message".to_string());
    assert!(
        !keys.verify_mac(
            &corrupted_node.serialize_for_auth(&conv_id),
            corrupted_node.authentication.mac().unwrap()
        ),
        "MAC verification should fail for tampered content"
    );

    // Scenario 2: Unpack a modified wire and check MAC
    let mut corrupted_wire = wire.clone();
    // Flip a bit in the encrypted payload
    corrupted_wire.encrypted_payload[50] ^= 0x01;

    // Unpacking the corrupted wire will result in a garbage node
    if let Ok(unpacked) = MerkleNode::unpack_wire(&corrupted_wire, &keys, &conv_id) {
        assert!(
            !keys.verify_mac(
                &unpacked.serialize_for_auth(&conv_id),
                unpacked.authentication.mac().unwrap()
            ),
            "MAC verification should fail for node unpacked from corrupted ciphertext"
        );
    }
}

// end of file
