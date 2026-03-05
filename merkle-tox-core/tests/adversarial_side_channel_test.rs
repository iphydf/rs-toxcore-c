use merkle_tox_core::crypto::{ConversationKeys, PackKeys};
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, LogicalIdentityPk, MerkleNode, PhysicalDevicePk,
};
use merkle_tox_core::testing::{create_signed_content_node, test_pack_content_keys};

#[test]
fn test_metadata_padding_uniformity() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([1u8; 32]);

    // Scenario: Small message vs Larger message
    let node_small = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Hi".to_string()),
        0,
        1,
        1000,
    );

    let node_larger = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![],
        Content::Text(
            "This is a much longer message that still fits in the same padding bin".to_string(),
        ),
        1,
        2,
        1001,
    );

    let ck_small = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let ck_larger = test_pack_content_keys(&keys, &conv_id, &sender_pk, 2);

    let wire_small = node_small
        .pack_wire(&PackKeys::Content(ck_small), false)
        .unwrap();
    let wire_larger = node_larger
        .pack_wire(&PackKeys::Content(ck_larger), false)
        .unwrap();

    // Verify both are padded to the same bin.
    // payload_data contains [nonce(12) || encrypted(padded_payload)]
    // The padded_payload part should be the same size for both.
    assert_eq!(
        wire_small.payload_data.len(),
        wire_larger.payload_data.len()
    );
    // 12 bytes nonce + MIN_PADDING_BIN bytes encrypted payload
    assert_eq!(
        wire_small.payload_data.len(),
        12 + tox_proto::constants::MIN_PADDING_BIN
    );
}

#[test]
fn test_padding_malleability_attack() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);
    let sender_pk = PhysicalDevicePk::from([1u8; 32]);
    let author_pk = LogicalIdentityPk::from([1u8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        author_pk,
        sender_pk,
        vec![],
        Content::Text("Authentic".to_string()),
        0,
        1,
        1000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let k_msg = ck.k_msg.clone();
    let mut wire = node.pack_wire(&PackKeys::Content(ck), false).unwrap();

    // The payload is: nonce(12) || ChaCha20(K_enc, nonce, padded_payload)
    // ChaCha20 is a stream cipher, so bit-flipping works (no tag on payload).
    // We'll flip a byte in the encrypted payload to corrupt the padding.
    // After decryption, the padding will be invalid → unpack should fail.

    // 1. Corrupt a byte near the end of the payload (padding area)
    let last = wire.payload_data.len() - 1;
    wire.payload_data[last] ^= 0xFF;

    // Note: Since we corrupted the payload, the AEAD routing tag will no longer
    // match (payload_hash changed), so try_decrypt_routing will fail first.
    // Test that unpack_wire_content with the right keys but corrupted payload fails.
    let res = MerkleNode::unpack_wire_content(&wire, sender_pk, author_pk, 1, &k_msg);
    assert!(
        matches!(
            res,
            Err(merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::InvalidPadding(_)
            ))
        ),
        "Unpacking with corrupted padding byte should fail with InvalidPadding, got: {:?}",
        res
    );

    // 2. Test that routing AEAD also rejects the tampered payload
    let sender_key = merkle_tox_core::dag::SenderKey::from(
        *merkle_tox_core::crypto::ratchet_init_sender(&keys.k_conv, &conv_id, &sender_pk)
            .as_bytes(),
    );
    let k_header =
        merkle_tox_core::crypto::derive_k_header_epoch(&keys.k_conv, &conv_id, &sender_key);
    let routing_result = MerkleNode::try_decrypt_routing(&wire, &k_header);
    assert!(
        routing_result.is_none(),
        "AEAD routing should reject tampered payload (AAD mismatch)"
    );
}

#[test]
fn test_sender_pk_metadata_privacy() {
    use merkle_tox_core::ProtocolMessage;

    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let sender_pk = PhysicalDevicePk::from([0xAAu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        sender_pk,
        vec![],
        Content::Text("Metadata privacy test".to_string()),
        0,
        1,
        1000,
    );

    let ck = test_pack_content_keys(&keys, &conv_id, &sender_pk, 1);
    let wire_node = node.pack_wire(&PackKeys::Content(ck), false).unwrap();

    let proto_msg = ProtocolMessage::MerkleNode {
        conversation_id: conv_id,
        hash: node.hash(),
        node: wire_node,
    };

    let serialized = tox_proto::serialize(&proto_msg).unwrap();

    // Check if sender_pk is present in the serialized bytes in the clear.
    // If it's present, it means metadata privacy is broken at the transport layer.
    let leaked = serialized.windows(32).any(|w| w == sender_pk.as_bytes());

    assert!(
        !leaked,
        "VULNERABILITY: sender_pk leaked in cleartext in ProtocolMessage::MerkleNode!"
    );
}
