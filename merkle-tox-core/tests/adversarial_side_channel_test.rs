use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, LogicalIdentityPk, MerkleNode, PhysicalDevicePk,
};
use merkle_tox_core::testing::create_signed_content_node;

#[test]
fn test_metadata_padding_uniformity() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    // Scenario: Small message vs Larger message
    let node_small = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        PhysicalDevicePk::from([1u8; 32]),
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
        PhysicalDevicePk::from([1u8; 32]),
        vec![],
        Content::Text(
            "This is a much longer message that still fits in the same padding bin".to_string(),
        ),
        1,
        2,
        1001,
    );

    let wire_small = node_small.pack_wire(&keys, false).unwrap();
    let wire_larger = node_larger.pack_wire(&keys, false).unwrap();

    // Verify both are padded to the same bin (e.g. 128 bytes)
    // The encrypted_payload contains [sender_pk(32), seq(8), content, metadata, padding]
    assert_eq!(
        wire_small.encrypted_payload.len(),
        wire_larger.encrypted_payload.len()
    );
    assert_eq!(
        wire_small.encrypted_payload.len(),
        tox_proto::constants::MIN_PADDING_BIN
    );
}

#[test]
fn test_padding_malleability_attack() {
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);
    let conv_id = ConversationId::from([0xEEu8; 32]);

    let node = create_signed_content_node(
        &conv_id,
        &keys,
        LogicalIdentityPk::from([1u8; 32]),
        PhysicalDevicePk::from([1u8; 32]),
        vec![],
        Content::Text("Authentic".to_string()),
        0,
        1,
        1000,
    );

    let mut wire = node.pack_wire(&keys, false).unwrap();

    // 1. Corrupt the padding byte (0x80)
    // We need to decrypt first because padding is INSIDE the encryption.
    let mac = wire.authentication.mac().unwrap();

    let mut payload = wire.encrypted_payload.clone();
    keys.decrypt_payload_with_mac(mac, &mut payload);

    // Find the 0x80 byte and change it
    if let Some(pos) = payload.iter().rposition(|&x| x == 0x80) {
        payload[pos] = 0x81;
    }

    keys.encrypt_payload_with_mac(mac, &mut payload);
    wire.encrypted_payload = payload;

    // Unpacking MUST fail
    let res = MerkleNode::unpack_wire(&wire, &keys, &conv_id);
    assert!(
        matches!(
            res,
            Err(merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::InvalidPadding(_)
            ))
        ),
        "Unpacking with corrupted padding byte should fail with InvalidPadding"
    );

    // 2. Corrupt the trailing zeroes
    let mut wire2 = node.pack_wire(&keys, false).unwrap();
    let mut payload2 = wire2.encrypted_payload.clone();
    keys.decrypt_payload_with_mac(mac, &mut payload2);

    // Change the very last byte from 0x00 to 0x01
    let last = payload2.len() - 1;
    payload2[last] = 0x01;

    keys.encrypt_payload_with_mac(mac, &mut payload2);
    wire2.encrypted_payload = payload2;

    let res2 = MerkleNode::unpack_wire(&wire2, &keys, &conv_id);
    assert!(
        matches!(
            res2,
            Err(merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::InvalidPadding(_)
            ))
        ),
        "Unpacking with corrupted trailing zeroes should fail with InvalidPadding"
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

    let wire_node = node.pack_wire(&keys, false).unwrap();

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
