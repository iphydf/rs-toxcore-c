use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, LogicalIdentityPk, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::{
    Conversation, ConversationData, MerkleToxEngine, VerificationStatus, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, apply_effects, create_signed_content_node};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_quarantine_future_node() {
    let self_pk = LogicalIdentityPk::from([1u8; 32]);
    let self_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let self_sk = PhysicalDeviceSk::from([10u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::with_sk(
        self_device_pk,
        self_pk,
        self_sk,
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

    // Initialize conversation keys
    store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            0,
        )),
    );

    let now_ms = engine.clock.network_time_ms();

    // Create a node 25 minutes in the future
    let future_node = create_signed_content_node(
        &conv_id,
        &ConversationKeys::derive(&k_conv),
        self_pk,
        self_device_pk,
        vec![],
        Content::Text("Future".to_string()),
        0,
        1,
        now_ms + 25 * 60 * 1000,
    );

    let effects = engine
        .handle_node(conv_id, future_node.clone(), &store, None)
        .unwrap();
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    apply_effects(effects, &store);
    assert_eq!(
        status,
        VerificationStatus::Speculative,
        "Future node should be quarantined (speculative)"
    );

    // Advance clock by 10 minutes (not enough, threshold is 10 mins)
    engine
        .clock
        .update_peer_offset(PhysicalDevicePk::from([2u8; 32]), 10 * 60 * 1000);
    let reverified = engine.reverify_speculative_for_conversation(conv_id, &store);
    assert!(
        !merkle_tox_core::testing::has_verified_in_effects(&reverified),
        "Node should still be quarantined"
    );

    // Advance clock by another 15 minutes (total 25 mins, enough)
    engine
        .clock
        .update_peer_offset(PhysicalDevicePk::from([2u8; 32]), 25 * 60 * 1000);
    let reverified = engine.reverify_speculative_for_conversation(conv_id, &store);
    assert!(
        merkle_tox_core::testing::has_verified_in_effects(&reverified),
        "Future node should be released from quarantine"
    );
}

#[test]
fn test_quarantine_earlier_than_parent() {
    let self_pk = LogicalIdentityPk::from([1u8; 32]);
    let self_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let self_sk = PhysicalDeviceSk::from([10u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::with_sk(
        self_device_pk,
        self_pk,
        self_sk,
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

    store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            0,
        )),
    );
    let keys = ConversationKeys::derive(&k_conv);

    let parent = create_signed_content_node(
        &conv_id,
        &keys,
        self_pk,
        self_device_pk,
        vec![],
        Content::Text("Parent".to_string()),
        0,
        1,
        10000,
    );
    let parent_hash = parent.hash();
    let effects = engine
        .handle_node(conv_id, parent.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Child with timestamp EARLIER than parent
    let child = create_signed_content_node(
        &conv_id,
        &keys,
        self_pk,
        self_device_pk,
        vec![parent_hash],
        Content::Text("Child".to_string()),
        1,
        2,
        5000, // < 10000
    );

    let effects = engine
        .handle_node(conv_id, child.clone(), &store, None)
        .unwrap();
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    apply_effects(effects, &store);
    assert_eq!(
        status,
        VerificationStatus::Speculative,
        "Child node earlier than parent should be quarantined"
    );
}
