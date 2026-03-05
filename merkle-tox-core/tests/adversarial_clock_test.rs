use merkle_tox_core::clock::{ManualTimeProvider, NetworkClock};
use merkle_tox_core::dag::{LogicalIdentityPk, PhysicalDevicePk};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_sybil_nudge_attack_unweighted() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut clock = NetworkClock::new(tp.clone());

    // 3 Honest peers with accurate time (0 offset)
    for i in 0..3 {
        clock.update_peer_offset(PhysicalDevicePk::from([i as u8; 32]), 0);
    }

    // 10 Malicious peers reporting +1 hour (3,600,000 ms)
    for i in 10..20 {
        clock.update_peer_offset(PhysicalDevicePk::from([i as u8; 32]), 3600000);
    }

    let target = clock.consensus_target_offset();
    // 13 identities (each device = unique identity via update_peer_offset).
    // Median of [0, 0, 0, 3.6m, 3.6m, ...] is 3.6m, but ±5min clamp caps it to 300_000.
    // This confirms the clamp mitigates the attack even when the unweighted median is vulnerable.
    assert_eq!(target, 300_000);
}

#[test]
fn test_sybil_nudge_attack_weighted() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut clock = NetworkClock::new(tp.clone());

    // 3 Honest peers with accurate time (0 offset), but high weight (e.g. verified friends)
    for i in 0..3 {
        let pk = PhysicalDevicePk::from([i as u8; 32]);
        clock.update_peer_offset_weighted(pk, LogicalIdentityPk::from([i as u8; 32]), 0, 10);
    }
    // Total honest weight = 30

    // 10 Malicious peers reporting +1 hour (3,600,000 ms) with low weight
    for i in 10..20 {
        let pk = PhysicalDevicePk::from([i as u8; 32]);
        clock.update_peer_offset_weighted(pk, LogicalIdentityPk::from([i as u8; 32]), 3600000, 1);
    }
    // Total malicious weight = 10

    let offset = clock.consensus_offset();
    // Total weight = 40. Target weight = 20.
    // Sorted: (0, 10), (0, 10), (0, 10), (3.6m, 1), ...
    // First (0, 10): current=10 <= 20
    // Second (0, 10): current=20 == 20. Median is (0 + 0) / 2 = 0.
    assert_eq!(offset, 0);
}

#[test]
fn test_quarantine_stability() {
    use merkle_tox_core::crypto::ConversationKeys;
    use merkle_tox_core::dag::{Content, ConversationId, KConv, PhysicalDevicePk};
    use merkle_tox_core::sync::NodeStore;
    use merkle_tox_core::testing::{InMemoryStore, create_signed_content_node};
    use rand::{SeedableRng, rngs::StdRng};

    let self_pk = PhysicalDevicePk::from([1u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = merkle_tox_core::engine::MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

    use merkle_tox_core::engine::{Conversation, ConversationData, conversation};
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            0,
        )),
    );
    let keys = ConversationKeys::derive(&k_conv);

    // 1. Receive a node dated 5 minutes in the future from a different sender.
    //    (Uses 5 minutes because the consensus offset is clamped to ±5 minutes.)
    let remote = merkle_tox_core::testing::TestIdentity::new();
    engine
        .identity_manager
        .add_member(conv_id, remote.master_pk, 0, 0);
    let cert =
        remote.make_device_cert_for(merkle_tox_core::dag::Permissions::ALL, i64::MAX, conv_id);
    let ctx = merkle_tox_core::identity::CausalContext::global();
    engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            remote.master_pk,
            &cert,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    merkle_tox_core::testing::register_test_ephemeral_key(&mut engine, &keys, &remote.device_pk);

    // Node is 15 minutes in the future → quarantined (> 10min from now).
    // After applying 300_000 (5min) clock offset, the effective "now" is
    // now+5min, and the node is only 10min ahead → just at the boundary.
    // Use 14 min so it's comfortably within range after the offset.
    let future_ts = engine.clock.network_time_ms() + 14 * 60 * 1000;
    let future_node = create_signed_content_node(
        &conv_id,
        &keys,
        remote.master_pk,
        remote.device_pk,
        vec![],
        Content::Text("I am from the future".to_string()),
        0,
        1,
        future_ts,
    );
    let future_hash = future_node.hash();

    let effects = engine
        .handle_node(conv_id, future_node, &store, None)
        .unwrap();
    assert!(!merkle_tox_core::testing::is_verified_in_effects(&effects));
    merkle_tox_core::testing::apply_effects(effects, &store);
    assert!(!store.is_verified(&future_hash));

    // 2. Author a new node
    let effects = engine
        .author_node(
            conv_id,
            Content::Text("I am from now".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let local_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. Verify the future node is NOT a parent of the new node
    assert!(
        !local_node.parents.contains(&future_hash),
        "New node should NOT use quarantined node as parent"
    );

    // 4. Advance wall clock by 5 minutes so the quarantined node (14min ahead)
    //    is now only 9 minutes ahead: within the 10min quarantine threshold.
    tp.advance(Duration::from_millis(5 * 60 * 1000));

    // 5. Trigger re-verification
    let effects = engine.reverify_speculative_for_conversation(conv_id, &store);
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 6. Now it should be verified
    assert!(
        store.is_verified(&future_hash),
        "Quarantined node should be released after clock catches up"
    );
}
