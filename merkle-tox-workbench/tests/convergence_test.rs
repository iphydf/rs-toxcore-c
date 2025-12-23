use merkle_tox_core::clock::TimeProvider;
use merkle_tox_core::dag::{Content, KConv};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_workbench::model::{Model, Topology};
use merkle_tox_workbench::msg::Msg;
use merkle_tox_workbench::update::update;
use std::time::Duration;

#[test]
fn test_convergence_simple() {
    // 1. Initialize a 3-node swarm, not paused, 0 auto-authoring rate
    let mut model = Model::new(3, 0, 0.0, false, 42, Topology::Mesh);
    let dt = Duration::from_millis(50);

    // 2. Run for a few steps to complete handshake
    for _ in 0..10 {
        update(&mut model, Msg::Tick(dt));
    }

    // 2.5. Initialize shared conversation keys
    let k_conv = KConv::from([0x11u8; 32]);
    let now_ms = model.time_provider.now_system_ms();
    for n in &mut model.nodes {
        let _ = n
            .node
            .store
            .put_conversation_key(&model.conversation_id, 0, k_conv.clone());
        n.node.engine.conversations.insert(
            model.conversation_id,
            merkle_tox_core::engine::Conversation::Established(
                merkle_tox_core::engine::ConversationData::<
                    merkle_tox_core::engine::conversation::Established,
                >::new(model.conversation_id, k_conv.clone(), now_ms),
            ),
        );
    }

    // Check handshake in topology (green lines)
    for ((_peer, _cid), session) in &model.nodes[0].node.engine.sessions {
        assert!(matches!(
            session,
            merkle_tox_core::engine::session::PeerSession::Active(_)
        ));
    }

    // 3. Author a message from Node 0
    let conv_id = model.conversation_id;
    let node0 = &mut model.nodes[0];

    let effects = node0
        .node
        .engine
        .author_node(
            conv_id,
            Content::Text("Hello Sync".to_string()),
            vec![],
            &node0.node.store,
        )
        .unwrap();

    let now = node0.node.time_provider.now_instant();
    let now_ms = node0.node.time_provider.now_system_ms() as u64;
    let mut dummy_wakeup = now;
    for effect in effects {
        node0
            .node
            .process_effect(effect, now, now_ms, &mut dummy_wakeup)
            .unwrap();
    }

    // 4. Run simulation until converged
    let mut converged = false;
    for _ in 0..100 {
        update(&mut model, Msg::Tick(dt));
        let (synced, heads) = model.get_convergence_stats();
        if synced == 3 && heads == 1 {
            converged = true;
            break;
        }
    }

    assert!(converged, "Swarm failed to converge on the single message");

    // 5. Verify everyone has 1 verified node and 0 speculative
    for n in &model.nodes {
        let (ver, spec) = n.node.store.get_node_counts(&model.conversation_id);
        assert_eq!(
            ver, 1,
            "Node {:?} should have 1 verified node",
            n.node.engine.self_pk
        );
        assert_eq!(
            spec, 0,
            "Node {:?} should have 0 speculative nodes",
            n.node.engine.self_pk
        );
    }
}
