use merkle_tox_core::clock::{ManualTimeProvider, TimeProvider};
use merkle_tox_core::dag::{Content, ConversationId, KConv, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, SimulatedTransport, VirtualHub};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn test_partitioned_swarm_convergence() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(tp.clone()));

    let node_count = 8;
    let mut nodes = Vec::new();
    let mut receivers = Vec::new();

    let conv_id = ConversationId::from([0x42u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    // Master identities for all nodes
    let mut identities = Vec::new();
    for _ in 0..node_count {
        identities.push(merkle_tox_core::testing::TestIdentity::new());
    }

    for i in 0..node_count {
        let pk = identities[i].device_pk;
        let rx = hub.register(pk);
        let transport = SimulatedTransport::new(pk, hub.clone());
        let store = InMemoryStore::new();
        store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();

        let mut engine = MerkleToxEngine::new(
            pk,
            identities[i].master_pk,
            StdRng::seed_from_u64(i as u64),
            tp.clone(),
        );

        // Add all identities as members to every engine
        for id in &identities {
            engine
                .identity_manager
                .add_member(conv_id, id.master_pk, 1, 0);
            // Authorize each device
            let cert = id.make_device_cert(Permissions::ALL, i64::MAX);
            engine
                .identity_manager
                .authorize_device(conv_id, id.master_pk, &cert, 0, 0)
                .unwrap();
        }

        engine.load_conversation_state(conv_id, &store).unwrap();

        let node = Arc::new(Mutex::new(MerkleToxNode::new(
            engine,
            transport,
            store,
            tp.clone(),
        )));

        nodes.push(node);
        receivers.push(rx);
    }

    // Fully mesh them in their initial state
    for (i, node_i) in nodes.iter().enumerate() {
        for (j, identity_j) in identities.iter().enumerate() {
            if i != j {
                let peer_pk = identity_j.device_pk;
                let mut n = node_i.lock().unwrap();
                let node_ref = &mut *n;
                let effects = node_ref
                    .engine
                    .start_sync(conv_id, Some(peer_pk), &node_ref.store);
                let now_inst = node_ref.time_provider.now_instant();
                let now_ms = node_ref.time_provider.now_system_ms() as u64;
                let mut dummy_wakeup = now_inst;
                for effect in effects {
                    node_ref
                        .process_effect(effect, now_inst, now_ms, &mut dummy_wakeup)
                        .unwrap();
                }
            }
        }
    }

    // 1. Partition the swarm into 2 groups of 4
    let group_size = 4;
    for g in 0..2 {
        let mut group_pks = std::collections::HashSet::new();
        for i in 0..group_size {
            group_pks.insert(identities[g * group_size + i].device_pk);
        }
        hub.add_partition(group_pks);
    }

    let author_count = 5; // total messages = 2 * 4 * 5 = 40
    let total_expected = 40;

    // author 5 messages in each group
    for g in 0..2 {
        for i in 0..group_size {
            let idx = g * group_size + i;
            let mut n = nodes[idx].lock().unwrap();
            for m in 0..author_count {
                let node_ref = &mut *n;
                let effects = node_ref
                    .engine
                    .author_node(
                        conv_id,
                        Content::Text(format!("G{} N{} M{}", g, i, m)),
                        vec![],
                        &node_ref.store,
                    )
                    .unwrap();

                let now_inst = node_ref.time_provider.now_instant();
                let now_ms = node_ref.time_provider.now_system_ms() as u64;
                let mut dummy_wakeup = now_inst;
                for effect in effects {
                    node_ref
                        .process_effect(effect, now_inst, now_ms, &mut dummy_wakeup)
                        .unwrap();
                }
            }
        }
    }

    // 2. Simulate communication WITHIN groups for 5 seconds
    let start = tp.now_instant();
    while tp.now_instant().duration_since(start) < Duration::from_secs(5) {
        for i in 0..node_count {
            let mut n = nodes[i].lock().unwrap();
            n.poll();
            while let Ok((from, data)) = receivers[i].try_recv() {
                n.handle_packet(from, &data);
            }
        }
        hub.poll();
        tp.advance(Duration::from_millis(20));
    }

    // 3. Heal partitions: allow all communication
    hub.clear_partitions();
    let heal_start = tp.now_instant();
    let timeout = Duration::from_secs(300);

    loop {
        let mut all_synced = true;
        let mut first_heads = None;
        let mut all_counts = Vec::new();

        for (i, node) in nodes.iter().enumerate().take(node_count) {
            let mut n = node.lock().unwrap();
            n.poll();
            while let Ok((from, data)) = receivers[i].try_recv() {
                n.handle_packet(from, &data);
            }

            let counts = n.store.get_node_counts(&conv_id);
            all_counts.push(counts);

            let heads = n.store.get_heads(&conv_id);
            if let Some(first) = &first_heads {
                let mut h_sorted = heads.clone();
                h_sorted.sort_unstable();
                if first != &h_sorted {
                    all_synced = false;
                }
            } else {
                let mut h_sorted = heads.clone();
                h_sorted.sort_unstable();
                first_heads = Some(h_sorted);
            }
        }

        if tp.now_instant().duration_since(heal_start).as_millis() % 5000 < 500 {
            println!("Progress: synced={}, counts={:?}", all_synced, all_counts);
        }

        if all_synced && first_heads.as_ref().is_some_and(|h| !h.is_empty()) {
            // Check that we have all expected messages (2 groups * 4 nodes * 5 msgs = 40)
            let mut all_reached_expected = true;
            for node in nodes.iter().take(node_count) {
                let c = node.lock().unwrap().store.get_node_counts(&conv_id).0;
                if c < total_expected {
                    all_reached_expected = false;
                    break;
                }
            }

            if all_reached_expected {
                println!(
                    "Full convergence reached: {} verified nodes across all peers",
                    total_expected
                );
                break;
            }
        }

        if tp.now_instant().duration_since(heal_start) > timeout {
            panic!(
                "Swarm failed to converge after heal. Final counts: {:?}",
                all_counts
            );
        }

        hub.poll();
        tp.advance(Duration::from_millis(50));
    }
}
