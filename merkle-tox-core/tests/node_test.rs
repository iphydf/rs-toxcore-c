use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::{ManualTimeProvider, TimeProvider};
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, NodeHash, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::MerkleToxEngine;

/// Creates an engine with a proper Ed25519 keypair from a seed byte.
fn engine_with_sk(
    seed: u8,
    rng_seed: u64,
    time_provider: Arc<dyn TimeProvider>,
) -> (PhysicalDevicePk, MerkleToxEngine) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pk = PhysicalDevicePk::from(sk.verifying_key().to_bytes());
    let engine = MerkleToxEngine::with_sk(
        pk,
        pk.to_logical(),
        PhysicalDeviceSk::from(sk.to_bytes()),
        StdRng::seed_from_u64(rng_seed),
        time_provider,
    );
    (pk, engine)
}
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::testing::{
    InMemoryStore, SimulatedTransport, VirtualHub, create_available_blob_info,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn test_node_to_node_sync() {
    let _ = tracing_subscriber::fmt::try_init();
    let time_provider = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(time_provider.clone()));

    let (alice_pk, alice_engine) = engine_with_sk(1, 1, time_provider.clone());
    let alice_rx = hub.register(alice_pk);
    let alice_transport = SimulatedTransport::new(alice_pk, hub.clone());
    let alice_store = InMemoryStore::new();
    let alice_node = Arc::new(Mutex::new(MerkleToxNode::new(
        alice_engine,
        alice_transport,
        alice_store,
        time_provider.clone(),
    )));

    let (bob_pk, bob_engine) = engine_with_sk(2, 2, time_provider.clone());
    let bob_rx = hub.register(bob_pk);
    let bob_transport = SimulatedTransport::new(bob_pk, hub.clone());
    let bob_store = InMemoryStore::new();
    let bob_node = Arc::new(Mutex::new(MerkleToxNode::new(
        bob_engine,
        bob_transport,
        bob_store,
        time_provider.clone(),
    )));

    let conv_id = ConversationId::from([0x42u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let node_ref = &mut *n;
        node_ref
            .store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();
        node_ref
            .engine
            .load_conversation_state(conv_id, &node_ref.store)
            .unwrap();
        let effects = node_ref.engine.start_sync(
            conv_id,
            Some(if node_ref.engine.self_pk == alice_pk {
                bob_pk
            } else {
                alice_pk
            }),
            &node_ref.store,
        );
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 1. Alice authors a message
    {
        let mut a = alice_node.lock().unwrap();
        let node_ref = &mut *a;
        let effects = node_ref
            .engine
            .author_node(
                conv_id,
                Content::Text("Alice Message".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let now = a.time_provider.now_instant();
        let now_ms = a.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            a.process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // Transfer Alice's ephemeral signing keys to Bob so he can verify
    {
        let a = alice_node.lock().unwrap();
        let eph_keys: Vec<_> = a
            .engine
            .self_ephemeral_signing_keys
            .iter()
            .map(|(epoch, sk)| {
                (
                    a.engine.self_pk,
                    *epoch,
                    merkle_tox_core::dag::EphemeralSigningPk::from(sk.verifying_key().to_bytes()),
                )
            })
            .collect();
        drop(a);
        let mut b = bob_node.lock().unwrap();
        for (sender_pk, epoch, vk) in eph_keys {
            b.engine
                .peer_ephemeral_signing_keys
                .insert((sender_pk, epoch), vk);
        }
    }

    // 2. Process simulation
    let virtual_start = time_provider.now_instant();
    let virtual_timeout = Duration::from_secs(10);
    while bob_node.lock().unwrap().store.get_node_counts(&conv_id).0 == 0 {
        if time_provider.now_instant().duration_since(virtual_start) > virtual_timeout {
            panic!("Timed out waiting for Bob to receive Alice's message");
        }
        {
            let mut a = alice_node.lock().unwrap();
            a.poll();
            while let Ok((from, data)) = alice_rx.try_recv() {
                a.handle_packet(from, &data);
            }
        }
        {
            let mut b = bob_node.lock().unwrap();
            b.poll();
            while let Ok((from, data)) = bob_rx.try_recv() {
                b.handle_packet(from, &data);
            }
        }
        hub.poll();
        time_provider.advance(Duration::from_millis(100));
    }

    let b_counts = bob_node.lock().unwrap().store.get_node_counts(&conv_id);
    assert!(
        b_counts.0 >= 1,
        "Bob should have at least 1 verified node, got {:?}",
        b_counts
    );
}

#[test]
fn test_node_blob_sync() {
    let _ = tracing_subscriber::fmt::try_init();
    let time_provider = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(time_provider.clone()));

    let (alice_pk, alice_engine) = engine_with_sk(1, 1, time_provider.clone());
    let alice_rx = hub.register(alice_pk);
    let alice_transport = SimulatedTransport::new(alice_pk, hub.clone());
    let alice_store = InMemoryStore::new();
    let alice_node = Arc::new(Mutex::new(MerkleToxNode::new(
        alice_engine,
        alice_transport,
        alice_store,
        time_provider.clone(),
    )));

    let (bob_pk, bob_engine) = engine_with_sk(2, 2, time_provider.clone());
    let bob_rx = hub.register(bob_pk);
    let bob_transport = SimulatedTransport::new(bob_pk, hub.clone());
    let bob_store = InMemoryStore::new();
    let bob_node = Arc::new(Mutex::new(MerkleToxNode::new(
        bob_engine,
        bob_transport,
        bob_store,
        time_provider.clone(),
    )));

    let conv_id = ConversationId::from([0x42u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let node_ref = &mut *n;
        node_ref
            .store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();
        node_ref
            .engine
            .load_conversation_state(conv_id, &node_ref.store)
            .unwrap();
        let effects = node_ref.engine.start_sync(
            conv_id,
            Some(if node_ref.engine.self_pk == alice_pk {
                bob_pk
            } else {
                alice_pk
            }),
            &node_ref.store,
        );
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 1. Alice authors a blob
    let blob_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let blob_hash = NodeHash::from(
        merkle_tox_core::cas::ChunkMerkleTree::from_chunks(
            blob_data.chunks(merkle_tox_core::cas::CHUNK_SIZE as usize),
        )
        .root(),
    );
    {
        let mut a = alice_node.lock().unwrap();
        let node_ref = &mut *a;
        node_ref
            .store
            .put_blob_info(create_available_blob_info(
                blob_hash,
                blob_data.len() as u64,
            ))
            .unwrap();
        node_ref
            .store
            .put_chunk(&conv_id, &blob_hash, 0, &blob_data, None)
            .unwrap();

        node_ref
            .engine
            .author_node(
                conv_id,
                Content::Blob {
                    hash: blob_hash,
                    name: "test.bin".to_string(),
                    mime_type: "application/octet-stream".to_string(),
                    size: blob_data.len() as u64,
                    metadata: tox_proto::BoundedBytes::new(),
                },
                vec![],
                &node_ref.store,
            )
            .map(|effects| {
                let now = node_ref.time_provider.now_instant();
                let now_ms = node_ref.time_provider.now_system_ms() as u64;
                let mut dummy_wakeup = now;
                for effect in effects {
                    node_ref
                        .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                        .unwrap();
                }
            })
            .unwrap();

        // Alice should advertise her inventory
        let sh = node_ref
            .engine
            .sessions
            .get(&(bob_pk, conv_id))
            .unwrap()
            .make_sync_heads(merkle_tox_core::sync::FLAG_CAS_INVENTORY);
        node_ref.send_message(bob_pk, ProtocolMessage::SyncHeads(sh));
    }

    // 2. Process simulation
    let virtual_start = time_provider.now_instant();
    let virtual_timeout = Duration::from_secs(20);
    while !bob_node.lock().unwrap().store.has_blob(&blob_hash) {
        if time_provider.now_instant().duration_since(virtual_start) > virtual_timeout {
            panic!("Timed out waiting for Bob to receive the blob");
        }
        {
            let mut a = alice_node.lock().unwrap();
            a.poll();
            while let Ok((from, data)) = alice_rx.try_recv() {
                a.handle_packet(from, &data);
            }
        }
        {
            let mut b = bob_node.lock().unwrap();
            b.poll();
            while let Ok((from, data)) = bob_rx.try_recv() {
                b.handle_packet(from, &data);
            }
        }
        hub.poll();
        time_provider.advance(Duration::from_millis(100));
    }

    assert!(bob_node.lock().unwrap().store.has_blob(&blob_hash));
    let bob_data = bob_node
        .lock()
        .unwrap()
        .store
        .get_chunk(&blob_hash, 0, blob_data.len() as u32)
        .expect("Bob should have the chunk");
    assert_eq!(bob_data, blob_data, "Blob data mismatch");
}

#[test]
fn test_node_long_hibernation() {
    let _ = tracing_subscriber::fmt::try_init();
    let time_provider = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(time_provider.clone()));

    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];

    let alice_rx = hub.register(alice_id.device_pk);
    let alice_transport = SimulatedTransport::new(alice_id.device_pk, hub.clone());
    let alice_store = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        time_provider.clone(),
    );
    room.setup_engine(&mut alice_engine, &alice_store);
    // Clear test ephemeral keys: the JIT SKD mechanism will distribute real keys
    // when author_node() is used with self_sk.
    alice_engine.peer_ephemeral_signing_keys.clear();
    let alice_node = Arc::new(Mutex::new(MerkleToxNode::new(
        alice_engine,
        alice_transport,
        alice_store,
        time_provider.clone(),
    )));

    let bob_rx = hub.register(bob_id.device_pk);
    let bob_transport = SimulatedTransport::new(bob_id.device_pk, hub.clone());
    let bob_store = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob_id.device_pk,
        bob_id.master_pk,
        PhysicalDeviceSk::from(bob_id.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        time_provider.clone(),
    );
    room.setup_engine(&mut bob_engine, &bob_store);
    // Clear test ephemeral keys: the JIT SKD mechanism will distribute real keys
    // when author_node() is used with self_sk.
    bob_engine.peer_ephemeral_signing_keys.clear();
    let bob_node = Arc::new(Mutex::new(MerkleToxNode::new(
        bob_engine,
        bob_transport,
        bob_store,
        time_provider.clone(),
    )));

    // Initial sync
    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let peer_pk = if n.engine.self_pk == alice_id.device_pk {
            bob_id.device_pk
        } else {
            alice_id.device_pk
        };
        let node_ref = &mut *n;
        let effects = node_ref
            .engine
            .start_sync(room.conv_id, Some(peer_pk), &node_ref.store);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 1. Bob authors a message and then "hibernates" (is silenced)
    {
        let mut b = bob_node.lock().unwrap();
        let node_ref = &mut *b;
        let effects = node_ref
            .engine
            .author_node(
                room.conv_id,
                Content::Text("Before Sleep".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let now = b.time_provider.now_instant();
        let now_ms = b.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            b.process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // Alice receives it
    let start = time_provider.now_instant();
    while alice_node
        .lock()
        .unwrap()
        .store
        .get_node_counts(&room.conv_id)
        .0
        < 2
    {
        if time_provider.now_instant().duration_since(start) > Duration::from_secs(5) {
            panic!("Timeout waiting for Alice to receive Bob's message");
        }
        {
            let mut a = alice_node.lock().unwrap();
            a.poll();
            while let Ok((f, d)) = alice_rx.try_recv() {
                a.handle_packet(f, &d);
            }
        }
        {
            let mut b = bob_node.lock().unwrap();
            b.poll();
            while let Ok((f, d)) = bob_rx.try_recv() {
                b.handle_packet(f, &d);
            }
        }
        hub.poll();
        time_provider.advance(Duration::from_millis(100));
    }

    // 2. Bob hibernates for 24 hours
    hub.add_partition([bob_id.device_pk].into_iter().collect());
    time_provider.advance(Duration::from_secs(24 * 3600));

    // Alice authors 10 messages during Bob's absence
    {
        let mut a = alice_node.lock().unwrap();
        for i in 0..10 {
            let node_ref = &mut *a;
            let effects = node_ref
                .engine
                .author_node(
                    room.conv_id,
                    Content::Text(format!("Alice {}", i)),
                    vec![],
                    &node_ref.store,
                )
                .unwrap();
            let now = a.time_provider.now_instant();
            let now_ms = a.time_provider.now_system_ms() as u64;
            let mut dummy_wakeup = now;
            for effect in effects {
                a.process_effect(effect, now, now_ms, &mut dummy_wakeup)
                    .unwrap();
            }
        }
    }

    // 3. Bob wakes up
    hub.clear_partitions();

    // After healing, we nudge the engines to re-advertise heads
    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let peer_pk = if n.engine.self_pk == alice_id.device_pk {
            bob_id.device_pk
        } else {
            alice_id.device_pk
        };
        let node_ref = &mut *n;
        let effects = node_ref
            .engine
            .start_sync(room.conv_id, Some(peer_pk), &node_ref.store);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // Simulate Bob catching up
    let start = time_provider.now_instant();
    let timeout = Duration::from_secs(90); // Increased to allow for background recon (60s)
    while bob_node
        .lock()
        .unwrap()
        .store
        .get_node_counts(&room.conv_id)
        .0
        < 16
    {
        if time_provider.now_instant().duration_since(start) > timeout {
            let counts = bob_node
                .lock()
                .unwrap()
                .store
                .get_node_counts(&room.conv_id);
            panic!(
                "Bob failed to catch up after hibernation. Counts: {:?}",
                counts
            );
        }
        {
            let mut a = alice_node.lock().unwrap();
            a.poll();
            while let Ok((f, d)) = alice_rx.try_recv() {
                a.handle_packet(f, &d);
            }
        }
        {
            let mut b = bob_node.lock().unwrap();
            b.poll();
            while let Ok((f, d)) = bob_rx.try_recv() {
                b.handle_packet(f, &d);
            }
        }
        hub.poll();
        time_provider.advance(Duration::from_millis(100));
    }

    // 1 genesis + 2 admin + 1 Bob msg + 10 Alice msgs + 2 JIT SKDs = 16
    assert_eq!(
        bob_node
            .lock()
            .unwrap()
            .store
            .get_node_counts(&room.conv_id)
            .0,
        16
    );
}

#[test]
fn test_node_ratchet_merge() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(tp.clone()));

    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];

    let alice_rx = hub.register(alice_id.device_pk);
    let alice_transport = SimulatedTransport::new(alice_id.device_pk, hub.clone());
    let alice_store = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &alice_store);
    alice_engine.peer_ephemeral_signing_keys.clear();
    let alice_node = Arc::new(Mutex::new(MerkleToxNode::new(
        alice_engine,
        alice_transport,
        alice_store,
        tp.clone(),
    )));

    let bob_rx = hub.register(bob_id.device_pk);
    let bob_transport = SimulatedTransport::new(bob_id.device_pk, hub.clone());
    let bob_store = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob_id.device_pk,
        bob_id.master_pk,
        PhysicalDeviceSk::from(bob_id.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &bob_store);
    bob_engine.peer_ephemeral_signing_keys.clear();
    let bob_node = Arc::new(Mutex::new(MerkleToxNode::new(
        bob_engine,
        bob_transport,
        bob_store,
        tp.clone(),
    )));

    // Initial sync to share keys and genesis
    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let peer_pk = if n.engine.self_pk == alice_id.device_pk {
            bob_id.device_pk
        } else {
            alice_id.device_pk
        };
        let node_ref = &mut *n;
        let effects = node_ref
            .engine
            .start_sync(room.conv_id, Some(peer_pk), &node_ref.store);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 1. Partition Alice and Bob
    hub.add_partition([alice_id.device_pk].into_iter().collect());
    hub.add_partition([bob_id.device_pk].into_iter().collect());

    // 2. Alice authors A, Bob authors B
    {
        let mut a = alice_node.lock().unwrap();
        let node_ref = &mut *a;
        let effects = node_ref
            .engine
            .author_node(
                room.conv_id,
                Content::Text("A".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let now = a.time_provider.now_instant();
        let now_ms = a.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            a.process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        let mut b = bob_node.lock().unwrap();
        let node_ref = &mut *b;
        let effects = node_ref
            .engine
            .author_node(
                room.conv_id,
                Content::Text("B".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let now = b.time_provider.now_instant();
        let now_ms = b.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            b.process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 3. Heal Partition
    hub.clear_partitions();

    // After healing, we might need to nudge the engines to re-advertise heads
    // because the initial SYNC_HEADS were dropped by the partition.
    for node in [&alice_node, &bob_node] {
        let mut n = node.lock().unwrap();
        let peer_pk = if n.engine.self_pk == alice_id.device_pk {
            bob_id.device_pk
        } else {
            alice_id.device_pk
        };
        let node_ref = &mut *n;
        let effects = node_ref
            .engine
            .start_sync(room.conv_id, Some(peer_pk), &node_ref.store);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }

    // 4. Run simulation until they have exchanged A and B
    let start = tp.now_instant();
    loop {
        let ac = alice_node
            .lock()
            .unwrap()
            .store
            .get_node_counts(&room.conv_id)
            .0;
        let bc = bob_node
            .lock()
            .unwrap()
            .store
            .get_node_counts(&room.conv_id)
            .0;
        // 3 setup + 2 own (JIT SKD + msg) + 2 peer (JIT SKD + msg) = 7
        if ac >= 7 && bc >= 7 {
            break;
        }

        if tp.now_instant().duration_since(start) > Duration::from_secs(10) {
            panic!(
                "Sync timeout during concurrent phase. Alice: {}, Bob: {}",
                ac, bc
            );
        }

        for node_rx in [(&alice_node, &alice_rx), (&bob_node, &bob_rx)] {
            let mut n = node_rx.0.lock().unwrap();
            n.poll();
            while let Ok((f, d)) = node_rx.1.try_recv() {
                n.handle_packet(f, &d);
            }
        }
        hub.poll();
        tp.advance(Duration::from_millis(100));
    }

    // 5. Alice authors C, which merges A and B
    let node_c = {
        let mut a = alice_node.lock().unwrap();
        let node_ref = &mut *a;
        let effects = node_ref
            .engine
            .author_node(
                room.conv_id,
                Content::Text("C (Merge)".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();

        let mut node_c = None;
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = &effect {
                node_c = Some(node.clone());
            }
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
        node_c.unwrap()
    };
    assert_eq!(
        node_c.parents.len(),
        3,
        "Node C must have three parents (A, B, and the setup_engine auth node)"
    );

    // 6. Run simulation until Bob receives and verifies C
    let start = tp.now_instant();
    loop {
        let bc = bob_node
            .lock()
            .unwrap()
            .store
            .get_node_counts(&room.conv_id)
            .0;
        // 7 (from sync phase) + 1 node C = 8
        if bc >= 8 {
            break;
        }

        if tp.now_instant().duration_since(start) > Duration::from_secs(10) {
            panic!("Sync timeout during merge phase. Bob: {}", bc);
        }

        for node_rx in [(&alice_node, &alice_rx), (&bob_node, &bob_rx)] {
            let mut n = node_rx.0.lock().unwrap();
            n.poll();
            while let Ok((f, d)) = node_rx.1.try_recv() {
                n.handle_packet(f, &d);
            }
        }
        hub.poll();
        tp.advance(Duration::from_millis(100));
    }

    // Final verification: Bob should have Node C verified
    assert!(bob_node.lock().unwrap().store.is_verified(&node_c.hash()));
}

// end of file
