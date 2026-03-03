use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash,
    PhysicalDevicePk, WireFlags,
};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::{NodeStore, RECONCILIATION_INTERVAL};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_engine(now: Instant) -> (MerkleToxEngine, Arc<ManualTimeProvider>, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    (engine, tp, self_pk)
}

// --- Gap 1: SyncRateLimited Backoff ---

#[test]
fn test_rate_limited_pauses_recon() {
    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // Start sync to create a session
    engine.start_sync(conv_id, Some(peer_pk), &store);
    // Activate the session
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Handle SyncRateLimited message
    let result = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncRateLimited {
                conversation_id: conv_id,
                retry_after_ms: 5000,
            },
            &store,
            None,
        )
        .unwrap();
    assert!(result.is_empty()); // No immediate effects

    // Verify rate_limited_until is set
    let session = engine.sessions.get(&(peer_pk, conv_id)).unwrap();
    assert!(session.common().rate_limited_until.is_some());

    // Poll should skip reconciliation for this session
    // Clear heads_dirty so we can observe recon behavior
    if let Some(PeerSession::Active(s)) = engine.sessions.get_mut(&(peer_pk, conv_id)) {
        s.common.heads_dirty = false;
        s.common.recon_dirty = true;
    }
    let effects = engine.poll(now, &store).unwrap();
    // No SyncShardChecksums should be emitted (recon is paused)
    let has_shard_checksums = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(_, ProtocolMessage::SyncShardChecksums { .. })
        )
    });
    assert!(
        !has_shard_checksums,
        "Recon should be paused while rate limited"
    );
}

#[test]
fn test_rate_limited_expires() {
    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // Start sync and activate
    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Set rate limited for 1000ms
    engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncRateLimited {
                conversation_id: conv_id,
                retry_after_ms: 1000,
            },
            &store,
            None,
        )
        .unwrap();

    // Advance past the retry_after window
    let later = now + Duration::from_millis(1500);
    if let Some(PeerSession::Active(s)) = engine.sessions.get_mut(&(peer_pk, conv_id)) {
        s.common.heads_dirty = false;
        s.common.recon_dirty = true;
        // Ensure enough time has passed for reconciliation interval
        s.common.last_recon_time = now - RECONCILIATION_INTERVAL - Duration::from_secs(1);
    }

    let effects = engine.poll(later, &store).unwrap();

    // Rate limit expired, so recon should proceed (SyncShardChecksums emitted)
    let has_shard_checksums = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(_, ProtocolMessage::SyncShardChecksums { .. })
        )
    });
    assert!(
        has_shard_checksums,
        "Recon should resume after rate limit expires"
    );

    // rate_limited_until should be cleared
    let session = engine.sessions.get(&(peer_pk, conv_id)).unwrap();
    assert!(session.common().rate_limited_until.is_none());
}

// --- Gap 2: Shallow Sync "Last N Messages" ---

#[test]
fn test_shallow_last_n() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let peer_pk = PhysicalDevicePk::from([3u8; 32]);

    // Start shallow sync with last_n = 3
    engine.start_shallow_sync_last_n(conversation_id, Some(peer_pk), &store, 3);

    // Activate
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Verify session has max_backfill_nodes = 3
    if let Some(PeerSession::Active(s)) = engine.sessions.get(&(peer_pk, conversation_id)) {
        assert!(s.common.shallow);
        assert_eq!(s.common.max_backfill_nodes, 3);
        assert_eq!(s.common.backfill_count, 0);
    } else {
        panic!("Expected active session");
    }

    // Simulate receiving content nodes: after 3, backfill should stop
    let mut session = SyncSession::<Handshake>::new(conversation_id, &store, true, now).activate(0);
    session.common.max_backfill_nodes = 3;
    session.common.backfill_count = 0;

    for i in 0..4u8 {
        let node = MerkleNode {
            parents: vec![NodeHash::from([i + 0x10; 32])],
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: (i + 1) as u64,
            topological_rank: 100 - i as u64,
            network_timestamp: 1000 + i as i64,
            content: Content::Text(format!("msg {}", i)),
            metadata: vec![],
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
            pow_nonce: 0,
        };
        session.on_node_received(&node, &store, None);
    }

    // After 4 content nodes with max_backfill_nodes=3:
    // Nodes 0,1 enqueue parents (count 1,2 < 3)
    // Node 2: count becomes 3 >= 3, returns early (no parent enqueued)
    // Node 3: count becomes 4 >= 3, returns early (no parent enqueued)
    assert!(session.common.backfill_count >= 3);
    let total_missing =
        session.common.missing_nodes_hot.len() + session.common.missing_nodes_cold.len();
    assert_eq!(
        total_missing, 2,
        "Only first 2 nodes should enqueue parents (3rd hits limit)"
    );
}

// --- Gap 3: Multicast Gossip ---

#[test]
fn test_gossip_broadcast() {
    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer1 = PhysicalDevicePk::from([2u8; 32]);
    let peer2 = PhysicalDevicePk::from([3u8; 32]);

    // Create a conversation (Pending, since we don't need keys for sketch)
    engine.conversations.insert(
        conv_id,
        merkle_tox_core::engine::Conversation::Pending(merkle_tox_core::engine::ConversationData {
            id: conv_id,
            state: merkle_tox_core::engine::conversation::Pending {
                speculative_nodes: std::collections::HashSet::new(),
                vouchers: std::collections::HashMap::new(),
            },
        }),
    );

    // Create active sessions for two peers
    let s1 = SyncSession::<Handshake>::new(conv_id, &store, false, now).activate(0);
    let s2 = SyncSession::<Handshake>::new(conv_id, &store, false, now).activate(0);
    engine
        .sessions
        .insert((peer1, conv_id), PeerSession::Active(s1));
    engine
        .sessions
        .insert((peer2, conv_id), PeerSession::Active(s2));

    // Clear heads_dirty and recon_dirty to isolate gossip effects
    for (_, session) in engine.sessions.iter_mut() {
        let c = session.common_mut();
        c.heads_dirty = false;
        c.recon_dirty = false;
        c.last_recon_time = now;
    }

    // First poll at now: gossip has never been sent, so it should fire
    // (default last_gossip_time is now - GOSSIP_INTERVAL)
    let effects = engine.poll(now, &store).unwrap();
    let sketch_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::SyncSketch(_))))
        .count();
    // Should send to both peers
    assert_eq!(sketch_count, 2, "Gossip sketch should be sent to 2 peers");

    // Verify the sketch is Tiny (16 cells)
    for e in &effects {
        if let Effect::SendPacket(_, ProtocolMessage::SyncSketch(sketch)) = e {
            assert_eq!(
                sketch.cells.len(),
                tox_reconcile::Tier::Tiny.cell_count(),
                "Gossip sketch should be Tiny"
            );
        }
    }

    // Poll again immediately. Should NOT resend gossip
    let effects2 = engine.poll(now + Duration::from_secs(1), &store).unwrap();
    let sketch_count2 = effects2
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::SyncSketch(_))))
        .count();
    assert_eq!(sketch_count2, 0, "Gossip should not be resent within 60s");
}

// --- Gap 4a: Hot/Cold Fetch Priority ---

#[test]
fn test_hot_cold_fetch_priority() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);

    let cold_hash = NodeHash::from([0xCCu8; 32]);
    let hot_hash = NodeHash::from([0xAAu8; 32]);

    // Manually place hashes in hot and cold queues
    session.common.missing_nodes_cold.push_back(cold_hash);
    session.common.missing_nodes_hot.push_back(hot_hash);

    // Fetch batch of 1: should get hot first
    let batch = session.next_fetch_batch(1).unwrap();
    assert_eq!(batch.hashes, vec![hot_hash]);

    // Fetch batch of 1 again: now cold
    let batch = session.next_fetch_batch(1).unwrap();
    assert_eq!(batch.hashes, vec![cold_hash]);

    // Both queues should be empty now
    assert!(session.common.missing_nodes_hot.is_empty());
    assert!(session.common.missing_nodes_cold.is_empty());
}

#[test]
fn test_enqueue_missing_classification() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    // Create a node at rank 2000 to serve as a head
    let head_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 2000,
        network_timestamp: 1000,
        content: Content::Text("head".to_string()),
        metadata: vec![],
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let head_hash = head_node.hash();
    store.put_node(&conversation_id, head_node, true).unwrap();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);
    session.common.local_heads.insert(head_hash);

    // Enqueue with rank close to head (within HOT_WINDOW_RANKS=1000): should be hot
    let near_hash = NodeHash::from([0x11u8; 32]);
    session.enqueue_missing(near_hash, Some(1500), &store);
    assert!(session.common.missing_nodes_hot.contains(&near_hash));

    // Enqueue with rank far from head: should be cold
    let far_hash = NodeHash::from([0x22u8; 32]);
    session.enqueue_missing(far_hash, Some(500), &store);
    assert!(session.common.missing_nodes_cold.contains(&far_hash));

    // Enqueue with no rank hint: defaults to hot
    let unknown_hash = NodeHash::from([0x33u8; 32]);
    session.enqueue_missing(unknown_hash, None, &store);
    assert!(session.common.missing_nodes_hot.contains(&unknown_hash));
}

// --- Gap 4b: Cold-First Eviction ---

#[test]
fn test_cold_first_eviction() {
    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // Create a head node at rank 2000
    let head_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 2000,
        network_timestamp: 1000,
        content: Content::Text("head".to_string()),
        metadata: vec![],
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let head_hash = head_node.hash();
    store.put_node(&conv_id, head_node, true).unwrap();
    store.set_heads(&conv_id, vec![head_hash]).unwrap();

    // Create a cold node (rank 500, far below HOT_WINDOW of 1000 from head 2000)
    let cold_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 2,
        topological_rank: 500,
        network_timestamp: 500,
        content: Content::Text("cold".to_string()),
        metadata: vec![],
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let cold_hash = cold_node.hash();
    store.put_node(&conv_id, cold_node, true).unwrap();

    // Create a hot node (rank 1500, within HOT_WINDOW of 1000 from head 2000)
    let hot_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 3,
        topological_rank: 1500,
        network_timestamp: 1500,
        content: Content::Text("hot".to_string()),
        metadata: vec![],
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let hot_hash = hot_node.hash();
    store.put_node(&conv_id, hot_node, true).unwrap();

    // Pre-fill opaque_store_usage: total well over quota so multiple entries
    // need eviction. Each entry is at 3/4 quota: total = 1.5 * quota.
    // After adding trigger (100 bytes), we need to evict until total <= quota.
    // Evicting cold (3/4 quota) brings total to 3/4 quota + 100 <= quota. Done.
    let quota = tox_proto::constants::OPAQUE_STORE_QUOTA;
    let entry_size = quota * 3 / 4;
    engine.opaque_store_usage.insert(
        conv_id,
        (
            entry_size * 2,
            vec![
                (cold_hash, entry_size, 100, peer_pk),
                (hot_hash, entry_size, 200, peer_pk),
            ],
        ),
    );

    // Start sync and activate session
    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Send a wire node that triggers eviction (total already over quota)
    let trigger_wire = merkle_tox_core::dag::WireNode {
        sender_hint: [0xFF; 4],
        flags: WireFlags::ENCRYPTED,
        parents: vec![],
        encrypted_routing: vec![],
        payload_data: vec![0u8; 100],
        topological_rank: 1800,
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
    };
    let trigger_hash = NodeHash::from([0xEEu8; 32]);

    let effects = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::MerkleNode {
                conversation_id: conv_id,
                hash: trigger_hash,
                node: trigger_wire,
            },
            &store,
            None,
        )
        .unwrap();

    // Collect evicted hashes in order
    let evicted: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::DeleteWireNode(_, hash) = e {
                Some(*hash)
            } else {
                None
            }
        })
        .collect();

    // After trigger (100 bytes), total = 1.5*quota + 100. Need to evict to <= quota.
    // Sort order: cold_hash (rank 500, cold) before hot_hash (rank 1500, hot).
    // Evicting cold (3/4 quota) brings total to 3/4 quota + 100, which is <= quota.
    // So only cold is evicted, hot survives, demonstrating cold-first eviction.
    assert!(!evicted.is_empty(), "At least one entry should be evicted");

    // The first (and possibly only) eviction should be the cold node
    // The trigger_hash (unknown rank → 0) may be evicted first since rank 0 < 500,
    // but among known-rank entries, cold must come before hot.
    assert!(
        evicted.contains(&cold_hash),
        "Cold node (rank 500) should be evicted"
    );
    assert!(
        !evicted.contains(&hot_hash),
        "Hot node (rank 1500) should NOT be evicted. Cold eviction suffices"
    );
}
