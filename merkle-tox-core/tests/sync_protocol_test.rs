use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ConversationId, Ed25519Signature, KConv, LogicalIdentityPk, MerkleNode, NodeAuth,
    NodeHash, PhysicalDevicePk, WireFlags,
};
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::engine::{Conversation, Effect, MerkleToxEngine};
use merkle_tox_core::sync::{NodeStore, RECONCILIATION_INTERVAL};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_engine(now: Instant) -> (MerkleToxEngine, Arc<ManualTimeProvider>, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    // The Sync* / MerkleNode handlers now drop messages naming a
    // conversation we have not joined locally. Every test in this
    // file uses `conv_id = [1u8; 32]`, so seed that conversation up
    // front to keep the existing fixtures focused on the protocol
    // behaviour they cover (rate-limit, reconciliation, sketch CPU
    // budgets, etc.).
    let conv_id = ConversationId::from([1u8; 32]);
    let established =
        ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
    engine
        .conversations
        .insert(conv_id, Conversation::Established(established));
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
                retry_after_ms: tox_proto::Untrusted::new(5000),
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
    let effects = engine.poll(now, &store, None).unwrap();
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
                retry_after_ms: tox_proto::Untrusted::new(1000),
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

    let effects = engine.poll(later, &store, None).unwrap();

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

/// §3.3b Sketch-spam adversarial coverage: when a peer has exhausted its
/// per-peer sketch CPU budget, the responder must emit `SyncRateLimited`
/// and must NOT process the sketch (no SyncShardChecksums, no PoW challenge
/// for sub-Medium sketches). Verifies the token-bucket mitigation is wired
/// end-to-end, not just present as a struct.
#[test]
fn test_sketch_spam_triggers_rate_limited_when_budget_exhausted() {
    use merkle_tox_core::engine::CpuBudget;
    use tox_reconcile::{IbltCell, SyncRange, SyncSketch};

    let now = Instant::now();
    let (mut engine, _tp, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // Simulate an attacker that has already drained the per-peer budget by
    // flooding sketches. A drained CpuBudget is the observable state the
    // handler should react to.
    let mut drained = CpuBudget::new(0);
    drained.remaining_ms = 0.0;
    engine.sketch_cpu_budgets.insert(peer_pk, drained);

    // A Small sketch (≤64 cells) skips the PoW gate and goes directly to
    // the budget check — the exact path an attacker would flood.
    let sketch = SyncSketch {
        conversation_id: conv_id,
        cells: tox_proto::BoundedVec::try_from_iter(std::iter::repeat_n(IbltCell::default(), 64)).expect("under MAX_SKETCH_CELLS"),
        range: SyncRange {
            min_rank: 0,
            max_rank: 100,
        },
    };

    let effects = engine
        .handle_message(peer_pk, ProtocolMessage::SyncSketch(sketch), &store, None)
        .unwrap();

    let rate_limited = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(p, ProtocolMessage::SyncRateLimited { .. }) if *p == peer_pk,
        )
    });
    assert!(
        rate_limited,
        "exhausted sketch budget must produce a SyncRateLimited backoff; \
         otherwise the per-peer CPU cap from merkle-tox-threat-model.md §3.3b \
         provides no real defense"
    );

    let processed = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(
                _,
                ProtocolMessage::SyncShardChecksums { .. }
                    | ProtocolMessage::ReconPowChallenge { .. }
                    | ProtocolMessage::FetchBatchReq(_),
            )
        )
    });
    assert!(
        !processed,
        "sketch must not be processed when budget is exhausted"
    );
}

/// Companion to the sketch-spam test: once the refill window has elapsed, a
/// previously-rate-limited peer must be accepted again. Verifies the token
/// bucket recovers rather than permanently locking out the peer — legitimate
/// peers must not be stuck behind an exhausted budget.
#[test]
fn test_sketch_budget_refills_after_window() {
    use merkle_tox_core::engine::CpuBudget;
    use tox_reconcile::{IbltCell, SyncRange, SyncSketch};

    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // Start with an exhausted budget, pinned to now_ms = 0.
    let mut drained = CpuBudget::new(0);
    drained.remaining_ms = 0.0;
    engine.sketch_cpu_budgets.insert(peer_pk, drained);

    // Advance the virtual clock past the refill window so the bucket refills
    // to full.
    tp.advance(Duration::from_millis(
        tox_proto::constants::SKETCH_CPU_WINDOW_MS as u64 + 1_000,
    ));

    let sketch = SyncSketch {
        conversation_id: conv_id,
        cells: tox_proto::BoundedVec::try_from_iter(std::iter::repeat_n(IbltCell::default(), 64)).expect("under MAX_SKETCH_CELLS"),
        range: SyncRange {
            min_rank: 0,
            max_rank: 100,
        },
    };

    let effects = engine
        .handle_message(peer_pk, ProtocolMessage::SyncSketch(sketch), &store, None)
        .unwrap();

    let rate_limited = effects.iter().any(|e| {
        matches!(e, Effect::SendPacket(_, ProtocolMessage::SyncRateLimited { .. }))
    });
    assert!(
        !rate_limited,
        "after the refill window elapses the budget must recover; legitimate \
         peers must not stay locked out forever"
    );
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
            parents: tox_proto::bounded_vec![NodeHash::from([i + 0x10; 32])],
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: (i + 1) as u64,
            topological_rank: 100 - i as u64,
            network_timestamp: 1000 + i as i64,
            content: Content::Text(format!("msg {}", i)),
            metadata: tox_proto::BoundedBytes::new(),
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
                genesis_flags: 0,
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
    let effects = engine.poll(now, &store, None).unwrap();
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
    let effects2 = engine.poll(now + Duration::from_secs(1), &store, None).unwrap();
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
    assert_eq!(batch.hashes.as_slice(), &[hot_hash]);

    // Fetch batch of 1 again: now cold
    let batch = session.next_fetch_batch(1).unwrap();
    assert_eq!(batch.hashes.as_slice(), &[cold_hash]);

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
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 2000,
        network_timestamp: 1000,
        content: Content::Text("head".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
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
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 2000,
        network_timestamp: 1000,
        content: Content::Text("head".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let head_hash = head_node.hash();
    store.put_node(&conv_id, head_node, true).unwrap();
    store.set_heads(&conv_id, vec![head_hash]).unwrap();

    // Create a cold node (rank 500, far below HOT_WINDOW of 1000 from head 2000)
    let cold_node = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 2,
        topological_rank: 500,
        network_timestamp: 500,
        content: Content::Text("cold".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let cold_hash = cold_node.hash();
    store.put_node(&conv_id, cold_node, true).unwrap();

    // Create a hot node (rank 1500, within HOT_WINDOW of 1000 from head 2000)
    let hot_node = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 3,
        topological_rank: 1500,
        network_timestamp: 1500,
        content: Content::Text("hot".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
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
        parents: tox_proto::BoundedVec::new(),
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
