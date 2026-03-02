use merkle_tox_core::cas::{BlobInfo, BlobStatus, SwarmSync};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ConversationId, MessageKey, NodeHash, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::engine::{Conversation, MerkleToxEngine};
use merkle_tox_core::sync::{POW_CHALLENGE_TIMEOUT, RECONCILIATION_INTERVAL};
use merkle_tox_core::testing::{InMemoryStore, TestRoom};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_swarm_sync_next_wakeup() {
    let now = Instant::now();
    let info = BlobInfo {
        hash: NodeHash::from([0u8; 32]),
        size: 1024,
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new(info);

    // No seeders, next wakeup should be long
    let wakeup = sync.next_wakeup(now);
    assert!(wakeup >= now + Duration::from_secs(3600));

    // Add a seeder. Now it should want to poll immediately to send requests.
    sync.add_seeder(PhysicalDevicePk::from([1u8; 32]));
    let wakeup = sync.next_wakeup(now);
    assert_eq!(wakeup, now);
}

#[test]
fn test_sync_session_next_wakeup() {
    let now = Instant::now();
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0u8; 32]);
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, now);

    // In Handshake state, no immediate wakeup for sync heads
    let wakeup = session.next_wakeup(now);
    assert!(wakeup >= now + Duration::from_secs(3600));

    // Move to Active state
    let active_session = session.activate(0);

    // heads_dirty is true by default, so should want immediate wakeup
    let wakeup = active_session.next_wakeup(now);
    assert_eq!(wakeup, now);
}

#[test]
fn test_node_poll_wakeup() {
    use merkle_tox_core::Transport;
    use merkle_tox_core::engine::MerkleToxEngine;
    use merkle_tox_core::node::MerkleToxNode;
    use rand::{SeedableRng, rngs::StdRng};

    struct DummyTransport;
    impl Transport for DummyTransport {
        fn local_pk(&self) -> PhysicalDevicePk {
            PhysicalDevicePk::from([0u8; 32])
        }
        fn send_raw(
            &self,
            _to: PhysicalDevicePk,
            _data: Vec<u8>,
        ) -> Result<(), merkle_tox_core::TransportError> {
            Ok(())
        }
    }

    let now = Instant::now();
    let tp = std::sync::Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let mut node = MerkleToxNode::new(engine, DummyTransport, store, tp);

    // Default wakeup should be relatively long (keepalive)
    let wakeup = node.poll();
    assert!(wakeup > now + Duration::from_secs(4));

    // Manually trigger an event that uses a timer.
    let conv_id = ConversationId::from([0u8; 32]);
    node.engine.start_sync(
        conv_id,
        Some(PhysicalDevicePk::from([1u8; 32])),
        &node.store,
    );

    // Move the session to Active to trigger sync heads advertisement
    let keys: Vec<_> = node.engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = node.engine.sessions.remove(&key) {
            node.engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Poll should return 'now' because session is Active and heads_dirty is true
    let wakeup = node.poll();
    assert!(wakeup <= now + Duration::from_millis(1));
}

#[test]
fn test_next_wakeup_active_session_past() {
    let now = Instant::now();
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0u8; 32]);
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, now);

    // Move to Active state
    let mut active_session = session.activate(0);
    active_session.common.heads_dirty = false;
    active_session.common.recon_dirty = false;

    // Advance time past the next reconciliation interval
    let future_now = now + RECONCILIATION_INTERVAL + Duration::from_secs(1);

    // next_wakeup should not be in the past
    let wakeup = active_session.next_wakeup(future_now);
    assert!(
        wakeup >= future_now,
        "Wakeup {:?} should not be in the past of {:?}",
        wakeup,
        future_now
    );
}

#[test]
fn test_swarm_sync_throttling_no_loop() {
    let now = Instant::now();
    let info = BlobInfo {
        hash: NodeHash::from([0u8; 32]),
        size: 1024, // 1 chunk
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new(info);
    let peer_a = PhysicalDevicePk::from([1u8; 32]);
    let peer_b = PhysicalDevicePk::from([2u8; 32]);
    sync.add_seeder(peer_a);
    sync.add_seeder(peer_b);

    // 1. Start fetching the only chunk from peer_a
    let reqs = sync.next_requests(1, now);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, peer_a);

    // 2. Peer_b is idle, and chunk 0 is still "missing" from tracker.
    // next_wakeup SHOULD NOT be 'now' because we can't send any more requests.
    let wakeup = sync.next_wakeup(now);

    let next_reqs = sync.next_requests(1, now);
    if next_reqs.is_empty() {
        assert!(
            wakeup > now,
            "Tight loop in SwarmSync! Wakeup is 'now' but no requests can be sent."
        );
    }
}

#[test]
fn test_sync_session_missing_nodes_loop() {
    let now = Instant::now();
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0u8; 32]);
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, now);

    // Move to Active state
    let mut active_session = session.activate(0);
    active_session.common.heads_dirty = false;
    active_session.common.recon_dirty = false;

    // Add a node to missing_nodes_hot that is already in in_flight_fetches
    let hash = NodeHash::from([1u8; 32]);
    active_session.common.missing_nodes_hot.push_back(hash);
    active_session.common.in_flight_fetches.insert(hash);

    // next_wakeup will currently return 'now' because missing_nodes_hot is not empty
    let wakeup = active_session.next_wakeup(now);

    // Check if we can actually send anything
    let req = active_session.next_fetch_batch(10);
    if req.is_none() {
        assert!(
            wakeup > now,
            "Tight loop in SyncSession! Wakeup is 'now' but no missing nodes can be fetched (all in-flight)."
        );
    }
}

#[test]
fn test_sync_session_challenge_timeout_no_loop() {
    let now = Instant::now();
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0u8; 32]);
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, now);

    // Move to Active state
    let mut active_session = session.activate(0);
    active_session.common.heads_dirty = false;
    active_session.common.recon_dirty = false;

    // Generate a challenge
    let sketch = tox_reconcile::SyncSketch {
        conversation_id: conv_id,
        cells: Vec::new(),
        range: tox_reconcile::SyncRange {
            min_rank: 0,
            max_rank: 100,
        },
    };
    let mut rng = rand::SeedableRng::seed_from_u64(0);
    let _nonce = active_session.generate_challenge(sketch, now, &mut rng);

    // Advance time past challenge timeout
    let future_now = now + POW_CHALLENGE_TIMEOUT + Duration::from_secs(1);

    // next_wakeup should not be 'now' (it would be 'now' if it returns the past expiry)
    let wakeup = active_session.next_wakeup(future_now);
    assert!(
        wakeup >= future_now,
        "Tight loop due to expired challenge! Wakeup {:?} is in the past of {:?}",
        wakeup,
        future_now
    );
}

#[test]
fn test_engine_poll_failure_no_loop() {
    use merkle_tox_core::Transport;
    use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
    use merkle_tox_core::engine::MerkleToxEngine;
    use merkle_tox_core::engine::session::PeerSession;
    use merkle_tox_core::node::MerkleToxNode;
    use rand::{SeedableRng, rngs::StdRng};

    struct FailingStore;
    impl merkle_tox_core::dag::NodeLookup for FailingStore {
        fn get_node_type(&self, _: &NodeHash) -> Option<merkle_tox_core::dag::NodeType> {
            None
        }
        fn get_rank(&self, _: &NodeHash) -> Option<u64> {
            None
        }
        fn get_admin_distance(&self, _: &NodeHash) -> Option<u64> {
            None
        }
        fn contains_node(&self, _: &NodeHash) -> bool {
            false
        }
        fn has_children(&self, _: &NodeHash) -> bool {
            false
        }
        fn get_soft_anchor_chain_length(&self, _: &NodeHash) -> Option<u64> {
            Some(0)
        }
    }
    impl merkle_tox_core::sync::BlobStore for FailingStore {
        fn has_blob(&self, _: &NodeHash) -> bool {
            false
        }
        fn get_blob_info(&self, _: &NodeHash) -> Option<merkle_tox_core::cas::BlobInfo> {
            None
        }
        fn get_chunk_with_proof(
            &self,
            _: &NodeHash,
            _: u64,
            _: u32,
        ) -> merkle_tox_core::error::MerkleToxResult<(Vec<u8>, Vec<u8>)> {
            Err(merkle_tox_core::error::MerkleToxError::Storage(
                "Simulated failure".to_string(),
            ))
        }
        fn get_chunk(
            &self,
            _: &NodeHash,
            _: u64,
            _: u32,
        ) -> merkle_tox_core::error::MerkleToxResult<Vec<u8>> {
            Err(merkle_tox_core::error::MerkleToxError::Storage(
                "Simulated failure".to_string(),
            ))
        }
        fn put_blob_info(
            &self,
            _: merkle_tox_core::cas::BlobInfo,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn put_chunk(
            &self,
            _: &ConversationId,
            _: &NodeHash,
            _: u64,
            _: &[u8],
            _: Option<&[u8]>,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
    }
    impl merkle_tox_core::sync::NodeStore for FailingStore {
        fn get_heads(&self, _: &ConversationId) -> Vec<NodeHash> {
            Vec::new()
        }
        fn set_heads(
            &self,
            _: &ConversationId,
            _: Vec<NodeHash>,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_admin_heads(&self, _: &ConversationId) -> Vec<NodeHash> {
            Vec::new()
        }
        fn set_admin_heads(
            &self,
            _: &ConversationId,
            _: Vec<NodeHash>,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn has_node(&self, _: &NodeHash) -> bool {
            false
        }
        fn is_verified(&self, _: &NodeHash) -> bool {
            false
        }
        fn get_node(&self, _: &NodeHash) -> Option<merkle_tox_core::dag::MerkleNode> {
            None
        }
        fn get_wire_node(&self, _: &NodeHash) -> Option<merkle_tox_core::dag::WireNode> {
            None
        }
        fn put_node(
            &self,
            _: &ConversationId,
            _: merkle_tox_core::dag::MerkleNode,
            _: bool,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn put_wire_node(
            &self,
            _: &ConversationId,
            _: &NodeHash,
            _: merkle_tox_core::dag::WireNode,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn remove_wire_node(
            &self,
            _: &ConversationId,
            _: &NodeHash,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_opaque_node_hashes(
            &self,
            _: &ConversationId,
        ) -> merkle_tox_core::error::MerkleToxResult<Vec<NodeHash>> {
            Ok(Vec::new())
        }
        fn get_speculative_nodes(
            &self,
            _: &ConversationId,
        ) -> Vec<merkle_tox_core::dag::MerkleNode> {
            Vec::new()
        }
        fn mark_verified(
            &self,
            _: &ConversationId,
            _: &NodeHash,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_last_sequence_number(&self, _: &ConversationId, _: &PhysicalDevicePk) -> u64 {
            0
        }
        fn get_node_counts(&self, _: &ConversationId) -> (usize, usize) {
            (0, 0)
        }
        fn get_verified_nodes_by_type(
            &self,
            _: &ConversationId,
            _: merkle_tox_core::dag::NodeType,
        ) -> merkle_tox_core::error::MerkleToxResult<Vec<merkle_tox_core::dag::MerkleNode>>
        {
            Ok(Vec::new())
        }
        fn get_node_hashes_in_range(
            &self,
            _: &ConversationId,
            _: &tox_reconcile::SyncRange,
        ) -> merkle_tox_core::error::MerkleToxResult<Vec<NodeHash>> {
            Err(merkle_tox_core::error::MerkleToxError::Storage(
                "Simulated failure".to_string(),
            ))
        }
        fn size_bytes(&self) -> u64 {
            0
        }
        fn put_conversation_key(
            &self,
            _: &ConversationId,
            _: u64,
            _: merkle_tox_core::dag::KConv,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_conversation_keys(
            &self,
            _: &ConversationId,
        ) -> merkle_tox_core::error::MerkleToxResult<Vec<(u64, merkle_tox_core::dag::KConv)>>
        {
            Ok(Vec::new())
        }
        fn update_epoch_metadata(
            &self,
            _: &ConversationId,
            _: u32,
            _: i64,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_epoch_metadata(
            &self,
            _: &ConversationId,
        ) -> merkle_tox_core::error::MerkleToxResult<Option<(u32, i64)>> {
            Ok(None)
        }
        fn put_ratchet_key(
            &self,
            _: &ConversationId,
            _: &NodeHash,
            _: merkle_tox_core::dag::ChainKey,
            _: u64,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
        fn get_ratchet_key(
            &self,
            _: &ConversationId,
            _: &NodeHash,
        ) -> merkle_tox_core::error::MerkleToxResult<Option<(merkle_tox_core::dag::ChainKey, u64)>>
        {
            Ok(None)
        }
        fn remove_ratchet_key(
            &self,
            _: &ConversationId,
            _: &NodeHash,
        ) -> merkle_tox_core::error::MerkleToxResult<()> {
            Ok(())
        }
    }

    struct DummyTransport;
    impl Transport for DummyTransport {
        fn local_pk(&self) -> PhysicalDevicePk {
            PhysicalDevicePk::from([0u8; 32])
        }
        fn send_raw(
            &self,
            _: PhysicalDevicePk,
            _: Vec<u8>,
        ) -> Result<(), merkle_tox_core::TransportError> {
            Ok(())
        }
    }

    let now = Instant::now();
    let tp = std::sync::Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut node = MerkleToxNode::new(engine, DummyTransport, FailingStore, tp);

    let conv_id = ConversationId::from([1u8; 32]);
    node.engine.start_sync(
        conv_id,
        Some(PhysicalDevicePk::from([2u8; 32])),
        &node.store,
    );

    // Move to Active
    let keys: Vec<_> = node.engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = node.engine.sessions.remove(&key) {
            let mut active = s.activate(0);
            active.common.recon_dirty = true;
            node.engine
                .sessions
                .insert(key, PeerSession::Active(active));
        }
    }

    // poll() will call engine.poll(), which will call make_sync_shard_checksums, which will FAIL.
    // next_wakeup will be 'now' because recon_dirty is true.
    let wakeup = node.poll();

    // If poll() failed, it MUST have cleared or backed off the trigger to avoid a tight loop.
    assert!(
        wakeup > now,
        "Tight loop detected after engine poll failure!"
    );
}

/// `poll()` should walk every established conversation and drop any
/// `skipped_keys` entry whose insertion timestamp is older than 24 hours.
#[test]
fn test_poll_evicts_stale_skipped_keys() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = rand::rngs::StdRng::seed_from_u64(42);

    // Start the network clock at ms = 0.
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 0i64));

    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();
    room.setup_engine(&mut alice_engine, &alice_store);

    // Inject a skipped key with insertion timestamp 0 (the epoch's birth).
    let dummy_sender = room.identities[1].device_pk;
    let stale_seq: u64 = 99;
    let dummy_key = MessageKey::from([0x99u8; 32]);

    if let Some(Conversation::Established(em)) = alice_engine.conversations.get_mut(&room.conv_id) {
        em.state
            .skipped_keys
            .insert((dummy_sender, stale_seq), (dummy_key, 0i64));
    }

    // Advance both the Instant and the network ms by 25 hours -- the key is stale.
    tp.advance(Duration::from_millis(86_400_001));

    // poll() should proactively sweep and evict expired entries.
    let poll_instant = base_instant + Duration::from_millis(86_400_001);
    let _effects = alice_engine.poll(poll_instant, &alice_store).unwrap();

    if let Some(Conversation::Established(em)) = alice_engine.conversations.get(&room.conv_id) {
        assert!(
            !em.state
                .skipped_keys
                .contains_key(&(dummy_sender, stale_seq)),
            "poll() must proactively evict skipped_keys entries older than 24 h; \
             currently cleanup only happens inside peek_keys() during message processing, \
             so stale keys accumulate forever in conversations that go quiet",
        );
    }
}

/// TTL eviction of skipped_keys happens in `peek_keys`, which is called with
/// the real `now_ms` from the caller.  This test verifies that stale keys
/// (older than 24 h) are evicted when `peek_keys` is invoked with an up-to-date
/// timestamp.
#[test]
fn test_peek_keys_evicts_stale_skipped_keys() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = rand::rngs::StdRng::seed_from_u64(42);

    // Epoch is created at ms = 1000.
    let epoch_ms: i64 = 1000;
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, epoch_ms));

    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();
    room.setup_engine(&mut alice_engine, &alice_store);

    // Inject a skipped key stamped at epoch creation time.
    let dummy_sender = room.identities[1].device_pk;
    let stale_seq: u64 = 42;
    let dummy_key = MessageKey::from([0x42u8; 32]);

    if let Some(Conversation::Established(em)) = alice_engine.conversations.get_mut(&room.conv_id) {
        em.state
            .skipped_keys
            .insert((dummy_sender, stale_seq), (dummy_key, epoch_ms));
        // Sanity: last_rotation_time_ms == epoch_ms.
        assert_eq!(em.state.last_rotation_time_ms, epoch_ms);
    }

    // Advance the clock to 25 h after the key was inserted.
    tp.advance(Duration::from_millis(86_400_001));
    let real_now_ms = epoch_ms + 86_400_001i64;

    // Call peek_keys with the real current time to trigger TTL eviction.
    if let Some(Conversation::Established(em)) = alice_engine.conversations.get_mut(&room.conv_id) {
        let _ = em.peek_keys(&dummy_sender, 1, real_now_ms);
        assert!(
            !em.state
                .skipped_keys
                .contains_key(&(dummy_sender, stale_seq)),
            "peek_keys must evict skipped_keys entries older than 24 h \
             when called with the real current time",
        );
    }
}

// end of file
