use merkle_tox_core::cas::{BlobInfo, BlobStatus, SwarmSync};
use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::testing::InMemoryStore;
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

    // Let's manually trigger something that has a timer.
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
