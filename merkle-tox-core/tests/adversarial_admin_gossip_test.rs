//! §AGD adversarial coverage for `AdminGossip`.
//!
//! The `missing_admin_nodes` deque is drained one hash per `poll()` via
//! a priority fetch. A hostile peer can push unique hashes faster than
//! we can drain them; without a cap, the deque grows without bound and
//! the peer gets a cheap memory-amplification vector (one 32-byte hash
//! per network message → one `VecDeque` entry for the session's
//! lifetime).
//!
//! The handler now enforces `MAX_MISSING_ADMIN_NODES`: further unique
//! hashes are silently ignored until drain catches up.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::session::PeerSession;
use merkle_tox_core::engine::{MAX_MISSING_ADMIN_NODES, MerkleToxEngine};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

fn make_engine(now: Instant) -> (MerkleToxEngine, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    );
    (engine, self_pk)
}

/// §AGD-1: A peer streaming distinct `AdminGossip` hashes must not be
/// able to inflate our per-session `missing_admin_nodes` deque past
/// `MAX_MISSING_ADMIN_NODES`. Without the cap, each unique hash would
/// add a permanent entry for the session's lifetime.
#[test]
fn admin_gossip_deque_is_bounded() {
    let (mut engine, _self_pk) = make_engine(Instant::now());
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Flood with 4× the cap worth of distinct hashes. None are in our
    // store, so every one passes the `!has_node` guard; none collides
    // with an existing deque entry, so every one passes the `!contains`
    // guard. The only remaining guard is the new cap.
    let flood = MAX_MISSING_ADMIN_NODES * 4;
    for i in 0..flood as u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        engine
            .handle_message(
                peer_pk,
                ProtocolMessage::AdminGossip {
                    conversation_id: conv_id,
                    hash: NodeHash::from(bytes),
                },
                &store,
                None,
            )
            .unwrap();
    }

    let session = engine.sessions.get(&(peer_pk, conv_id)).unwrap();
    let PeerSession::Active(active) = session else {
        panic!("expected Active session");
    };
    let len = active.common.missing_admin_nodes.len();
    assert!(
        len <= MAX_MISSING_ADMIN_NODES,
        "missing_admin_nodes grew to {} (cap {})",
        len,
        MAX_MISSING_ADMIN_NODES,
    );
}
