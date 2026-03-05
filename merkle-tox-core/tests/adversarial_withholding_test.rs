//! Adversarial coverage for threat-model §3.11 Selective Data Withholding.
//!
//! A compromised member advertises heads but refuses to serve requested
//! nodes to stall the sync. The spec claims the mitigation is:
//!  - bounded voucher set (MAX_VOUCHERS_PER_HASH = 3)
//!  - per-voucher timeout (VOUCHER_TIMEOUT_MS = 10s)
//!  - multi-peer fetch fallback
//!  - engine penalizes the stalled peer and requests from the next peer
//!
//! **Threshold policy.** A single voucher timeout is not evidence of
//! malice — in any lossy network (1% drop-rate is common), a lost
//! `MerkleNode` reply looks identical to withholding. Under the
//! originally-shipped 1-timeout → tier-1 policy, `blob_fetch_retries_on_loss`
//! regressed: one lost sync-layer reply blacklisted an innocent peer for
//! 10 min, and the blob transfer stalled because the receiver dropped
//! every subsequent response from that peer.
//!
//! The guard now requires `WITHHOLDING_THRESHOLD` consecutive timeouts
//! from the same peer without any intervening successful `MerkleNode`
//! receipt. A peer who serves *anything* resets their counter. Only a
//! persistent refuser crosses the threshold and gets blacklisted.

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::engine::{MerkleToxEngine, WITHHOLDING_THRESHOLD};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn setup_voucher(
    engine: &mut MerkleToxEngine,
    conv_id: ConversationId,
    peer: PhysicalDevicePk,
    target: NodeHash,
    stamped_ms: i64,
) {
    use merkle_tox_core::dag::KConv;
    use merkle_tox_core::engine::conversation::{Conversation, ConversationData, Established};
    use std::collections::{BTreeMap, HashMap, HashSet};

    engine.conversations.entry(conv_id).or_insert_with(|| {
        let k_conv = KConv::from([0u8; 32]);
        let mut epochs = HashMap::new();
        epochs.insert(
            0,
            merkle_tox_core::crypto::ConversationKeys::derive(&k_conv),
        );
        let established = Established {
            epochs,
            sender_ratchets: BTreeMap::new(),
            skipped_keys: HashMap::new(),
            current_epoch: 0,
            message_count: 0,
            last_rotation_time_ms: 0,
            vouchers: HashMap::new(),
            sender_keys: HashMap::new(),
            shared_keys_sent_to: HashSet::new(),
            jit_headers: HashMap::new(),
            identity_pending: false,
            genesis_flags: 0,
            self_message_count: 0,
            self_last_rekey_time_ms: 0,
        };
        Conversation::Established(ConversationData {
            id: conv_id,
            state: established,
        })
    });
    if let Some(Conversation::Established(em)) = engine.conversations.get_mut(&conv_id) {
        em.state
            .vouchers
            .entry(target)
            .or_default()
            .insert(peer, stamped_ms);
    }
    if let Some(PeerSession::Active(sa)) = engine.sessions.get_mut(&(peer, conv_id)) {
        sa.common.in_flight_fetches.insert(target);
    }
}

fn make_engine(now: Instant) -> (MerkleToxEngine, Arc<ManualTimeProvider>) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    (engine, tp)
}

fn activate_session(
    engine: &mut MerkleToxEngine,
    peer: PhysicalDevicePk,
    conv_id: ConversationId,
    now: Instant,
) {
    let store = InMemoryStore::new();
    let handshake = SyncSession::<Handshake>::new(conv_id, &store, false, now);
    engine
        .sessions
        .insert((peer, conv_id), PeerSession::Active(handshake.activate(0)));
}

/// §3.11 WH-1: A single voucher timeout must NOT blacklist the peer —
/// in a lossy network one lost reply is indistinguishable from
/// withholding, and false positives break legitimate sync.
#[test]
fn single_voucher_timeout_does_not_blacklist() {
    let now = Instant::now();
    let (mut engine, tp) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer = PhysicalDevicePk::from([0xAAu8; 32]);
    let target = NodeHash::from([0x77u8; 32]);

    activate_session(&mut engine, peer, conv_id, now);
    setup_voucher(&mut engine, conv_id, peer, target, 0);

    let timeout_ms = tox_proto::constants::VOUCHER_TIMEOUT_MS as u64;
    tp.advance(Duration::from_millis(timeout_ms + 1_000));
    let later = now + Duration::from_millis(timeout_ms + 1_000);
    let _ = engine.poll(later, &store, None).unwrap();

    let now_after = (timeout_ms + 1_000) as i64;
    assert!(
        !engine.is_blacklisted(&peer, now_after),
        "a single voucher timeout is indistinguishable from packet loss — \
         must not blacklist on one miss",
    );

    // The hash still needs to be released so a fallback voucher can be tried.
    let stuck = matches!(
        engine.sessions.get(&(peer, conv_id)),
        Some(PeerSession::Active(sa)) if sa.common.in_flight_fetches.contains(&target)
    );
    assert!(!stuck, "target must be removed from peer's in-flight set");
}

/// §3.11 WH-2: After `WITHHOLDING_THRESHOLD` consecutive timeouts from
/// the same peer with no intervening successful receipt, the peer is
/// blacklisted. This is the actual withholding signal.
#[test]
fn repeated_timeouts_blacklist_the_peer() {
    let now = Instant::now();
    let (mut engine, tp) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer = PhysicalDevicePk::from([0xAAu8; 32]);

    activate_session(&mut engine, peer, conv_id, now);

    let timeout_ms = tox_proto::constants::VOUCHER_TIMEOUT_MS as u64;
    let mut cursor = now;
    for i in 0..WITHHOLDING_THRESHOLD as u8 {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = i;
        let target = NodeHash::from(hash_bytes);
        let stamped_ms = (cursor - now).as_millis() as i64;
        setup_voucher(&mut engine, conv_id, peer, target, stamped_ms);

        tp.advance(Duration::from_millis(timeout_ms + 1_000));
        cursor += Duration::from_millis(timeout_ms + 1_000);
        let _ = engine.poll(cursor, &store, None).unwrap();
    }

    let now_ms_after = (cursor - now).as_millis() as i64;
    assert!(
        engine.is_blacklisted(&peer, now_ms_after),
        "peer missed {} consecutive vouchers — must be blacklisted per §3.11",
        WITHHOLDING_THRESHOLD,
    );
}

/// §3.11 WH-3: Any successful `MerkleNode` receipt from the peer resets
/// the counter. A peer who serves *something* isn't withholding.
#[test]
fn successful_receipt_resets_withholding_counter() {
    let now = Instant::now();
    let (mut engine, tp) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer = PhysicalDevicePk::from([0xAAu8; 32]);

    activate_session(&mut engine, peer, conv_id, now);

    let timeout_ms = tox_proto::constants::VOUCHER_TIMEOUT_MS as u64;
    let mut cursor = now;

    // First THRESHOLD-1 timeouts (one short of blacklist).
    for i in 0..(WITHHOLDING_THRESHOLD - 1) as u8 {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = i;
        let target = NodeHash::from(hash_bytes);
        let stamped_ms = (cursor - now).as_millis() as i64;
        setup_voucher(&mut engine, conv_id, peer, target, stamped_ms);
        tp.advance(Duration::from_millis(timeout_ms + 1_000));
        cursor += Duration::from_millis(timeout_ms + 1_000);
        let _ = engine.poll(cursor, &store, None).unwrap();
    }

    // Peer serves something — this must reset the counter.
    engine.reset_withholding_count(peer);

    // Another THRESHOLD-1 timeouts: should STILL not blacklist (counter
    // started fresh).
    for i in 0..(WITHHOLDING_THRESHOLD - 1) as u8 {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x80 | i;
        let target = NodeHash::from(hash_bytes);
        let stamped_ms = (cursor - now).as_millis() as i64;
        setup_voucher(&mut engine, conv_id, peer, target, stamped_ms);
        tp.advance(Duration::from_millis(timeout_ms + 1_000));
        cursor += Duration::from_millis(timeout_ms + 1_000);
        let _ = engine.poll(cursor, &store, None).unwrap();
    }

    let now_ms_after = (cursor - now).as_millis() as i64;
    assert!(
        !engine.is_blacklisted(&peer, now_ms_after),
        "peer served a node between timeout bursts — the counter must reset, \
         and the second burst must not re-trigger blacklist on its own",
    );
}
