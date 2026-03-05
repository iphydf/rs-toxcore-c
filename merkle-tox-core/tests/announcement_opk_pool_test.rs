//! OPK pool-size regression tests.
//!
//! Per `doc/planning/constants-cost-reference.md` §2 and
//! `merkle-tox-handshake-ecies.md`: each OPK in an Announcement is
//! consumed by exactly one X3DH handshake. When a user returns from
//! offline and finds K pending inbound handshakes, the first
//! `(opk_pool_size - 1)` consume fresh OPKs (full forward secrecy);
//! the remainder fall back to `last_resort_key` (weaker FS — single
//! long-lived key, no per-handshake forward secrecy).
//!
//! By the consumption convention in `engine/mod.rs::consume_recipient_opk`,
//! `pre_keys[0]` is treated as the SPK (never consumed); `pre_keys[1..]`
//! are the OPK pool. So `available_opks = pre_keys.len() - 1`.
//!
//! These tests guard against a regression where a future change to
//! `engine/authoring.rs::author_announcement` reduces the runtime OPK
//! count below what typical and worst-case offline-returner scenarios
//! need.

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{Content, ControlAction, KConv, Permissions, PhysicalDeviceSk};
use merkle_tox_core::engine::{Conversation, ConversationData, MerkleToxEngine, conversation};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestIdentity};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// Authors an Announcement and returns its `pre_keys` length.
fn author_announcement_pool_size() -> usize {
    let rng = StdRng::seed_from_u64(42);
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp,
    );
    let store = InMemoryStore::new();

    // Minimal conversation bootstrap so author_announcement has somewhere to
    // attach. We don't need a peer here; the test inspects only the
    // generated `pre_keys` count from the local-author flow.
    let k_conv = KConv::from([0x42u8; 32]);
    let _ = ConversationKeys::derive(&k_conv);
    let conv_id = merkle_tox_core::dag::ConversationId::from([0x77u8; 32]);

    engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 0, 0);
    let cert = alice.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
    let ctx = merkle_tox_core::identity::CausalContext::global();
    engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    let now = engine.clock.network_time_ms();
    store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id, k_conv, now,
        )),
    );

    let effects = engine.author_announcement(conv_id, &store).unwrap();
    let ann_node = merkle_tox_core::testing::get_node_from_effects(effects);

    match &ann_node.content {
        Content::Control(ControlAction::Announcement { pre_keys, .. }) => pre_keys.len(),
        _ => panic!("expected Announcement content"),
    }
}

/// Minimum bar: an Announcement must carry at least enough OPKs to handle
/// the typical-user offline-returner scenario from
/// `doc/planning/constants-cost-reference.md` §2.
///
/// Scenario: a user offline ~30 days returns to ~8 pending inbound
/// X3DH handshakes (a reasonable mean for a user with ~10 active
/// conversations and modest inbound rotation). All 8 must consume
/// fresh OPKs; none must fall back to `last_resort_key`. With 1 SPK +
/// N OPKs in `pre_keys`, available OPKs = N. We need N ≥ 8, i.e.,
/// `pre_keys.len() ≥ 9`.
///
/// At the historical pool=5 (1 SPK + 4 OPKs), 4 of 8 incoming
/// handshakes fall to `last_resort_key`, a 50% FS regression. This
/// test fails in that configuration and passes once the runtime
/// default is raised.
#[test]
fn test_announcement_provides_enough_opks_for_typical_offline_returner() {
    let pool_size = author_announcement_pool_size();
    let available_opks = pool_size.saturating_sub(1); // first entry is SPK
    assert!(
        available_opks >= 8,
        "Announcement carries only {} OPKs (pre_keys.len()={}). \
         A typical user returning after ~30 days with ~8 pending \
         inbound handshakes needs ≥8 fresh OPKs to avoid falling \
         through to `last_resort_key` (weaker FS). See \
         doc/planning/constants-cost-reference.md §2.",
        available_opks,
        pool_size,
    );
}

/// Stronger bar: heavy-user worst-case offline-returner scenario.
///
/// Scenario: a heavy user (50 active conversations) offline 60+ days
/// returns to ~50 pending inbound handshakes. Pool=5 fails 46/50 = 92%
/// to `last_resort_key`. Pool=64 (recommended) leaves 0 fall-throughs.
/// This test asserts pool ≥ 50 — well below the cap of 100 but enough
/// to protect the heavy-user offline-returner case.
#[test]
fn test_announcement_provides_enough_opks_for_heavy_user_offline() {
    let pool_size = author_announcement_pool_size();
    let available_opks = pool_size.saturating_sub(1);
    assert!(
        available_opks >= 50,
        "Announcement carries only {} OPKs. A heavy user (50 \
         active conversations) offline 60+ days returning to ~50 \
         pending inbound handshakes needs ≥50 fresh OPKs. Cap is \
         100 (MAX_HANDSHAKES_PER_ANNOUNCEMENT); recommended runtime \
         default per cost-reference §2 is 64.",
        available_opks,
    );
}

/// Upper bar: don't exceed the type-level cap.
///
/// `MAX_HANDSHAKES_PER_ANNOUNCEMENT = 100` is the `BoundedVec` capacity.
/// If a future change exceeds this, the `try_push` in `author_announcement`
/// will panic. This test asserts we stay within the cap with margin.
#[test]
fn test_announcement_pool_size_within_cap() {
    let pool_size = author_announcement_pool_size();
    let cap = tox_proto::constants::MAX_HANDSHAKES_PER_ANNOUNCEMENT as usize;
    assert!(
        pool_size <= cap,
        "Announcement pool size {} exceeds cap of {}; \
         author_announcement would have panicked on try_push.",
        pool_size,
        cap,
    );
}
