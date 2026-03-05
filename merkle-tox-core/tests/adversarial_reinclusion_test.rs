//! Adversarial coverage for `ProtocolMessage::ReinclusionRequest`.
//!
//! The handler at `handlers/mod.rs:925-1001` splits trust between two
//! sender identifiers:
//!
//!   - `requester_pk` — a *payload* field the peer supplies freely;
//!     used to decide whether the request is authorised (snapshot
//!     member lookup).
//!   - `sender_pk` — the *transport-authenticated* friend-connection
//!     public key; used as the recipient of the `ReinclusionResponse`
//!     and (via `rotate_conversation_key`) receives the fresh KeyWrap.
//!
//! Any peer can forge `ReinclusionRequest { sender_pk: Bob_pk, ... }`
//! while actually being Carol. The admin validates "Bob is a snapshot
//! member" (true) and runs the rotation. Two concrete harms:
//!
//!   1. Forced k_conv rotation DoS — any peer triggers a rotation.
//!   2. Membership-leak oracle — the `accepted: true/false` response
//!      confirms whether a named logical key is in a given snapshot.
//!
//! Fix: require `sender_pk == requester_pk` at the top of the match
//! arm — the transport layer already authenticates `sender_pk`.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ControlAction, ConversationId, MemberInfo, NodeHash, Permissions, PhysicalDeviceSk,
    SnapshotData,
};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow, make_cert,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

struct Scenario {
    alice: TestIdentity,
    bob: TestIdentity,
    carol: TestIdentity,
    conv_id: ConversationId,
    snapshot_hash: NodeHash,
    engine: MerkleToxEngine,
    store: InMemoryStore,
}

fn setup_scenario() -> Scenario {
    let _ = tracing_subscriber::fmt::try_init();
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let carol = TestIdentity::new();
    let conv_id = ConversationId::from([0xA5u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(0xA11CE),
        tp,
    );
    let store = InMemoryStore::new();

    // Genesis so Alice is founder (admin).
    let genesis = create_genesis_pow(&conv_id, &alice, "Reinclusion §KW-R test");
    let effects = engine
        .handle_node(conv_id, genesis.clone(), &store, None)
        .expect("genesis");
    apply_effects(effects, &store);

    // AnchorSnapshot listing Bob as a member. Carol is NOT named.
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    let snapshot = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis.hash()],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: genesis.hash(),
                members: tox_proto::bounded_vec![MemberInfo {
                    public_key: bob.master_pk,
                    role: 1,
                    joined_at: 1000,
                }],
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
            cert,
        },
        1,
        2,
        1000,
    );
    let snapshot_hash = snapshot.hash();
    let effects = engine
        .handle_node(conv_id, snapshot.clone(), &store, None)
        .expect("anchor snapshot");
    apply_effects(effects, &store);

    Scenario {
        alice,
        bob,
        carol,
        conv_id,
        snapshot_hash,
        engine,
        store,
    }
}

fn has_reinclusion_response(effects: &[Effect]) -> bool {
    effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(_, ProtocolMessage::ReinclusionResponse { .. })
        )
    })
}

/// §KW-R-1 — A request whose transport `sender_pk` does not match the
/// payload `requester_pk` must be silently dropped. The admin
/// (self) must not emit any response, and must not trigger a k_conv
/// rotation. Carol (not a snapshot member) impersonates Bob (member).
#[test]
fn test_forged_reinclusion_request_from_non_matching_sender_is_dropped() {
    let mut s = setup_scenario();

    let effects = s
        .engine
        .handle_message(
            s.carol.device_pk, // transport-authenticated = Carol
            ProtocolMessage::ReinclusionRequest {
                conversation_id: s.conv_id,
                // Lie: payload claims Bob, but transport is Carol.
                sender_pk: tox_proto::Claimed::new(s.bob.device_pk),
                healing_snapshot_hash: s.snapshot_hash,
            },
            &s.store,
            None,
        )
        .expect("handle_message");

    assert!(
        !has_reinclusion_response(&effects),
        "forged ReinclusionRequest must not elicit any response — the \
         response acts as a membership-leak oracle (confirms whether \
         the named logical key is in the snapshot)",
    );

    // No rotation side-effects either. If the fix erroneously
    // returned early but still ran rotation, we'd see `WriteStore`
    // effects for new admin nodes. Catch that by asserting we did
    // not produce any node-write effects.
    let node_writes: Vec<_> = effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteStore { .. }))
        .collect();
    assert!(
        node_writes.is_empty(),
        "forged ReinclusionRequest must not trigger a k_conv rotation \
         (would be observable as new admin-track nodes) — got {} \
         WriteStore effects",
        node_writes.len(),
    );
}

/// §KW-R-2 — Regression guard: a *legitimate* request (Bob as both
/// transport sender and payload sender) must still be accepted and
/// produce a `ReinclusionResponse`. Pairs with the adversarial case
/// above so the fix can't be "reject everything".
#[test]
fn test_legitimate_reinclusion_request_still_accepted() {
    let mut s = setup_scenario();

    let effects = s
        .engine
        .handle_message(
            s.bob.device_pk,
            ProtocolMessage::ReinclusionRequest {
                conversation_id: s.conv_id,
                sender_pk: tox_proto::Claimed::new(s.bob.device_pk),
                healing_snapshot_hash: s.snapshot_hash,
            },
            &s.store,
            None,
        )
        .expect("handle_message");

    assert!(
        has_reinclusion_response(&effects),
        "genuine ReinclusionRequest from a snapshot member must be \
         answered (accepted or denied based on snapshot contents) — \
         not silently dropped",
    );
}

/// §KW-R-3 — A request whose transport sender matches the payload but
/// names a *non-member* (Carol herself) must be denied, not dropped.
/// This ensures the sender-binding fix doesn't accidentally bypass
/// the pre-existing snapshot-membership check.
#[test]
fn test_reinclusion_request_from_non_member_is_denied() {
    let mut s = setup_scenario();
    // Silence unused warnings for fields we carry around.
    let _ = (&s.alice, &s.bob);

    let effects = s
        .engine
        .handle_message(
            s.carol.device_pk,
            ProtocolMessage::ReinclusionRequest {
                conversation_id: s.conv_id,
                sender_pk: tox_proto::Claimed::new(s.carol.device_pk),
                healing_snapshot_hash: s.snapshot_hash,
            },
            &s.store,
            None,
        )
        .expect("handle_message");

    let denied = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(
                _,
                ProtocolMessage::ReinclusionResponse {
                    accepted: false,
                    ..
                },
            )
        )
    });
    assert!(
        denied,
        "non-member legitimate requester must be denied (accepted=false), \
         proving the membership check still fires after the sender gate",
    );
}

/// Bob-as-self scenario: Bob runs his own engine and is authorised
/// into Alice's conversation with `MESSAGE` permission only — NOT
/// admin. Even when the incoming request is perfectly legitimate at
/// the sender-binding and snapshot-membership level, Bob must not
/// respond: he has no authority to issue a `KeyWrap` rotation, so
/// emitting a `ReinclusionResponse` would be both useless and a
/// membership-leak oracle.
///
/// This scenario depends on `is_admin(self_pk, self_logical_pk)`
/// working correctly for non-founder devices. An earlier version of
/// the handler called `is_admin(self_pk, self_pk.to_logical())` —
/// the `to_logical()` call produces a synthetic logical identity
/// with the same bytes as the device PK, so `get_permissions`
/// hits the founder shortcut (`device_pk == logical_pk.to_physical()`)
/// and always returns `Permissions::ALL`. That silently turned the
/// admin gate into a no-op for every device.
fn setup_bob_as_non_admin_self() -> (MerkleToxEngine, InMemoryStore, ConversationId, TestIdentity) {
    let _ = tracing_subscriber::fmt::try_init();
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let member = TestIdentity::new();
    let conv_id = ConversationId::from([0xB0u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(0xB0B),
        tp,
    );
    let store = InMemoryStore::new();

    let genesis = create_genesis_pow(&conv_id, &alice, "Reinclusion §KW-R-4 test");
    let effects = bob_engine
        .handle_node(conv_id, genesis.clone(), &store, None)
        .expect("genesis");
    apply_effects(effects, &store);

    // Alice authorises Bob as MESSAGE-only. This cert is what makes
    // Bob a non-admin — anything checking `is_admin(bob.device_pk,
    // bob.master_pk)` must return false.
    let cert = make_cert(
        &alice.master_sk,
        bob.device_pk,
        Permissions::MESSAGE,
        9_999_999,
        conv_id,
    );
    let auth_bob = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis.hash()],
        ControlAction::AuthorizeDevice { cert },
        1,
        2,
        1000,
    );
    let effects = bob_engine
        .handle_node(conv_id, auth_bob, &store, None)
        .expect("authorize bob");
    apply_effects(effects, &store);

    // Publish a snapshot listing `member` so the ReinclusionRequest
    // membership check would otherwise pass. Founder signs it.
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    let snapshot = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis.hash()],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: genesis.hash(),
                members: tox_proto::bounded_vec![MemberInfo {
                    public_key: member.master_pk,
                    role: 1,
                    joined_at: 1000,
                }],
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
            cert,
        },
        2,
        3,
        2000,
    );
    let snapshot_hash = snapshot.hash();
    let effects = bob_engine
        .handle_node(conv_id, snapshot.clone(), &store, None)
        .expect("anchor snapshot");
    apply_effects(effects, &store);

    // Return `member` under a sentinel hash so the test can construct
    // a request pointing at the right snapshot.
    let mut member = member;
    member.device_sk = ed25519_dalek::SigningKey::from_bytes(snapshot_hash.as_bytes());
    (bob_engine, store, conv_id, member)
}

/// §KW-R-4 — When self is not an admin, ReinclusionRequest must be
/// silently dropped even for a perfectly legitimate request
/// (sender_pk matches requester_pk matches a snapshot member).
/// Today's handler uses `is_admin(self_pk, self_pk.to_logical())`,
/// which hits the founder shortcut in `get_permissions_recursive`
/// and always returns true — turning the admin gate into a no-op.
/// The fix is to pair `self_pk` with the real `self_logical_pk`.
#[test]
fn test_reinclusion_request_silently_dropped_when_self_is_not_admin() {
    let (mut bob_engine, store, conv_id, member) = setup_bob_as_non_admin_self();
    // `member.device_sk` was repurposed above to carry the snapshot hash.
    let snapshot_hash = NodeHash::from(*member.device_sk.as_bytes());
    // Use `member.device_pk` as both transport sender and claim —
    // perfectly matched, no forgery. The only defect is that Bob
    // (self) is not an admin.
    let effects = bob_engine
        .handle_message(
            member.device_pk,
            ProtocolMessage::ReinclusionRequest {
                conversation_id: conv_id,
                sender_pk: tox_proto::Claimed::new(member.device_pk),
                healing_snapshot_hash: snapshot_hash,
            },
            &store,
            None,
        )
        .expect("handle_message");

    let response_emitted = effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendPacket(_, ProtocolMessage::ReinclusionResponse { .. }),
        )
    });
    assert!(
        !response_emitted,
        "self is a MESSAGE-only device; the handler must not emit any \
         ReinclusionResponse — the admin check is the load-bearing \
         gate, and it must use self_logical_pk (not the synthetic \
         self_pk.to_logical()) or the founder shortcut makes it a no-op",
    );
}
