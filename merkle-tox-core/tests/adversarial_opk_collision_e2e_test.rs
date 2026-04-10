//! §3.8 OPK Collision History Erasure — end-to-end integration test.
//!
//! Companion to `adversarial_opk_collision_test.rs` (which pins the
//! primitives). This exercises the full `handle_node` flow with two
//! valid, signed KeyWrap nodes from competing admins targeting the
//! same OPK. The attribution recorded in `consumed_opk_ids` must
//! resolve to the senior admin (Alice) regardless of arrival order;
//! otherwise a malicious junior admin could grind ephemeral keys to
//! retroactively orphan the senior's KeyWrap and its descendants.

use merkle_tox_core::crypto::ecies_wrap;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EphemeralX25519Pk, EphemeralX25519Sk, KConv, NodeHash,
    Permissions, PhysicalDeviceSk, WrappedKey,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    apply_effects, create_admin_node, create_genesis_pow, make_cert, sign_admin_node, test_node,
    InMemoryStore, TestIdentity,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

struct Scenario {
    alice: TestIdentity,
    bob: TestIdentity,
    charlie: TestIdentity,
    conv_id: ConversationId,
    genesis: merkle_tox_core::dag::MerkleNode,
    auth_alice: merkle_tox_core::dag::MerkleNode,
    auth_bob: merkle_tox_core::dag::MerkleNode,
    charlie_opk_pk: EphemeralX25519Pk,
    charlie_opk_id: NodeHash,
    alice_keywrap: merkle_tox_core::dag::MerkleNode,
    bob_keywrap: merkle_tox_core::dag::MerkleNode,
}

fn build_scenario() -> Scenario {
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([0x3Au8; 32]);

    // Genesis: alice as founder (rank 0 / logical member).
    let genesis = create_genesis_pow(&conv_id, &alice, "§3.8 e2e OPK Collision");

    // AuthorizeDevice(alice) at rank 1 — self-delegation puts alice.device_pk
    // into authorized_devices with ADMIN permission. Required so her
    // KeyWrap hits the `if is_authorized` branch at verification.rs:362
    // where the OPK collision resolution lives.
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    let auth_alice = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1, // rank 1
        1,
        1000,
    );

    // AuthorizeDevice(bob) at rank 2 — bob authorizes his own device.
    // Junior to alice by auth_rank (1 < 2).
    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    let auth_bob = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.master_sk,
        vec![auth_alice.hash()],
        ControlAction::AuthorizeDevice { cert: bob_cert },
        2, // rank 2
        1,
        1000,
    );

    // Charlie's OPK (X25519 keypair). Both KeyWraps wrap to this OPK.
    let charlie_opk_sk_bytes = [0x42u8; 32];
    let x_sk = x25519_dalek::StaticSecret::from(charlie_opk_sk_bytes);
    let charlie_opk_pk =
        EphemeralX25519Pk::from(x25519_dalek::PublicKey::from(&x_sk).to_bytes());
    let charlie_opk_id = NodeHash::from(*blake3::hash(charlie_opk_pk.as_bytes()).as_bytes());

    // Two distinct k_conv values so a spurious decrypt would reveal which
    // admin's payload was accepted.
    let k_conv_alice = KConv::from([0xA1u8; 32]);
    let k_conv_bob = KConv::from([0xB2u8; 32]);

    let alice_keywrap = build_keywrap(
        &conv_id,
        &alice,
        &[auth_bob.hash()],
        3,         // rank 3: later than auth_bob (rank 2)
        2,         // seq 2 for alice.device_sk (genesis used seq 1)
        &charlie_opk_pk,
        charlie_opk_id,
        &k_conv_alice,
    );

    let bob_keywrap = build_keywrap(
        &conv_id,
        &bob,
        &[auth_bob.hash()],
        3,         // rank 3: concurrent with alice_keywrap
        2,         // seq 2 for bob.device_sk (auth_bob used seq 1)
        &charlie_opk_pk,
        charlie_opk_id,
        &k_conv_bob,
    );

    Scenario {
        alice,
        bob,
        charlie,
        conv_id,
        genesis,
        auth_alice,
        auth_bob,
        charlie_opk_pk,
        charlie_opk_id,
        alice_keywrap,
        bob_keywrap,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_keywrap(
    conv_id: &ConversationId,
    sender: &TestIdentity,
    parents: &[NodeHash],
    rank: u64,
    seq: u64,
    charlie_opk_pk: &EphemeralX25519Pk,
    charlie_opk_id: NodeHash,
    k_conv_to_wrap: &KConv,
) -> merkle_tox_core::dag::MerkleNode {
    // Sender's ECIES ephemeral keypair.
    let eph_sk_bytes = {
        // Derive a deterministic per-sender ephemeral key so test failures
        // are reproducible. Mixing in the device_pk gives distinct keys.
        let mut bytes = [0u8; 32];
        for (i, b) in sender.device_pk.as_bytes().iter().enumerate() {
            bytes[i] = b ^ 0x5A;
        }
        bytes
    };
    let eph_sk = EphemeralX25519Sk::from(eph_sk_bytes);
    let eph_x_sk = x25519_dalek::StaticSecret::from(eph_sk_bytes);
    let eph_pk = EphemeralX25519Pk::from(x25519_dalek::PublicKey::from(&eph_x_sk).to_bytes());

    // Use charlie's OPK as the SPK slot (simplifies the test — receiver's
    // ephemeral_keys contains the OPK, and the receiver tries every entry
    // as an SPK candidate in verification.rs).
    // Wrap to charlie's OPK as both the SPK slot AND the OPK slot, so
    // the wrap material matches what the receiver computes during
    // unwrap (`ecies_unwrap_32` includes the OPK contribution
    // whenever `find_opk_sk(opk_id)` returns Some, which it does
    // here because we provisioned charlie_opk_pk in
    // `ephemeral_keys`). Necessary post-2a-fix because
    // `consumed_opk_ids` insert is now conditional on successful
    // decryption — the test cannot rely on pre-claim to populate it.
    let ciphertext = ecies_wrap(
        &eph_sk,
        charlie_opk_pk,       // SPK slot
        Some(charlie_opk_pk), // OPK slot (same key in this test fixture)
        None,
        k_conv_to_wrap.as_bytes(),
    );

    let wrapped = WrappedKey {
        recipient_pk: {
            // We wrap to the recipient *device* in the receiver's engine.
            // Set this via caller; store it here using a marker and fix up below.
            merkle_tox_core::dag::PhysicalDevicePk::from([0u8; 32])
        },
        ciphertext,
        opk_id: charlie_opk_id,
    };

    let mut node = test_node();
    node.author_pk = sender.master_pk;
    node.parents = tox_proto::BoundedVec::try_from_iter(parents.iter().cloned())
        .expect("test fixtures must respect MAX_PARENTS");
    node.content = Content::KeyWrap {
        generation: 1,
        anchor_hash: NodeHash::from([0u8; 32]),
        ephemeral_pk: eph_pk,
        wrapped_keys: tox_proto::bounded_vec![wrapped],
    };
    node.topological_rank = rank;
    node.sequence_number = seq;
    node.network_timestamp = 2000;
    sign_admin_node(&mut node, conv_id, &sender.device_sk);
    node
}

fn charlie_engine_with_setup(scenario: &Scenario) -> (MerkleToxEngine, InMemoryStore) {
    let tp = Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(
        Instant::now(),
        3000,
    ));

    let mut charlie_engine = MerkleToxEngine::with_sk(
        scenario.charlie.device_pk,
        scenario.charlie.master_pk,
        PhysicalDeviceSk::from(scenario.charlie.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();

    for node in [&scenario.genesis, &scenario.auth_alice, &scenario.auth_bob] {
        let effects = charlie_engine
            .handle_node(scenario.conv_id, node.clone(), &store, None)
            .expect("admin chain node");
        apply_effects(effects, &store);
    }

    // Manually add bob and charlie as logical members so list_members > 2
    // triggers the group tie-breaker in OPK collision resolution.
    charlie_engine
        .identity_manager
        .add_member(scenario.conv_id, scenario.bob.master_pk, 1, 1000);
    charlie_engine
        .identity_manager
        .add_member(scenario.conv_id, scenario.charlie.master_pk, 1, 1000);

    // Provision charlie's OPK keypair so ECIES unwrap can find it.
    let charlie_opk_sk = EphemeralX25519Sk::from([0x42u8; 32]);
    charlie_engine
        .ephemeral_keys
        .insert(scenario.charlie_opk_pk, charlie_opk_sk);

    (charlie_engine, store)
}

fn keywrap_with_recipient(
    template: &merkle_tox_core::dag::MerkleNode,
    recipient: merkle_tox_core::dag::PhysicalDevicePk,
    conv_id: &ConversationId,
    signer: &ed25519_dalek::SigningKey,
) -> merkle_tox_core::dag::MerkleNode {
    let mut node = template.clone();
    if let Content::KeyWrap { wrapped_keys, .. } = &mut node.content {
        for w in wrapped_keys.iter_mut() {
            w.recipient_pk = recipient;
        }
    }
    sign_admin_node(&mut node, conv_id, signer);
    node
}

fn drive_collision(alice_first: bool) -> (merkle_tox_core::dag::PhysicalDevicePk, merkle_tox_core::dag::PhysicalDevicePk) {
    let scenario = build_scenario();
    let (mut engine, store) = charlie_engine_with_setup(&scenario);

    // Fix up each keywrap's recipient_pk to charlie's device, then re-sign
    // (recipient_pk is inside the content, which is part of the signature).
    let alice_kw = keywrap_with_recipient(
        &scenario.alice_keywrap,
        scenario.charlie.device_pk,
        &scenario.conv_id,
        &scenario.alice.device_sk,
    );
    let bob_kw = keywrap_with_recipient(
        &scenario.bob_keywrap,
        scenario.charlie.device_pk,
        &scenario.conv_id,
        &scenario.bob.device_sk,
    );

    let (first, second) = if alice_first {
        (&alice_kw, &bob_kw)
    } else {
        (&bob_kw, &alice_kw)
    };

    let first_effects = engine
        .handle_node(scenario.conv_id, first.clone(), &store, None)
        .expect("first keywrap");
    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&first_effects),
        "first KeyWrap must verify (precondition for collision path)",
    );
    apply_effects(first_effects, &store);
    let second_effects = engine
        .handle_node(scenario.conv_id, second.clone(), &store, None)
        .expect("second keywrap");
    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&second_effects),
        "second KeyWrap must verify (precondition for collision path)",
    );
    apply_effects(second_effects, &store);

    let (_, winner_sender, _) = engine
        .consumed_opk_ids
        .get(&scenario.charlie_opk_id)
        .copied()
        .expect("consumed_opk_ids must record the winner after collision");
    (winner_sender, scenario.alice.device_pk)
}

#[test]
fn test_opk_collision_alice_first_alice_wins() {
    let (winner, alice_device_pk) = drive_collision(true);
    assert_eq!(
        winner, alice_device_pk,
        "Alice (senior, rank 0) must win the OPK collision when her \
         KeyWrap arrives first — her consumed_opk_ids entry must persist \
         across Bob's junior challenge",
    );
}

#[test]
fn test_opk_collision_bob_first_alice_still_wins() {
    let (winner, alice_device_pk) = drive_collision(false);
    assert_eq!(
        winner, alice_device_pk,
        "Alice (senior, rank 0) must win the OPK collision even when \
         Bob's KeyWrap is processed first. If attribution depended on \
         arrival order, a malicious junior admin could grind ephemeral \
         keys to retroactively orphan the senior's KeyWrap (§3.8)",
    );
}
