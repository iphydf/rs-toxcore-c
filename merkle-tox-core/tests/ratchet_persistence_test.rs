use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, Permissions, PhysicalDeviceDhSk, PhysicalDeviceSk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::TestRoom;
use merkle_tox_core::testing::store::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;

use std::time::Instant;

#[test]
fn test_ratchet_state_lost_on_restart() {
    let _ = tracing_subscriber::fmt::try_init();
    // 1. Setup Environment
    let store = Arc::new(InMemoryStore::new());
    let room = TestRoom::new(2); // Alice and Bob
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];

    let time = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let rng = rand::rngs::StdRng::seed_from_u64(42);

    // 2. Initialize Alice (Online)
    let mut alice_engine = MerkleToxEngine::with_full_keys(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        PhysicalDeviceDhSk::from(merkle_tox_core::crypto::ed25519_sk_to_x25519(
            &alice_id.device_sk.to_bytes(),
        )),
        rng.clone(),
        time.clone(),
    );
    room.setup_engine(&mut alice_engine, &*store);

    // 3. Alice authors Node 1. This advances her internal ratchet state.
    // Node 1 is now in the store.
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Message 1".to_string()),
            vec![],
            &*store,
        )
        .expect("Failed to author node 1");
    let node1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &*store);

    // 4. Initialize Bob (Receiver)
    let mut bob_engine = MerkleToxEngine::with_full_keys(
        bob_id.device_pk,
        bob_id.master_pk,
        PhysicalDeviceSk::from(bob_id.device_sk.to_bytes()),
        PhysicalDeviceDhSk::from(merkle_tox_core::crypto::ed25519_sk_to_x25519(
            &bob_id.device_sk.to_bytes(),
        )),
        rng.clone(),
        time.clone(),
    );
    let bob_store = Arc::new(InMemoryStore::new());
    room.setup_engine(&mut bob_engine, &*bob_store);

    // Bob receives Node 1 and updates his ratchet state to match Alice's (post-Node 1)
    let effects = bob_engine
        .handle_node(room.conv_id, node1.clone(), &*bob_store, Some(&*bob_store))
        .expect("Bob failed to handle node 1");
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
    merkle_tox_core::testing::apply_effects(effects, &*bob_store);

    // 5. Simulate Alice Restart (The "Reload")
    // We create a NEW engine instance for Alice.
    // Crucially, we pass the SAME store, simulating persistence.
    let mut alice_restarted = MerkleToxEngine::with_full_keys(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        PhysicalDeviceDhSk::from(merkle_tox_core::crypto::ed25519_sk_to_x25519(
            &alice_id.device_sk.to_bytes(),
        )),
        rand::rngs::StdRng::seed_from_u64(999), // New session RNG
        time.clone(),
    );

    // In a real app, IdentityManager state is rebuilt from DB/Projection.
    // Since IdentityManager is pure memory in this mock, we restore it manually.
    for id in &room.identities {
        alice_restarted
            .identity_manager
            .add_member(room.conv_id, id.master_pk, 1, 0);
        id.authorize_in_engine(
            &mut alice_restarted,
            room.conv_id,
            Permissions::ALL,
            i64::MAX,
        );
    }

    // THIS IS THE TEST: Loading state from the store.
    // It *should* load the ratchet state (head_chains) so Alice knows where she left off.
    alice_restarted
        .load_conversation_state(room.conv_id, &*store)
        .expect("Failed to load state");

    // 6. Alice (Restarted) authors Node 2.
    // If she recovered her state, she will use the correct chain key derived from Node 1.
    // If she lost her state, she will default to the Epoch Root key.
    let effects = alice_restarted
        .author_node(
            room.conv_id,
            Content::Text("Message 2".to_string()),
            vec![],
            &*store,
        )
        .expect("Failed to author node 2");
    let node2 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &*store);

    // 7. Bob attempts to verify Node 2.
    // Bob has the correct state (he tracked Node 1).
    // If Alice used the wrong key, Bob will reject it.
    let effects = bob_engine
        .handle_node(room.conv_id, node2.clone(), &*bob_store, Some(&*bob_store))
        .expect("Bob failed to handle node 2");

    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&effects),
        "Bob should have verified the message from restarted Alice, proving that ratchet state was successfully persisted and restored."
    );
    merkle_tox_core::testing::apply_effects(effects, &*bob_store);
}
