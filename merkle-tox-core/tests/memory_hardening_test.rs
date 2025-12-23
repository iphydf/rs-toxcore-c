use std::cell::Cell;

/// A "Poisoned" wrapper for sensitive keys that tracks whether it has been zeroed.
/// This mimics what the 'zeroize' crate would do, but allows us to inspect state in tests.
struct SensitiveKey {
    _data: [u8; 32],
    is_zeroed: Cell<bool>,
}

impl SensitiveKey {
    fn new(data: [u8; 32]) -> Self {
        Self {
            _data: data,
            is_zeroed: Cell::new(false),
        }
    }

    fn zeroize(&self) {
        // In a real implementation, this would use core::ptr::write_volatile
        // or a similar mechanism to ensure the compiler doesn't optimize it away.
        self.is_zeroed.set(true);
    }
}

#[test]
fn test_security_mandate_memory_zeroing_principle() {
    // This test demonstrates the MANDATE from merkle-tox-ratchet.md:
    // "Implementations MUST overwrite old chain keys with zeros in memory."

    let key = SensitiveKey::new([0x42; 32]);
    assert!(!key.is_zeroed.get());

    // Simulate a ratchet step where the old key is cleared
    key.zeroize();

    assert!(
        key.is_zeroed.get(),
        "Sensitive key was not zeroed after use!"
    );
}

#[test]
fn test_engine_ratchet_key_persistence_leak() {
    use merkle_tox_core::clock::ManualTimeProvider;
    use merkle_tox_core::dag::{Content, PhysicalDeviceSk};
    use merkle_tox_core::engine::MerkleToxEngine;
    use merkle_tox_core::sync::NodeStore;
    use merkle_tox_core::testing::{InMemoryStore, TestRoom};
    use rand::SeedableRng;
    use std::sync::Arc;
    use std::time::Instant;

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Author message 1
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Msg 1".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 2. Author message 2 (advances ratchet)
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Msg 2".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node2 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. AUDIT: Does the store still contain the ratchet key for Msg 1?
    // According to the Forward Secrecy mandate, OLD keys should be deleted.
    // However, the current implementation (load_conversation_state) suggests we store keys for heads.
    // Once Node 2 is authored, Node 1 is no longer a head.

    let k1 = store.get_ratchet_key(&room.conv_id, &node1.hash()).unwrap();
    let k2 = store.get_ratchet_key(&room.conv_id, &node2.hash()).unwrap();

    assert!(k2.is_some(), "Current head ratchet key should be persisted");

    // This assertion will likely FAIL in the current implementation because
    // the store currently acts as a permanent log.
    assert!(
        k1.is_none(),
        "Protocol Violation: Old ratchet key for {} still exists in storage after ratchet advanced!",
        hex::encode(node1.hash().as_bytes())
    );
}
