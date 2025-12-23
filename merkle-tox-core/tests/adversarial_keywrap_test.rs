use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, PhysicalDeviceSk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{InMemoryStore, TestRoom};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_key_wrap_two_time_pad_vulnerability() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room with Alice and Bob
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(0),
        tp.clone(),
    );

    room.setup_engine(&mut alice_engine, &store);

    // 2. Alice performs first rotation (Epoch 1)
    let effects1 = alice_engine
        .rotate_conversation_key(room.conv_id, &store)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects1.clone(), &store);

    let k_conv1 = effects1
        .iter()
        .find_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteConversationKey(_, epoch, k) = e
                && *epoch == 1
            {
                return Some(k.clone());
            }
            None
        })
        .expect("Epoch 1 key not found");

    let wrap1 = effects1
        .iter()
        .find_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e
                && let Content::KeyWrap { wrapped_keys, .. } = &node.content
            {
                return wrapped_keys
                    .iter()
                    .find(|w| w.recipient_pk == bob_id.device_pk)
                    .cloned();
            }
            None
        })
        .expect("KeyWrap for Bob in Epoch 1 not found");

    // 3. Alice performs second rotation (Epoch 2)
    let effects2 = alice_engine
        .rotate_conversation_key(room.conv_id, &store)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects2.clone(), &store);

    let k_conv2 = effects2
        .iter()
        .find_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteConversationKey(_, epoch, k) = e
                && *epoch == 2
            {
                return Some(k.clone());
            }
            None
        })
        .expect("Epoch 2 key not found");

    let wrap2 = effects2
        .iter()
        .find_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e
                && let Content::KeyWrap { wrapped_keys, .. } = &node.content
            {
                return wrapped_keys
                    .iter()
                    .find(|w| w.recipient_pk == bob_id.device_pk)
                    .cloned();
            }
            None
        })
        .expect("KeyWrap for Bob in Epoch 2 not found");

    // 4. Demonstrate Two-Time Pad
    // If the vulnerability exists, wrap1.ciphertext ^ k_conv1 == wrap2.ciphertext ^ k_conv2
    // which is the same as wrap1.ciphertext ^ wrap2.ciphertext == k_conv1 ^ k_conv2

    let mut c_xor = [0u8; 32];
    for (c, (w1, w2)) in c_xor
        .iter_mut()
        .zip(wrap1.ciphertext.iter().zip(&wrap2.ciphertext))
    {
        *c = w1 ^ w2;
    }

    let mut k_xor = [0u8; 32];
    for (k, (k1, k2)) in k_xor
        .iter_mut()
        .zip(k_conv1.as_bytes().iter().zip(k_conv2.as_bytes().iter()))
    {
        *k = k1 ^ k2;
    }

    assert_ne!(
        c_xor, k_xor,
        "VULNERABILITY DETECTED: Two-time pad in KeyWrap! Keystream is reused across rotations."
    );
}
