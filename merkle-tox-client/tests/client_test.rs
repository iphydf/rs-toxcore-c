use merkle_tox_client::MerkleToxClient;
use merkle_tox_client::state::MemberRole;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, Permissions, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::identity::sign_delegation;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::{Transport, TransportError};
use merkle_tox_sqlite::Storage;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

struct MockTransport {
    local_pk: PhysicalDevicePk,
}

impl Transport for MockTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        self.local_pk
    }
    fn send_raw(&self, _to: PhysicalDevicePk, _data: Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_client_basic_actions() {
    let self_sk = [10u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
    let self_master_pk = LogicalIdentityPk::from(signing_key.verifying_key().to_bytes());
    let self_device_pk = PhysicalDevicePk::from(signing_key.verifying_key().to_bytes());
    let conversation_id = ConversationId::from([0xAA; 32]);

    let transport = MockTransport {
        local_pk: self_device_pk,
    };
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let engine = MerkleToxEngine::with_sk(
        self_device_pk,
        self_master_pk,
        PhysicalDeviceSk::from(self_sk),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let store = Storage::open_in_memory().unwrap();
    let node = Arc::new(Mutex::new(MerkleToxNode::new(engine, transport, store, tp)));

    let client = MerkleToxClient::new(node.clone(), conversation_id);

    // Initial state
    let state = client.state().await;
    assert_eq!(state.conversation_id, conversation_id);
    assert!(state.messages.is_empty());

    // Send a message. In this test, we manually trigger handle_event because
    // we haven't started the background orchestration loop.
    let (msg_hash, events) = {
        let mut node_lock = node.lock().await;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .author_node(
                conversation_id,
                Content::Text("Hello World".to_string()),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let n = effects
            .iter()
            .find_map(|e| {
                if let Effect::WriteStore(_, n, _) = e {
                    Some(n.clone())
                } else {
                    None
                }
            })
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        (n.hash(), events)
    };

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    // Verify state updated
    let state = client.state().await;
    assert_eq!(state.messages.len(), 1);
    assert_eq!(state.messages[0].hash, msg_hash);
    if let Content::Text(text) = &state.messages[0].content {
        assert_eq!(text, "Hello World");
    }

    // Set title
    let events = {
        let mut node_lock = node.lock().await;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .author_node(
                conversation_id,
                Content::Control(merkle_tox_core::dag::ControlAction::SetTitle(
                    "New Title".to_string(),
                )),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        events
    };

    for e in events {
        client.handle_event(e).await.unwrap();
    }
    let state = client.state().await;
    assert_eq!(state.title, "New Title");
}

#[tokio::test]
async fn test_client_membership_and_auth() {
    let self_sk = [10u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
    let self_master_pk = LogicalIdentityPk::from(signing_key.verifying_key().to_bytes());
    let self_device_pk = PhysicalDevicePk::from(signing_key.verifying_key().to_bytes());
    let conversation_id = ConversationId::from([0xAA; 32]);

    let transport = MockTransport {
        local_pk: self_device_pk,
    };
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let engine = MerkleToxEngine::with_sk(
        self_device_pk,
        self_master_pk,
        PhysicalDeviceSk::from(self_sk),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let store = Storage::open_in_memory().unwrap();
    let node = Arc::new(Mutex::new(MerkleToxNode::new(engine, transport, store, tp)));

    let client = MerkleToxClient::new(node.clone(), conversation_id);

    // Manually authorize self as admin in engine's identity manager so we can invite/authorize
    {
        let mut node_lock = node.lock().await;
        node_lock
            .engine
            .identity_manager
            .add_member(conversation_id, self_master_pk, 1, 0); // role 1 = admin

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
        let cert = sign_delegation(&signing_key, self_device_pk, Permissions::ALL, i64::MAX);

        node_lock
            .engine
            .identity_manager
            .authorize_device(conversation_id, self_master_pk, &cert, 0, 0)
            .unwrap();
    }

    // Invite Alice
    let alice_pk = LogicalIdentityPk::from([2u8; 32]);
    let events = {
        let mut node_lock = node.lock().await;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .author_node(
                conversation_id,
                Content::Control(merkle_tox_core::dag::ControlAction::Invite(
                    merkle_tox_core::dag::InviteAction {
                        invitee_pk: alice_pk,
                        role: 0,
                    },
                )),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        events
    };

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    let state = client.state().await;
    assert!(state.members.contains_key(&alice_pk));
    assert_eq!(
        state.members.get(&alice_pk).unwrap().role,
        MemberRole::Member
    );

    // Authorize Alice's device
    let alice_dev_pk = PhysicalDevicePk::from([22u8; 32]);
    let events = {
        let mut node_lock = node.lock().await;
        let node_ref = &mut *node_lock;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
        let cert = sign_delegation(&signing_key, alice_dev_pk, Permissions::MESSAGE, i64::MAX);
        let effects = node_ref
            .engine
            .author_node(
                conversation_id,
                Content::Control(merkle_tox_core::dag::ControlAction::AuthorizeDevice { cert }),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        events
    };

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    let state = client.state().await;
    assert!(state.authorized_devices.contains(&alice_dev_pk));
}

#[tokio::test]
async fn test_client_state_rebuild() {
    let self_sk = [10u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
    let self_master_pk = LogicalIdentityPk::from(signing_key.verifying_key().to_bytes());
    let self_device_pk = PhysicalDevicePk::from(signing_key.verifying_key().to_bytes());
    let conversation_id = ConversationId::from([0xAA; 32]);

    let transport = MockTransport {
        local_pk: self_device_pk,
    };
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let engine = MerkleToxEngine::with_sk(
        self_device_pk,
        self_master_pk,
        PhysicalDeviceSk::from(self_sk),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let store = Storage::open_in_memory().unwrap();
    let node = Arc::new(Mutex::new(MerkleToxNode::new(engine, transport, store, tp)));

    let client = MerkleToxClient::new(node.clone(), conversation_id);

    // 1. Setup initial state with some nodes
    let events = {
        let mut node_lock = node.lock().await;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .author_node(
                conversation_id,
                Content::Control(merkle_tox_core::dag::ControlAction::SetTitle(
                    "Initial Title".to_string(),
                )),
                vec![],
                &node_ref.store,
            )
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_ref
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        events
    };

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    // 2. Create a NEW client on the same node/store
    let client2 = MerkleToxClient::new(node.clone(), conversation_id);

    // client2 state is empty initially
    let state2 = client2.state().await;
    assert_eq!(state2.title, "");

    // 3. Refresh state from history
    client2.refresh_state().await.unwrap();

    let state2 = client2.state().await;
    assert_eq!(state2.title, "Initial Title");
    assert!(!state2.heads.is_empty());
}

#[tokio::test]
async fn test_client_automated_x3dh_onboarding() {
    let alice_sk = [10u8; 32];
    let alice_master_pk = LogicalIdentityPk::from(
        ed25519_dalek::SigningKey::from_bytes(&alice_sk)
            .verifying_key()
            .to_bytes(),
    );
    let alice_device_pk = PhysicalDevicePk::from(
        ed25519_dalek::SigningKey::from_bytes(&alice_sk)
            .verifying_key()
            .to_bytes(),
    );
    let conversation_id = ConversationId::from([0xAA; 32]);

    // Alice setup (Admin)
    let alice_transport = MockTransport {
        local_pk: alice_device_pk,
    };
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let alice_engine = MerkleToxEngine::with_sk(
        alice_device_pk,
        alice_master_pk,
        PhysicalDeviceSk::from(alice_sk),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let alice_store = Storage::open_in_memory().unwrap();
    let alice_node = Arc::new(Mutex::new(MerkleToxNode::new(
        alice_engine,
        alice_transport,
        alice_store,
        tp.clone(),
    )));
    let alice_client = MerkleToxClient::new(alice_node.clone(), conversation_id);

    // Bob setup (New device)
    let bob_sk = [20u8; 32];
    let bob_master_pk = LogicalIdentityPk::from(
        ed25519_dalek::SigningKey::from_bytes(&bob_sk)
            .verifying_key()
            .to_bytes(),
    );
    let bob_device_pk = PhysicalDevicePk::from(
        ed25519_dalek::SigningKey::from_bytes(&bob_sk)
            .verifying_key()
            .to_bytes(),
    );
    let bob_transport = MockTransport {
        local_pk: bob_device_pk,
    };
    let bob_engine = MerkleToxEngine::with_sk(
        bob_device_pk,
        bob_master_pk,
        PhysicalDeviceSk::from(bob_sk),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    let bob_store = Storage::open_in_memory().unwrap();
    let bob_node = Arc::new(Mutex::new(MerkleToxNode::new(
        bob_engine,
        bob_transport,
        bob_store,
        tp,
    )));
    let bob_client = MerkleToxClient::new(bob_node.clone(), conversation_id);

    // 1. Setup Alice as Admin
    {
        let mut node_lock = alice_node.lock().await;
        let MerkleToxNode { engine, store, .. } = &mut *node_lock;
        engine
            .identity_manager
            .add_member(conversation_id, alice_master_pk, 1, 0); // role 1 = admin

        // Also add Bob as member so Alice is willing to share the key with him
        engine
            .identity_manager
            .add_member(conversation_id, bob_master_pk, 0, 0);

        let cert = sign_delegation(
            &ed25519_dalek::SigningKey::from_bytes(&alice_sk),
            alice_device_pk,
            Permissions::ALL,
            i64::MAX,
        );
        engine
            .identity_manager
            .authorize_device(conversation_id, alice_master_pk, &cert, 0, 0)
            .unwrap();

        // Give Alice the conversation key
        let effects = engine
            .rotate_conversation_key(conversation_id, store)
            .unwrap();
        let now = node_lock.time_provider.now_instant();
        let now_ms = node_lock.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_lock
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }
    }
    alice_client.refresh_state().await.unwrap();

    // 2. Bob authors an Announcement
    let (_ann_node, ann_events) = {
        let mut node_lock = bob_node.lock().await;
        let MerkleToxNode { engine, store, .. } = &mut *node_lock;
        let effects = engine.author_announcement(conversation_id, store).unwrap();
        let n = effects
            .iter()
            .find_map(|e| {
                if let Effect::WriteStore(_, n, _) = e {
                    Some(n.clone())
                } else {
                    None
                }
            })
            .unwrap();
        let events: Vec<_> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::EmitEvent(ev) = e {
                    Some(ev.clone())
                } else {
                    None
                }
            })
            .collect();

        let now = node_lock.time_provider.now_instant();
        let now_ms = node_lock.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            node_lock
                .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                .unwrap();
        }

        (n, events)
    };

    // 3. Alice receives Bob's Announcement and should trigger automated X3DH
    for e in ann_events {
        alice_client.handle_event(e).await.unwrap();
    }

    // Capture Alice's responses. handle_event doesn't return messages, it authors them to store.
    let alice_heads = {
        let node_lock = alice_node.lock().await;
        node_lock.store.get_heads(&conversation_id)
    };

    // Alice should have authored a KeyWrap node
    let mut found_key_wrap = false;
    for head in alice_heads {
        let node = {
            let node_lock = alice_node.lock().await;
            node_lock.store.get_node(&head).unwrap()
        };
        if let Content::KeyWrap { .. } = node.content {
            found_key_wrap = true;

            // 4. Bob receives Alice's KeyWrap
            let (_, events) = {
                let mut node_lock = bob_node.lock().await;
                let MerkleToxNode { engine, store, .. } = &mut *node_lock;
                let effects = engine
                    .handle_node(conversation_id, node, store, None)
                    .unwrap();
                let events: Vec<_> = effects
                    .iter()
                    .filter_map(|e| {
                        if let Effect::EmitEvent(ev) = e {
                            Some(ev.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                let now = node_lock.time_provider.now_instant();
                let now_ms = node_lock.time_provider.now_system_ms() as u64;
                let mut dummy_wakeup = now;
                for effect in effects {
                    node_lock
                        .process_effect(effect, now, now_ms, &mut dummy_wakeup)
                        .unwrap();
                }

                ((), events)
            };
            for e in events {
                bob_client.handle_event(e).await.unwrap();
            }
            break;
        }
    }

    assert!(
        found_key_wrap,
        "Alice should have automatically authored a KeyWrap node for Bob"
    );

    // 5. Verify Bob now has the conversation key
    let bob_has_key = {
        let node_lock = bob_node.lock().await;
        node_lock
            .engine
            .conversations
            .get(&conversation_id)
            .map(|c| c.is_established())
            .unwrap_or(false)
    };
    assert!(
        bob_has_key,
        "Bob should have received the conversation key via automated X3DH"
    );
}
