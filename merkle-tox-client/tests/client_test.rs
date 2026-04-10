use merkle_tox_client::MerkleToxClient;
use merkle_tox_client::policy::PolicyHandler;
use merkle_tox_client::state::{ClientEvent, MemberRole};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ConversationId, Ed25519Signature, EmojiSource, LogicalIdentityPk, MerkleNode,
    NodeAuth, NodeHash, Permissions, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::identity::sign_delegation;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::{NodeEvent, Transport, TransportError};
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
        let cert = sign_delegation(
            &signing_key,
            self_device_pk,
            Permissions::ALL,
            i64::MAX,
            conversation_id,
        );

        let ctx = merkle_tox_core::identity::CausalContext::global();
        node_lock
            .engine
            .identity_manager
            .authorize_device(
                &ctx,
                conversation_id,
                self_master_pk,
                &cert,
                0,
                0,
                merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            )
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
        let cert = sign_delegation(
            &signing_key,
            alice_dev_pk,
            Permissions::MESSAGE,
            i64::MAX,
            conversation_id,
        );
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
            conversation_id,
        );
        let ctx = merkle_tox_core::identity::CausalContext::global();
        engine
            .identity_manager
            .authorize_device(
                &ctx,
                conversation_id,
                alice_master_pk,
                &cert,
                0,
                0,
                merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            )
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
        let mut heads = node_lock.store.get_heads(&conversation_id);
        // KeyWrap nodes are admin-type, so also check admin heads.
        for h in node_lock.store.get_admin_heads(&conversation_id) {
            if !heads.contains(&h) {
                heads.push(h);
            }
        }
        heads
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

// --- Helper ---

fn make_test_node(content: Content, author_pk: LogicalIdentityPk) -> MerkleNode {
    MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk,
        sender_pk: PhysicalDevicePk::from(*author_pk.as_bytes()),
        sequence_number: 1,
        topological_rank: 1,
        network_timestamp: 1000,
        content,
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    }
}

type TestNode = Arc<Mutex<MerkleToxNode<MockTransport, Storage>>>;

fn setup_client() -> (
    TestNode,
    MerkleToxClient<MockTransport, Storage>,
    ConversationId,
) {
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
    (node, client, conversation_id)
}

/// Author a node on the engine and return its hash + emitted NodeEvents.
async fn author_and_process(
    node: &TestNode,
    conversation_id: ConversationId,
    content: Content,
) -> (NodeHash, Vec<NodeEvent>) {
    let mut node_lock = node.lock().await;
    let node_ref = &mut *node_lock;
    let effects = node_ref
        .engine
        .author_node(conversation_id, content, Vec::new(), &node_ref.store)
        .unwrap();

    let hash = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, n, _) = e {
                Some(n.hash())
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

    (hash, events)
}

// --- New tests ---

#[tokio::test]
async fn test_client_event_stream_message() {
    let (node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let (hash, events) =
        author_and_process(&node, conversation_id, Content::Text("Hi".into())).await;

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    // The broadcast channel should have received a MessageReceived event
    let ev = rx.try_recv().unwrap();
    if let ClientEvent::MessageReceived {
        hash: h,
        content: Content::Text(text),
        ..
    } = ev
    {
        assert_eq!(h, hash);
        assert_eq!(text, "Hi");
    } else {
        panic!("Expected MessageReceived, got {:?}", ev);
    }
}

#[tokio::test]
async fn test_client_event_stream_title_change() {
    let (node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let (_, events) = author_and_process(
        &node,
        conversation_id,
        Content::Control(merkle_tox_core::dag::ControlAction::SetTitle(
            "Room A".into(),
        )),
    )
    .await;

    for e in events {
        client.handle_event(e).await.unwrap();
    }

    let ev = rx.try_recv().unwrap();
    if let ClientEvent::TitleChanged { title, .. } = ev {
        assert_eq!(title, "Room A");
    } else {
        panic!("Expected TitleChanged, got {:?}", ev);
    }
}

#[tokio::test]
async fn test_handle_node_speculative() {
    let (_node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let author_pk = LogicalIdentityPk::from([5u8; 32]);
    let node = make_test_node(Content::Text("speculative msg".into()), author_pk);
    let hash = node.hash();

    client
        .handle_event(NodeEvent::NodeSpeculative {
            conversation_id,
            hash,
            node,
        })
        .await
        .unwrap();

    let state = client.state().await;
    assert_eq!(state.speculative_messages.len(), 1);
    assert_eq!(state.speculative_messages[0].hash, hash);

    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::SpeculativeMessage { .. }));
}

#[tokio::test]
async fn test_handle_node_identity_pending() {
    let (_node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let author_pk = LogicalIdentityPk::from([6u8; 32]);
    let node = make_test_node(Content::Text("pending msg".into()), author_pk);
    let hash = node.hash();

    client
        .handle_event(NodeEvent::NodeIdentityPending {
            conversation_id,
            hash,
            node,
        })
        .await
        .unwrap();

    let state = client.state().await;
    assert_eq!(state.identity_pending_messages.len(), 1);
    assert_eq!(state.identity_pending_messages[0].hash, hash);

    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::IdentityPendingMessage { .. }));
}

#[tokio::test]
async fn test_handle_node_invalidated() {
    let (node_arc, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    // First add a verified message
    let (hash, events) = author_and_process(
        &node_arc,
        conversation_id,
        Content::Text("will be invalidated".into()),
    )
    .await;

    for e in events {
        client.handle_event(e).await.unwrap();
    }
    // Drain the MessageReceived event from broadcast
    let _ = rx.try_recv();

    let state = client.state().await;
    assert_eq!(state.messages.len(), 1);

    // Now invalidate it
    client
        .handle_event(NodeEvent::NodeInvalidated {
            conversation_id,
            hash,
        })
        .await
        .unwrap();

    let state = client.state().await;
    assert!(state.messages.is_empty());

    let ev = rx.try_recv().unwrap();
    if let ClientEvent::NodeInvalidated { hash: h, .. } = ev {
        assert_eq!(h, hash);
    } else {
        panic!("Expected NodeInvalidated, got {:?}", ev);
    }
}

#[tokio::test]
async fn test_handle_blob_available() {
    let (_node, client, _conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let hash = NodeHash::from([0xBBu8; 32]);
    client
        .handle_event(NodeEvent::BlobAvailable { hash })
        .await
        .unwrap();

    let ev = rx.try_recv().unwrap();
    if let ClientEvent::BlobAvailable { hash: h } = ev {
        assert_eq!(h, hash);
    } else {
        panic!("Expected BlobAvailable, got {:?}", ev);
    }
}

#[tokio::test]
async fn test_equivocation_event() {
    let (_node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let device_pk = PhysicalDevicePk::from([7u8; 32]);
    let existing_hash = NodeHash::from([1u8; 32]);
    let conflicting_hash = NodeHash::from([2u8; 32]);

    client
        .handle_event(NodeEvent::EquivocationDetected {
            conversation_id,
            device_pk,
            seq: 42,
            existing_hash,
            conflicting_hash,
        })
        .await
        .unwrap();

    let ev = rx.try_recv().unwrap();
    if let ClientEvent::EquivocationDetected {
        seq,
        device_pk: dpk,
        ..
    } = ev
    {
        assert_eq!(seq, 42);
        assert_eq!(dpk, device_pk);
    } else {
        panic!("Expected EquivocationDetected, got {:?}", ev);
    }
}

#[tokio::test]
async fn test_peer_reachability() {
    let (_node, client, _conversation_id) = setup_client();
    let mut rx = client.subscribe();

    let peer_pk = PhysicalDevicePk::from([8u8; 32]);

    // Connect
    client.set_peer_available(peer_pk, true).await;
    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::PeerConnected { .. }));

    // Disconnect
    client.set_peer_available(peer_pk, false).await;
    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::PeerDisconnected { .. }));

    // Re-connect should emit again
    client.set_peer_available(peer_pk, true).await;
    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::PeerConnected { .. }));
}

#[tokio::test]
async fn test_speculative_promoted_on_verify() {
    let (_node_arc, client, conversation_id) = setup_client();

    // Add a speculative message
    let author_pk = LogicalIdentityPk::from([9u8; 32]);
    let spec_node = make_test_node(Content::Text("pending verify".into()), author_pk);
    let spec_hash = spec_node.hash();

    client
        .handle_event(NodeEvent::NodeSpeculative {
            conversation_id,
            hash: spec_hash,
            node: spec_node.clone(),
        })
        .await
        .unwrap();

    let state = client.state().await;
    assert_eq!(state.speculative_messages.len(), 1);

    // Now verify the same hash
    client
        .handle_event(NodeEvent::NodeVerified {
            conversation_id,
            hash: spec_hash,
            node: spec_node,
        })
        .await
        .unwrap();

    let state = client.state().await;
    assert!(
        state.speculative_messages.is_empty(),
        "Speculative message should be removed after verification"
    );
    // The verified message is in the main messages list
    assert_eq!(state.messages.len(), 1);
    assert_eq!(state.messages[0].hash, spec_hash);
}

#[tokio::test]
async fn test_reaction_via_api() {
    let (node_arc, client, conversation_id) = setup_client();

    // First send a message
    let (msg_hash, events) = author_and_process(
        &node_arc,
        conversation_id,
        Content::Text("react to me".into()),
    )
    .await;
    for e in events {
        client.handle_event(e).await.unwrap();
    }

    // Now react to it
    let (_, events) = author_and_process(
        &node_arc,
        conversation_id,
        Content::Reaction {
            target_hash: msg_hash,
            emoji: EmojiSource::Unicode("thumbsup".into()),
        },
    )
    .await;
    for e in events {
        client.handle_event(e).await.unwrap();
    }

    let state = client.state().await;
    let msg = state.messages.iter().find(|m| m.hash == msg_hash).unwrap();
    assert!(msg.reactions.contains_key("thumbsup"));
}

#[tokio::test]
async fn test_redaction_via_api() {
    let (node_arc, client, conversation_id) = setup_client();

    // Send a message
    let (msg_hash, events) = author_and_process(
        &node_arc,
        conversation_id,
        Content::Text("delete me".into()),
    )
    .await;
    for e in events {
        client.handle_event(e).await.unwrap();
    }

    // Redact it
    let (_, events) = author_and_process(
        &node_arc,
        conversation_id,
        Content::Redaction {
            target_hash: msg_hash,
            reason: "spam".into(),
        },
    )
    .await;
    for e in events {
        client.handle_event(e).await.unwrap();
    }

    let state = client.state().await;
    let msg = state.messages.iter().find(|m| m.hash == msg_hash).unwrap();
    assert!(msg.is_redacted);
}

#[tokio::test]
async fn test_send_blob_via_api() {
    let (node_arc, client, _conversation_id) = setup_client();

    let data = b"hello blob data".to_vec();
    let blob_hash = NodeHash::from(*blake3::hash(&data).as_bytes());

    let result = client
        .send_blob("test.bin".into(), "application/octet-stream".into(), data)
        .await;
    assert!(result.is_ok());

    // Verify blob is in store
    let node_lock = node_arc.lock().await;
    let info = node_lock.store.get_blob_info(&blob_hash);
    assert!(info.is_some());
}

#[tokio::test]
async fn test_poll_returns_valid_wakeup() {
    let (node_arc, _client, _conversation_id) = setup_client();

    let wakeup = {
        let mut node_lock = node_arc.lock().await;
        node_lock.poll()
    };

    // Wakeup should be in the future (at least not before now - epsilon)
    assert!(wakeup >= Instant::now() - std::time::Duration::from_secs(1));
}

#[tokio::test]
async fn test_custom_policy() {
    use merkle_tox_client::state::ChatState;
    use merkle_tox_core::dag::PublicKey;

    struct NeverAuthorizePolicy;
    impl PolicyHandler for NeverAuthorizePolicy {
        fn should_authorize(&self, _: &PublicKey, _: &PublicKey) -> bool {
            false
        }
        fn should_rotate_keys(&self, _: &ChatState) -> bool {
            false
        }
        fn should_respond_to_pulse(&self, _: &PublicKey) -> bool {
            false
        }
        fn full_sync_interval(&self) -> std::time::Duration {
            std::time::Duration::from_secs(60)
        }
        fn should_sync_with(&self, _: &PhysicalDevicePk) -> bool {
            false
        }
    }

    let self_sk = [10u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&self_sk);
    let self_master_pk = LogicalIdentityPk::from(signing_key.verifying_key().to_bytes());
    let self_device_pk = PhysicalDevicePk::from(signing_key.verifying_key().to_bytes());
    let conversation_id = ConversationId::from([0xBB; 32]);

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

    let client = MerkleToxClient::with_policy(
        node.clone(),
        conversation_id,
        Arc::new(NeverAuthorizePolicy),
    );

    // PeerHandshakeComplete should NOT auto-authorize due to custom policy
    let peer_pk = PhysicalDevicePk::from([99u8; 32]);
    client
        .handle_event(NodeEvent::PeerHandshakeComplete { peer_pk })
        .await
        .unwrap();

    // No devices should be authorized
    let state = client.state().await;
    assert!(!state.authorized_devices.contains(&peer_pk));
}

#[tokio::test]
async fn test_history_snapshot_needed_event() {
    let (_node, client, conversation_id) = setup_client();
    let mut rx = client.subscribe();

    client
        .handle_event(NodeEvent::HistorySnapshotNeeded { conversation_id })
        .await
        .unwrap();

    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev, ClientEvent::HistorySnapshotNeeded { .. }));
}
