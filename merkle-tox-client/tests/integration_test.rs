//! Cross-node integration tests for MerkleToxClient.
//!
//! Each test creates two independent client instances (Alice and Bob) with separate
//! engines and stores, authors nodes via test helpers, transfers them between nodes,
//! and verifies materialized state consistency.

use merkle_tox_client::MerkleToxClient;
use merkle_tox_client::state::ClientEvent;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EmojiSource, InviteAction, MerkleNode, NodeHash,
    Permissions, PhysicalDeviceSk,
};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::identity::sign_delegation;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    TestIdentity, TestRoom, create_admin_node, create_msg, create_signed_content_node,
};
use merkle_tox_core::{NodeEvent, Transport, TransportError};
use merkle_tox_sqlite::Storage;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

struct MockTransport {
    local_pk: merkle_tox_core::dag::PhysicalDevicePk,
}

impl Transport for MockTransport {
    fn local_pk(&self) -> merkle_tox_core::dag::PhysicalDevicePk {
        self.local_pk
    }
    fn send_raw(
        &self,
        _to: merkle_tox_core::dag::PhysicalDevicePk,
        _data: Vec<u8>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

type TestNode = Arc<Mutex<MerkleToxNode<MockTransport, Storage>>>;

struct TwoClients {
    room: TestRoom,
    alice_node: TestNode,
    bob_node: TestNode,
    alice_client: MerkleToxClient<MockTransport, Storage>,
    bob_client: MerkleToxClient<MockTransport, Storage>,
}

fn make_node(identity: &TestIdentity, seed: u64, room: &TestRoom) -> TestNode {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::with_sk(
        identity.device_pk,
        identity.master_pk,
        PhysicalDeviceSk::from(identity.device_sk.to_bytes()),
        StdRng::seed_from_u64(seed),
        tp.clone(),
    );
    let store = Storage::open_in_memory().unwrap();
    room.setup_engine(&mut engine, &store);
    let transport = MockTransport {
        local_pk: identity.device_pk,
    };
    Arc::new(Mutex::new(MerkleToxNode::new(engine, transport, store, tp)))
}

fn setup_two_clients() -> TwoClients {
    let room = TestRoom::new(2);
    let conv_id = room.conv_id;

    let alice_node = make_node(&room.identities[0], 0, &room);
    let bob_node = make_node(&room.identities[1], 1, &room);

    let alice_client = MerkleToxClient::new(alice_node.clone(), conv_id);
    let bob_client = MerkleToxClient::new(bob_node.clone(), conv_id);

    TwoClients {
        room,
        alice_node,
        bob_node,
        alice_client,
        bob_client,
    }
}

/// Fetches admin_heads from a node's store (must be called outside of other locks).
async fn get_admin_heads(node: &TestNode, conv_id: &ConversationId) -> Vec<NodeHash> {
    let lock = node.lock().await;
    lock.store.get_admin_heads(conv_id)
}

/// Delivers a pre-created node to a receiving node+client.
/// Processes engine effects and feeds emitted NodeEvents to the client.
async fn deliver_node(
    to_node: &TestNode,
    to_client: &MerkleToxClient<MockTransport, Storage>,
    conv_id: ConversationId,
    node: MerkleNode,
) -> Vec<NodeEvent> {
    let events = {
        let mut lock = to_node.lock().await;
        let node_ref = &mut *lock;

        let effects = node_ref
            .engine
            .handle_node(conv_id, node, &node_ref.store, None)
            .unwrap();

        let events: Vec<NodeEvent> = effects
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

    for event in &events {
        to_client.handle_event(event.clone()).await.unwrap();
    }
    events
}

/// Delivers a node to both the authoring side and the receiving side.
async fn deliver_both(tc: &TwoClients, node: MerkleNode, author_idx: usize) {
    let (author_node, author_client, recv_node, recv_client) = if author_idx == 0 {
        (
            &tc.alice_node,
            &tc.alice_client,
            &tc.bob_node,
            &tc.bob_client,
        )
    } else {
        (
            &tc.bob_node,
            &tc.bob_client,
            &tc.alice_node,
            &tc.alice_client,
        )
    };

    deliver_node(author_node, author_client, tc.room.conv_id, node.clone()).await;
    deliver_node(recv_node, recv_client, tc.room.conv_id, node).await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_integration_message_delivery() {
    let tc = setup_two_clients();

    // Use admin_heads as parents so the auth nodes are in causal ancestors
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    let msg = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads,
        "Hello Bob",
        2,
        2,
        1000,
    );
    let msg_hash = msg.hash();

    deliver_both(&tc, msg, 0).await;

    // Bob's state should have the message
    let bob_state = tc.bob_client.state().await;
    assert_eq!(bob_state.messages.len(), 1);
    assert_eq!(bob_state.messages[0].hash, msg_hash);
    assert_eq!(
        bob_state.messages[0].author_pk,
        tc.room.identities[0].master_pk
    );
    if let Content::Text(text) = &bob_state.messages[0].content {
        assert_eq!(text, "Hello Bob");
    } else {
        panic!("Expected Text content");
    }

    // Alice's state should also have the message
    let alice_state = tc.alice_client.state().await;
    assert_eq!(alice_state.messages.len(), 1);
    assert_eq!(alice_state.messages[0].hash, msg_hash);
}

#[tokio::test]
async fn test_integration_bidirectional_chat() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    // Alice sends msg1
    let msg1 = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads.clone(),
        "msg1",
        2,
        2,
        1000,
    );
    let msg1_hash = msg1.hash();
    deliver_both(&tc, msg1, 0).await;

    // Alice sends msg2 (child of msg1 + admin_heads for causal ordering)
    let mut msg2_parents = vec![msg1_hash];
    msg2_parents.extend(admin_heads.clone());
    let msg2 = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        msg2_parents,
        "msg2",
        3,
        3,
        2000,
    );
    deliver_both(&tc, msg2, 0).await;

    // Bob sends msg3
    let msg3 = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[1],
        admin_heads,
        "msg3",
        2,
        2,
        1500,
    );
    deliver_both(&tc, msg3, 1).await;

    // Both should see 3 messages
    let alice_state = tc.alice_client.state().await;
    assert_eq!(alice_state.messages.len(), 3);

    let bob_state = tc.bob_client.state().await;
    assert_eq!(bob_state.messages.len(), 3);

    // Verify content
    let alice_texts: Vec<String> = alice_state
        .messages
        .iter()
        .filter_map(|m| {
            if let Content::Text(t) = &m.content {
                Some(t.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(alice_texts.contains(&"msg1".to_string()));
    assert!(alice_texts.contains(&"msg2".to_string()));
    assert!(alice_texts.contains(&"msg3".to_string()));
}

#[tokio::test]
async fn test_integration_title_and_topic_sync() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    // Alice sets title (admin node signed with device_sk)
    let title_node = create_admin_node(
        &tc.room.conv_id,
        tc.room.identities[0].master_pk,
        &tc.room.identities[0].device_sk,
        admin_heads,
        ControlAction::SetTitle("Room Name".to_string()),
        2,
        2,
        1000,
    );
    let title_hash = title_node.hash();
    deliver_both(&tc, title_node, 0).await;

    // Alice sets topic
    let topic_node = create_admin_node(
        &tc.room.conv_id,
        tc.room.identities[0].master_pk,
        &tc.room.identities[0].device_sk,
        vec![title_hash],
        ControlAction::SetTopic("Discussion topic".to_string()),
        3,
        3,
        2000,
    );
    deliver_both(&tc, topic_node, 0).await;

    let bob_state = tc.bob_client.state().await;
    assert_eq!(bob_state.title, "Room Name");
    assert_eq!(bob_state.topic, "Discussion topic");

    let alice_state = tc.alice_client.state().await;
    assert_eq!(alice_state.title, "Room Name");
    assert_eq!(alice_state.topic, "Discussion topic");
}

#[tokio::test]
async fn test_integration_reaction_cross_client() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    // Alice sends a text message
    let msg = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads,
        "React to this",
        2,
        2,
        1000,
    );
    let msg_hash = msg.hash();
    deliver_both(&tc, msg, 0).await;

    // Bob reacts with thumbs up (msg_hash is child of admin node, so it's in ancestors)
    let reaction = create_signed_content_node(
        &tc.room.conv_id,
        &tc.room.keys,
        tc.room.identities[1].master_pk,
        tc.room.identities[1].device_pk,
        vec![msg_hash],
        Content::Reaction {
            target_hash: msg_hash,
            emoji: EmojiSource::Unicode("\u{1f44d}".to_string()),
        },
        3,
        2,
        2000,
    );
    deliver_both(&tc, reaction, 1).await;

    // Alice should see the reaction on her message
    let alice_state = tc.alice_client.state().await;
    assert_eq!(alice_state.messages.len(), 1);
    let alice_msg = &alice_state.messages[0];
    assert_eq!(alice_msg.hash, msg_hash);
    assert!(alice_msg.reactions.contains_key("\u{1f44d}"));
    assert!(alice_msg.reactions["\u{1f44d}"].contains(&tc.room.identities[1].master_pk));

    // Bob should also see it
    let bob_state = tc.bob_client.state().await;
    let bob_msg = &bob_state.messages[0];
    assert!(bob_msg.reactions.contains_key("\u{1f44d}"));
}

#[tokio::test]
async fn test_integration_redaction_cross_client() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    // Alice sends a text message
    let msg = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads,
        "Delete me",
        2,
        2,
        1000,
    );
    let msg_hash = msg.hash();
    deliver_both(&tc, msg, 0).await;

    // Alice redacts her own message
    let redaction = create_signed_content_node(
        &tc.room.conv_id,
        &tc.room.keys,
        tc.room.identities[0].master_pk,
        tc.room.identities[0].device_pk,
        vec![msg_hash],
        Content::Redaction {
            target_hash: msg_hash,
            reason: "mistake".to_string(),
        },
        3,
        3,
        2000,
    );
    deliver_both(&tc, redaction, 0).await;

    // Bob should see the message as redacted
    let bob_state = tc.bob_client.state().await;
    assert_eq!(bob_state.messages.len(), 1);
    assert!(bob_state.messages[0].is_redacted);

    // Alice should also see it redacted
    let alice_state = tc.alice_client.state().await;
    assert!(alice_state.messages[0].is_redacted);
}

#[tokio::test]
async fn test_integration_invite_authorize_flow() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.alice_node, &tc.room.conv_id).await;

    // Create Carol identity
    let carol = TestIdentity::new();

    // Alice invites Carol as member
    let invite_node = create_admin_node(
        &tc.room.conv_id,
        tc.room.identities[0].master_pk,
        &tc.room.identities[0].device_sk,
        admin_heads.clone(),
        ControlAction::Invite(InviteAction {
            invitee_pk: carol.master_pk,
            role: 0, // Member
        }),
        2,
        2,
        1000,
    );
    deliver_both(&tc, invite_node, 0).await;

    // Alice authorizes Carol's device.
    // AuthorizeDevice is an admin node — its parents must be admin nodes too
    // (chain isolation). Use admin_heads, not invite_hash (Invite is Content type).
    let carol_cert = sign_delegation(
        &tc.room.identities[0].master_sk,
        carol.device_pk,
        Permissions::MESSAGE,
        i64::MAX,
        tc.room.conv_id,
    );
    let auth_node = create_admin_node(
        &tc.room.conv_id,
        tc.room.identities[0].master_pk,
        &tc.room.identities[0].device_sk,
        admin_heads.clone(),
        ControlAction::AuthorizeDevice { cert: carol_cert },
        2,
        3,
        2000,
    );
    deliver_both(&tc, auth_node, 0).await;

    // Bob should see Carol as a member
    let bob_state = tc.bob_client.state().await;
    assert!(
        bob_state.members.contains_key(&carol.master_pk),
        "Bob should see Carol as a member"
    );

    // Bob should see Carol's device as authorized
    assert!(
        bob_state.authorized_devices.contains(&carol.device_pk),
        "Bob should see Carol's device as authorized"
    );

    // Alice should see the same
    let alice_state = tc.alice_client.state().await;
    assert!(alice_state.members.contains_key(&carol.master_pk));
    assert!(alice_state.authorized_devices.contains(&carol.device_pk));
}

#[tokio::test]
async fn test_integration_event_stream_cross_client() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.bob_node, &tc.room.conv_id).await;

    // Bob subscribes before message arrives
    let mut rx = tc.bob_client.subscribe();

    // Alice sends a message, delivered to Bob
    let msg = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads,
        "Event test",
        2,
        2,
        1000,
    );
    let msg_hash = msg.hash();
    deliver_node(&tc.bob_node, &tc.bob_client, tc.room.conv_id, msg).await;

    // Bob's subscriber should receive a MessageReceived event
    let event = rx.try_recv().expect("Should have received an event");
    match event {
        ClientEvent::MessageReceived {
            hash,
            conversation_id,
            ..
        } => {
            assert_eq!(hash, msg_hash);
            assert_eq!(conversation_id, tc.room.conv_id);
        }
        other => panic!("Expected MessageReceived, got {:?}", other),
    }
}

#[tokio::test]
async fn test_integration_refresh_after_cross_node_transfer() {
    let tc = setup_two_clients();
    let admin_heads = get_admin_heads(&tc.bob_node, &tc.room.conv_id).await;

    // Alice sends messages, delivered to Bob
    let msg1 = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        admin_heads.clone(),
        "refresh msg1",
        2,
        2,
        1000,
    );
    let msg1_hash = msg1.hash();
    deliver_node(&tc.bob_node, &tc.bob_client, tc.room.conv_id, msg1).await;

    let mut msg2_parents = vec![msg1_hash];
    msg2_parents.extend(admin_heads.clone());
    let msg2 = create_msg(
        &tc.room.conv_id,
        &tc.room.keys,
        &tc.room.identities[0],
        msg2_parents,
        "refresh msg2",
        3,
        3,
        2000,
    );
    deliver_node(&tc.bob_node, &tc.bob_client, tc.room.conv_id, msg2).await;

    // Set title, delivered to Bob
    let title_node = create_admin_node(
        &tc.room.conv_id,
        tc.room.identities[0].master_pk,
        &tc.room.identities[0].master_sk,
        admin_heads,
        ControlAction::SetTitle("Refresh Test Room".to_string()),
        2,
        2,
        1000,
    );
    deliver_node(&tc.bob_node, &tc.bob_client, tc.room.conv_id, title_node).await;

    // Capture Bob's current state
    let bob_state = tc.bob_client.state().await;
    assert_eq!(bob_state.messages.len(), 2);
    assert_eq!(bob_state.title, "Refresh Test Room");

    // Create a brand new client on the same Bob node (simulates app restart)
    let new_bob_client = MerkleToxClient::new(tc.bob_node.clone(), tc.room.conv_id);
    new_bob_client.refresh_state().await.unwrap();

    let rebuilt_state = new_bob_client.state().await;

    // Rebuilt state should match
    assert_eq!(rebuilt_state.messages.len(), bob_state.messages.len());
    assert_eq!(rebuilt_state.title, bob_state.title);
    assert_eq!(rebuilt_state.messages[0].hash, bob_state.messages[0].hash);
    assert_eq!(rebuilt_state.messages[1].hash, bob_state.messages[1].hash);
}
