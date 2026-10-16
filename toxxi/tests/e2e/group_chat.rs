use std::time::Duration;
use toxxi::model::{PendingItem, WindowId};
use toxxi::tester::TestHarness;
use toxxi::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario: Group Chat Nickname...");

    let bob_address = h.clients[1].tox_id;

    // 1. Set nicknames
    h.clients[0].cmd("/nick Alice").await;
    h.clients[1].cmd("/nick Bob").await;

    // wait for nick to be updated in model
    h.wait_for(
        |clients| {
            clients[0].model.domain.self_name == "Alice"
                && clients[1].model.domain.self_name == "Bob"
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Nicknames not updated in model");

    // 2. Alice creates a group
    tlog!(h, "Alice creating group 'Project Alpha'...");
    h.clients[0].cmd("/group create Project Alpha").await;

    // Wait for group to be created
    h.wait_for(
        |clients| {
            clients[0]
                .model
                .domain
                .conversations
                .values()
                .any(|c| c.name == "Project Alpha")
        },
        Duration::from_secs(5),
    )
    .await
    .expect("Alice failed to create group");

    let alice_group_id = h.clients[0]
        .model
        .domain
        .conversations
        .iter()
        .find(|(_, c)| c.name == "Project Alpha")
        .map(|(id, _)| match id {
            WindowId::Group(n) => *n,
            _ => panic!("Not a group"),
        })
        .unwrap();

    // 3. Alice invites Bob
    tlog!(h, "Alice inviting Bob to group...");
    let bob_friend_num = h.clients[0]
        .find_friend(bob_address)
        .expect("Alice doesn't know Bob");
    h.clients[0]
        .cmd(&format!("/group invite {}", bob_friend_num.0))
        .await;

    // 4. Bob waits for invite and accepts
    tlog!(h, "Bob waiting for invite...");
    h.wait_for(
        |clients| {
            clients[1]
                .model
                .domain
                .pending_items
                .iter()
                .any(|item| matches!(item, PendingItem::GroupInvite { .. }))
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Bob failed to receive group invite");

    let invite_idx = h.clients[1]
        .model
        .domain
        .pending_items
        .iter()
        .position(|item| matches!(item, PendingItem::GroupInvite { .. }))
        .unwrap();

    tlog!(h, "Bob accepting invite index {}...", invite_idx);
    h.clients[1].cmd(&format!("/accept {}", invite_idx)).await;

    // 5. Wait for Bob to join
    h.wait_for(
        |clients| {
            clients[1]
                .model
                .domain
                .conversations
                .values()
                .any(|c| c.name == "Project Alpha")
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Bob failed to join group");

    let bob_group_id = h.clients[1]
        .model
        .domain
        .conversations
        .iter()
        .find(|(_, c)| c.name == "Project Alpha")
        .map(|(id, _)| match id {
            WindowId::Group(n) => *n,
            _ => panic!("Not a group"),
        })
        .unwrap();

    // 6. Check Bob's nickname in Alice's view of the group
    tlog!(h, "Checking Bob's nickname in Alice's view...");
    h.wait_for(
        |clients| {
            if let Some(alice_conv) = clients[0]
                .model
                .domain
                .conversations
                .get(&WindowId::Group(alice_group_id))
            {
                alice_conv.peers.iter().any(|p| p.name == "Bob")
            } else {
                false
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Alice doesn't see Bob with name 'Bob'");

    // 7. Check Alice's nickname in Bob's view of the group
    tlog!(h, "Checking Alice's nickname in Bob's view...");
    h.wait_for(
        |clients| {
            if let Some(bob_conv) = clients[1]
                .model
                .domain
                .conversations
                .get(&WindowId::Group(bob_group_id))
            {
                bob_conv.peers.iter().any(|p| p.name == "Alice")
            } else {
                false
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Bob doesn't see Alice with name 'Alice'");

    // 7.5 Wait for peers to sync
    tlog!(h, "Waiting for peers to sync in group...");
    h.wait_for(
        |clients| {
            let alice_conv = clients[0]
                .model
                .domain
                .conversations
                .get(&WindowId::Group(alice_group_id))
                .unwrap();
            let bob_conv = clients[1]
                .model
                .domain
                .conversations
                .get(&WindowId::Group(bob_group_id))
                .unwrap();
            !alice_conv.peers.is_empty() && !bob_conv.peers.is_empty()
        },
        Duration::from_secs(30),
    )
    .await
    .expect("Peers failed to sync in group");

    // 8. Alice sets the topic
    tlog!(h, "Alice setting group topic to 'E2E Test Topic'...");
    h.clients[0].set_active_window_by_id(WindowId::Group(alice_group_id));
    h.clients[0].cmd("/topic E2E Test Topic").await;

    // 9. Bob waits for topic update
    tlog!(h, "Bob waiting for topic update...");
    h.wait_for(
        |clients| {
            if let Some(bob_conv) = clients[1]
                .model
                .domain
                .conversations
                .get(&WindowId::Group(bob_group_id))
            {
                bob_conv.topic == Some("E2E Test Topic".to_string())
                    && bob_conv.messages.iter().any(|m| {
                        m.content.as_text() == Some("* Alice changed the topic to: E2E Test Topic")
                    })
            } else {
                false
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("Bob failed to receive topic update or system message");

    // 10. Alice verifies topic in her view
    tlog!(h, "Alice verifying topic and system message...");
    let alice_conv = h.clients[0]
        .model
        .domain
        .conversations
        .get(&WindowId::Group(alice_group_id))
        .unwrap();
    assert_eq!(alice_conv.topic, Some("E2E Test Topic".to_string()));
    assert!(
        alice_conv.messages.iter().any(|m| {
            m.content.as_text() == Some("* Alice changed the topic to: E2E Test Topic")
        })
    );

    tlog!(h, "Scenario: Group Chat Nickname passed.");
}
