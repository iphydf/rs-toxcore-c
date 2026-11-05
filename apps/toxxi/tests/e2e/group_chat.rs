use std::time::Duration;
use toxxi::model::{PendingItem, WindowId};
use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

pub async fn run(h: &mut TestHarness) {
    tlog!(h, "Scenario: Group Chat Nickname...");

    let bob_address = h.clients[1].tox_id;

    h.clients[0].cmd("/nick Alice").await;
    h.clients[1].cmd("/nick Bob").await;

    h.wait_for(
        |clients| {
            clients[0].model.domain.self_name == "Alice"
                && clients[1].model.domain.self_name == "Bob"
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Nicknames not updated in model");

    tlog!(h, "Alice creating group 'Project Alpha'...");
    h.clients[0].cmd("/group create Project Alpha").await;

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

    tlog!(h, "Alice inviting Bob to group...");
    let bob = toxxi::utils::short_key(&bob_address.public_key());
    h.clients[0].cmd(&format!("/group invite {}", bob)).await;

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

    // Alice sees Bob's nick in the group.
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

    // Bob sees Alice's nick.
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

    // Wait for the peers to sync.
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

    tlog!(h, "Alice setting group topic to 'E2E Test Topic'...");
    h.clients[0].set_active_window_by_id(WindowId::Group(alice_group_id));
    h.clients[0].cmd("/topic E2E Test Topic").await;

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
