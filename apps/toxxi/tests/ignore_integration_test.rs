use std::time::Duration;
use toxxi_testing::tester::TestHarness;
use toxxi_testing::tlog;

#[tokio::test]
#[ignore = "Slow real-Tox 3-node group integration test; routinely exceeds the \
            default 300s 'medium' Bazel timeout because of real friend-handshake \
            and group-creation delays. Run explicitly via --test_arg=--ignored \
            with a generous --test_timeout."]
async fn test_group_ignore_integration() {
    let mut h = TestHarness::new(3);
    h.link_all().await;

    // Clear the friend requests from linking.
    for client in &mut h.clients {
        client.model.domain.pending_items.clear();
    }

    let alice_idx = 0;
    let bob_idx = 1;
    let charlie_idx = 2;

    // Set names, as an empty name fails to create a group.
    h.clients[alice_idx].cmd("/nick Alice").await;
    h.clients[bob_idx].cmd("/nick Bob").await;
    h.clients[charlie_idx].cmd("/nick Charlie").await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    h.run_step().await;

    tlog!(h, "Alice creating group...");
    h.clients[alice_idx].cmd("/group create IgnoreTest").await;

    h.wait_for(
        |clients| !clients[alice_idx].model.session.group_numbers.is_empty(),
        Duration::from_secs(15),
    )
    .await
    .expect("Alice failed to create group");

    let group_num = *h.clients[alice_idx]
        .model
        .session
        .group_numbers
        .keys()
        .next()
        .unwrap();
    let chat_id = h.clients[alice_idx].model.session.group_numbers[&group_num];

    tlog!(h, "Alice inviting Bob and Charlie...");
    let bob = toxxi::utils::short_key(&h.clients[bob_idx].tox_id.public_key());
    let charlie = toxxi::utils::short_key(&h.clients[charlie_idx].tox_id.public_key());

    h.clients[alice_idx]
        .cmd(&format!("/group invite {}", bob))
        .await;
    h.clients[alice_idx]
        .cmd(&format!("/group invite {}", charlie))
        .await;

    tlog!(h, "Bob and Charlie accepting invites...");
    h.wait_for(
        |clients| {
            !clients[bob_idx].model.domain.pending_items.is_empty()
                && !clients[charlie_idx].model.domain.pending_items.is_empty()
        },
        Duration::from_secs(5),
    )
    .await
    .expect("Invites not received");

    h.clients[bob_idx].cmd("/accept 0").await;
    h.clients[charlie_idx].cmd("/accept 0").await;

    tlog!(h, "Waiting for full group convergence...");
    h.wait_for(
        |clients| {
            let alice_peers = clients[alice_idx]
                .model
                .domain
                .conversations
                .get(&toxxi::model::WindowId::Group(chat_id))
                .map(|c| c.peers.len())
                .unwrap_or(0);
            alice_peers == 2
        },
        Duration::from_secs(30),
    )
    .await
    .expect("Group failed to converge");

    eprintln!("Alice ignores Bob...");
    // Bob's key in the group isn't his Tox key.
    let bob_group_pk = {
        let conv = h.clients[alice_idx]
            .model
            .domain
            .conversations
            .get(&toxxi::model::WindowId::Group(chat_id))
            .unwrap();
        conv.peers.iter().find(|p| p.name == "Bob").unwrap().id.0
    };
    let bob_pk_hex = toxxi::utils::encode_hex(&bob_group_pk.0);

    let group_window_idx = h.clients[alice_idx]
        .model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == toxxi::model::WindowId::Group(chat_id))
        .unwrap();
    h.clients[alice_idx].set_active_window(group_window_idx);

    eprintln!("Alice ignores Bob (Group PK: {})...", bob_pk_hex);
    h.clients[alice_idx]
        .cmd(&format!("/ignore {}", bob_pk_hex))
        .await;

    let conv = h.clients[alice_idx]
        .model
        .domain
        .conversations
        .get(&toxxi::model::WindowId::Group(chat_id))
        .unwrap();
    assert!(conv.ignored_peers.contains(&bob_group_pk));

    eprintln!("Alice unignores Bob...");
    h.clients[alice_idx]
        .cmd(&format!("/unignore {}", bob_pk_hex))
        .await;

    h.shutdown().await;
}
