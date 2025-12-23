use std::time::Duration;
use toxxi::tester::TestHarness;
use toxxi::tlog;

#[tokio::test]
async fn test_group_ignore_integration() {
    let mut h = TestHarness::new(3);
    h.link_all().await;

    // Clear any pending friend requests that accumulated during linking
    for client in &mut h.clients {
        client.model.domain.pending_items.clear();
    }

    let alice_idx = 0;
    let bob_idx = 1;
    let charlie_idx = 2;

    // Set names to avoid empty name errors during group creation
    h.clients[alice_idx].cmd("/nick Alice").await;
    h.clients[bob_idx].cmd("/nick Bob").await;
    h.clients[charlie_idx].cmd("/nick Charlie").await;

    // Wait a bit for names to set (worker processing)
    tokio::time::sleep(Duration::from_millis(500)).await;
    h.run_step().await;

    // 1. Alice creates group
    tlog!(h, "Alice creating group...");
    h.clients[alice_idx].cmd("/group create IgnoreTest").await;

    // Wait for Alice to see the group
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

    // 2. Alice invites Bob and Charlie
    tlog!(h, "Alice inviting Bob and Charlie...");
    // Need friend numbers
    let bob_fid = h.clients[alice_idx]
        .find_friend(h.clients[bob_idx].tox_id)
        .unwrap();
    let charlie_fid = h.clients[alice_idx]
        .find_friend(h.clients[charlie_idx].tox_id)
        .unwrap();

    h.clients[alice_idx]
        .cmd(&format!("/group invite {}", bob_fid.0))
        .await;
    h.clients[alice_idx]
        .cmd(&format!("/group invite {}", charlie_fid.0))
        .await;

    // 3. Bob and Charlie accept
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

    // 4. Wait for full connectivity in group
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
            // Alice should see Bob and Charlie (2 peers)
            alice_peers == 2
        },
        Duration::from_secs(30),
    )
    .await
    .expect("Group failed to converge");

    // 5. Alice ignores Bob
    eprintln!("Alice ignores Bob...");
    // Find Bob's PK in the group (it might be ephemeral/different from long-term PK)
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

    // Verify ignore state in model
    let conv = h.clients[alice_idx]
        .model
        .domain
        .conversations
        .get(&toxxi::model::WindowId::Group(chat_id))
        .unwrap();
    assert!(conv.ignored_peers.contains(&bob_group_pk));

    // 8. Alice unignores Bob
    eprintln!("Alice unignores Bob...");
    h.clients[alice_idx]
        .cmd(&format!("/unignore {}", bob_pk_hex))
        .await;

    h.shutdown().await;
}
