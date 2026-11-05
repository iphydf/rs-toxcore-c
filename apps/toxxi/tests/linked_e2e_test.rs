use std::time::Duration;
use toxcore::tox::Connection;
use toxxi::model::{MessageContent, MessageStatus, WindowId};
use toxxi::msg::ToxAction;
use toxxi_testing::tester::{TestClient, TestHarness, find_free_ports};

/// A home with a friend, and a third toxxi linked to the home's account.
async fn linked() -> TestHarness {
    let mut h = home_and_friend().await;
    add_device(&mut h);
    link(&mut h).await;
    h
}

/// A home and a friend who wrote it.
async fn home_and_friend() -> TestHarness {
    let mut h = TestHarness::new(2);
    h.link_all().await;
    h.clients[0].cmd("/nick Home").await;
    h.clients[1].cmd("/nick Friend").await;
    let home = h.clients[0].tox_id.public_key();
    let friend = h.clients[1].tox_id.public_key();
    h.clients[1].model.ensure_window(WindowId::Friend(home));
    h.clients[1].set_active_window_by_id(WindowId::Friend(home));
    h.clients[1].cmd("hello home").await;
    h.wait_for(
        |clients| {
            clients[0]
                .model
                .domain
                .conversations
                .get(&WindowId::Friend(friend))
                .is_some_and(|conv| {
                    conv.messages
                        .iter()
                        .any(|m| m.content == MessageContent::Text("hello home".to_owned()))
                })
        },
        Duration::from_secs(30),
    )
    .await
    .expect("the home didn't get the friend's message");

    h
}

/// A third toxxi, on the home's network but nobody's friend.
fn add_device(h: &mut TestHarness) {
    let port = find_free_ports(1)[0];
    let device = TestClient::new(2, port, h.start_time);
    device
        .ctx
        .tx_tox_action
        .send(ToxAction::Bootstrap(
            "127.0.0.1".to_owned(),
            h.clients[0].port,
            h.clients[0].dht_id,
        ))
        .unwrap();
    h.clients.push(device);
}

/// Links the third toxxi to the home's account.
async fn link(h: &mut TestHarness) {
    h.clients[0].cmd("/device pair").await;
    let link = h.clients[0].model.ui.qr.take().expect("no pairing link");
    h.clients[2].cmd(&format!("/link {link}")).await;
}

#[tokio::test]
async fn a_linked_toxxi_shows_the_homes_account() {
    let mut h = linked().await;
    let home = h.clients[0].tox_id;
    let friend = h.clients[1].tox_id.public_key();

    h.wait_for(
        |clients| {
            let device = &clients[2].model;
            device
                .domain
                .friends
                .get(&friend)
                .is_some_and(|info| info.name == "Friend" && info.connection != Connection::None)
                && device
                    .domain
                    .conversations
                    .get(&WindowId::Friend(friend))
                    .is_some_and(|conv| {
                        conv.messages
                            .iter()
                            .any(|m| m.content == MessageContent::Text("hello home".to_owned()))
                    })
        },
        Duration::from_secs(60),
    )
    .await
    .expect("the linked toxxi didn't show the home's friend and chat");

    let device = &h.clients[2].model;
    assert_eq!(device.domain.tox_id, home, "the account is the home's");
    assert_eq!(device.domain.self_name, "Home");
    assert!(
        !device.domain.friends.contains_key(&home.public_key()),
        "the home isn't a friend of its account"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn a_linked_toxxi_sends_through_the_home() {
    let mut h = linked().await;
    let home = h.clients[0].tox_id.public_key();
    let friend = h.clients[1].tox_id.public_key();
    h.wait_for(
        |clients| {
            clients[2]
                .model
                .domain
                .friends
                .get(&friend)
                .is_some_and(|info| info.connection != Connection::None)
        },
        Duration::from_secs(60),
    )
    .await
    .expect("the linked toxxi didn't see the friend online");

    h.clients[2].set_active_window_by_id(WindowId::Friend(friend));
    h.clients[2].cmd("hello from the device").await;
    h.clients[2].cmd("/nick Renamed").await;

    let said = |conv: Option<&toxxi::model::Conversation>| {
        conv.and_then(|conv| {
            conv.messages
                .iter()
                .find(|m| m.content == MessageContent::Text("hello from the device".to_owned()))
        })
        .map(|m| m.status)
    };
    h.wait_for(
        |clients| {
            said(
                clients[1]
                    .model
                    .domain
                    .conversations
                    .get(&WindowId::Friend(home)),
            )
            .is_some()
                && clients[1]
                    .model
                    .domain
                    .friends
                    .get(&home)
                    .is_some_and(|info| info.name == "Renamed")
                && said(
                    clients[2]
                        .model
                        .domain
                        .conversations
                        .get(&WindowId::Friend(friend)),
                ) == Some(MessageStatus::Received)
        },
        Duration::from_secs(60),
    )
    .await
    .expect("the friend didn't get the device's message and new name, delivered");
    h.shutdown().await;
}

fn group_named(client: &TestClient, name: &str) -> Option<WindowId> {
    client
        .model
        .domain
        .conversations
        .iter()
        .find(|(window_id, conv)| matches!(window_id, WindowId::Group(_)) && conv.name == name)
        .map(|(window_id, _)| *window_id)
}

#[tokio::test]
async fn a_linked_toxxi_makes_and_joins_chats_through_the_home() {
    let mut h = linked().await;
    let home = h.clients[0].tox_id.public_key();
    h.wait_for(
        |clients| {
            clients[2]
                .model
                .session
                .replica
                .as_ref()
                .is_some_and(|r| r.in_session())
        },
        Duration::from_secs(60),
    )
    .await
    .expect("the linked toxxi didn't sync");

    h.clients[2].cmd("/group create Den").await;
    h.wait_for(
        |clients| group_named(&clients[2], "Den").is_some(),
        Duration::from_secs(60),
    )
    .await
    .expect("the home didn't make the device's group");

    h.clients[1].cmd("/group create Club").await;
    h.wait_for(
        |clients| group_named(&clients[1], "Club").is_some(),
        Duration::from_secs(30),
    )
    .await
    .expect("the friend didn't make a group");
    let club = group_named(&h.clients[1], "Club").unwrap();
    h.clients[1].set_active_window_by_id(club);
    let home_key = toxxi::utils::short_key(&home);
    h.clients[1].cmd(&format!("/group invite {home_key}")).await;
    h.wait_for(
        |clients| !clients[2].model.domain.pending_items.is_empty(),
        Duration::from_secs(60),
    )
    .await
    .expect("the linked toxxi didn't see the invite");

    h.clients[2].cmd("/accept").await;
    h.wait_for(
        |clients| group_named(&clients[2], "Club").is_some(),
        Duration::from_secs(60),
    )
    .await
    .expect("the home didn't join the group the device accepted");
    assert!(h.clients[2].model.domain.pending_items.is_empty());

    let device_club = group_named(&h.clients[2], "Club").unwrap();
    h.clients[2].set_active_window_by_id(device_club);
    h.clients[2].cmd("hello club").await;
    h.wait_for(
        |clients| {
            clients[1].model.domain.conversations[&club]
                .messages
                .iter()
                .any(|m| m.content == MessageContent::Text("hello club".to_owned()))
        },
        Duration::from_secs(60),
    )
    .await
    .inspect_err(|_| {
        for (i, c) in h.clients.iter().enumerate() {
            for m in c.model.domain.console_messages.iter().rev().take(6) {
                eprintln!("DBG client {i} console: {:?}", m.content);
            }
        }
    })
    .expect("the friend didn't get the device's group message");

    let friend = h.clients[1].tox_id.public_key();
    h.clients[2].cmd("/friend remove Friend").await;
    h.wait_for(
        |clients| {
            !clients[0].model.domain.friends.contains_key(&friend)
                && !clients[2].model.domain.friends.contains_key(&friend)
        },
        Duration::from_secs(60),
    )
    .await
    .expect("the home didn't remove the friend the device removed");
    h.shutdown().await;
}
