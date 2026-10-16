use std::time::{Duration, Instant};
use toxcore::tox::events::Event;
use toxcore::tox::{FriendNumber, Options, Tox, ToxConnection};
use toxcore::types::{MessageType, Tox_Err_Friend_Custom_Packet, ToxError};
use toxxi::model::WindowId;
use toxxi::msg::{Cmd, GroupSetting, ToxAction};
use toxxi::sync::account::{AccountState, InviteStatus};
use toxxi::sync::event::{ChatId, Content, EventId, GraphId};
use toxxi::sync::fact::{Connection, Subject, Value};
use toxxi::sync::frame::{Outbox, Reassembler, SendError};
use toxxi::sync::pairing::PairingCode;
use toxxi::sync::protocol::SessionMessage;
use toxxi::sync::replica::Replica;
use toxxi::sync::store::EventStore;
use toxxi::tester::{TestClient, TestHarness, find_free_ports};

fn said(client: &TestClient, text: &str) -> bool {
    client
        .model
        .domain
        .console_messages
        .iter()
        .any(|m| m.content.as_text().is_some_and(|t| t.ends_with(text)))
}

#[tokio::test]
async fn test_devices_exchange_hello_over_tox() {
    let mut h = TestHarness::new(2);
    h.link_all().await;

    h.wait_for(
        |clients| clients.iter().all(|c| said(c, "speaks sync v1")),
        Duration::from_secs(30),
    )
    .await
    .expect("Hello wasn't exchanged on connect");

    let device = h.clients[0]
        .find_friend(h.clients[1].tox_id)
        .expect("home doesn't know the device");
    h.clients[0]
        .cmd(&format!("/device allow {}", device.0))
        .await;

    h.wait_for(
        |clients| said(&clients[1], "speaks sync v1, account sync"),
        Duration::from_secs(30),
    )
    .await
    .expect("the allowed device wasn't offered account sync");

    h.shutdown().await;
}

/// A linked device as bTox is one: plain Tox, keeping a copy of its home's
/// account.
struct Device {
    tox: Tox,
    home: FriendNumber,
    replica: Replica,
    incoming: Reassembler,
    outbox: Outbox,
    // Friend messages from the home device.
    received: Vec<String>,
}

impl Device {
    fn pair(home: &TestClient, link: &str) -> Self {
        let port = find_free_ports(1)[0];
        let mut options = Options::new().unwrap();
        options.set_ipv6_enabled(false);
        options.set_local_discovery_enabled(true);
        options.set_start_port(port);
        options.set_end_port(port);
        let tox = Tox::new(options).unwrap();
        tox.bootstrap("127.0.0.1", home.port, &home.dht_id).unwrap();

        let code = PairingCode::from_hex(link.split("?pair=").nth(1).unwrap()).unwrap();
        let friend = tox
            .friend_add(&home.tox_id, code.request_message().as_bytes())
            .unwrap()
            .get_number();
        Self {
            replica: Replica::new(
                tox.public_key(),
                &home.tox_id.public_key(),
                EventStore::default(),
            ),
            tox,
            home: friend,
            incoming: Reassembler::default(),
            outbox: Outbox::default(),
            received: Vec::new(),
        }
    }

    fn step(&mut self) {
        let mut replies = Vec::new();
        for event in &self.tox.events().unwrap() {
            match event {
                Event::FriendConnectionStatus(e) if e.friend_number() == self.home => {
                    if e.connection_status() == ToxConnection::TOX_CONNECTION_NONE {
                        self.replica.offline();
                    } else {
                        replies.push(Replica::hello());
                    }
                }
                Event::FriendLosslessPacket(e) if e.friend_number() == self.home => {
                    if let Ok(Some(bytes)) = self.incoming.push(e.data())
                        && let Ok(Some(message)) = SessionMessage::decode(&bytes)
                    {
                        replies.extend(self.replica.received(message));
                    }
                }
                Event::FriendMessage(e) if e.friend_number() == self.home => {
                    self.received
                        .push(String::from_utf8_lossy(e.message()).into_owned());
                }
                _ => {}
            }
        }
        self.push(replies);
        let tox = &self.tox;
        self.outbox.flush(|friend, packet| {
            tox.friend(friend)
                .send_lossless_packet(packet)
                .map_err(|e| match e {
                    ToxError::FriendCustomPacket(
                        Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ,
                    ) => SendError::Full,
                    _ => SendError::Gone,
                })
        });
    }

    fn push(&mut self, messages: Vec<SessionMessage>) {
        for message in messages {
            self.outbox.push(self.home, &message.encode());
        }
    }

    fn send(&mut self, graph: GraphId, text: &str) -> EventId {
        let content = Content::Send {
            sender: "Device".to_owned(),
            message: text.as_bytes().to_vec(),
            kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        };
        let (id, push) = self.replica.author(graph, 0, content);
        self.push(push);
        id
    }

    fn account(&self, home: &TestClient) -> AccountState {
        let account = GraphId::account(&home.tox_id.public_key());
        AccountState::of(self.replica.store(), &account)
    }
}

async fn run_until(
    h: &mut TestHarness,
    device: &mut Device,
    what: &str,
    done: impl Fn(&TestHarness, &Device) -> bool,
) {
    let start = Instant::now();
    while !done(h, device) {
        assert!(start.elapsed() < Duration::from_secs(40), "{}", what);
        h.run_step().await;
        device.step();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_a_paired_device_syncs_and_sends() {
    let mut h = TestHarness::new(1);
    let (tox_id, dht_id) = (h.clients[0].tox_id, h.clients[0].dht_id);
    h.wait_for(
        |clients| clients[0].tox_id != tox_id && clients[0].dht_id != dht_id,
        Duration::from_secs(5),
    )
    .await
    .expect("the home didn't start");

    h.clients[0].cmd("/device pair").await;
    let link = h.clients[0].model.ui.qr.clone().expect("no pairing link");
    let mut device = Device::pair(&h.clients[0], &link);
    let me = device.tox.public_key();

    // The home records its new friend, the device, in the account.
    run_until(
        &mut h,
        &mut device,
        "the device didn't get the account",
        |h, device| {
            device
                .account(&h.clients[0])
                .friends
                .get(&me)
                .is_some_and(|f| f.wanted)
                && device
                    .replica
                    .live()
                    .of(&Subject::Friend(me))
                    .iter()
                    .any(|v| matches!(v, Value::Connection(c) if *c != Connection::None))
        },
    )
    .await;

    // The device is a friend of the account too, so it can message itself.
    let chat = GraphId::friend(&h.clients[0].tox_id.public_key(), &me);
    let id = device.send(chat, "from the device");
    run_until(
        &mut h,
        &mut device,
        "the home didn't deliver it",
        |_, device| {
            device.received.iter().any(|text| text == "from the device")
                && device
                    .replica
                    .store()
                    .graph(&chat)
                    .iter()
                    .any(|(_, event)| event.content == Content::Delivered { intent: id })
        },
    )
    .await;

    h.shutdown().await;
}

/// Has the friend invite the home to its group, and answers on `device`.
async fn answer_new_invite(
    h: &mut TestHarness,
    device: &mut Device,
    password: Option<&str>,
) -> EventId {
    let home = h.clients[1].find_friend(h.clients[0].tox_id).unwrap();
    h.clients[1].cmd(&format!("/group invite {}", home.0)).await;
    let pending = |h: &TestHarness, device: &Device| {
        device
            .account(&h.clients[0])
            .invites
            .iter()
            .find(|(_, invite)| invite.status == InviteStatus::Pending)
            .map(|(id, _)| *id)
    };
    run_until(
        h,
        device,
        "the device didn't get the invite",
        |h, device| pending(h, device).is_some(),
    )
    .await;
    let invite = pending(h, device).unwrap();
    let (_, push) = device.replica.author(
        GraphId::account(&h.clients[0].tox_id.public_key()),
        0,
        Content::AnswerInvite {
            invite,
            join: true,
            password: password.map(str::to_owned),
        },
    );
    device.push(push);
    invite
}

#[tokio::test]
async fn test_a_device_joins_a_group_with_a_password_it_was_invited_to() {
    let mut h = TestHarness::new(2);
    h.link_all().await;
    h.clients[0].cmd("/device pair").await;
    let link = h.clients[0].model.ui.qr.clone().expect("no pairing link");
    let mut device = Device::pair(&h.clients[0], &link);

    // Tox needs a name to create or join a group.
    h.clients[0].cmd("/nick Home").await;
    h.clients[1].cmd("/nick Friend").await;
    h.clients[1].cmd("/group create Invited").await;
    h.wait_for(
        |clients| !clients[1].model.session.group_numbers.is_empty(),
        Duration::from_secs(15),
    )
    .await
    .expect("the friend didn't create the group");
    let group = *h.clients[1]
        .model
        .session
        .group_numbers
        .values()
        .next()
        .unwrap();
    let friend = &mut h.clients[1];
    friend
        .ctx
        .execute(
            vec![Cmd::Tox(ToxAction::SetGroupSetting(
                group,
                GroupSetting::Password("secret".to_owned()),
            ))],
            &mut friend.model,
        )
        .await;
    // Tox checks a group's password only after it takes an invite, which it
    // takes only once: one answered without the password is spent.
    let spent = answer_new_invite(&mut h, &mut device, None).await;
    run_until(
        &mut h,
        &mut device,
        "the group didn't ask for its password",
        |h, device| {
            device.account(&h.clients[0]).invites[&spent].status
                == InviteStatus::Failed {
                    needs_password: true,
                }
        },
    )
    .await;

    // A new invite answered with it joins the group, which every device then
    // has.
    let invite = answer_new_invite(&mut h, &mut device, Some("secret")).await;
    run_until(
        &mut h,
        &mut device,
        "the home didn't join the group",
        |h, device| {
            let account = device.account(&h.clients[0]);
            account.invites[&invite].status == InviteStatus::Joined(ChatId::Group(group))
                && account.chats().any(|chat| chat == ChatId::Group(group))
                && h.clients[0]
                    .model
                    .domain
                    .conversations
                    .get(&WindowId::Group(group))
                    .is_some_and(|conversation| conversation.name == "Invited")
        },
    )
    .await;

    h.shutdown().await;
}
