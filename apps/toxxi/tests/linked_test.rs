use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{Connection, GroupNumber};
use toxcore::types::{GroupChatId, MessageType, PublicKey};
use toxxi::model::{FriendInfo, MessageContent, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::sync::event::Content;
use toxxi_testing::network::{Network, model};

const HOME: PublicKey = PublicKey([1u8; 32]);
const DEVICE: PublicKey = PublicKey([2u8; 32]);
const GROUP: GroupChatId = GroupChatId([9u8; 32]);
const CLUB: WindowId = WindowId::Group(GROUP);

/// A home in a group, and another toxxi that was in it too, as its own
/// account, before linking to the home.
fn was_in_the_homes_group() -> (Network, usize, usize) {
    let mut net = Network::default();
    let home = net.add(model("Home", HOME));
    let device = net.add(model("Device", DEVICE));
    let joined = |peer: PublicKey| Content::PeerJoined {
        peer,
        name: "Peer".to_owned(),
    };
    let m = &mut net.peers[home].model;
    m.session.group_numbers.insert(GroupNumber(0), GROUP);
    m.ensure_group_window(GROUP);
    m.add_notice(CLUB, joined(PublicKey([5u8; 32])));
    // A group's history is the same graph for every member.
    let m = &mut net.peers[device].model;
    m.ensure_group_window(GROUP);
    m.add_notice(CLUB, joined(PublicKey([6u8; 32])));
    net.tick();
    (net, home, device)
}

fn link(net: &mut Network, home: usize, device: usize) {
    net.enter(home, "/device pair");
    let link = net.peers[home].model.ui.qr.take().expect("no pairing link");
    net.enter(device, &format!("/link {link}"));
    net.tick();
}

#[test]
fn a_linked_toxxi_writes_in_a_group_it_was_in_before() {
    let (mut net, home, device) = was_in_the_homes_group();
    link(&mut net, home, device);
    assert!(
        net.peers[device]
            .model
            .domain
            .conversations
            .contains_key(&CLUB)
    );

    let index = net.peers[device]
        .model
        .ui
        .window_ids
        .iter()
        .position(|id| *id == CLUB)
        .unwrap();
    net.peers[device].model.set_active_window(index);
    net.enter(device, "after linking");
    net.tick();

    let text = MessageContent::Text("after linking".to_owned());
    assert!(
        net.peers[home].model.domain.conversations[&CLUB]
            .messages
            .iter()
            .any(|m| m.content == text),
        "the home didn't take the device's message"
    );
    assert!(net.peers[home].done.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::SendGroupMessage(GROUP, MessageType::Normal, bytes, _))
            if bytes == b"after linking"
    )));
}

#[test]
fn a_toxxi_in_a_group_isnt_linked() {
    let (mut net, home, device) = was_in_the_homes_group();
    net.peers[device]
        .model
        .session
        .group_numbers
        .insert(GroupNumber(0), GROUP);
    link(&mut net, home, device);
    assert_eq!(net.peers[device].model.config.home, None);
}

/// A linked toxxi goes by "toxxi", and the home names each device as the
/// device names itself, whenever that changes.
#[test]
fn the_home_names_devices_as_they_name_themselves() {
    let mut net = Network::default();
    let home = net.add(model("Home", HOME));
    let device = net.add(model("", DEVICE));
    link(&mut net, home, device);
    let device_name = |net: &Network| net.peers[home].model.account.devices.get(&DEVICE).cloned();
    assert_eq!(device_name(&net).as_deref(), Some("toxxi"));

    net.send(
        home,
        toxxi::msg::Msg::Tox(toxxi::msg::ToxEvent::FriendName(DEVICE, "Phone".to_owned())),
    );
    net.tick();
    assert_eq!(device_name(&net).as_deref(), Some("Phone"));
}

/// A linked toxxi only has the latest page of a chat. Scrolling to the top
/// fetches the page before it.
#[test]
fn scrolling_up_on_a_linked_toxxi_brings_older_messages() {
    const BOB: PublicKey = PublicKey([3u8; 32]);
    let mut net = Network::default();
    let home = net.add(model("Home", HOME));
    let device = net.add(model("Device", DEVICE));
    net.peers[home].model.domain.friends.insert(
        BOB,
        FriendInfo {
            name: "Bob".to_owned(),
            public_key: Some(BOB),
            status_message: String::new(),
            connection: Connection::Udp,
            is_typing: false,
        },
    );
    for n in 0..120 {
        let text = format!("{n}").into_bytes();
        net.send(
            home,
            Msg::Tox(ToxEvent::Message(BOB, MessageType::Normal, text)),
        );
    }
    net.tick();
    link(&mut net, home, device);

    let chat = WindowId::Friend(BOB);
    let shown = |net: &Network| {
        net.peers[device].model.domain.conversations[&chat]
            .messages
            .iter()
            .filter(|m| {
                m.content
                    .as_text()
                    .is_some_and(|t| t.parse::<u32>().is_ok())
            })
            .count()
    };
    let first = shown(&net);
    assert!(first < 120, "the device has it all already");

    let m = &mut net.peers[device].model;
    let index = m.ui.window_ids.iter().position(|id| *id == chat).unwrap();
    m.set_active_window(index);
    // Pretend the last render had 50 lines, 10 of them on screen.
    let state = m.ui.window_state.entry(chat).or_default();
    state.last_height = 10;
    state.msg_list_state.total_height = 50;
    net.send(
        device,
        Msg::Input(Event::Key(KeyEvent::new(
            KeyCode::PageUp,
            KeyModifiers::SHIFT,
        ))),
    );
    assert_eq!(shown(&net), first + 50);
}
