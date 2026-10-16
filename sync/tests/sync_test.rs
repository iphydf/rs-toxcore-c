//! What only this implementation does; sync/conformance holds what every
//! one does.

use std::fs;
use std::io::Write;
use tox_sync::account::AccountState;
use tox_sync::event::{ChatId, ChatKind, Content, GraphId};
use tox_sync::fact::{Connection, Facts, Role, Subject, Value};
use tox_sync::frame::{FrameError, MAX_MESSAGE, Outbox, Reassembler, SendError, frames};
use tox_sync::pairing::{Pairing, PairingCode, VALID_FOR};
use tox_sync::protocol::{Features, SessionMessage};
use tox_sync::replica::Replica;
use tox_sync::store::{EVENTS_FILE, EventStore, append_log, read_log};
use toxcore::tox::FriendNumber;
use toxcore::types::{GroupChatId, PublicKey};

// Hello{version: 1, features: 1} as one packet.
const HELLO_PACKET: [u8; 7] = [0xb0, 0x03, 0x92, 0x00, 0x92, 0x01, 0x01];

const ALICE: PublicKey = PublicKey([1u8; 32]);
const BOB: PublicKey = PublicKey([2u8; 32]);
const DEVICE: PublicKey = PublicKey([3u8; 32]);

#[test]
fn test_long_messages_are_split_and_joined() {
    let message: Vec<u8> = (0..3000).map(|i| i as u8).collect();
    let packets = frames(&message);
    assert_eq!(packets.len(), 3);

    let mut reassembler = Reassembler::default();
    assert_eq!(reassembler.push(&packets[0]), Ok(None));
    assert_eq!(reassembler.push(&packets[1]), Ok(None));
    assert_eq!(reassembler.push(&packets[2]), Ok(Some(message)));

    let too_long = frames(&vec![0; MAX_MESSAGE + 1]);
    let results: Vec<_> = too_long.iter().map(|p| reassembler.push(p)).collect();
    assert!(results.contains(&Err(FrameError::TooLong)));
    assert!(results.iter().all(|r| !matches!(r, Ok(Some(_)))));
    assert_eq!(reassembler.push(&HELLO_PACKET).unwrap().unwrap().len(), 5);

    // A message cut off by a reconnect doesn't spoil the next one.
    assert_eq!(reassembler.push(&packets[0]), Ok(None));
    assert_eq!(reassembler.push(&HELLO_PACKET).unwrap().unwrap().len(), 5);
    // Older versions mark only the final frame.
    let mut old = HELLO_PACKET;
    old[1] = 0x01;
    assert_eq!(reassembler.push(&old).unwrap().unwrap().len(), 5);
}

#[test]
fn test_outbox_waits_while_toxcore_is_full() {
    let friend = FriendNumber(0);
    let mut outbox = Outbox::default();
    outbox.push(friend, &[0; 2000]);

    let mut sent = 0;
    outbox.flush(|_, _| Err(SendError::Full));
    outbox.flush(|_, _| {
        sent += 1;
        Ok(())
    });
    assert_eq!(sent, 2);

    outbox.push(friend, &[0; 2000]);
    outbox.flush(|_, _| Err(SendError::Gone));
    outbox.flush(|_, _| panic!("dropped when the friend went away"));
}

#[test]
fn test_half_written_record_is_cut_off() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(EVENTS_FILE);
    append_log(&path, &[vec![1, 2, 3], vec![4]]).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0, 0, 0, 100, 9, 9])
        .unwrap();

    assert_eq!(read_log(&path).unwrap(), vec![vec![1, 2, 3], vec![4]]);
    append_log(&path, &[vec![5]]).unwrap();
    assert_eq!(read_log(&path).unwrap().len(), 3);
}

#[test]
fn test_live_facts_follow_changes() {
    let chat = ChatId::Group(GroupChatId([4u8; 32]));
    let peer = |pk| Subject::Peer { chat, pk };
    let mut before = Facts::default();
    before.set(Subject::Friend(BOB), Value::Connection(Connection::Tcp));
    before.set(peer(ALICE), Value::Name("Alice".to_owned()));
    before.set(peer(ALICE), Value::Role(Role::User));
    let mut now = Facts::default();
    now.set(Subject::Friend(BOB), Value::Connection(Connection::Udp));
    now.set(peer(DEVICE), Value::Name("Dev".to_owned()));

    let mut device = before.clone();
    device.update(before.changes(&now));
    assert_eq!(device, now);
}

#[test]
fn test_replica_keeps_live_facts() {
    let mut replica = Replica::new(DEVICE, &ALICE, EventStore::default());
    replica.received(SessionMessage::hello(Features::ACCOUNT_SYNC));
    for (facts, all) in [
        (vec![(Subject::Friend(ALICE), Value::Typing(true))], true),
        (vec![(Subject::Friend(BOB), Value::Typing(true))], true),
        (
            vec![(Subject::Friend(BOB), Value::Connection(Connection::Udp))],
            false,
        ),
    ] {
        replica.received(SessionMessage::Facts { facts, all });
    }
    assert!(replica.live().of(&Subject::Friend(ALICE)).is_empty());
    assert_eq!(
        replica.live().of(&Subject::Friend(BOB)),
        [Value::Typing(true), Value::Connection(Connection::Udp)]
    );
}

#[test]
fn test_an_invite_keeps_the_password_answered() {
    let graph = GraphId::account(&ALICE);
    let mut store = EventStore::default();
    let (invite, _) = store.create(
        graph,
        ALICE,
        0,
        Content::ChatInvite {
            from: BOB,
            kind: ChatKind::Group,
            name: "Tox".to_owned(),
            invite: vec![1, 2, 3],
        },
    );
    store.create(
        graph,
        DEVICE,
        0,
        Content::AnswerInvite {
            invite,
            join: true,
            password: Some("secret".to_owned()),
        },
    );
    let state = AccountState::of(&store, &graph);
    assert_eq!(state.invites[&invite].password.as_deref(), Some("secret"));
}

#[test]
fn test_pairing_codes_work_once_and_expire() {
    let code = PairingCode::from_hex("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(
        PairingCode::from_request(&code.request_message()),
        Some(code)
    );
    assert_eq!(PairingCode::from_request("pair:not hex"), None);

    let start = std::time::Instant::now();
    let mut pairing = Pairing::default();
    let code = pairing.issue(start);
    assert!(!pairing.redeem(PairingCode::from_hex(&"0".repeat(32)).unwrap(), start));
    assert!(pairing.redeem(code, start));
    assert!(!pairing.redeem(code, start));

    let late = pairing.issue(start);
    assert!(!pairing.redeem(late, start + VALID_FOR));
}

#[test]
fn test_a_message_this_version_doesnt_know_is_skipped_however_deep() {
    // As any friend can send: an unknown tag, its payload nested 100,000 deep.
    let mut bytes = vec![0x92, 0x63];
    bytes.extend(std::iter::repeat_n(0x91u8, 100_000));
    bytes.push(0x00);
    assert_eq!(SessionMessage::decode(&bytes).unwrap(), None);
}
