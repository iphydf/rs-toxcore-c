use chatlog::{Filter, Line, lines, plain, read_events};
use regex::RegexBuilder;
use tox_sync::event::{ChatId, Content, GraphId};
use tox_sync::fact::{Subject, Value};
use tox_sync::store::{EventStore, append_log};
use toxcore::types::{GroupChatId, MessageType, PublicKey};

const ACCOUNT: PublicKey = PublicKey([1; 32]);
const FRIEND: PublicKey = PublicKey([2; 32]);
const GROUP: ChatId = ChatId::Group(GroupChatId([3; 32]));

fn received(sender: &str, text: &str) -> Content {
    Content::Received {
        from: None,
        sender: sender.to_owned(),
        message: text.as_bytes().to_vec(),
        kind: MessageType::Normal,
    }
}

/// Writes a log with a named group, a named friend and a few messages, and
/// returns the lines read back from it.
fn log() -> Vec<Line> {
    let mut store = EventStore::default();
    let account = GraphId::account(&ACCOUNT);
    let name = |subject, name: &str| Content::Fact {
        subject,
        value: Value::Name(name.to_owned()),
    };
    let records = vec![
        store
            .create(account, ACCOUNT, 0, name(Subject::Chat(GROUP), "Dev"))
            .1,
        store
            .create(account, ACCOUNT, 0, name(Subject::Friend(FRIEND), "bob"))
            .1,
        store
            .create(GROUP.graph(), ACCOUNT, 3000, received("carol", "second"))
            .1,
        store
            .create(
                GROUP.graph(),
                ACCOUNT,
                1000,
                received("bob", "first\nline two"),
            )
            .1,
        store
            .create(
                GROUP.graph(),
                ACCOUNT,
                2000,
                Content::PeerJoined {
                    peer: FRIEND,
                    name: "dave".to_owned(),
                },
            )
            .1,
        store
            .create(
                GraphId::friend(&ACCOUNT, &FRIEND),
                ACCOUNT,
                4000,
                received("bob", "Hello"),
            )
            .1,
        // A record we can't decode.
        vec![0xff; 5],
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.log");
    append_log(&path, &records).unwrap();
    let (events, unread) = read_events(&path).unwrap();
    assert_eq!(unread, 1);
    lines(&events)
}

fn texts(lines: &[Line]) -> Vec<String> {
    lines
        .iter()
        .map(|l| format!("{} {} {}", l.chat, l.sender, l.text))
        .collect()
}

#[test]
fn messages_come_oldest_first_under_their_chats_names() {
    let kept = Filter::default().apply(log());
    assert_eq!(
        texts(&kept),
        [
            "#Dev bob first\nline two",
            "#Dev carol second",
            "bob bob Hello"
        ]
    );
}

#[test]
fn events_show_only_when_asked_for() {
    let kept = Filter {
        events: true,
        ..Default::default()
    }
    .apply(log());
    assert_eq!(kept[1].text, "dave joined");
    assert_eq!(kept.len(), 4);
}

#[test]
fn filters_narrow_by_chat_sender_text_and_time() {
    let by = |filter: Filter| texts(&filter.apply(log()));
    assert_eq!(
        by(Filter {
            chat: Some("dev".into()),
            from: Some("BOB".into()),
            ..Default::default()
        })
        .len(),
        1
    );
    let hello = RegexBuilder::new("^hel+o$")
        .case_insensitive(true)
        .build()
        .unwrap();
    assert_eq!(
        by(Filter {
            grep: Some(hello),
            ..Default::default()
        }),
        ["bob bob Hello"]
    );
    assert_eq!(
        by(Filter {
            since: Some(3000),
            until: Some(4000),
            ..Default::default()
        }),
        ["#Dev carol second"]
    );
    assert_eq!(
        by(Filter {
            last: Some(1),
            ..Default::default()
        }),
        ["bob bob Hello"]
    );
}

#[test]
fn a_message_of_several_lines_is_indented_under_its_first() {
    let line = &Filter::default().apply(log())[0];
    assert!(plain(line).ends_with("#Dev  <bob> first\n    line two"));
}
