use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{
    Address, FriendMessageId, FriendNumber, GroupNumber, ToxConferenceType, ToxConnection,
    ToxUserStatus,
};
use toxcore::types::{
    ConferenceId, FileId, GroupChatId, MAX_MESSAGE_LENGTH, MessageType, PublicKey, ToxFileControl,
    ToxGroupJoinFail, ToxGroupPrivacyState, ToxGroupRole, ToxGroupVoiceState, ToxLogLevel,
};
use toxxi::config::Config;
use toxxi::model::{
    DomainState, FriendInfo, GroupSettings, MessageStatus, Model, PeerId, PeerInfo, PendingItem,
    WindowId,
};
use toxxi::msg::{Cmd, IOAction, IOEvent, Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::sync::account::InviteStatus;
use toxxi::sync::event::{BlobId, ChatId, ChatKind, Content, Event, EventId, GraphId};
use toxxi::sync::fact::{CallState, Privacy, Role, Subject, Value};
use toxxi::sync::files::file_id;
use toxxi::sync::pairing::PairingCode;
use toxxi::sync::protocol::{BLOB_FILE_KIND, CallAction, Features, SessionMessage};
use toxxi::sync::setting::{MAX_SETTING, Mute, Scope, Setting, Variant};
use toxxi::sync::store::EventStore;
use toxxi::update::{handle_command, update};

const ME: PublicKey = PublicKey([0u8; 32]);
const DEVICE: PublicKey = PublicKey([1u8; 32]);
const BOB: PublicKey = PublicKey([2u8; 32]);

fn friend(name: &str, pk: PublicKey) -> FriendInfo {
    FriendInfo {
        name: name.to_owned(),
        public_key: Some(pk),
        status_message: String::new(),
        connection: ToxConnection::TOX_CONNECTION_UDP,
        is_typing: false,
    }
}

/// What `cmds` send `to`, now or once their events are kept.
fn sent_to(cmds: &[Cmd], to: PublicKey) -> Vec<SessionMessage> {
    cmds.iter()
        .flat_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SyncSend(pk, bytes)) => vec![(pk, bytes)],
            Cmd::IO(IOAction::AppendEvents(_, pushes)) => {
                pushes.iter().map(|(pk, bytes)| (pk, bytes)).collect()
            }
            _ => Vec::new(),
        })
        .filter(|(pk, _)| **pk == to)
        .filter_map(|(_, bytes)| SessionMessage::decode(bytes).ok().flatten())
        .collect()
}

fn events_in(messages: &[SessionMessage]) -> Vec<Event> {
    messages
        .iter()
        .flat_map(|message| match message {
            SessionMessage::Events(events) => events.clone(),
            _ => Vec::new(),
        })
        .map(|bytes| Event::decode(&bytes).unwrap())
        .collect()
}

/// `msg`, and the tick that records what it changed in the account.
fn settled(model: &mut Model, msg: Msg) -> Vec<Cmd> {
    let mut cmds = update(model, msg);
    cmds.extend(update(model, Msg::System(SystemEvent::Tick)));
    cmds
}

fn from(model: &mut Model, pk: PublicKey, message: SessionMessage) -> Vec<Cmd> {
    let number = if pk == DEVICE { 0 } else { 1 };
    settled(
        model,
        Msg::Tox(ToxEvent::SyncMessage(
            FriendNumber(number),
            message.encode(),
        )),
    )
}

#[test]
fn test_device_syncs_the_account() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    for (number, name, pk) in [(0, "Device", DEVICE), (1, "Bob", BOB)] {
        model
            .session
            .friend_numbers
            .insert(FriendNumber(number), pk);
        model.domain.friends.insert(pk, friend(name, pk));
    }

    let hello = SessionMessage::hello(Features::ACCOUNT_SYNC);
    let allowed = handle_command(&mut model, "/device allow 0");
    assert!(allowed.contains(&Cmd::IO(IOAction::SaveConfig(None))));
    assert!(allowed.contains(&Cmd::Tox(ToxAction::SyncSend(DEVICE, hello.encode()))));

    let to_device = sent_to(&from(&mut model, DEVICE, hello.clone()), DEVICE);
    assert!(matches!(to_device[0], SessionMessage::Summary(_)));
    assert!(matches!(
        to_device[1],
        SessionMessage::Facts { all: true, .. }
    ));
    assert!(events_in(&to_device).iter().any(|event| event.content
        == Content::Fact {
            subject: Subject::Friend(BOB),
            value: Value::Name("Bob".to_owned()),
        }));
    // A device that started over before Tox noticed gets our Hello again.
    let again = sent_to(&from(&mut model, DEVICE, hello.clone()), DEVICE);
    assert_eq!(again[0], hello);

    let account = GraphId::account(&ME);
    let reply = sent_to(
        &from(&mut model, DEVICE, SessionMessage::Summary(Vec::new())),
        DEVICE,
    );
    let Some(heads) = reply.iter().find_map(|message| match message {
        SessionMessage::Heads { graph, heads } if *graph == account => Some(heads),
        _ => None,
    }) else {
        panic!("expected the account's heads, got {:?}", reply);
    };
    let wanted = events_in(&sent_to(
        &from(&mut model, DEVICE, SessionMessage::Want(heads.clone())),
        DEVICE,
    ));
    assert_eq!(wanted.len(), heads.len());

    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::FriendName(FriendNumber(1), "Robert".to_owned())),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::Fact {
                    subject: Subject::Friend(BOB),
                    value: Value::Name("Robert".to_owned()),
                })
    );

    assert!(
        sent_to(
            &from(&mut model, BOB, SessionMessage::Want(heads.clone())),
            BOB
        )
        .is_empty()
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(0),
            ToxConnection::TOX_CONNECTION_NONE,
            Some(DEVICE),
        )),
    );
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FriendName(FriendNumber(1), "Bobby".to_owned())),
    );
    assert!(sent_to(&cmds, DEVICE).is_empty());

    handle_command(&mut model, "/device remove 0");
    assert!(model.saved_config.sync_devices.is_empty());
}

#[test]
fn test_the_accounts_devices_are_recorded() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    // One allowed before devices were recorded.
    let config = Config {
        sync_devices: vec![DEVICE],
        ..Config::default()
    };
    let mut model = Model::new(domain, config.clone(), config);
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    model.domain.friends.insert(DEVICE, friend("Phone", DEVICE));
    model.record_account();
    assert_eq!(
        model.account.devices.get(&DEVICE).map(String::as_str),
        Some("Phone")
    );

    // A device names itself, and adds another it paired.
    let account = GraphId::account(&ME);
    // It writes after the account's events, as a device in sync does.
    let mut device_events = EventStore::default();
    for (id, _) in model.events.by_rank(&account) {
        device_events
            .insert(model.events.bytes(&id).unwrap())
            .unwrap();
    }
    let write = |store: &mut EventStore, content| store.create(account, DEVICE, 0, content).1;
    let renamed = write(
        &mut device_events,
        Content::Device {
            pk: DEVICE,
            name: "My phone".to_owned(),
        },
    );
    let paired = write(
        &mut device_events,
        Content::Device {
            pk: BOB,
            name: String::new(),
        },
    );
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![renamed, paired]),
    );
    assert_eq!(
        model.account.devices.get(&DEVICE).map(String::as_str),
        Some("My phone")
    );
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AcceptFriend(BOB))));
    assert!(model.config.sync_devices.contains(&BOB));

    // It removes that one, but can't remove this one.
    let gone = write(&mut device_events, Content::DeviceGone { pk: BOB });
    let me_gone = write(&mut device_events, Content::DeviceGone { pk: ME });
    from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![gone, me_gone]),
    );
    assert!(!model.config.sync_devices.contains(&BOB));
    assert!(!model.account.devices.contains_key(&BOB));
    assert!(
        model.events.heads_of(&account).iter().all(|head| {
            model.events.get(head).unwrap().content != Content::DeviceGone { pk: ME }
        })
    );
}

#[test]
fn test_devices_found_join_and_invite_to_chats() {
    let mut model = with_device_and_bob();
    let account = GraphId::account(&ME);
    let group = GroupChatId([5u8; 32]);
    model.ensure_group_window(group);
    let mut device = EventStore::default();
    let mut write = |content| device.create(account, DEVICE, 0, content);

    let (found, founding) = write(Content::NewChat {
        kind: ChatKind::Group,
        name: "Lab".to_owned(),
        privacy: Privacy::Private,
    });
    let (join, joining) = write(Content::JoinChat {
        chat_id: group,
        password: Some("pw".to_owned()),
    });
    let (_, inviting) = write(Content::InviteToChat {
        chat: ChatId::Group(group),
        friend: BOB,
    });
    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![founding, joining, inviting]),
    );
    assert!(cmds.contains(&Cmd::Tox(ToxAction::MakeChat(
        found,
        ChatKind::Group,
        Privacy::Private,
        "Lab".to_owned()
    ))));
    assert!(cmds.contains(&Cmd::Tox(ToxAction::JoinChatById(
        join,
        group,
        Some("pw".to_owned())
    ))));
    assert!(cmds.contains(&Cmd::Tox(ToxAction::InviteFriendToGroup(group, BOB))));

    // What Tox made of them goes to the devices.
    let made = ChatId::Group(GroupChatId([8u8; 32]));
    let mut told = settled(&mut model, Msg::Tox(ToxEvent::ChatMade(found, Some(made))));
    told.extend(settled(
        &mut model,
        Msg::Tox(ToxEvent::ChatMade(join, None)),
    ));
    let results: Vec<Content> = events_in(&sent_to(&told, DEVICE))
        .into_iter()
        .map(|event| event.content)
        .filter(|content| matches!(content, Content::ChatJoined { .. }))
        .collect();
    assert_eq!(
        results,
        vec![
            Content::ChatJoined {
                intent: found,
                chat: Some(made)
            },
            Content::ChatJoined {
                intent: join,
                chat: None
            },
        ]
    );
}

#[test]
fn test_pairing_adds_a_device() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    handle_command(&mut model, "/device pair");
    let link = model.ui.qr.clone().unwrap();
    let code = PairingCode::from_hex(link.split("?pair=").nth(1).unwrap()).unwrap();

    let request = |model: &mut Model, message: String| {
        update(model, Msg::Tox(ToxEvent::FriendRequest(DEVICE, message)))
    };
    request(&mut model, "pair:00".to_owned());
    assert_eq!(model.domain.pending_items.len(), 1);

    let cmds = request(&mut model, code.request_message());
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AcceptFriend(DEVICE))));
    assert!(cmds.contains(&Cmd::IO(IOAction::SaveConfig(None))));
    assert_eq!(model.saved_config.sync_devices, vec![DEVICE]);

    // The device's Hello can come before Tox reports it online.
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    let hello = SessionMessage::hello(Features::ACCOUNT_SYNC);
    let replies = sent_to(&from(&mut model, DEVICE, hello.clone()), DEVICE);
    assert_eq!(replies[0], hello);
    assert!(matches!(replies[1], SessionMessage::Summary(_)));
    let online = update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(0),
            ToxConnection::TOX_CONNECTION_UDP,
            Some(DEVICE),
        )),
    );
    assert!(!sent_to(&online, DEVICE).contains(&hello));

    // Each code pairs one device.
    request(&mut model, code.request_message());
    assert!(matches!(
        model.domain.pending_items.last(),
        Some(PendingItem::FriendRequest { pk: DEVICE, .. })
    ));
    // The first went with its friend added.
    assert_eq!(model.domain.pending_items.len(), 1);
}

#[test]
fn test_device_sends_a_message() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    for (number, name, pk) in [(0, "Device", DEVICE), (1, "Bob", BOB)] {
        model
            .session
            .friend_numbers
            .insert(FriendNumber(number), pk);
        model.domain.friends.insert(pk, friend(name, pk));
    }
    handle_command(&mut model, "/device allow 0");
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );

    let chat = GraphId::friend(&ME, &BOB);
    let mut device = EventStore::default();
    let send = |text: &str| Content::Send {
        sender: "Me".to_owned(),
        message: text.as_bytes().to_vec(),
        kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
    };
    let (id, bytes) = device.create(chat, DEVICE, 0, send("hi"));
    // Each first in its graph, so the device's next events don't follow them.
    let first = |graph, author, content| EventStore::default().create(graph, author, 0, content).1;
    let dropped = [
        first(chat, BOB, send("not the device's")),
        first(chat, DEVICE, send(&"too long".repeat(10_000))),
        first(GraphId::friend(&ME, &ME), DEVICE, send("no such chat")),
        first(
            GraphId::account(&ME),
            DEVICE,
            Content::FriendRequest {
                pk: BOB,
                message: "only the home writes these".to_owned(),
            },
        ),
    ];
    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events([vec![bytes], dropped.to_vec()].concat()),
    );
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::SendMessage(BOB, _, text, _)) if text == b"hi"
    )));
    assert!(model.events.get(&id).is_some());
    // The device has its events already.
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .all(|event| event.author != DEVICE)
    );
    for bytes in &dropped {
        assert!(model.events.get(&EventId::of(bytes)).is_none());
    }

    // Sent and delivered like any message toxxi sends.
    let msg = &model.domain.conversations[&WindowId::Friend(BOB)].messages[0];
    let internal_id = msg.internal_id;
    assert_eq!(msg.status, MessageStatus::Sending);
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(
            FriendNumber(1),
            FriendMessageId(7),
            internal_id,
        )),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content == Content::Sent { intent: id })
    );

    // One longer than Tox takes goes in parts, as the one message.
    let (_, long) = device.create(chat, DEVICE, 0, send(&"a".repeat(3000)));
    let parts: Vec<_> = from(&mut model, DEVICE, SessionMessage::Events(vec![long]))
        .into_iter()
        .filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(BOB, _, part, internal_id)) => {
                Some((part.len(), internal_id))
            }
            _ => None,
        })
        .collect();
    assert_eq!(parts.len(), 3);
    assert!(
        parts
            .iter()
            .all(|&(len, id)| len <= MAX_MESSAGE_LENGTH && id == parts[0].1)
    );
    // So does one that isn't text.
    let (_, bytes) = device.create(
        chat,
        DEVICE,
        0,
        Content::Send {
            sender: "Me".to_owned(),
            message: vec![0xff; 3000],
            kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        },
    );
    let parts: Vec<_> = from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]))
        .into_iter()
        .filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(BOB, _, part, _)) => Some(part.len()),
            _ => None,
        })
        .collect();
    assert_eq!(parts.len(), 3);
    assert!(parts.iter().all(|&len| len <= MAX_MESSAGE_LENGTH));

    // A closed window's messages are forgotten.
    let bob = |model: &Model| {
        model
            .message_events
            .keys()
            .filter(|(window, _)| *window == WindowId::Friend(BOB))
            .count()
    };
    assert!(bob(&model) > 0);
    model.close_window(WindowId::Friend(BOB));
    assert_eq!(bob(&model), 0);
}

#[test]
fn test_a_devices_offline_messages_go_in_order() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    let mut device = EventStore::default();
    let written: Vec<_> = ["a", "b", "c"]
        .map(|text| {
            device
                .create(
                    chat,
                    DEVICE,
                    0,
                    Content::Send {
                        sender: "Me".to_owned(),
                        message: text.as_bytes().to_vec(),
                        kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                    },
                )
                .1
        })
        .into();

    // Each is asked for after its child, which waits for it.
    let mut sent = Vec::new();
    for (i, bytes) in written.iter().enumerate().rev() {
        let cmds = from(
            &mut model,
            DEVICE,
            SessionMessage::Events(vec![bytes.clone()]),
        );
        if i > 0 {
            assert_eq!(
                sent_to(&cmds, DEVICE),
                [SessionMessage::Want(vec![EventId::of(&written[i - 1])])]
            );
        }
        sent.extend(cmds.into_iter().filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(BOB, _, text, _)) => Some(text),
            _ => None,
        }));
    }
    assert_eq!(sent, [b"a", b"b", b"c"]);

    // A first event that ranks after others would rank after every later one.
    let (_, first) = EventStore::default().create(
        GraphId::account(&ME),
        DEVICE,
        0,
        Content::ReadUpTo {
            graph: chat,
            event: EventId::of(&written[2]),
            rank: 2,
        },
    );
    let mut poisoned = Event::decode(&first).unwrap();
    poisoned.rank = 1 << 52;
    let bytes = poisoned.encode();
    from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![bytes.clone()]),
    );
    assert!(!model.events.contains(&EventId::of(&bytes)));
}

#[test]
fn test_messages_record_the_account_on_the_next_tick() {
    let mut model = with_device_and_bob();
    model.domain.friends.get_mut(&BOB).unwrap().name = "Robert".to_owned();
    let renamed = |cmds: &[Cmd]| {
        events_in(&sent_to(cmds, DEVICE)).iter().any(|event| {
            event.content
                == Content::Fact {
                    subject: Subject::Friend(BOB),
                    value: Value::Name("Robert".to_owned()),
                }
        })
    };
    let log = ToxEvent::Log(
        ToxLogLevel::TOX_LOG_LEVEL_DEBUG,
        String::new(),
        0,
        String::new(),
        String::new(),
    );
    assert!(!renamed(&update(&mut model, Msg::Tox(log))));
    assert!(renamed(&update(&mut model, Msg::System(SystemEvent::Tick))));
}

/// toxxi with Bob as a friend and the device in session, both online.
fn with_device_and_bob() -> Model {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    for (number, name, pk) in [(0, "Device", DEVICE), (1, "Bob", BOB)] {
        model
            .session
            .friend_numbers
            .insert(FriendNumber(number), pk);
        model.domain.friends.insert(pk, friend(name, pk));
    }
    handle_command(&mut model, "/device allow 0");
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    model
}

#[test]
fn test_device_answers_files() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    let mut offered = Vec::new();
    for (number, name) in [(1u8, "cat.png"), (2, "virus.exe")] {
        update(
            &mut model,
            Msg::Tox(ToxEvent::FileRecv(
                FriendNumber(1),
                FileId([number; 32]),
                0,
                10_000_000,
                name.to_owned(),
            )),
        );
        let (id, _) = *model.events.graph(&chat).last().unwrap();
        offered.push(id);
    }

    let mut device = EventStore::default();
    let answers: Vec<Vec<u8>> = [(offered[0], true), (offered[1], false)]
        .into_iter()
        .map(|(file, accepted)| {
            device
                .create(chat, DEVICE, 0, Content::FileAnswered { file, accepted })
                .1
        })
        .collect();
    let cmds = from(&mut model, DEVICE, SessionMessage::Events(answers));
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::IO(IOAction::OpenFileForReceiving(BOB, FileId([1, ..]), name, _)) if name == "cat.png"
    )));
    for (number, control) in [
        (1, ToxFileControl::TOX_FILE_CONTROL_RESUME),
        (2, ToxFileControl::TOX_FILE_CONTROL_CANCEL),
    ] {
        assert!(cmds.contains(&Cmd::Tox(ToxAction::FileControl(
            BOB,
            FileId([number; 32]),
            control
        ))));
    }
    // The declined file has ended, for every device to see.
    assert!(
        model
            .events
            .graph(&chat)
            .iter()
            .any(|(_, event)| event.content
                == Content::FileEnded {
                    file: offered[1],
                    ok: false,
                    blob: None,
                })
    );
}

#[test]
fn test_our_names_and_keys_in_chats_are_recorded() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    let chat_id = GroupChatId([5u8; 32]);
    model.session.group_numbers.insert(GroupNumber(0), chat_id);
    model.ensure_group_window(chat_id);
    model.record_account();
    let window = WindowId::Group(chat_id);
    model
        .domain
        .conversations
        .get_mut(&window)
        .unwrap()
        .self_name = Some("iphy".to_owned());
    model.session.group_settings.insert(
        chat_id,
        GroupSettings {
            privacy: ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PUBLIC,
            peer_limit: 100,
            password: String::new(),
            topic_lock: false,
            voice_state: ToxGroupVoiceState::TOX_GROUP_VOICE_STATE_ALL,
            self_pk: BOB,
        },
    );

    let account = GraphId::account(&ME);
    model.record_account();
    let recorded = model.events.graph(&account).len();
    model.record_account();
    assert_eq!(model.events.graph(&account).len(), recorded);
    let facts = model
        .account
        .facts
        .of(&Subject::Chat(ChatId::Group(chat_id)));
    assert!(facts.contains(&Value::SelfName("iphy".to_owned())));
    assert!(facts.contains(&Value::SelfKey(BOB)));
}

/// The live facts sent to the device.
fn live_to_device(cmds: &[Cmd]) -> Vec<(Subject, Value)> {
    sent_to(cmds, DEVICE)
        .into_iter()
        .flat_map(|message| match message {
            SessionMessage::Facts { facts, .. } => facts,
            _ => Vec::new(),
        })
        .collect()
}

#[test]
fn test_devices_see_members_and_change_tox() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    model
        .domain
        .friends
        .insert(DEVICE, friend("Device", DEVICE));
    handle_command(&mut model, "/device allow 0");
    let chat_id = GroupChatId([5u8; 32]);
    let chat = ChatId::Group(chat_id);
    model.session.group_numbers.insert(GroupNumber(0), chat_id);
    model.ensure_group_window(chat_id);
    model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
        .unwrap()
        .peers
        .push(PeerInfo {
            id: PeerId(BOB),
            name: "Bob".to_owned(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    model.record_account();

    let bob = Subject::Peer { chat, pk: BOB };
    let start = from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    let members = live_to_device(&start);
    assert!(members.contains(&(bob, Value::Name("Bob".to_owned()))));
    assert!(members.contains(&(bob, Value::Role(Role::User))));

    let alice = PublicKey([8u8; 32]);
    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            GroupNumber(0),
            toxcore::tox::GroupPeerNumber(1),
            "Alice".to_owned(),
            ToxGroupRole::TOX_GROUP_ROLE_MODERATOR,
            alice,
        )),
    );
    assert!(live_to_device(&cmds).contains(&(
        Subject::Peer { chat, pk: alice },
        Value::Role(Role::Moderator)
    )));
    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerLeave(
            GroupNumber(0),
            toxcore::tox::GroupPeerNumber(1),
        )),
    );
    assert_eq!(
        live_to_device(&cmds),
        [(Subject::Peer { chat, pk: alice }, Value::Present(false))]
    );

    let wish = |model: &mut Model, subject, value| {
        let (_, bytes) = synced_account(model).create(
            GraphId::account(&ME),
            DEVICE,
            0,
            Content::Want { subject, value },
        );
        from(model, DEVICE, SessionMessage::Events(vec![bytes]))
    };
    assert!(
        wish(&mut model, bob, Value::Role(Role::Moderator)).contains(&Cmd::Tox(
            ToxAction::ModerateGroupPeer(
                chat_id,
                BOB,
                Some(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR)
            )
        ))
    );
    // Not something Tox can be told.
    let before = model.events.graph(&GraphId::account(&ME)).len();
    wish(
        &mut model,
        Subject::Friend(BOB),
        Value::Name("Robert".to_owned()),
    );
    assert_eq!(model.events.graph(&GraphId::account(&ME)).len(), before);
    // Nor a name longer than Tox takes, which stays as it was.
    let cmds = wish(&mut model, Subject::Account, Value::Name("é".repeat(100)));
    assert!(
        !cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::SetName(_))))
    );
    assert_eq!(model.domain.self_name, "Me");

    let cmds = wish(&mut model, Subject::Chat(chat), Value::Joined(false));
    assert!(cmds.contains(&Cmd::Tox(ToxAction::LeaveGroup(chat_id))));
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::Fact {
                    subject: Subject::Chat(chat),
                    value: Value::Joined(false),
                })
    );
}

#[test]
fn test_messages_keep_their_bytes() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(FriendNumber(1), BOB);
    model.domain.friends.insert(BOB, friend("Bob", BOB));
    // Not all text: clients put other data into messages too.
    let bytes = b"hi\xff\0\x07".to_vec();
    update(
        &mut model,
        Msg::Tox(ToxEvent::Message(
            FriendNumber(1),
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            bytes.clone(),
        )),
    );

    let chat = GraphId::friend(&ME, &BOB);
    let recorded = model.events.graph(&chat);
    assert!(matches!(
        &recorded[..],
        [(_, event)] if matches!(&event.content, Content::Received { message, .. } if *message == bytes)
    ));
    let window = WindowId::Friend(BOB);
    let texts = |model: &Model| -> Vec<String> {
        model.domain.conversations[&window]
            .messages
            .iter()
            .filter_map(|msg| msg.content.as_text().map(str::to_owned))
            .collect()
    };
    assert_eq!(texts(&model), ["hi\u{fffd}\0\x07"]);
    model.domain.conversations.remove(&window);
    model.ensure_friend_window(BOB);
    assert_eq!(texts(&model), ["hi\u{fffd}\0\x07"]);
}

#[test]
fn test_read_markers() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    for (number, name, pk) in [(0, "Device", DEVICE), (1, "Bob", BOB)] {
        model
            .session
            .friend_numbers
            .insert(FriendNumber(number), pk);
        model.domain.friends.insert(pk, friend(name, pk));
    }
    handle_command(&mut model, "/device allow 0");
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    let chat = GraphId::friend(&ME, &BOB);
    let message = |model: &mut Model| {
        update(
            model,
            Msg::Tox(ToxEvent::Message(
                FriendNumber(1),
                MessageType::TOX_MESSAGE_TYPE_NORMAL,
                b"hi".to_vec(),
            )),
        )
    };

    // Unread here, so not read anywhere.
    message(&mut model);
    assert!(!model.account.read.contains_key(&chat));
    assert_eq!(
        model.ui.window_state[&WindowId::Friend(BOB)].unread_count,
        1
    );

    // Read on the device: read here too.
    let (rank, newest) = model
        .events
        .heads_of(&chat)
        .iter()
        .map(|id| (model.events.get(id).unwrap().rank, *id))
        .max()
        .unwrap();
    let mut device = EventStore::default();
    // Marking a concurrent event of the same rank reads it too.
    let concurrent = EventId([0u8; 32]);
    let read = Content::ReadUpTo {
        graph: chat,
        event: concurrent,
        rank,
    };
    let (_, bytes) = device.create(GraphId::account(&ME), DEVICE, 0, read);
    let (_, unknown) = device.create(
        GraphId::account(&ME),
        DEVICE,
        0,
        Content::ReadUpTo {
            graph: GraphId::friend(&ME, &ME),
            event: newest,
            rank,
        },
    );
    from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![bytes, unknown.clone()]),
    );
    assert_eq!(model.account.read[&chat], (rank, concurrent));
    assert_eq!(
        model.ui.window_state[&WindowId::Friend(BOB)].unread_count,
        0
    );
    // Kept, as the device has it, though there's no such chat.
    assert!(model.events.get(&EventId::of(&unknown)).is_some());

    // Read here: the devices hear of it.
    message(&mut model);
    let index = model
        .ui
        .window_ids
        .iter()
        .position(|id| *id == WindowId::Friend(BOB))
        .unwrap();
    model.set_active_window(index);
    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::FriendName(FriendNumber(1), "Robert".to_owned())),
    );
    assert!(events_in(&sent_to(&cmds, DEVICE))
        .iter()
        .any(|event| matches!(event.content, Content::ReadUpTo { graph, rank: r, .. } if graph == chat && r > rank)));

    // Shown with nobody there, it's read only once someone acts in it.
    let read = |cmds: &[Cmd]| {
        events_in(&sent_to(cmds, DEVICE))
            .iter()
            .any(|event| matches!(event.content, Content::ReadUpTo { graph, .. } if graph == chat))
    };
    assert!(!read(&message(&mut model)));
    let key = KeyEvent::new(KeyCode::End, KeyModifiers::NONE);
    let mut cmds = update(&mut model, Msg::Input(CrosstermEvent::Key(key)));
    cmds.extend(update(&mut model, Msg::System(SystemEvent::Tick)));
    assert!(read(&cmds));
}

#[test]
fn test_device_merges_chats_and_changes_settings() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    model
        .domain
        .friends
        .insert(DEVICE, friend("Device", DEVICE));
    handle_command(&mut model, "/device allow 0");
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    let group = GroupChatId([5u8; 32]);
    model.ensure_group_window(group);
    let conference_id = ConferenceId([6u8; 32]);
    let conference = ChatId::Conference(conference_id);
    let merge = |chat| Content::MergeChat {
        chat,
        bot: BOB,
        into: ChatId::Group(group),
        into_bot: PublicKey([7u8; 32]),
        merged: true,
    };

    // A chat this account isn't in is merged as the device has it, as one
    // it left since.
    let mut device = EventStore::default();
    let account = GraphId::account(&ME);
    let (unknown, bytes) = device.create(account, DEVICE, 0, merge(conference));
    from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(model.events.get(&unknown).is_some());

    model.ensure_conference_window(conference_id);
    let mut device = EventStore::default();
    let (merged, bytes) = device.create(account, DEVICE, 0, merge(conference));
    from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(model.events.get(&merged).is_some());
    assert_eq!(model.account.merges[&conference].bot, BOB);

    // Of changes made at once, the one later by ID wins, whichever comes
    // first.
    let mut changes = [true, false].map(|on| {
        let content = Content::MergeChat {
            chat: conference,
            bot: BOB,
            into: ChatId::Group(group),
            into_bot: PublicKey([7u8; 32]),
            merged: on,
        };
        let mut store = EventStore::default();
        store.insert(model.events.bytes(&merged).unwrap()).unwrap();
        store.create(account, DEVICE, 1, content)
    });
    changes.sort_by_key(|(id, _)| *id);
    let [(_, loser), (_, winner)] = changes;
    let winner_merges = matches!(
        Event::decode(&winner).unwrap().content,
        Content::MergeChat { merged: true, .. }
    );
    from(&mut model, DEVICE, SessionMessage::Events(vec![winner]));
    from(&mut model, DEVICE, SessionMessage::Events(vec![loser]));
    assert_eq!(
        model.account.merges.contains_key(&conference),
        winner_merges
    );

    let scope = Scope::Conversation(GraphId::group(&group));
    let mute = Mute {
        until: None,
        mentions: true,
    };
    let set = |scope, setting| Content::Setting { scope, setting };
    let mut device = EventStore::default();
    let (muted, bytes) = device.create(account, DEVICE, 2, set(scope.clone(), mute.clone().into()));
    from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(model.events.get(&muted).is_some());
    assert_eq!(model.account.setting::<Mute>(&scope), Some(&mute));

    // Too long, while one of a conversation the account left since is kept.
    let mut long = vec![0xc5, 0x04, 0x00];
    long.resize(3 + MAX_SETTING, 0);
    for (content, kept) in [
        (
            set(
                scope.clone(),
                Setting::Unknown {
                    discriminant: 7,
                    data: long,
                }
                .into(),
            ),
            false,
        ),
        (
            set(
                Scope::Conversation(GraphId::group(&GroupChatId([9u8; 32]))),
                mute.clone().into(),
            ),
            true,
        ),
    ] {
        let (id, bytes) = EventStore::default().create(account, DEVICE, 3, content);
        from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
        assert_eq!(model.events.get(&id).is_some(), kept);
    }

    let cleared = Content::ClearSetting {
        scope: scope.clone(),
        kind: Mute::KIND,
    };
    let (cleared, bytes) = device.create(account, DEVICE, 4, cleared);
    from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(model.events.get(&cleared).is_some());
    assert_eq!(model.account.setting::<Mute>(&scope), None);
}

/// The device's file of `blob`, as it sends it.
fn device_file(chat: GraphId, blob: BlobId) -> (EventId, Vec<u8>) {
    EventStore::default().create(
        chat,
        DEVICE,
        0,
        Content::File {
            sender: "Me".to_owned(),
            file_id: None,
            name: "cat.png".to_owned(),
            size: 3,
            incoming: false,
            blob: Some(blob),
        },
    )
}

fn ended(model: &Model, chat: &GraphId, file: EventId) -> Option<Content> {
    model
        .events
        .graph(chat)
        .iter()
        .map(|(_, event)| event.content.clone())
        .find(|content| matches!(content, Content::FileEnded { file: f, .. } if *f == file))
}

#[test]
fn test_device_sends_a_file() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    let blob = BlobId([9u8; 32]);
    let (file, bytes) = device_file(chat, blob);

    // toxxi fetches the blob from the device first.
    let cmds = from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(sent_to(&cmds, DEVICE).contains(&SessionMessage::WantBlob(blob)));
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            FriendNumber(0),
            file_id(&blob),
            BLOB_FILE_KIND,
            3,
            String::new(),
        )),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::ReceiveBlob(DEVICE, blob, 3))));
    let cmds = update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(DEVICE, file_id(&blob), 0, 3)),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::StoreBlob(DEVICE, blob))));

    // Then sends it to Bob, as the device's message.
    let cmds = update(&mut model, Msg::IO(IOEvent::BlobStored(DEVICE, blob, true)));
    let Some((path, sent)) = cmds.iter().find_map(|cmd| match cmd {
        Cmd::Tox(ToxAction::FileSend(BOB, 0, 3, name, path, Some(id))) if name == "cat.png" => {
            Some((path.clone(), *id))
        }
        _ => None,
    }) else {
        panic!("not sent to Bob: {:?}", cmds);
    };
    let events = model.events.graph(&chat).len();
    update(
        &mut model,
        Msg::IO(IOEvent::FileStarted(BOB, sent, path, 3)),
    );
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FileChunkSent(FriendNumber(1), sent, 0, 3)),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::FinishFile(BOB, sent))));
    update(
        &mut model,
        Msg::IO(IOEvent::FileFinished(BOB, sent, Some(blob))),
    );
    assert_eq!(model.events.graph(&chat).len(), events + 1);
    assert_eq!(
        ended(&model, &chat, file),
        Some(Content::FileEnded {
            file,
            ok: true,
            blob: Some(blob),
        })
    );
}

#[test]
fn test_file_fails_without_its_blob() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    let blob = BlobId([9u8; 32]);
    let (file, bytes) = device_file(chat, blob);
    from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));

    from(&mut model, DEVICE, SessionMessage::NoBlob(blob));
    assert_eq!(
        ended(&model, &chat, file),
        Some(Content::FileEnded {
            file,
            ok: false,
            blob: None,
        })
    );
}

#[test]
fn test_devices_fetch_blobs() {
    let mut model = with_device_and_bob();
    let blob = BlobId([9u8; 32]);
    let missing = BlobId([8u8; 32]);
    model.blobs.insert(blob);

    let cmds = from(&mut model, DEVICE, SessionMessage::WantBlob(missing));
    assert_eq!(
        sent_to(&cmds, DEVICE),
        vec![SessionMessage::NoBlob(missing)]
    );
    let cmds = from(&mut model, DEVICE, SessionMessage::WantBlob(blob));
    assert_eq!(
        cmds,
        vec![Cmd::IO(IOAction::SendBlob(DEVICE, blob, BLOB_FILE_KIND))]
    );
    let cmds = update(
        &mut model,
        Msg::IO(IOEvent::FileStarted(
            DEVICE,
            file_id(&blob),
            "blob".to_owned(),
            3,
        )),
    );
    assert_eq!(
        cmds,
        vec![Cmd::IO(IOAction::OpenFileForSending(
            DEVICE,
            file_id(&blob),
            "blob".to_owned()
        ))]
    );
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FileChunkSent(
            FriendNumber(0),
            file_id(&blob),
            0,
            3,
        )),
    );
    assert_eq!(
        cmds,
        vec![Cmd::IO(IOAction::CloseFile(DEVICE, file_id(&blob)))]
    );
}

fn calls_with_bob(model: &Model) -> Vec<Content> {
    model
        .events
        .graph(&GraphId::friend(&ME, &BOB))
        .into_iter()
        .map(|(_, event)| event.content.clone())
        .filter(|content| matches!(content, Content::Call { .. } | Content::CallEnded { .. }))
        .collect()
}

fn call(model: &mut Model, action: CallAction) -> Vec<Cmd> {
    from(
        model,
        DEVICE,
        SessionMessage::Call {
            friend: BOB,
            action,
        },
    )
}

#[test]
fn test_devices_take_the_accounts_calls() {
    let mut model = with_device_and_bob();
    let bob = Subject::Friend(BOB);

    let cmds = update(&mut model, Msg::Tox(ToxEvent::CallRinging(BOB, true)));
    assert!(
        live_to_device(&cmds).contains(&(bob, Value::Call(CallState::Ringing { video: true })))
    );
    let cmds = call(&mut model, CallAction::Connect { video: false });
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::CallConnect {
            friend: BOB,
            device: DEVICE,
            video: false,
        })
    )));
    assert!(live_to_device(&cmds).contains(&(bob, Value::Call(CallState::Answered))));
    update(&mut model, Msg::Tox(ToxEvent::CallConnected(BOB)));
    let cmds = update(&mut model, Msg::Tox(ToxEvent::CallEnded(BOB)));
    assert!(live_to_device(&cmds).contains(&(bob, Value::Call(CallState::None))));

    // Declined where it rang, so not missed.
    update(&mut model, Msg::Tox(ToxEvent::CallRinging(BOB, false)));
    let cmds = call(&mut model, CallAction::HangUp);
    assert!(
        cmds.iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::CallHangUp(BOB))))
    );

    // Placed from the device.
    let cmds = call(&mut model, CallAction::Connect { video: true });
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::CallConnect {
            friend: BOB,
            device: DEVICE,
            video: true,
        })
    )));
    update(&mut model, Msg::Tox(ToxEvent::CallEnded(BOB)));

    let history = calls_with_bob(&model);
    assert!(
        matches!(
            history.as_slice(),
            [
                Content::Call {
                    incoming: true,
                    video: true,
                    ..
                },
                Content::CallEnded {
                    duration: Some(_),
                    declined: false,
                    ..
                },
                Content::Call {
                    incoming: true,
                    video: false,
                    ..
                },
                Content::CallEnded {
                    duration: None,
                    declined: true,
                    ..
                },
                Content::Call {
                    incoming: false,
                    video: true,
                    ..
                },
                Content::CallEnded {
                    duration: None,
                    declined: false,
                    ..
                },
            ]
        ),
        "{history:?}"
    );
}

/// The device's answer to `invite`, as it sends it.
fn answer_invite(
    model: &mut Model,
    invite: EventId,
    join: bool,
    password: Option<&str>,
) -> Vec<Cmd> {
    let mut device = EventStore::default();
    for id in model.events.heads_of(&GraphId::account(&ME)).to_vec() {
        device.insert(model.events.bytes(&id).unwrap()).unwrap();
    }
    device.insert(model.events.bytes(&invite).unwrap()).unwrap();
    let (_, bytes) = device.create(
        GraphId::account(&ME),
        DEVICE,
        0,
        Content::AnswerInvite {
            invite,
            join,
            password: password.map(str::to_owned),
        },
    );
    from(model, DEVICE, SessionMessage::Events(vec![bytes]))
}

fn invite_status(model: &Model, invite: EventId) -> InviteStatus {
    model.account.invites[&invite].status
}

#[test]
fn test_devices_answer_invites() {
    let mut model = with_device_and_bob();
    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupInvite(
            FriendNumber(1),
            "010203".to_owned(),
            "Tox".to_owned(),
        )),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::ChatInvite {
                    from: BOB,
                    kind: ChatKind::Group,
                    name: "Tox".to_owned(),
                    invite: vec![1, 2, 3],
                })
    );
    let group = *model.account.invites.keys().next().unwrap();

    // Bob is online, so it's joined at once, and then no longer pending here.
    let cmds = answer_invite(&mut model, group, true, None);
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AcceptGroupInvite(
        BOB,
        "010203".to_owned(),
        "Tox".to_owned(),
        String::new(),
        Some(group),
    ))));
    let chat = ChatId::Group(GroupChatId([5u8; 32]));
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::InviteJoined(group, Some(chat))),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::InviteJoined {
                    invite: group,
                    chat: Some(chat),
                    needs_password: false,
                })
    );
    assert_eq!(invite_status(&model, group), InviteStatus::Joined(chat));
    assert!(model.domain.pending_items.is_empty());

    // Bob is offline: it's joined once he's back.
    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(1),
            ToxConnection::TOX_CONNECTION_NONE,
            Some(BOB),
        )),
    );
    settled(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceInvite(
            FriendNumber(1),
            ToxConferenceType::TOX_CONFERENCE_TYPE_TEXT,
            "0405".to_owned(),
        )),
    );
    let conference = *model
        .account
        .invites
        .iter()
        .find(|(_, invite)| invite.kind == ChatKind::Conference)
        .unwrap()
        .0;
    let join = Cmd::Tox(ToxAction::JoinConference(
        BOB,
        "0405".to_owned(),
        Some(conference),
    ));
    assert!(!answer_invite(&mut model, conference, true, None).contains(&join));
    assert_eq!(invite_status(&model, conference), InviteStatus::Joining);
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(1),
            ToxConnection::TOX_CONNECTION_UDP,
            Some(BOB),
        )),
    );
    assert!(cmds.contains(&join));

    // Where Tox refuses, it stays pending here, to try again.
    update(
        &mut model,
        Msg::Tox(ToxEvent::InviteJoined(conference, None)),
    );
    assert_eq!(
        invite_status(&model, conference),
        InviteStatus::Failed {
            needs_password: false
        }
    );
    assert_eq!(model.domain.pending_items.len(), 1);
    assert!(handle_command(&mut model, "/accept 0").contains(&join));
    update(
        &mut model,
        Msg::Tox(ToxEvent::InviteJoined(conference, None)),
    );
    handle_command(&mut model, "/reject 0");
    assert_eq!(invite_status(&model, conference), InviteStatus::Declined);
}

#[test]
fn test_a_group_that_turns_the_home_away_spends_its_invite() {
    let mut model = with_device_and_bob();
    settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupInvite(
            FriendNumber(1),
            "010203".to_owned(),
            "Tox".to_owned(),
        )),
    );
    let invite = *model.account.invites.keys().next().unwrap();
    assert!(
        answer_invite(&mut model, invite, true, Some("wrong")).contains(&Cmd::Tox(
            ToxAction::AcceptGroupInvite(
                BOB,
                "010203".to_owned(),
                "Tox".to_owned(),
                "wrong".to_owned(),
                Some(invite),
            )
        ))
    );
    let group = GroupChatId([5u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(GroupNumber(0), group, None)),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::InviteJoined(invite, Some(ChatId::Group(group)))),
    );

    // Tox joined it, then the group turned the account away.
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::GroupJoinFail(
            GroupNumber(0),
            ToxGroupJoinFail::TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD,
        )),
    );
    assert!(cmds.contains(&Cmd::Tox(ToxAction::LeaveGroup(group))));
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::InviteJoined {
                    invite,
                    chat: None,
                    needs_password: true,
                })
    );
    assert!(model.domain.pending_items.is_empty());

    // Tox takes an invite only once, so answering again can't join.
    let cmds = answer_invite(&mut model, invite, true, Some("secret"));
    assert!(!cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::AcceptGroupInvite(..) | ToxAction::JoinGroup(..))
    )));
    assert!(matches!(
        model.account.invites[&invite].status,
        InviteStatus::Failed { .. }
    ));
}

#[test]
fn test_a_new_tox_ends_the_calls_and_files_of_the_last() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    // One a crash left without its end, and one going on.
    model.events.create(
        chat,
        ME,
        0,
        Content::Call {
            sender: "Bob".to_owned(),
            incoming: true,
            video: false,
        },
    );
    update(&mut model, Msg::Tox(ToxEvent::CallRinging(BOB, false)));
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            FriendNumber(1),
            FileId([3u8; 32]),
            0,
            6,
            "a.txt".to_owned(),
        )),
    );
    let (offered, _) = model.events.graph(&chat).last().copied().unwrap();

    update(&mut model, Msg::Tox(ToxEvent::Started));
    assert!(model.session.calls.is_empty());
    let calls = calls_with_bob(&model);
    assert_eq!(
        calls
            .iter()
            .filter(|content| matches!(content, Content::CallEnded { .. }))
            .count(),
        2
    );
    assert!(matches!(
        ended(&model, &chat, offered),
        Some(Content::FileEnded { ok: false, .. })
    ));
    assert!(model.domain.file_transfers.is_empty());
    // Its sessions start over.
    assert!(model.session.sync_sessions.is_empty());
}

#[test]
fn test_a_call_ends_with_its_friend() {
    let mut model = with_device_and_bob();
    update(&mut model, Msg::Tox(ToxEvent::CallRinging(BOB, false)));
    let cmds = model.remove_friend(BOB);
    assert!(cmds.contains(&Cmd::Tox(ToxAction::CallHangUp(BOB))));
    assert!(model.session.calls.is_empty());
    assert!(matches!(
        calls_with_bob(&model).last(),
        Some(Content::CallEnded { .. })
    ));
}

#[test]
fn test_an_accepted_request_is_never_declined() {
    let mut model = with_device_and_bob();
    let carol = PublicKey([3u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendRequest(carol, "hi".to_owned())),
    );
    let cmds = handle_command(&mut model, "/accept 0");
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AcceptFriend(carol))));
    model.record_account();
    settled(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(2),
            ToxConnection::TOX_CONNECTION_NONE,
            Some(carol),
        )),
    );
    assert!(model.domain.pending_items.is_empty());
    let answers: Vec<_> = model
        .events
        .graph(&GraphId::account(&ME))
        .into_iter()
        .map(|(_, event)| event.content.clone())
        .filter(|content| {
            matches!(content, Content::WantFriend { pk, .. } | Content::UnwantFriend { pk } if *pk == carol)
        })
        .collect();
    assert!(
        matches!(answers[..], [Content::WantFriend { .. }]),
        "{answers:?}"
    );
}

#[test]
fn test_an_empty_file_is_sent() {
    let mut model = with_device_and_bob();
    model.ensure_friend_window(BOB);
    let file = FileId([4u8; 32]);
    update(
        &mut model,
        Msg::IO(IOEvent::FileStarted(BOB, file, "/tmp/empty".to_owned(), 0)),
    );
    // All toxcore asks of it.
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FileChunkRequest(FriendNumber(1), file, 0, 0)),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::FinishFile(BOB, file))));
    assert!(model.session.finishing.contains(&file));

    update(&mut model, Msg::IO(IOEvent::FileFinished(BOB, file, None)));
    assert!(model.session.finishing.is_empty());
    let chat = GraphId::friend(&ME, &BOB);
    assert!(
        model
            .events
            .graph(&chat)
            .iter()
            .any(|(_, event)| matches!(event.content, Content::FileEnded { ok: true, .. }))
    );
}

#[test]
fn test_a_file_sent_again_ends_as_its_own() {
    let mut model = with_device_and_bob();
    model.ensure_friend_window(BOB);
    let file = FileId([6u8; 32]);
    let start = |model: &mut Model| {
        update(
            model,
            Msg::IO(IOEvent::FileStarted(BOB, file, "/tmp/a.txt".to_owned(), 3)),
        )
    };
    start(&mut model);
    update(
        &mut model,
        Msg::IO(IOEvent::FileError(BOB, file, "gone".to_owned())),
    );
    // Resumed, as /file send does with its ID.
    start(&mut model);
    update(&mut model, Msg::IO(IOEvent::FileFinished(BOB, file, None)));

    let events: Vec<_> = model
        .events
        .graph(&GraphId::friend(&ME, &BOB))
        .into_iter()
        .map(|(id, event)| (id, event.content.clone()))
        .collect();
    let files: Vec<EventId> = events
        .iter()
        .filter(|(_, content)| matches!(content, Content::File { .. }))
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(files.len(), 2);
    for (file, ended_ok) in [(files[0], false), (files[1], true)] {
        assert!(matches!(
            ended(&model, &GraphId::friend(&ME, &BOB), file),
            Some(Content::FileEnded { ok, .. }) if ok == ended_ok
        ));
    }
}

#[test]
fn test_a_device_is_sent_a_few_blobs_at_once() {
    let mut model = with_device_and_bob();
    let blobs: Vec<BlobId> = (0..9).map(|i| BlobId([i; 32])).collect();
    let mut sent = Vec::new();
    for blob in &blobs {
        model.blobs.insert(*blob);
        for cmd in from(&mut model, DEVICE, SessionMessage::WantBlob(*blob)) {
            if let Cmd::IO(IOAction::SendBlob(DEVICE, blob, _)) = cmd {
                sent.push(blob);
            }
        }
    }
    assert_eq!(sent, blobs[..8]);

    // One done makes room for the next.
    update(
        &mut model,
        Msg::IO(IOEvent::FileStarted(
            DEVICE,
            file_id(&blobs[0]),
            "blob".to_owned(),
            3,
        )),
    );
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FileChunkSent(
            FriendNumber(0),
            file_id(&blobs[0]),
            0,
            3,
        )),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::SendBlob(
        DEVICE,
        blobs[8],
        BLOB_FILE_KIND
    ))));

    // A device removed gets none it was waiting for.
    model.blobs.insert(BlobId([9; 32]));
    from(
        &mut model,
        DEVICE,
        SessionMessage::WantBlob(BlobId([9; 32])),
    );
    assert!(!model.session.blob_queue.is_empty());
    handle_command(&mut model, "/device remove 0");
    assert!(model.session.blob_queue.is_empty());
}

#[test]
fn test_a_file_with_a_name_tox_doesnt_take_fails() {
    let mut model = with_device_and_bob();
    let chat = GraphId::friend(&ME, &BOB);
    let blob = BlobId([9u8; 32]);
    model.blobs.insert(blob);
    let (file, bytes) = EventStore::default().create(
        chat,
        DEVICE,
        0,
        Content::File {
            sender: "Me".to_owned(),
            file_id: None,
            name: "é".repeat(200),
            size: 3,
            incoming: false,
            blob: Some(blob),
        },
    );
    let cmds = from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(
        !cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::FileSend(..))))
    );
    assert!(matches!(
        ended(&model, &chat, file),
        Some(Content::FileEnded { ok: false, .. })
    ));
}

#[test]
fn test_a_device_allowed_online_starts_its_session() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    model
        .domain
        .friends
        .insert(DEVICE, friend("Device", DEVICE));
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    assert!(!model.session.sync_sessions.contains(&DEVICE));

    let cmds = handle_command(&mut model, "/device allow 0");
    assert!(model.session.sync_sessions.contains(&DEVICE));
    assert!(
        sent_to(&cmds, DEVICE)
            .iter()
            .any(|message| matches!(message, SessionMessage::Summary(_)))
    );
}

#[test]
fn test_an_event_another_device_let_through_reaches_the_first() {
    let mut model = with_device_and_bob();
    let other = PublicKey([5u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(2), other);
    model.domain.friends.insert(other, friend("Other", other));
    handle_command(&mut model, "/device allow 2");
    let from_other = |model: &mut Model, message: SessionMessage| {
        update(
            model,
            Msg::Tox(ToxEvent::SyncMessage(FriendNumber(2), message.encode())),
        )
    };
    from_other(&mut model, SessionMessage::hello(Features::ACCOUNT_SYNC));

    // The device read what the other device wrote, which hasn't come yet.
    let chat = GraphId::friend(&ME, &BOB);
    let send = |text: &str| Content::Send {
        sender: "Me".to_owned(),
        message: text.as_bytes().to_vec(),
        kind: MessageType::TOX_MESSAGE_TYPE_NORMAL,
    };
    let mut store = EventStore::default();
    let (first, first_bytes) = store.create(chat, other, 0, send("first"));
    let (second, second_bytes) = store.create(chat, DEVICE, 0, send("second"));
    from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![second_bytes]),
    );

    let cmds = from_other(&mut model, SessionMessage::Events(vec![first_bytes]));
    let ids = |to| -> Vec<EventId> {
        sent_to(&cmds, to)
            .iter()
            .flat_map(|message| match message {
                SessionMessage::Events(events) => events.iter().map(|e| EventId::of(e)).collect(),
                _ => Vec::new(),
            })
            .collect()
    };
    assert!(ids(DEVICE).contains(&first) && !ids(DEVICE).contains(&second));
    assert!(ids(other).contains(&second) && !ids(other).contains(&first));
}

fn avatar_of(model: &Model, subject: &Subject) -> Option<Option<BlobId>> {
    model.account.facts.find(subject, |value| match value {
        Value::Avatar(avatar) => Some(*avatar),
        _ => None,
    })
}

#[test]
fn test_a_friends_avatar_is_kept() {
    let mut model = with_device_and_bob();
    let blob = BlobId([9u8; 32]);
    let offer = |size| {
        Msg::Tox(ToxEvent::FileRecv(
            FriendNumber(1),
            file_id(&blob),
            toxxi::sync::avatars::FILE_KIND,
            size,
            String::new(),
        ))
    };

    let cmds = update(&mut model, offer(3));
    assert!(cmds.contains(&Cmd::IO(IOAction::ReceiveBlob(BOB, blob, 3))));
    let cmds = update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(BOB, file_id(&blob), 0, 3)),
    );
    assert!(cmds.contains(&Cmd::IO(IOAction::StoreBlob(BOB, blob))));
    update(&mut model, Msg::IO(IOEvent::BlobStored(BOB, blob, true)));
    assert_eq!(avatar_of(&model, &Subject::Friend(BOB)), Some(Some(blob)));

    // An avatar toxxi holds isn't taken again, and an empty one is none.
    let cancel = Cmd::Tox(ToxAction::FileControl(
        BOB,
        file_id(&blob),
        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL,
    ));
    assert!(update(&mut model, offer(3)).contains(&cancel));
    assert!(update(&mut model, offer(0)).contains(&cancel));
    assert_eq!(avatar_of(&model, &Subject::Friend(BOB)), Some(None));
    // Nor one bigger than Tox's avatars are.
    let cmds = update(&mut model, offer(toxxi::sync::avatars::MAX_SIZE + 1));
    assert_eq!(cmds, vec![cancel]);
}

#[test]
fn test_devices_wish_for_the_accounts_avatar() {
    let mut model = with_device_and_bob();
    let blob = BlobId([9u8; 32]);
    let (_, bytes) = EventStore::default().create(
        GraphId::account(&ME),
        DEVICE,
        0,
        Content::Want {
            subject: Subject::Account,
            value: Value::Avatar(Some(blob)),
        },
    );

    // toxxi fetches the blob from the device first.
    let cmds = from(&mut model, DEVICE, SessionMessage::Events(vec![bytes]));
    assert!(sent_to(&cmds, DEVICE).contains(&SessionMessage::WantBlob(blob)));
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            FriendNumber(0),
            file_id(&blob),
            BLOB_FILE_KIND,
            3,
            String::new(),
        )),
    );
    update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(DEVICE, file_id(&blob), 0, 3)),
    );

    // Then makes it the account's and sends it to Bob, who is online.
    let cmds = update(&mut model, Msg::IO(IOEvent::BlobStored(DEVICE, blob, true)));
    assert_eq!(avatar_of(&model, &Subject::Account), Some(Some(blob)));
    assert!(cmds.contains(&Cmd::IO(IOAction::SendBlob(
        BOB,
        blob,
        toxxi::sync::avatars::FILE_KIND
    ))));
}

#[test]
fn test_friends_coming_online_are_told_there_is_no_avatar() {
    let mut model = with_device_and_bob();
    let cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            FriendNumber(1),
            ToxConnection::TOX_CONNECTION_UDP,
            Some(BOB),
        )),
    );
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::FileSend(
            BOB,
            toxxi::sync::avatars::FILE_KIND,
            0,
            ..
        ))
    )));
}

#[test]
fn test_private_messages_in_groups() {
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Me".to_owned(),
        String::new(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(FriendNumber(0), DEVICE);
    model
        .domain
        .friends
        .insert(DEVICE, friend("Device", DEVICE));
    handle_command(&mut model, "/device allow 0");
    let chat_id = GroupChatId([5u8; 32]);
    let window = WindowId::Group(chat_id);
    model.session.group_numbers.insert(GroupNumber(0), chat_id);
    model.ensure_group_window(chat_id);
    model
        .domain
        .conversations
        .get_mut(&window)
        .unwrap()
        .peers
        .push(PeerInfo {
            id: PeerId(BOB),
            name: "Bob Smith".to_owned(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    from(
        &mut model,
        DEVICE,
        SessionMessage::hello(Features::ACCOUNT_SYNC),
    );
    let normal = MessageType::TOX_MESSAGE_TYPE_NORMAL;

    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupPrivateMessage(
            GroupNumber(0),
            normal,
            "Bob Smith".to_owned(),
            b"psst".to_vec(),
            BOB,
        )),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content
                == Content::ReceivedPrivately {
                    from: BOB,
                    sender: "Bob Smith".to_owned(),
                    message: b"psst".to_vec(),
                    kind: normal,
                })
    );

    // The peer's name may have spaces, and the rest is the message.
    let pos = model.ui.window_ids.iter().position(|&w| w == window);
    model.set_active_window(pos.unwrap());
    let cmds = handle_command(&mut model, "/whisper Bob Smith hello there");
    assert!(cmds.contains(&Cmd::Tox(ToxAction::SendGroupPrivateMessage(
        chat_id,
        BOB,
        normal,
        b"hello there".to_vec(),
        model.domain.conversations[&window].messages[1].internal_id,
    ))));
    assert!(matches!(
        model.domain.conversations[&window].messages[..],
        [ref theirs, ref ours] if theirs.privately == Some(BOB) && ours.privately == Some(BOB)
    ));

    // A device's goes to Tox alone too, and only in groups.
    let chat = GraphId::group(&chat_id);
    let privately = Content::SendPrivately {
        to: BOB,
        sender: "Me".to_owned(),
        message: b"from the device".to_vec(),
        kind: normal,
    };
    let (id, bytes) = EventStore::default().create(chat, DEVICE, 0, privately.clone());
    let elsewhere = EventStore::default()
        .create(GraphId::friend(&ME, &BOB), DEVICE, 0, privately)
        .1;
    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![bytes, elsewhere.clone()]),
    );
    let internal_id = model.domain.conversations[&window].messages[2].internal_id;
    assert!(cmds.contains(&Cmd::Tox(ToxAction::SendGroupPrivateMessage(
        chat_id,
        BOB,
        normal,
        b"from the device".to_vec(),
        internal_id,
    ))));
    assert!(model.events.get(&EventId::of(&elsewhere)).is_none());
    let cmds = settled(
        &mut model,
        Msg::Tox(ToxEvent::GroupMessageSent(GroupNumber(0), internal_id)),
    );
    assert!(
        events_in(&sent_to(&cmds, DEVICE))
            .iter()
            .any(|event| event.content == Content::Sent { intent: id })
    );
}

#[test]
fn test_devices_add_accept_and_remove_friends() {
    let mut model = with_device_and_bob();
    let carol = PublicKey([3u8; 32]);
    let dave = PublicKey([4u8; 32]);
    model.domain.pending_items.push(PendingItem::FriendRequest {
        pk: dave,
        message: "hi".to_owned(),
    });
    let account = GraphId::account(&ME);
    let mut device = synced_account(&model);
    let mut write = |content| device.create(account, DEVICE, 0, content).1;
    let events = vec![
        write(Content::WantFriend {
            pk: carol,
            request_message: Some("from my phone".to_owned()),
            nospam: Some(0x01020304),
        }),
        write(Content::WantFriend {
            pk: dave,
            request_message: None,
            nospam: None,
        }),
        write(Content::UnwantFriend { pk: BOB }),
        // The account's devices stay its friends.
        write(Content::UnwantFriend { pk: DEVICE }),
    ];
    let cmds = from(&mut model, DEVICE, SessionMessage::Events(events.clone()));
    let address = Address::from_public_key(carol, 0x01020304);
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AddFriend(
        toxxi::utils::encode_hex(&address.0),
        "from my phone".to_owned(),
    ))));
    assert!(cmds.contains(&Cmd::Tox(ToxAction::AcceptFriend(dave))));
    assert!(cmds.contains(&Cmd::Tox(ToxAction::DeleteFriend(BOB))));
    assert!(model.events.get(&EventId::of(&events[3])).is_none());
    assert!(model.domain.friends.contains_key(&DEVICE));
    // Wanted until Tox says otherwise, so the account keeps them.
    assert!(model.domain.friends.contains_key(&carol));
    assert!(model.account.friends[&carol].wanted);
}

/// The account graph as the home holds it, for a device that has synced it.
fn synced_account(model: &Model) -> EventStore {
    let mut store = EventStore::default();
    for (id, _) in model.events.by_rank(&GraphId::account(&ME)) {
        store.insert(model.events.bytes(&id).unwrap()).unwrap();
    }
    store
}

#[test]
fn test_a_friend_change_written_offline_loses_to_a_later_one() {
    let mut model = with_device_and_bob();
    let account = GraphId::account(&ME);
    let (_, removed_offline) =
        EventStore::default().create(account, DEVICE, 0, Content::UnwantFriend { pk: BOB });
    let (_, wanted_since) = synced_account(&model).create(
        account,
        DEVICE,
        0,
        Content::WantFriend {
            pk: BOB,
            request_message: None,
            nospam: None,
        },
    );
    from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![wanted_since]),
    );

    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![removed_offline]),
    );
    assert!(!cmds.contains(&Cmd::Tox(ToxAction::DeleteFriend(BOB))));
    assert!(model.domain.friends.contains_key(&BOB));
    assert!(model.account.friends[&BOB].wanted);
}

#[test]
fn test_a_wish_written_offline_loses_to_a_later_change() {
    let mut model = with_device_and_bob();
    let (_, wished_offline) = EventStore::default().create(
        GraphId::account(&ME),
        DEVICE,
        0,
        Content::Want {
            subject: Subject::Account,
            value: Value::Name("Old".to_owned()),
        },
    );
    handle_command(&mut model, "/nick New");
    update(&mut model, Msg::System(SystemEvent::Tick));

    let cmds = from(
        &mut model,
        DEVICE,
        SessionMessage::Events(vec![wished_offline]),
    );
    assert!(!cmds.contains(&Cmd::Tox(ToxAction::SetName("Old".to_owned()))));
    assert_eq!(model.domain.self_name, "New");
}
