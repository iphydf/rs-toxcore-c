use toxcore::tox::{Address, FriendMessageId, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    FriendInfo, Message, MessageStatus, Model, ToxSelfInfo, WindowId, load_or_initialize,
    save_state,
};
use toxxi::msg::{Cmd, IOAction, Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::script::ScriptRequest;
use toxxi::sync::store::{EVENTS_FILE, append_log};
use toxxi::update::{handle_command, update};
use toxxi::waits::WAITS;

const ALICE: PublicKey = PublicKey([1u8; 32]);

fn start(config_dir: &std::path::Path) -> Model {
    load_or_initialize(
        config_dir,
        ToxSelfInfo {
            tox_id: Address([0u8; 38]),
            name: "Me".to_owned(),
            status_msg: String::new(),
            status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
        },
        vec![(
            FriendNumber(0),
            FriendInfo {
                name: "Alice".to_owned(),
                public_key: Some(ALICE),
                status_message: String::new(),
                connection: ToxConnection::TOX_CONNECTION_NONE,
                is_typing: false,
            },
        )],
        vec![],
        vec![],
        Config::default(),
        Config::default(),
    )
}

/// Does what the IO worker does with the commands.
fn save(config_dir: &std::path::Path, cmds: &[Cmd]) {
    for cmd in cmds {
        if let Cmd::IO(IOAction::AppendEvents(records, _)) = cmd {
            append_log(&config_dir.join(EVENTS_FILE), records).unwrap();
        }
    }
}

fn messages(model: &Model) -> Vec<(String, bool, Option<String>, MessageStatus)> {
    model.domain.conversations[&WindowId::Friend(ALICE)]
        .messages
        .iter()
        .map(|m: &Message| {
            (
                m.sender.clone(),
                m.is_self,
                m.content.as_text().map(str::to_owned),
                m.status,
            )
        })
        .collect()
}

#[test]
fn test_conversation_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut model = start(dir.path());

    let mut cmds = update(
        &mut model,
        Msg::Tox(ToxEvent::Message(
            FriendNumber(0),
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            b"hi".to_vec(),
        )),
    );
    let sent = handle_command(&mut model, "/msg 0 hello");
    let internal_id = sent
        .iter()
        .find_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(_, _, _, id)) => Some(*id),
            _ => None,
        })
        .unwrap();
    cmds.extend(sent);
    cmds.extend(handle_command(&mut model, "/msg 0 unsent"));
    cmds.extend(update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(
            FriendNumber(0),
            FriendMessageId(7),
            internal_id,
        )),
    ));
    cmds.extend(update(
        &mut model,
        Msg::Tox(ToxEvent::ReadReceipt(FriendNumber(0), FriendMessageId(7))),
    ));
    save(dir.path(), &cmds);
    save_state(dir.path(), &model).unwrap();

    let before = messages(&model);
    assert_eq!(before.len(), 3);
    assert_eq!(before[1].3, MessageStatus::Received);
    let mut after = messages(&start(dir.path()));
    // Never sent, so it's sent again after the restart.
    assert_eq!(after[2].3, MessageStatus::Pending);
    after[2].3 = before[2].3;
    assert_eq!(after, before);
}

#[test]
fn test_unsent_message_is_resent_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut model = start(dir.path());
    let cmds = handle_command(&mut model, "/msg 0 unsent");
    save(dir.path(), &cmds);

    let mut model = start(dir.path());
    let resent: Vec<Cmd> = (0..25)
        .flat_map(|_| update(&mut model, Msg::System(SystemEvent::Tick)))
        .collect();
    assert!(resent.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::SendMessage(pk, _, text, _)) if *pk == ALICE && text == b"unsent"
    )));
    assert_eq!(messages(&model)[0].3, MessageStatus::Sending);
}

#[test]
fn test_a_receipt_is_for_its_own_message_only() {
    let dir = tempfile::tempdir().unwrap();
    let sent = |model: &mut Model, text: &str, id: u32| {
        let mut cmds = handle_command(model, &format!("/msg 0 {text}"));
        let internal_id = cmds
            .iter()
            .find_map(|cmd| match cmd {
                Cmd::Tox(ToxAction::SendMessage(_, _, _, id)) => Some(*id),
                _ => None,
            })
            .unwrap();
        cmds.extend(update(
            model,
            Msg::Tox(ToxEvent::MessageSent(
                FriendNumber(0),
                FriendMessageId(id),
                internal_id,
            )),
        ));
        cmds.extend(update(
            model,
            Msg::Tox(ToxEvent::ReadReceipt(FriendNumber(0), FriendMessageId(id))),
        ));
        save(dir.path(), &cmds);
    };
    let statuses = |model: &Model| -> Vec<(String, MessageStatus)> {
        messages(model)
            .into_iter()
            .map(|(_, _, text, status)| (text.unwrap(), status))
            .collect()
    };

    // Not delivered before Tox stops: the next numbers messages from the
    // start again.
    let mut model = start(dir.path());
    let mut cmds = handle_command(&mut model, "/msg 0 before");
    let internal_id = model.domain.conversations[&WindowId::Friend(ALICE)].messages[0].internal_id;
    cmds.extend(update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(
            FriendNumber(0),
            FriendMessageId(1),
            internal_id,
        )),
    ));
    save(dir.path(), &cmds);
    update(&mut model, Msg::Tox(ToxEvent::Started));
    sent(&mut model, "reloaded", 1);
    assert_eq!(
        statuses(&model),
        [
            ("before".to_owned(), MessageStatus::Sent(0)),
            ("reloaded".to_owned(), MessageStatus::Received),
        ]
    );
    save_state(dir.path(), &model).unwrap();

    let mut model = start(dir.path());
    sent(&mut model, "after", 1);
    assert_eq!(
        statuses(&model)[0],
        ("before".to_owned(), MessageStatus::Sent(0))
    );
}

#[test]
fn test_read_receipt_wait_ends_on_the_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut model = start(dir.path());
    let wait = WAITS.iter().find(|w| w.name == "WaitReadReceipt").unwrap();
    let req = ScriptRequest::WaitReadReceipt(0);
    let receipt = Msg::Tox(ToxEvent::ReadReceipt(FriendNumber(0), FriendMessageId(3)));

    let internal_id = handle_command(&mut model, "/msg 0 read me")
        .iter()
        .find_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(_, _, _, id)) => Some(*id),
            _ => None,
        })
        .unwrap();
    update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(
            FriendNumber(0),
            FriendMessageId(3),
            internal_id,
        )),
    );
    assert!(!(wait.is_fulfilled)(&model, &receipt, Some(&req)));

    update(&mut model, receipt.clone());
    assert!((wait.is_fulfilled)(&model, &receipt, Some(&req)));
}
