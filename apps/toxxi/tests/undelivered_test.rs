use toxcore::tox::{Connection, FriendMessageId};
use toxcore::types::PublicKey;
use toxxi::model::{Model, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::{handle_enter, update};
use toxxi_testing::{add_test_friend, create_test_model};

const A: PublicKey = PublicKey([1; 32]);

fn sent_to_a(cmds: &[Cmd]) -> Vec<Vec<u8>> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(pk, _, bytes, _)) if *pk == A => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// A friend online, sent "hi", which Tox took but whose receipt hasn't come.
fn hi_without_receipt() -> Model {
    let mut model = create_test_model();
    add_test_friend(&mut model, A);
    let a = model
        .ui
        .window_ids
        .iter()
        .position(|w| *w == WindowId::Friend(A))
        .unwrap();
    model.set_active_window(a);
    let cmds = handle_enter(&mut model, "hi");
    let Some(Cmd::Tox(ToxAction::SendMessage(_, _, _, internal_id))) = cmds
        .iter()
        .find(|cmd| matches!(cmd, Cmd::Tox(ToxAction::SendMessage(..))))
    else {
        panic!("hi wasn't sent: {cmds:?}");
    };
    update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(A, FriendMessageId(1), *internal_id)),
    );
    model
}

fn status(model: &mut Model, connection: Connection) -> Vec<Cmd> {
    update(model, Msg::Tox(ToxEvent::FriendStatus(A, connection)))
}

/// Tox forgets what it sent a friend who went offline before the receipt
/// came, so it goes again when they're back.
#[test]
fn a_message_without_a_receipt_goes_again_when_the_friend_is_back() {
    let mut model = hi_without_receipt();

    let offline = status(&mut model, Connection::None);
    assert!(sent_to_a(&offline).is_empty());
    let back = status(&mut model, Connection::Tcp);
    assert_eq!(sent_to_a(&back), vec![b"hi".to_vec()]);
}

#[test]
fn a_friend_changing_how_they_connect_gets_nothing_again() {
    let mut model = hi_without_receipt();

    let udp = status(&mut model, Connection::Udp);
    assert!(sent_to_a(&udp).is_empty());
}

/// After a restart, a message without a receipt may well have arrived: it
/// stays where it is, or friends get old history again.
#[test]
fn a_message_from_before_a_restart_doesnt_go_again() {
    let mut model = hi_without_receipt();
    update(&mut model, Msg::Tox(ToxEvent::Started));

    let back = status(&mut model, Connection::Tcp);
    assert!(sent_to_a(&back).is_empty());
}
