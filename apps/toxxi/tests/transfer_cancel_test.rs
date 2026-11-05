use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::{FileId, FileKind, PublicKey};
use toxxi::model::Model;
use toxxi::msg::{Cmd, IOAction, Msg, ToxEvent};
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

const A: PublicKey = PublicKey([1; 32]);
const FILE: FileId = FileId([1; 32]);

fn offered() -> Model {
    let mut model = create_test_model();
    add_test_friend(&mut model, A);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            A,
            FILE,
            FileKind::DATA,
            1000,
            "file".to_owned(),
        )),
    );
    model
}

/// Tox only sends an event when the friend cancels, so our own cancel must
/// close the file and remove the transfer from the list.
#[test]
fn cancelling_a_transfer_ends_it_here_too() {
    let mut model = offered();
    send_key(&mut model, KeyCode::Char('f'), KeyModifiers::CONTROL);
    send_key(&mut model, KeyCode::Esc, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Up, KeyModifiers::empty());
    let cmds = send_key(&mut model, KeyCode::Char('x'), KeyModifiers::empty());
    assert!(
        cmds.contains(&Cmd::IO(IOAction::CancelFile(A, FILE))),
        "{cmds:?}"
    );
    assert!(model.domain.file_transfers.is_empty());
}

/// Tox ends a deleted friend's transfers without sending events.
#[test]
fn removing_a_friend_ends_their_transfers() {
    let mut model = offered();
    let cmds = model.remove_friend(A);
    assert!(
        cmds.contains(&Cmd::IO(IOAction::CancelFile(A, FILE))),
        "{cmds:?}"
    );
    assert!(model.domain.file_transfers.is_empty());
}
