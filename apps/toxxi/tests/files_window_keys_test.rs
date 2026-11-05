use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::{FileControl, FileId, FileKind, PublicKey};
use toxxi::model::WindowId;
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

const A: PublicKey = PublicKey([1; 32]);
const B: PublicKey = PublicKey([2; 32]);

/// The Files window lists transfers by file ID, so B's comes first though A
/// sorts first. A key acts on the transfer it highlights.
#[test]
fn a_key_in_the_files_window_acts_on_the_transfer_highlighted() {
    let mut model = create_test_model();
    add_test_friend(&mut model, A);
    add_test_friend(&mut model, B);
    for (pk, file_id) in [(B, FileId([1; 32])), (A, FileId([2; 32]))] {
        update(
            &mut model,
            Msg::Tox(ToxEvent::FileRecv(
                pk,
                file_id,
                FileKind::DATA,
                1000,
                "file".to_owned(),
            )),
        );
    }

    send_key(&mut model, KeyCode::Char('f'), KeyModifiers::CONTROL);
    assert_eq!(model.active_window_id(), WindowId::Files);
    send_key(&mut model, KeyCode::Esc, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Up, KeyModifiers::empty());
    assert_eq!(
        model.ui.window_state[&WindowId::Files]
            .msg_list_state
            .selected_index,
        Some(0)
    );

    let cmds = send_key(&mut model, KeyCode::Char('x'), KeyModifiers::empty());
    assert!(
        matches!(
            cmds.as_slice(),
            [Cmd::Tox(ToxAction::FileControl(pk, FileId([1, ..]), FileControl::Cancel)), ..] if *pk == B
        ),
        "{cmds:?}"
    );
}
