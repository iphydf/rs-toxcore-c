use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::PublicKey;
use toxxi::model::WindowId;
use toxxi::msg::{Cmd, ToxAction};
use toxxi::update::handle_enter;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

const A: PublicKey = PublicKey([1; 32]);
const B: PublicKey = PublicKey([2; 32]);
const C: PublicKey = PublicKey([3; 32]);
const D: PublicKey = PublicKey([4; 32]);

/// Closing a window before the one shown mustn't move us into another chat,
/// where what we type next would go.
#[test]
fn removing_an_earlier_friend_keeps_us_in_our_chat() {
    let mut model = create_test_model();
    for pk in [A, B, C, D] {
        add_test_friend(&mut model, pk);
    }
    let c = model
        .ui
        .window_ids
        .iter()
        .position(|w| *w == WindowId::Friend(C))
        .unwrap();
    model.set_active_window(c);

    handle_enter(
        &mut model,
        &format!("/friend remove {}", toxxi::utils::short_key(&A)),
    );
    assert!(!model.domain.friends.contains_key(&A));
    assert_eq!(model.active_window_id(), WindowId::Friend(C));

    for ch in "hi".chars() {
        send_key(&mut model, KeyCode::Char(ch), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    let to: Vec<_> = cmds
        .iter()
        .filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SendMessage(pk, ..)) => Some(*pk),
            _ => None,
        })
        .collect();
    assert_eq!(to, vec![C]);
}

#[test]
fn removing_the_friend_shown_shows_a_window_still_there() {
    let mut model = create_test_model();
    for pk in [A, B] {
        add_test_friend(&mut model, pk);
    }
    let b = model.ui.window_ids.len() - 1;
    model.set_active_window(b);

    handle_enter(
        &mut model,
        &format!("/friend remove {}", toxxi::utils::short_key(&B)),
    );
    assert!(model.ui.window_ids.contains(&model.active_window_id()));
    assert_ne!(model.active_window_id(), WindowId::Friend(B));
}
