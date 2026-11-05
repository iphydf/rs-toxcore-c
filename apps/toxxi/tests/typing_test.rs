use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::PublicKey;
use toxxi::model::{Model, WindowId};
use toxxi::msg::{Cmd, Msg, SystemEvent, ToxAction};
use toxxi::time::FakeTimeProvider;
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

const A: PublicKey = PublicKey([1; 32]);
const B: PublicKey = PublicKey([2; 32]);

fn at(start: Instant, after: Duration) -> Arc<FakeTimeProvider> {
    Arc::new(FakeTimeProvider::new(start + after, SystemTime::UNIX_EPOCH))
}

/// A model with friends A and B, typing in A's chat.
fn typing_to_a(start: Instant) -> Model {
    let mut model = create_test_model().with_time_provider(at(start, Duration::ZERO));
    add_test_friend(&mut model, A);
    add_test_friend(&mut model, B);
    let a = model
        .ui
        .window_ids
        .iter()
        .position(|w| *w == WindowId::Friend(A))
        .unwrap();
    model.set_active_window(a);
    let cmds = send_key(&mut model, KeyCode::Char('h'), KeyModifiers::empty());
    assert_eq!(typing(&cmds), vec![(A, true)]);
    model
}

fn typing(cmds: &[Cmd]) -> Vec<(PublicKey, bool)> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Tox(ToxAction::SetTyping(pk, on)) => Some((*pk, *on)),
            _ => None,
        })
        .collect()
}

fn tick(model: &mut Model) -> Vec<(PublicKey, bool)> {
    typing(&update(model, Msg::System(SystemEvent::Tick)))
}

#[test]
fn a_friend_stops_seeing_us_type_when_we_go_to_another_chat() {
    let start = Instant::now();
    let mut model = typing_to_a(start);

    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    assert_eq!(model.active_window_id(), WindowId::Friend(B));
    assert_eq!(tick(&mut model), vec![(A, false)]);
    assert_eq!(tick(&mut model), vec![]);
}

#[test]
fn a_friend_stops_seeing_us_type_when_we_pause() {
    let start = Instant::now();
    let mut model = typing_to_a(start);

    assert_eq!(tick(&mut model), vec![]);
    model.time_provider = at(start, Duration::from_secs(4));
    assert_eq!(tick(&mut model), vec![(A, false)]);
    assert_eq!(tick(&mut model), vec![]);
}

#[test]
fn typing_in_another_chat_tells_both_friends() {
    let start = Instant::now();
    let mut model = typing_to_a(start);

    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    let cmds = send_key(&mut model, KeyCode::Char('h'), KeyModifiers::empty());
    assert_eq!(typing(&cmds), vec![(A, false), (B, true)]);
}
