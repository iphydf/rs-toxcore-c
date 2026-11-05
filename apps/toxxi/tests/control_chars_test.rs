use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::{MessageType, PublicKey};
use toxxi::model::WindowId;
use toxxi::msg::{Msg, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model};

const A: PublicKey = PublicKey([1; 32]);

/// What a friend writes reaches the screen without control characters: an
/// escape sequence would make the terminal do what they say, like set the
/// clipboard or the window title.
#[test]
fn a_friends_escape_sequences_dont_reach_the_terminal() {
    let mut model = create_test_model();
    add_test_friend(&mut model, A);
    let evil = "\x1b]52;c;cm0gLXJmIH4K\x07\x1b[2J";
    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendName(A, format!("Eve{evil}"))),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatusMessage(A, format!("hi{evil}"))),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::Message(
            A,
            MessageType::Normal,
            format!("hello{evil}").into_bytes(),
        )),
    );
    let a = model
        .ui
        .window_ids
        .iter()
        .position(|w| *w == WindowId::Friend(A))
        .unwrap();
    model.set_active_window(a);

    let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let screen: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("hello"), "{screen}");
    assert!(screen.contains("Eve"), "{screen}");

    let controls: Vec<String> = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .filter(|symbol| symbol.chars().any(char::is_control))
        .map(|symbol| format!("{symbol:?}"))
        .collect();
    assert_eq!(controls, Vec::<String>::new());
}
