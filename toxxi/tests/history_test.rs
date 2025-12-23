use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::msg::Msg;
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

fn send_key(model: &mut Model, code: KeyCode) {
    let event = CrosstermEvent::Key(KeyEvent::new(code, KeyModifiers::empty()));
    update(model, Msg::Input(event));
    model.ui.input_state.ensure_layout(80, "> ");
}

fn send_char(model: &mut Model, c: char) {
    send_key(model, KeyCode::Char(c));
}

fn send_enter(model: &mut Model) {
    send_key(model, KeyCode::Enter);
}

fn get_text(input: &toxxi::widgets::InputBoxState) -> String {
    input.text.clone()
}

#[test]
fn test_history_navigation() {
    let mut model = create_test_model();

    // Type "first" and Enter
    for c in "first".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    // Type "second" and Enter
    for c in "second".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    assert_eq!(model.ui.input_history.len(), 2);
    assert_eq!(model.ui.input_history[0], "first");
    assert_eq!(model.ui.input_history[1], "second");

    // Press Up -> "second"
    send_key(&mut model, KeyCode::Up);
    assert_eq!(get_text(&model.ui.input_state), "second");

    // Press Up -> "first"
    send_key(&mut model, KeyCode::Up);
    assert_eq!(get_text(&model.ui.input_state), "first");

    // Press Down -> "second"
    send_key(&mut model, KeyCode::Down);
    assert_eq!(get_text(&model.ui.input_state), "second");

    // Press Down -> "" (original input)
    send_key(&mut model, KeyCode::Down);
    assert_eq!(get_text(&model.ui.input_state), "");
}

#[test]
fn test_history_save_current_input() {
    let mut model = create_test_model();

    // Add something to history
    for c in "history".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    // Type something but don't enter
    for c in "current".chars() {
        send_char(&mut model, c);
    }

    // Press Up -> "history"
    send_key(&mut model, KeyCode::Up);
    assert_eq!(get_text(&model.ui.input_state), "history");

    // Press Down -> "current"
    send_key(&mut model, KeyCode::Down);
    assert_eq!(get_text(&model.ui.input_state), "current");
}

#[test]
fn test_history_deduplication() {
    let mut model = create_test_model();

    for c in "same".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    for c in "same".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    assert_eq!(model.ui.input_history.len(), 1);
}

// end of tests
