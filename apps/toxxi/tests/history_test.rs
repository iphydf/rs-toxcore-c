use crossterm::event::{KeyCode, KeyModifiers};
use toxxi::model::Model;
use toxxi_testing::{create_test_model, send_key};

fn send_char(model: &mut Model, c: char) {
    send_key(model, KeyCode::Char(c), KeyModifiers::NONE);
}

fn send_enter(model: &mut Model) {
    send_key(model, KeyCode::Enter, KeyModifiers::NONE);
}

fn get_text(input: &toxxi::widgets::InputBoxState) -> String {
    input.text.clone()
}

#[test]
fn test_history_navigation() {
    let mut model = create_test_model();

    for c in "first".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    for c in "second".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    assert_eq!(model.ui.input_history.len(), 2);
    assert_eq!(model.ui.input_history[0], "first");
    assert_eq!(model.ui.input_history[1], "second");

    // Up: "second".
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);
    assert_eq!(get_text(&model.ui.input_state), "second");

    // Up: "first".
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);
    assert_eq!(get_text(&model.ui.input_state), "first");

    // Down: "second".
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(get_text(&model.ui.input_state), "second");

    // Down: the input from before.
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(get_text(&model.ui.input_state), "");
}

#[test]
fn test_history_save_current_input() {
    let mut model = create_test_model();

    for c in "history".chars() {
        send_char(&mut model, c);
    }
    send_enter(&mut model);

    // Typed but not sent.
    for c in "current".chars() {
        send_char(&mut model, c);
    }

    // Up: "history".
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);
    assert_eq!(get_text(&model.ui.input_state), "history");

    // Down: "current" again.
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);
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
