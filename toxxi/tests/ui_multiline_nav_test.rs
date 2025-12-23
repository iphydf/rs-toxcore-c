use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, InputMode, Model};
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

fn key_event(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn get_input_text(model: &Model) -> String {
    model.ui.input_state.text.clone()
}

#[test]
fn test_ui_multiline_navigation() {
    let mut model = create_test_model();

    // 0. Add some history
    model.ui.input_history.push("History 1".to_string());
    model.ui.input_history.push("History 2".to_string());

    // 1. Switch to MultiLine mode
    model.ui.input_mode = InputMode::MultiLine;

    // 2. Insert two lines of text
    // "Line 1"
    for c in "Line 1".chars() {
        update(
            &mut model,
            Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Char(c)))),
        );
    }
    // Enter
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Enter))),
    );
    // "Line 2"
    for c in "Line 2".chars() {
        update(
            &mut model,
            Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Char(c)))),
        );
    }

    // Verify state
    model.ui.input_state.ensure_layout(80, "> ");
    let cursor_before_y = model.ui.input_state.cursor().1;
    assert_eq!(cursor_before_y, 1, "Should be on the second line");

    // 3. Press UP (Should move to previous line)
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Up))),
    );

    // 4. Verify cursor moved up
    model.ui.input_state.ensure_layout(80, "> ");
    let cursor_after_y = model.ui.input_state.cursor().1;
    assert_eq!(
        cursor_after_y,
        cursor_before_y - 1,
        "Cursor should have moved up 1 line. Before: {}, After: {}",
        cursor_before_y,
        cursor_after_y
    );

    // Verify history didn't trigger (content check)
    let current_text = get_input_text(&model);
    assert!(
        current_text.contains("Line 1"),
        "Text should preserve multi-line content"
    );

    // 5. Press UP again (Should trigger History if at top)
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Up))),
    );

    // Verify replaced by "History 2" (last item)
    let text = get_input_text(&model);
    assert!(
        text.contains("History 2"),
        "Should have history item. Got: {:?}",
        text
    );

    // 6. Press DOWN (Should navigate within history item if it has trailing line, or return to saved input)
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Down))),
    );

    // Note: get_input_text flattens. "Line 1\nLine 2"
    let restored_text = get_input_text(&model);
    assert!(
        restored_text.contains("Line 1"),
        "Should restore original input. Got: {}",
        restored_text
    );
}
