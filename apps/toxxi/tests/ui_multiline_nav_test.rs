use crossterm::event::{KeyCode, KeyModifiers};
use toxxi::model::{InputMode, Model};
use toxxi_testing::{create_test_model, send_key};

fn get_input_text(model: &Model) -> String {
    model.ui.input_state.text.clone()
}

#[test]
fn test_ui_multiline_navigation() {
    let mut model = create_test_model();

    model.ui.input_history.push("History 1".to_string());
    model.ui.input_history.push("History 2".to_string());

    model.ui.input_mode = InputMode::MultiLine;

    for c in "Line 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::NONE);
    for c in "Line 2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }

    model.ui.input_state.ensure_layout(80, "> ");
    let cursor_before_y = model.ui.input_state.cursor().1;
    assert_eq!(cursor_before_y, 1, "Should be on the second line");

    // Up moves to the previous line.
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    model.ui.input_state.ensure_layout(80, "> ");
    let cursor_after_y = model.ui.input_state.cursor().1;
    assert_eq!(
        cursor_after_y,
        cursor_before_y - 1,
        "Cursor should have moved up 1 line. Before: {}, After: {}",
        cursor_before_y,
        cursor_after_y
    );

    // History isn't used.
    let current_text = get_input_text(&model);
    assert!(
        current_text.contains("Line 1"),
        "Text should preserve multi-line content"
    );

    // Up at the top line goes to the history.
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    let text = get_input_text(&model);
    assert!(
        text.contains("History 2"),
        "Should have history item. Got: {:?}",
        text
    );

    // Down returns to the input from before the history.
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);

    let restored_text = get_input_text(&model);
    assert!(
        restored_text.contains("Line 1"),
        "Should restore original input. Got: {}",
        restored_text
    );
}
