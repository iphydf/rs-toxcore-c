use toxxi::widgets::InputBoxState;

#[test]
fn test_word_navigation_basics() {
    let mut state = InputBoxState::new();
    state.text = "Hello world  toxxi".to_string();

    // Jump right
    state.move_cursor_word_right(false);
    assert_eq!(state.cursor_pos, 5); // After "Hello"

    state.move_cursor_word_right(false);
    assert_eq!(state.cursor_pos, 11); // After "world"

    state.move_cursor_word_right(false);
    assert_eq!(state.cursor_pos, 18); // End of "toxxi"

    // Jump left
    state.move_cursor_word_left(false);
    assert_eq!(state.cursor_pos, 13); // Start of "toxxi"

    state.move_cursor_word_left(false);
    assert_eq!(state.cursor_pos, 6); // Start of "world"
}

#[test]
fn test_word_navigation_punctuation() {
    let mut state = InputBoxState::new();
    state.text = "toxcore-rs/toxxi.git".to_string();

    state.move_cursor_word_right(false);
    // In many editors, punctuation acts as a boundary.
    assert_eq!(state.cursor_pos, 7); // After "toxcore"

    state.move_cursor_word_right(false);
    assert_eq!(state.cursor_pos, 8); // After "-"
}

#[test]
fn test_unicode_grapheme_boundaries() {
    let mut state = InputBoxState::new();
    // "A" (1) + "🤝🏾" (7) + "B" (1) = 9 bytes
    state.text = "A🤝🏾B".to_string();

    state.move_to_start(false);
    state.move_cursor_right(false);
    assert_eq!(state.cursor_pos, 1);

    state.move_cursor_right(false);
    assert_eq!(state.cursor_pos, 1 + "🤝🏾".len()); // Correctly skips the whole multi-byte emoji

    state.delete_prev_char();
    assert_eq!(state.text, "AB");
}

#[test]
fn test_selection_replacement() {
    let mut state = InputBoxState::new();
    state.text = "The quick brown fox".to_string();

    // Select "quick "
    state.selection = Some((4, 10));
    state.insert_char('f');
    state.insert_char('a');
    state.insert_char('s');
    state.insert_char('t');
    state.insert_char(' ');

    assert_eq!(state.text, "The fast brown fox");
    assert_eq!(state.selection, None);
}

#[test]
fn test_mode_toggling() {
    let mut state = InputBoxState::new();
    assert_eq!(
        state.mode(),
        toxxi::widgets::input_box::InputMode::SendOnEnter
    );

    state.toggle_mode();
    assert_eq!(
        state.mode(),
        toxxi::widgets::input_box::InputMode::NewlineOnEnter
    );
}

#[test]
fn test_vertical_navigation() {
    let mut state = InputBoxState::new();
    state.text = "Line 1\nLine 2\nLine 3".to_string();
    let width = 20;

    // Trigger render to populate cached lines
    let mut buf = ratatui::buffer::Buffer::empty(ratatui::layout::Rect::new(0, 0, width, 10));
    let widget = toxxi::widgets::InputBox::default();
    ratatui::widgets::StatefulWidget::render(widget, buf.area, &mut buf, &mut state);

    state.move_to_start(false);
    assert_eq!(state.cursor_pos, 0);

    // Move down to Line 2.
    // Every line is now indented by the prompt width (2).
    // Moving down from the start of Line 1 (col 2) lands at col 2 of Line 2.
    state.move_cursor_down(false);
    assert_eq!(state.cursor_pos, 7); // Start of "Line 2"

    // Move down to Line 3.
    state.move_cursor_down(false);
    assert_eq!(state.cursor_pos, 14); // Start of "Line 3"

    // Move up to Line 2.
    state.move_cursor_up(false);
    assert_eq!(state.cursor_pos, 7);

    // Move up to Line 1.
    state.move_cursor_up(false);
    assert_eq!(state.cursor_pos, 0);
}

#[test]
fn test_selection_expansion() {
    let mut state = InputBoxState::new();
    state.text = "Hello World".to_string();

    state.move_to_start(false);
    state.move_cursor_right(true); // Select 'H'
    assert_eq!(state.selection, Some((0, 1)));

    state.move_cursor_right(true); // Select 'He'
    assert_eq!(state.selection, Some((0, 2)));

    state.move_cursor_word_right(true); // Select 'Hello'
    assert_eq!(state.selection, Some((0, 5)));

    state.move_cursor_left(false); // Clear selection
    assert_eq!(state.selection, None);
    assert_eq!(state.cursor_pos, 4); // After 'l' in 'Hell'
}

#[test]
fn test_undo_redo() {
    let mut state = InputBoxState::new();
    state.insert_char('a');
    state.insert_char('b');
    state.insert_char('c');
    assert_eq!(state.text, "abc");

    state.undo();
    assert_eq!(state.text, "ab");

    state.undo();
    assert_eq!(state.text, "a");

    state.redo();
    assert_eq!(state.text, "ab");

    state.insert_char('!');
    assert_eq!(state.text, "ab!");

    // Redo stack should be cleared after new insertion
    state.redo();
    assert_eq!(state.text, "ab!");
}

#[test]
fn test_clipboard_internal() {
    let mut state = InputBoxState::new();
    state.text = "Copy this text".to_string();

    // Select "this"
    state.selection = Some((5, 9));
    state.copy();
    assert_eq!(state.clipboard, "this");

    state.move_to_end(false);
    state.insert_char(' ');
    state.paste();
    assert_eq!(state.text, "Copy this text this");

    // Cut "Copy"
    state.selection = Some((0, 4));
    state.cut();
    assert_eq!(state.text, " this text this");
    assert_eq!(state.clipboard, "Copy");
}

#[test]
fn test_newline_normalization() {
    let mut state = InputBoxState::new();

    // Windows style
    state.insert_str("Hello\r\nWorld");
    assert_eq!(state.text, "Hello\nWorld");

    // Old Mac style
    state.clear();
    state.insert_str("Foo\rBar");
    assert_eq!(state.text, "Foo\nBar");

    // Mixed
    state.clear();
    state.insert_str("One\rTwo\r\nThree\nFour");
    assert_eq!(state.text, "One\nTwo\nThree\nFour");
}

// end of file
