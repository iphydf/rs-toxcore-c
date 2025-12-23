use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::{InputBox, InputBoxState};

#[test]
fn test_render_input_box_empty() {
    let backend = TestBackend::new(20, 3);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 3);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_empty", rendered);
    });
}

#[test]
fn test_render_input_box_with_text() {
    let backend = TestBackend::new(20, 3);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();
    state.text = "Hello".to_string();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 3);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_with_text", rendered);
    });
}

#[test]
fn test_render_input_box_wrapped() {
    let backend = TestBackend::new(10, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();
    state.text = "This is a long text that should wrap".to_string();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 10, 5);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_wrapped", rendered);
    });
}

#[test]
fn test_render_input_box_multiline() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();
    state.text = "Line 1\nLine 2".to_string();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 5);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_multiline", rendered);
    });
}

#[test]
fn test_input_box_state_delete_word() {
    let mut state = InputBoxState::new();
    state.text = "Hello world toxxi".to_string();
    state.cursor_pos = 11; // After "world"

    state.delete_word_left();
    assert_eq!(state.text, "Hello  toxxi");
    assert_eq!(state.cursor_pos, 6);

    state.text = "Hello world toxxi".to_string();
    state.cursor_pos = 6; // At 'w'
    state.delete_word_right();
    assert_eq!(state.text, "Hello  toxxi");
    assert_eq!(state.cursor_pos, 6);
}

#[test]
fn test_input_box_state_readline_shortcuts() {
    let mut state = InputBoxState::new();
    state.text = "Hello world".to_string();
    state.cursor_pos = 6; // At 'w'

    state.move_to_end(false);
    assert_eq!(state.cursor_pos, 11);

    state.move_to_start(false);
    assert_eq!(state.cursor_pos, 0);

    state.cursor_pos = 6;
    state.delete_to_end();
    assert_eq!(state.text, "Hello ");
    assert_eq!(state.cursor_pos, 6);

    state.delete_to_start();
    assert_eq!(state.text, "");
    assert_eq!(state.cursor_pos, 0);
}

#[test]
fn test_input_box_grapheme_deletion() {
    let mut state = InputBoxState::new();
    // Handshake + brown skin tone
    state.text = "A🤝🏾B".to_string();
    state.cursor_pos = 1 + "🤝🏾".len(); // After the emoji

    // Delete emoji from the right
    state.delete_prev_char();
    assert_eq!(state.text, "AB");
    assert_eq!(state.cursor_pos, 1);

    // Undo/Reset and test from the left
    state.text = "A🤝🏾B".to_string();
    state.cursor_pos = 1; // Before emoji
    state.delete_next_char();
    assert_eq!(state.text, "AB");
    assert_eq!(state.cursor_pos, 1);
}

#[test]
fn test_render_input_box_unicode() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();
    // "Hello" + Chinese + Handshake with brown skin tone + more text
    state.text = "你好 🤝🏾 Toxxi 🦀".to_string();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 5);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_unicode", rendered);
    });
}

#[test]
fn test_render_input_box_unicode_wrap_stress() {
    let backend = TestBackend::new(15, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = InputBoxState::new();
    // Long sentence designed to wrap exactly at or near emoji modifiers
    state.text = "Testing 🦀 width and 🤝🏾 wrapping with 你好! And some more text to force wraps."
        .to_string();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 15, 10);
            let widget = InputBox::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_box_unicode_wrap_stress", rendered);
    });
}

// end of file
