use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxxi::ui::draw;
use toxxi_testing::{create_test_model, send_key};

#[test]
fn test_ui_horizontal_navigation_rendering() {
    let mut model = create_test_model();

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    for c in "ABC".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }

    // Left twice: at 'B'.
    send_key(&mut model, KeyCode::Left, KeyModifiers::NONE);
    send_key(&mut model, KeyCode::Left, KeyModifiers::NONE);

    // Right once: at 'C'.
    send_key(&mut model, KeyCode::Right, KeyModifiers::NONE);

    // Right again stays at the end, without scrolling.
    send_key(&mut model, KeyCode::Right, KeyModifiers::NONE);

    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x, cursor_y) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x, 5,
        "Cursor should be at column 5 (2 prompt + 3 text)"
    );
    assert_eq!(cursor_y, 0, "Cursor should stay on line 0");

    let vscroll = model.ui.input_state.scroll;
    assert_eq!(vscroll, 0, "Vertical scroll should be 0. Got: {}", vscroll);

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let input_row_idx = 22;
    let input_row: String = (0..80)
        .map(|x| buffer[(x, input_row_idx)].symbol())
        .collect();

    assert!(
        input_row.contains("ABC"),
        "Input row should contain 'ABC'. Got: '{}'",
        input_row
    );

    let cursor_pos = terminal.get_cursor_position().unwrap();
    assert_eq!(
        cursor_pos.x, 6,
        "Cursor X should be 6 (1 border + 2 prompt + 3 text)"
    );
    assert_eq!(
        cursor_pos.y, 22,
        "Cursor Y should be 22 (row above bottom border)"
    );
}
