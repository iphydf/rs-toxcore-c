use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::ui::draw;

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

#[test]
fn test_input_overflow_cursor_position() {
    let mut model = create_test_model();

    // Set terminal width to 20
    let width = 20;
    let backend = TestBackend::new(width, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    // Input prompt was "> ", but now we use plain TextArea.
    // Available width for text is 20.

    // 1. Text fits (10 chars)
    let text1 = "1234567890";
    model.ui.input_state.set_value(text1.to_string());
    model.ui.input_state.set_cursor(0, 10);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let cursor = terminal.get_cursor_position().unwrap();
    // Cursor should be at 1 (border) + 2 (prompt) + 10 = 13.
    assert_eq!(cursor.x, 13);
    assert_eq!(cursor.y, 8); // text row

    // 2. Text overflows (25 chars)
    let text2 = "1234567890123456789012345";
    model.ui.input_state.set_value(text2.to_string());
    model.ui.input_state.set_cursor(0, 25);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let cursor = terminal.get_cursor_position().unwrap();
    // Row 6: top border
    // Row 7: prompt + 17 chars (fits 18 chars total with wrap indicator)
    // Row 8: prompt + 8 chars (next line)
    // Row 9: bottom border
    assert_eq!(cursor.y, 8);

    // Also verify what is drawn.
    let buffer = terminal.backend().buffer();
    let row_8: String = (0..20).map(|x| buffer[(x, 8)].symbol()).collect();

    // The second line of text should be visible on row 8.
    // prompt is "> "
    assert!(
        row_8.contains("12345"),
        "Expected row 8 containing '12345', got: '{}'",
        row_8
    );
}
