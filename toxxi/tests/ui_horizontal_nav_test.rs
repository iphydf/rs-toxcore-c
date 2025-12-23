use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::msg::Msg;
use toxxi::ui::draw;
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

#[test]
fn test_ui_horizontal_navigation_rendering() {
    let mut model = create_test_model();

    // Setup backend
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Insert text "ABC"
    for c in "ABC".chars() {
        update(
            &mut model,
            Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Char(c)))),
        );
    }

    // 2. Move Cursor Left 2 times (to 'B')
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Left))),
    );
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Left))),
    );

    // 3. Move Right 1 time (to 'C')
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Right))),
    );

    // 4. Press Right Arrow again (should stay at end, not scroll)
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Right))),
    );

    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x, cursor_y) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x, 5,
        "Cursor should be at column 5 (2 prompt + 3 text)"
    );
    assert_eq!(cursor_y, 0, "Cursor should stay on line 0");

    let vscroll = model.ui.input_state.scroll;
    assert_eq!(vscroll, 0, "Vertical scroll should be 0. Got: {}", vscroll);

    // 5. Draw
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    // 6. Verify Content
    let buffer = terminal.backend().buffer();
    let input_row_idx = 22;
    let input_row: String = (0..80)
        .map(|x| buffer[(x, input_row_idx)].symbol())
        .collect();

    // "ABC" should be present
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
