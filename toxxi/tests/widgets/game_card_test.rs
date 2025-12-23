use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::GameCard;

#[test]
fn test_render_game_card() {
    let backend = TestBackend::new(50, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = GameCard::new("Chess".to_string(), "Alice".to_string());

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 50, 3);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("game_card", rendered);
    });
}

#[test]
fn test_render_game_card_focused() {
    let backend = TestBackend::new(50, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = GameCard::new("2048".to_string(), "Bob".to_string()).focused(true);

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 50, 3);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("game_card_focused", rendered);
    });
}
