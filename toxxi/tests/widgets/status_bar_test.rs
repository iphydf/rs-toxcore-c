use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::StatusBar;

#[test]
fn test_render_status_bar() {
    let backend = TestBackend::new(80, 1);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = StatusBar::new(
        "Tester".to_string(),
        "Online".to_string(),
        "ABCDEF1234567890".to_string(),
    )
    .dht_health(vec![0, 2, 8, 15, 30]);

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 1);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("status_bar", rendered);
    });
}

// end of file
