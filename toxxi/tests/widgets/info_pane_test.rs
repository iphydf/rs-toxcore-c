use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::{InfoPane, info_pane::Participant};

#[test]
fn test_render_info_pane() {
    let backend = TestBackend::new(30, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = InfoPane::new("Alice".to_string())
        .details(vec![
            ("Status".to_string(), "Online".to_string()),
            ("Mood".to_string(), "Happy".to_string()),
        ])
        .participants(vec![Participant::new("Alice"), Participant::new("Bob")]);

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 30, 15);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("info_pane", rendered);
    });
}

// end of file
