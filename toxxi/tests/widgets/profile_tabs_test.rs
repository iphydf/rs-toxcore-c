use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::ProfileTabs;

#[test]
fn test_render_profile_tabs() {
    let backend = TestBackend::new(80, 1);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = ProfileTabs::new(
        vec![
            "Personal".to_string(),
            "Work".to_string(),
            "Bot".to_string(),
        ],
        1,
    );

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 1);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("profile_tabs", rendered);
    });
}

// end of file
