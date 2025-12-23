use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::{QuickSwitcher, QuickSwitcherItem, QuickSwitcherState};

#[test]
fn test_render_quick_switcher() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = QuickSwitcherState::default();
    state.input_state.text = "ali".to_string();
    state.items = vec![
        QuickSwitcherItem {
            name: "Alice".to_string(),
            description: "Online".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            name: "Aliens Group".to_string(),
            description: "42 members".to_string(),
            prefix: "g".to_string(),
        },
    ];
    state.list_state.select(Some(0));

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 24);
            let widget = QuickSwitcher::default();
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("quick_switcher", rendered);
    });
}

// end of file
