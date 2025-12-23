use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::{Command, CommandMenu, CommandMenuState};

#[test]
fn test_render_command_menu() {
    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    let commands = vec![
        Command::new("about", "Show version info"),
        Command::new("file", "Manage file transfers").args("send <path>"),
        Command::new("help", "Show help"),
        Command::new("msg", "Send a private message").args("<name> <text>"),
        Command::new("quit", "Exit Toxxi"),
    ];

    let mut state = CommandMenuState::new(commands);
    state.next();
    state.next();
    state.next();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 10);
            let widget = CommandMenu::default();
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("command_menu", rendered);
    });
}

// end of file
