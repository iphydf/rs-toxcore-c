use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::widgets::{ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus};

#[test]
fn test_render_message_list_scrollbar_overlap() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();

    // Enough messages for a scrollbar: height is 5, and a 20-character message
    // wraps in width 20.
    let messages: Vec<ChatMessage> = (0..10)
        .map(|i| ChatMessage {
            sender: "User".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200 + i as u64 * 60,
            content: MessageContent::Text("12345678901234567890".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        })
        .collect();

    let mut state = MessageListState::default();
    // As if the last render was taller than the area, so the first pass draws the scrollbar.
    state.total_height = 100;

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 5);
            let widget = MessageList::new(&messages)
                .wide_mode(false) // Narrow mode
                .show_scrollbar(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // The rightmost column (19) has the scrollbar.
    for y in 0..5 {
        let cell = &buffer[(19, y)];
        let symbol = cell.symbol();
        // Scrollbar symbols used: "↑", "↓", "│", "█" (and " " for empty track parts)
        assert!(
            ["↑", "↓", "│", "█", " "].contains(&symbol),
            "Expected scrollbar symbol at (19, {}), found '{}'",
            y,
            symbol
        );
    }

    // A '↳' left of the scrollbar, from the wrap.
    let mut found_soft_wrap = false;
    for y in 0..5 {
        let cell = &buffer[(18, y)];
        if cell.symbol() == "↳" {
            found_soft_wrap = true;
            break;
        }
    }

    assert!(
        found_soft_wrap,
        "Expected to find soft wrap symbol '↳' at column 18. Instead found symbols at col 18: {:?}",
        (0..5).map(|y| buffer[(18, y)].symbol()).collect::<Vec<_>>()
    );
}
