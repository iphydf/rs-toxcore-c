use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::widgets::{ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus};

#[test]
fn test_render_message_list_scrollbar_overlap() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();

    // Create enough messages to trigger scrollbar. Height is 5.
    // Each message is at least 1 line.
    // We use a long message that forces wrapping.
    // Width is 20. "12345678901234567890" is 20 chars.
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
    // Simulate previous render state where total_height > area.height to force scrollbar logic in first pass
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

    // Check the rightmost column (index 19)
    // It should contain scrollbar symbols.
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

    // Check for '↳' at index 18 (one to the left of scrollbar)
    // Since we forced a wrap, we expect at least one '↳'
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
