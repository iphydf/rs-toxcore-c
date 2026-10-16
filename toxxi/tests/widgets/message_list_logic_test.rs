use toxxi::widgets::message_list::wrap_text;

#[test]
fn test_wrap_text_unicode() {
    let text = "你好世界";
    let lines: Vec<String> = wrap_text(text, 4).into_iter().map(|l| l.text).collect(); // Each char is width 2
    assert_eq!(lines, vec!["你好", "世界"]);
}

#[test]
fn test_wrap_text_mixed() {
    let text = "Hello 你好";
    let lines: Vec<String> = wrap_text(text, 6).into_iter().map(|l| l.text).collect();
    assert_eq!(lines, vec!["Hello", "你好"]);
}

#[test]
fn test_wrap_text_long_word() {
    let text = "ExtremelyLongWord";
    let lines: Vec<String> = wrap_text(text, 5).into_iter().map(|l| l.text).collect();
    assert_eq!(lines, vec!["Extre", "melyL", "ongWo", "rd"]);
}

#[test]
fn test_wrap_text_paragraphs() {
    let text = "Line 1\n\nLine 3";
    let lines: Vec<String> = wrap_text(text, 10).into_iter().map(|l| l.text).collect();
    assert_eq!(lines, vec!["Line 1", "", "Line 3"]);
}

#[test]
fn test_message_list_stacked_layout_rendering() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let backend = TestBackend::new(20, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text("Hello Stacked!".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 10);
            let widget = MessageList::new(&messages).wide_mode(false); // Narrow/Stacked
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    let mut found_header = false;
    let mut found_content = false;

    for y in 0..10 {
        let line: String = (0..20).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains("12:00 Alice ●") {
            found_header = true;
        }
        if line.contains("Hello Stacked!") {
            found_content = true;
        }
    }

    assert!(found_header, "Header not found in narrow mode output");
    assert!(found_content, "Content not found in narrow mode output");
}

#[test]
fn test_message_list_granular_scrolling() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 40;
    let height = 5;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    // A message that will wrap into multiple lines.
    // Content width in wide mode with sender_width 10: 40 - (8+2+10+3) = 17.
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text(
            "Line 1. Line 2. Line 3. Line 4. Line 5. Line 6.".to_string(),
        ),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];

    let mut state = MessageListState::default();

    // Render with scroll = 0 (bottom)
    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    let mut found_end = false;
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains("Line 6.") {
            found_end = true;
            break;
        }
    }
    assert!(found_end, "End of message should be visible at scroll 0");

    // Scroll up by 1 line
    state.scroll_up();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    // If it's line-level scrolling, the bottom line (Line 6) should now be hidden.
    let buffer = terminal.backend().buffer();
    let mut found_end_after_scroll = false;
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains("Line 6.") {
            found_end_after_scroll = true;
            break;
        }
    }
    assert!(
        !found_end_after_scroll,
        "End of message should be hidden after scrolling up by 1 line"
    );
}

#[test]
fn test_message_list_total_height() {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::StatefulWidget};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let mut state = MessageListState::default();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("Short".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Bob".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 1736251260,
            content: MessageContent::Text("Another short one".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        },
    ];

    let widget = MessageList::new(&messages);
    let area = Rect::new(0, 0, 80, 10);
    let mut buffer = Buffer::empty(area);

    widget.render(area, &mut buffer, &mut state);

    // Each short message should be 1 line in wide mode (80 width is plenty).
    // Total height should be 2.
    assert_eq!(state.total_height, 2);
}

#[test]
fn test_message_list_scroll_clamping() {
    use toxxi::widgets::MessageListState;

    let mut state = MessageListState::default();

    // Initial state
    assert_eq!(state.scroll, 0);

    // Scroll down at bottom should stay at 0
    state.scroll_down();
    assert_eq!(state.scroll, 0);

    // Scroll to bottom from elsewhere
    state.scroll = 100;
    state.scroll_to_bottom();
    assert_eq!(state.scroll, 0);
}

#[test]
fn test_message_list_partial_card_scrolling() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 40;
    let height = 5;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    // A card is exactly 3 lines high.
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::FileTransfer {
            name: "test.dat".to_string(),
            size: 1024,
            progress: 0.5,
            speed: "100KB/s".to_string(),
            is_incoming: true,
            paused: false,
            eta: "1s".to_string(),
        },
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];

    let mut state = MessageListState::default();

    // Render with scroll = 1 (Skip bottom border of the card)
    state.scroll = 1;
    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Check if the bottom border (usually contains "╰") is gone from the last line (y=4)
    let last_line: String = (0..width).map(|x| buffer[(x, 4)].symbol()).collect();
    assert!(
        !last_line.contains('╰'),
        "Bottom border should be scrolled off"
    );

    // Check all lines
    let mut found_progress = false;
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains('█') || line.contains('░') {
            found_progress = true;
        }
    }
    assert!(
        found_progress,
        "Progress bar should be visible somewhere in the buffer"
    );
}

#[test]
fn test_message_list_dynamic_sender_width() {
    use toxxi::widgets::{ChatMessage, MessageContent, MessageList, MessageStatus};

    let messages = vec![
        ChatMessage {
            sender: "Short".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1,
            content: MessageContent::Text("Hi".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "VeryLongSenderNameIndeed".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 2,
            content: MessageContent::Text("Hi again".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        },
    ];

    let widget = MessageList::new(&messages).sender_width(12);
    // "VeryLongSenderNameIndeed" is 24 chars long.
    // Our clamp is 5..12, so it should be exactly 12.
    assert_eq!(widget.get_sender_width(), 12);

    // Test with only short names
    let short_messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1,
        content: MessageContent::Text("Hi".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let short_widget = MessageList::new(&short_messages).sender_width(5);
    // "Alice" is 5 chars long. Should be 5.
    assert_eq!(short_widget.get_sender_width(), 5);
}

#[test]
fn test_message_list_emoji_nick_alignment() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 30;
    let height = 3;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    // "🦀" has width 2 but 1 char.
    // If we use format!("{:>5}", "🦀"), we get 4 spaces + "🦀" = width 6.
    // This would overwrite the separator if sender_width is 5.
    let messages = vec![ChatMessage {
        sender: "🦀".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1,
        content: MessageContent::Text("Emoji test".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];

    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(
                MessageList::new(&messages).sender_width(5),
                area,
                &mut state,
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Find the separator "|"
    let mut found_separator = false;
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains('|') {
            found_separator = true;
            // Expected layout for sender_width 5 and sender "🦀":
            // [12:00] ● _ _ _ 🦀 | Emoji test
            // 012345678901234567
            //           ^ ^ ^ ^ ^ ^
            //           1 1 1 1 1 1
            //           0 1 2 3 4 5

            // In the broken state (format!):
            // "    🦀" (4 spaces + 🦀) -> Width 6.
            // Written at x+10 (10):
            // 10, 11, 12, 13: " "
            // 14, 15: "🦀"
            // Then " | " written at x+10+5 = 15:
            // 15: " ", 16: "|", 17: " "
            // The space at 15 overwrites the second half of 🦀.

            // So in broken state:
            // Cell 13: " "
            // Cell 14: "🦀" (first half)
            // Cell 15: " " (overwritten)

            // The test should verify that cell 12 is a space and cell 13 is a space.
            // AND cell 14 is the emoji.
            // BUT if it was correctly padded (3 spaces):
            // 10, 11, 12: " "
            // 13, 14: "🦀"
            // 15: " " (separator)

            assert_eq!(
                buffer[(12, y)].symbol(),
                " ",
                "Cell 12 should be a padding space"
            );
            assert_eq!(
                buffer[(13, y)].symbol(),
                "🦀",
                "Cell 13 should be the start of the emoji"
            );
        }
    }
    assert!(found_separator, "Separator bar should be found");
}

#[test]
fn test_message_list_complex_unicode_nick_alignment() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 40;
    let height = 3;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. ZWJ Sequence: Family Emoji (👨‍👩‍👧‍👦) - Often width 2 in modern terminals, but composed of many chars.
    // 2. Combiner Sequence: A with many accents (Ấ̌̋̏) - Width 1.
    let zalgo_a = "A\u{0302}\u{0301}\u{030c}\u{030b}\u{030f}";
    let family = "👨‍👩‍👧‍👦";

    let messages = vec![
        ChatMessage {
            sender: zalgo_a.to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1,
            content: MessageContent::Text("Zalgo test".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: family.to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 2,
            content: MessageContent::Text("Family test".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        },
    ];

    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(
                MessageList::new(&messages).sender_width(5),
                area,
                &mut state,
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Our render logic draws newest messages at the bottom.
    // y=2: Family test (Bob/Me)
    // y=1: Zalgo test (Alice)

    let zalgo_y = 1;
    let family_y = 2;

    // Zalgo A has width 1. Family emoji has width 2.
    // sender_width is calculated as max(widths).clamp(5, 12).
    // Here max(1, 2) = 2, which is clamped to 5.

    // So separator should be at x = 10 (timestamp) + 5 (sender) = 15.
    // Zalgo A should be at x = 14.
    assert_eq!(
        buffer[(14, zalgo_y)].symbol(),
        zalgo_a,
        "Zalgo A should be at cell 14"
    );
    assert_eq!(
        buffer[(15, zalgo_y)].symbol(),
        " ",
        "Cell 15 should be space before separator"
    );

    // Family emoji should be at x = 13..14 (width 2).
    assert_eq!(
        buffer[(13, family_y)].symbol(),
        family,
        "Family emoji should be at cell 13"
    );
    assert_eq!(
        buffer[(15, family_y)].symbol(),
        " ",
        "Cell 15 should be space before separator"
    );
}

#[test]
fn test_message_list_scroll_out_of_bounds() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 20;
    let height = 5;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    let messages = vec![ChatMessage {
        sender: "A".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1,
        content: MessageContent::Text("L1".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];

    let mut state = MessageListState::default();
    // Scroll far past the total height (which is 1)
    state.scroll = 10;

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    // Buffer should be empty (all whitespace or empty symbols)
    for y in 0..height {
        for x in 0..width {
            let symbol = buffer[(x, y)].symbol();
            assert!(
                symbol.trim().is_empty() || symbol == " ",
                "Screen should be empty when scrolled past content"
            );
        }
    }
}

#[test]
fn test_message_list_scrollbar_position() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 20;
    let height = 5;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut messages = Vec::new();
    for i in 0..10 {
        messages.push(ChatMessage {
            sender: "A".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: i as u64,
            content: MessageContent::Text(format!("Line {}", i)),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        });
    }

    let mut state = MessageListState::default();
    state.scroll = 0; // Bottom

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let mut thumb_y = None;
    for y in 0..height {
        if buffer[(width - 1, y)].symbol() == "█" {
            thumb_y = Some(y);
            break;
        }
    }

    let thumb_y = thumb_y.expect("Scrollbar thumb '█' should be found");
    assert!(
        thumb_y >= height / 2,
        "Scrollbar thumb should be at the bottom when scroll=0 (got y={})",
        thumb_y
    );
}

#[test]
fn test_message_list_nick_elision_direction() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let width = 40;
    let height = 5;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 100,
            content: MessageContent::Text("First".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 110,
            content: MessageContent::Text("Second".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Bob".to_string(),
            timestamp: "12:02".to_string(),
            unix_timestamp: 120,
            content: MessageContent::Text("Third".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];

    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, width, height);
            f.render_stateful_widget(MessageList::new(&messages), area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Bottom-up rendering (height=5):
    // y=4: "Third" (Bob)  - idx 2
    // y=3: "Second" (Alice) - idx 1 (Elided)
    // y=2: "First" (Alice) - idx 0

    let line_bob: String = (0..width).map(|x| buffer[(x, 4)].symbol()).collect();
    let line_alice_2: String = (0..width).map(|x| buffer[(x, 3)].symbol()).collect();
    let line_alice_1: String = (0..width).map(|x| buffer[(x, 2)].symbol()).collect();

    assert!(
        line_alice_1.contains("Alice"),
        "First message from Alice should show nick"
    );
    assert!(
        !line_alice_2.contains("Alice"),
        "Second message from Alice should ELIDE nick"
    );
    assert!(
        line_bob.contains("Bob"),
        "Message from Bob should show nick"
    );
}

#[test]
fn test_message_selection_navigation() {
    use toxxi::widgets::{ChatMessage, MessageContent, MessageListState, MessageStatus};

    let messages = [
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1,
            content: MessageContent::Text("Msg 1".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Bob".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 2,
            content: MessageContent::Text("Msg 2".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];

    let mut state = MessageListState::new();

    // Default selection should be None
    assert!(state.selected_index.is_none());

    // Navigation down (from None should select the latest message at the bottom)
    state.select_next(messages.len());
    assert_eq!(state.selected_index, Some(1));

    // Navigation up
    state.select_previous();
    assert_eq!(state.selected_index, Some(0));

    // Clamping at the top
    state.select_previous();
    assert_eq!(state.selected_index, Some(0));
}

#[test]
fn test_message_list_focus_propagation() {
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};
    use toxxi::widgets::{
        ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus,
    };

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1,
        content: MessageContent::FileTransfer {
            name: "test.dat".to_string(),
            size: 1024,
            progress: 0.5,
            speed: "100KB/s".to_string(),
            is_incoming: true,
            paused: false,
            eta: "1s".to_string(),
        },
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];

    let mut state = MessageListState::new();
    state.selected_index = Some(0); // Focus the file transfer

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 10);
            let widget = MessageList::new(&messages).focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // If the FileTransferCard received focused: true, it should render its hints
    let mut found_hints = false;
    for y in 0..10 {
        let line: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if line.contains("(a) Accept") {
            found_hints = true;
            break;
        }
    }

    assert!(
        found_hints,
        "FileTransferCard should render hints when selected in MessageList"
    );
}

#[test]
fn test_scroll_to_timestamp() {
    use toxxi::widgets::{ChatMessage, MessageContent, MessageListState, MessageStatus};

    let mut messages = Vec::new();
    for i in 0..100 {
        messages.push(ChatMessage {
            sender: "User".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: i as u64,
            content: MessageContent::Text(format!("Message {}", i)),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        });
    }

    let mut state = MessageListState::new();
    // Assuming we want to jump to message with timestamp 50
    // We need a helper to find the message by timestamp and calculate scroll
    state.jump_to_timestamp(50, &messages);

    // After jumping, we expect the selected index to be 50
    assert_eq!(state.selected_index, Some(50));
    // And it should be marked for "need scroll to selected" or similar
}

// end of file
