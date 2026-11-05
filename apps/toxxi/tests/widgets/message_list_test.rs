use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::widgets::{ChatMessage, MessageContent, MessageList, MessageListState, MessageStatus};
use toxxi_testing::{buffer_to_string, configure_insta};

#[test]
fn test_render_message_list_rich_content() {
    let backend = TestBackend::new(80, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::FileTransfer {
            name: "vacation.jpg".to_string(),
            size: 2 * 1024 * 1024,
            progress: 0.5,
            speed: "1.2 MB/s".to_string(),
            is_incoming: true,
            paused: false,
            eta: "1s".to_string(),
        },
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 80, 15);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(5);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_rich", rendered);
    });
}

#[test]
fn test_render_message_list_unicode() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text("你好! 🤝🏾 How is the 🦀?".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 10);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(5);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_unicode", rendered);
    });
}

#[test]
fn test_render_message_list_unicode_wrap_stress() {
    let backend = TestBackend::new(30, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("Long Unicode Stress Test: 你好! 🦀🤝🏾🦀🤝🏾🦀🤝🏾🦀🤝🏾🦀🤝🏾🦀🤝🏾🦀🤝🏾🦀🤝🏾 and wrapping continues here.".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 30, 15);
            let widget = MessageList::new(&messages).wide_mode(false); // Narrow mode forces more wraps
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_unicode_wrap_stress", rendered);
    });
}

#[test]
fn test_render_message_list_grapheme_wrap_boundary() {
    let backend = TestBackend::new(10, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    // "12345678" is 8 columns and "🤝🏾" is 2, so it fits width 10 exactly.
    // "123456789🤝🏾" wraps the whole emoji to the next line.
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text("123456789🤝🏾".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 10, 5);
            let widget = MessageList::new(&messages).wide_mode(false);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_grapheme_boundary", rendered);
    });
}

#[test]
fn test_render_message_list_wide() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("Hello!".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Tester".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 1736251260,
            content: MessageContent::Text("Hey Alice, how are you?".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        },
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:02".to_string(),
            unix_timestamp: 1736251320,
            content: MessageContent::Text("I'm good, thanks!".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 10);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(6);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_wide", rendered);
    });
}

#[test]
fn test_render_message_list_narrow() {
    let backend = TestBackend::new(30, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("Hello!".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Tester".to_string(),
            timestamp: "12:01".to_string(),
            unix_timestamp: 1736251260,
            content: MessageContent::Text("Hey Alice!".to_string()),
            status: MessageStatus::Delivered,
            is_me: true,
            highlighted: false,
        },
    ];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 30, 10);
            let widget = MessageList::new(&messages).wide_mode(false);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_narrow", rendered);
    });
}

#[test]
fn test_render_message_list_grouping_wide() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("First message".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251210, // 10 seconds later
            content: MessageContent::Text("Second message (grouped)".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:05".to_string(),
            unix_timestamp: 1736251500, // 5 minutes later (not grouped)
            content: MessageContent::Text("Third message (not grouped)".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 10);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(5);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_grouping_wide", rendered);
    });
}

#[test]
fn test_render_message_list_grouping_narrow() {
    let backend = TestBackend::new(30, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251200,
            content: MessageContent::Text("First message".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
        ChatMessage {
            sender: "Alice".to_string(),
            timestamp: "12:00".to_string(),
            unix_timestamp: 1736251210, // 10 seconds later
            content: MessageContent::Text("Second message (grouped)".to_string()),
            status: MessageStatus::Delivered,
            is_me: false,
            highlighted: false,
        },
    ];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 30, 10);
            let widget = MessageList::new(&messages).wide_mode(false);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_grouping_narrow", rendered);
    });
}

#[test]
fn test_render_message_list_long_nickname() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![ChatMessage {
        sender: "SuperLongNicknameThatExceedsLimit".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text("Testing layout with long name".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 10);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(12);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_long_nickname", rendered);
    });
}

#[test]
fn test_render_message_list_custom_sender_width() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let messages = vec![ChatMessage {
        sender: "Alice".to_string(),
        timestamp: "12:00".to_string(),
        unix_timestamp: 1736251200,
        content: MessageContent::Text("Message with narrow sender col".to_string()),
        status: MessageStatus::Delivered,
        is_me: false,
        highlighted: false,
    }];
    let mut state = MessageListState::default();

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 10);
            let widget = MessageList::new(&messages).wide_mode(true).sender_width(5);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("message_list_custom_width", rendered);
    });
}
