use ratatui::{
    Terminal,
    backend::TestBackend,
    style::{Color, Modifier},
};
use toxxi::widgets::{EmojiGrid, EmojiGridState};

#[test]
fn test_emoji_grid_rendering_small() {
    let backend = TestBackend::new(20, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    let candidates = vec![
        "😀".to_string(),
        "😁".to_string(),
        "😂".to_string(),
        "🤣".to_string(),
        "😃".to_string(),
    ];

    let mut state = EmojiGridState::default();

    terminal
        .draw(|f| {
            let widget = EmojiGrid::new(&candidates, 2); // '😂' selected
            f.render_stateful_widget(widget, f.area(), &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // With width 20, inner width is 18 (due to borders).
    // Item width is 3 (2 chars + 1 padding).
    // Cols = 18 / 3 = 6.
    // So all 5 candidates should fit in the first row.

    // Check title
    // " Emojis " at (1, 0)
    assert_eq!(buffer.cell((1, 0)).unwrap().symbol(), " ");
    assert_eq!(buffer.cell((2, 0)).unwrap().symbol(), "E");

    // Check content
    // Row 0 (inside border) is at y=1.
    // Col 0: "😀" at x=1
    assert_eq!(buffer.cell((1, 1)).unwrap().symbol(), "😀");

    // Col 1: "😁" at x=1+3=4
    assert_eq!(buffer.cell((4, 1)).unwrap().symbol(), "😁");

    // Col 2: "😂" at x=1+6=7 (Selected)
    let cell = buffer.cell((7, 1)).unwrap();
    assert_eq!(cell.symbol(), "😂");
    assert!(cell.modifier.contains(Modifier::BOLD));

    // Col 3: "🤣" at x=1+9=10 (Unselected)
    let cell_next = buffer.cell((10, 1)).unwrap();
    assert_eq!(cell_next.symbol(), "🤣");
    assert_eq!(cell_next.fg, Color::Reset); // Default style
}

#[test]
fn test_emoji_grid_rendering_narrow_wrap() {
    let backend = TestBackend::new(10, 10); // Very narrow
    let mut terminal = Terminal::new(backend).unwrap();

    let candidates = vec![
        "1️⃣".to_string(),
        "2️⃣".to_string(),
        "3️⃣".to_string(),
        "4️⃣".to_string(),
    ];

    let mut state = EmojiGridState::default();

    terminal
        .draw(|f| {
            let widget = EmojiGrid::new(&candidates, 3); // '4️⃣' selected
            f.render_stateful_widget(widget, f.area(), &mut state);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Width 10. Inner width = 8.
    // Item width = 3.
    // Cols = 8 / 3 = 2.
    // Layout:
    // Row 0: 1️⃣, 2️⃣
    // Row 1: 3️⃣, 4️⃣

    // Row 0, Col 0: "1️⃣" at x=1, y=1
    assert_eq!(buffer.cell((1, 1)).unwrap().symbol(), "1️⃣");

    // Row 0, Col 1: "2️⃣" at x=1+3=4, y=1
    assert_eq!(buffer.cell((4, 1)).unwrap().symbol(), "2️⃣");

    // Row 1, Col 0: "3️⃣" at x=1, y=2
    assert_eq!(buffer.cell((1, 2)).unwrap().symbol(), "3️⃣");

    // Row 1, Col 1: "4️⃣" at x=4, y=2 (Selected)
    let cell = buffer.cell((4, 2)).unwrap();
    assert_eq!(cell.symbol(), "4️⃣");
    assert_eq!(cell.fg, Color::Yellow);
}

#[test]
fn test_emoji_grid_scrolling() {
    // Height 5. Inner height = 3.
    // Width 10. Inner width = 8. Cols = 2.
    // We need enough items to force scroll.
    // 3 visible rows * 2 cols = 6 items visible.
    // Use 10 items to ensure scrolling is required.
    let backend = TestBackend::new(10, 5);
    let mut terminal = Terminal::new(backend).unwrap();

    let candidates: Vec<String> = (0..10).map(|i| format!("{}", i)).collect(); // "0", "1"...

    let mut state = EmojiGridState::default();

    // Select last item (index 9). Should scroll to bottom.
    // Rows: 5 total (0..4). Visible: 3.
    // Selected row: 4.
    // Scroll should be: 4 - 3 + 1 = 2.
    // Visible rows: 2, 3, 4.

    terminal
        .draw(|f| {
            let widget = EmojiGrid::new(&candidates, 9);
            f.render_stateful_widget(widget, f.area(), &mut state);
        })
        .unwrap();

    assert_eq!(state.scroll, 2);

    let buffer = terminal.backend().buffer();

    // Top visible row (buffer y=1) should contain items from Row 2 (indices 4, 5)
    // "4" at x=1, y=1
    assert_eq!(buffer.cell((1, 1)).unwrap().symbol(), "4");

    // Bottom visible row (buffer y=3) should contain items from Row 4 (indices 8, 9)
    // "9" at x=4, y=3 (Selected)
    let cell = buffer.cell((4, 3)).unwrap();
    assert_eq!(cell.symbol(), "9");
    assert_eq!(cell.fg, Color::Yellow);

    // Check scrollbar
    // Scrollbar should be at x=9 (right edge)
    // With 5 total rows and 3 visible, thumb should be near bottom.
    assert_eq!(buffer.cell((9, 3)).unwrap().symbol(), "█"); // Thumb
}

#[test]
fn test_emoji_grid_empty() {
    let backend = TestBackend::new(20, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let candidates: Vec<String> = vec![];
    let mut state = EmojiGridState::default();

    terminal
        .draw(|f| {
            let widget = EmojiGrid::new(&candidates, 0);
            f.render_stateful_widget(widget, f.area(), &mut state);
        })
        .unwrap();

    // Should render borders but no content, and not panic
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer.cell((0, 0)).unwrap().symbol(), "┌");
}
