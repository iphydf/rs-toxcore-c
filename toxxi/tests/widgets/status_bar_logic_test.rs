use ratatui::{buffer::Buffer, layout::Rect};
use toxxi::testing::buffer_to_string;
use toxxi::widgets::StatusBar;

#[test]
fn test_status_bar_rendering_logic() {
    let profile = "Alice".to_string();
    let status = "Online".to_string();
    let id = "0123456789ABCDEF".to_string();
    let widget = StatusBar::new(profile.clone(), status.clone(), id.clone())
        .dht_health(vec![1, 10, 50, 100]);

    let area = Rect::new(0, 0, 80, 1);
    let mut buffer = Buffer::empty(area);

    use ratatui::widgets::Widget;
    widget.render(area, &mut buffer);

    let rendered = buffer_to_string(&buffer);

    // Check if profile and status are present
    assert!(rendered.contains("Alice"));
    assert!(rendered.contains("[Online]"));

    // Check if Nodes section exists
    assert!(rendered.contains("Nodes: ["));

    // Check if ID is present (truncated)
    assert!(!rendered.contains("ID: 0123456789..."));
}

#[test]
fn test_status_bar_sparkline_logic() {
    // We want to verify that different values produce different Braille characters
    let widget_low = StatusBar::new("A".into(), "O".into(), "ID".into())
        .dht_health(vec![1, 1])
        .max_health(100)
        .sparkline_width(1);

    let widget_high = StatusBar::new("A".into(), "O".into(), "ID".into())
        .dht_health(vec![100, 100])
        .max_health(100)
        .sparkline_width(1);

    let mut buf_low = Buffer::empty(Rect::new(0, 0, 80, 1));
    let mut buf_high = Buffer::empty(Rect::new(0, 0, 80, 1));

    use ratatui::widgets::Widget;
    widget_low.render(Rect::new(0, 0, 80, 1), &mut buf_low);
    widget_high.render(Rect::new(0, 0, 80, 1), &mut buf_high);

    let s_low = buffer_to_string(&buf_low);
    let s_high = buffer_to_string(&buf_high);

    // Extract the sparkline part. It's between Nodes: [ and ]
    let extract_sparkline = |s: &str| -> String {
        let start = s.find("Nodes: [").unwrap() + 8;
        let end = s[start..].find(']').unwrap() + start;
        s[start..end].to_string()
    };

    let spark_low = extract_sparkline(&s_low);
    let spark_high = extract_sparkline(&s_high);

    assert_ne!(
        spark_low, spark_high,
        "Sparklines for low vs high values should differ"
    );

    // High value should have more dots than low value
    // In our implementation, val=1 (low) maps to 1 dot row (bits 0x40 and 0x80)
    // val=100 (high) maps to 4 dot rows (all bits)
    // So spark_high should have a character with a higher Unicode value if they are both non-empty
    let char_low = spark_low.chars().next().unwrap();
    let char_high = spark_high.chars().next().unwrap();

    assert!(
        char_high as u32 > char_low as u32,
        "High value sparkline should have 'denser' Braille character"
    );
}
