use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use toxxi::export::buffer_to_svg;

#[test]
fn test_buffer_to_svg_simple() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 2, 1));
    buffer[(0, 0)]
        .set_symbol("A")
        .set_style(Style::default().fg(Color::Red));
    buffer[(1, 0)]
        .set_symbol("B")
        .set_style(Style::default().bg(Color::Blue));

    let svg = buffer_to_svg(&buffer);

    // Basic structure checks
    assert!(svg.starts_with("<svg"));
    assert!(svg.ends_with("</svg>"));

    // Check dimensions (10x20 chars)
    // Width: 2 * 10 = 20
    // Height: 1 * 20 = 20
    assert!(svg.contains("width=\"20\""), "SVG missing width=\"20\"");
    assert!(svg.contains("height=\"20\""), "SVG missing height=\"20\"");

    // Check content
    // 'A' is Red (#aa0000)
    assert!(svg.contains(">A</tspan>"));
    assert!(svg.contains("fill:#aa0000"));

    // 'B' has Blue background (#0000aa) and default white text (#ffffff)
    assert!(svg.contains(">B</tspan>"));
    assert!(svg.contains("fill:#0000aa")); // Background rect
    assert!(svg.contains("fill:#ffffff")); // Text color
}

#[test]
fn test_buffer_to_svg_special_chars() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 1, 1));
    buffer[(0, 0)].set_symbol("<");

    let svg = buffer_to_svg(&buffer);

    assert!(svg.contains("&lt;"));
    assert!(!svg.contains("><<")); // Should not contain raw < inside tag
}
