use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use toxxi::export::{CharCategory, SvgModel};

#[test]
fn test_svg_model_emoji_isolation() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    // "a 📥 b"
    buffer.set_string(0, 0, "a 📥 b", ratatui::style::Style::default());

    let model = SvgModel::from_buffer(&buffer);

    // The emoji is in the Emoji category, the rest in Normal,
    // and the spaces are gaps.
    let fg_texts = model.fg_texts;
    assert_eq!(fg_texts.len(), 3);

    assert_eq!(fg_texts[0].text, "a");
    assert_eq!(fg_texts[0].x, 0);
    assert_eq!(fg_texts[0].width, 1);
    assert_eq!(fg_texts[0].category, CharCategory::Normal);

    assert_eq!(fg_texts[1].text, "📥");
    assert_eq!(fg_texts[1].x, 2);
    assert_eq!(fg_texts[1].width, 2);
    assert_eq!(fg_texts[1].category, CharCategory::Emoji);

    assert_eq!(fg_texts[2].text, "b");
    assert_eq!(fg_texts[2].x, 5);
    assert_eq!(fg_texts[2].width, 1);
    assert_eq!(fg_texts[2].category, CharCategory::Normal);
}

#[test]
fn test_svg_model_consecutive_emoji_isolation() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    // "📥📥"
    buffer.set_string(0, 0, "📥📥", ratatui::style::Style::default());

    let model = SvgModel::from_buffer(&buffer);

    // Adjacent text of the same colour is merged into one run.
    let fg_texts = model.fg_texts;
    assert_eq!(fg_texts.len(), 1);

    assert_eq!(fg_texts[0].text, "📥📥");
    assert_eq!(fg_texts[0].x, 0);
    // '📥'(2) + '📥'(2) = 4
    assert_eq!(fg_texts[0].width, 4);
}

#[test]
fn test_svg_model_background_run() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    for x in 0..5 {
        buffer[(x, 0)].set_bg(Color::Red);
    }

    let model = SvgModel::from_buffer(&buffer);
    assert_eq!(model.bg_rects.len(), 1);
    assert_eq!(model.bg_rects[0].x, 0);
    assert_eq!(model.bg_rects[0].width, 5);
    assert_eq!(model.bg_rects[0].color, "#aa0000");
}
