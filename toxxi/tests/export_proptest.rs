use proptest::prelude::*;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use toxxi::export::{SvgModel, buffer_to_svg, color_to_hex};
use unicode_width::UnicodeWidthStr;

fn arb_color() -> impl Strategy<Value = Color> {
    prop_oneof![
        Just(Color::Reset),
        Just(Color::Black),
        Just(Color::Red),
        Just(Color::Green),
        Just(Color::Yellow),
        Just(Color::Blue),
        Just(Color::Magenta),
        Just(Color::Cyan),
        Just(Color::Gray),
        Just(Color::DarkGray),
        Just(Color::LightRed),
        Just(Color::LightGreen),
        Just(Color::LightYellow),
        Just(Color::LightBlue),
        Just(Color::LightMagenta),
        Just(Color::LightCyan),
        Just(Color::White),
        (0..255u8, 0..255u8, 0..255u8).prop_map(|(r, g, b)| Color::Rgb(r, g, b)),
        (0..255u8).prop_map(Color::Indexed),
    ]
}

prop_compose! {
    fn arb_style()(
        fg in prop::option::weighted(0.5, arb_color()),
        bg in prop::option::weighted(0.5, arb_color()),
    ) -> Style {
        let mut style = Style::default();
        if let Some(fg) = fg { style = style.fg(fg); }
        if let Some(bg) = bg { style = style.bg(bg); }
        style
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    #[test]
    fn test_svg_model_invariants(
        width in 1..50u16,
        height in 1..20u16,
        operations in prop::collection::vec(
            (0..50u16, 0..20u16, r"\PC*", arb_style()),
            0..30
        )
    ) {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        for (x, y, s, style) in operations {
            if x < width && y < height {
                buffer.set_stringn(x, y, &s, (width - x) as usize, style);
            }
        }

        let model = SvgModel::from_buffer(&buffer);

        // 1. Verify SVG dimensions
        prop_assert_eq!(model.width, width);
        prop_assert_eq!(model.height, height);

        // 2. Verify Background coverage and alignment
        for (i, r1) in model.bg_rects.iter().enumerate() {
            prop_assert!(r1.width > 0, "BgRect width must be positive");
            prop_assert!(r1.x + r1.width <= width, "BgRect out of bounds x");
            prop_assert!(r1.y < height, "BgRect out of bounds y");

            for r2 in model.bg_rects.iter().skip(i + 1) {
                if r1.y == r2.y {
                    prop_assert!(r1.x + r1.width <= r2.x || r2.x + r2.width <= r1.x,
                        "Overlapping BgRects at y={}: [{}, {}] and [{}, {}]",
                        r1.y, r1.x, r1.x + r1.width, r2.x, r2.x + r2.width);
                }
            }
        }

        // 3. Verify Foreground coverage and alignment
        for (i, t1) in model.fg_texts.iter().enumerate() {
            prop_assert!(t1.width > 0, "FgText width must be positive");
            prop_assert!(t1.x + t1.width <= width, "FgText out of bounds x");
            prop_assert!(t1.y < height, "FgText out of bounds y");

            // Critical invariant for alignment: text width MUST match logical width
            prop_assert_eq!(t1.text.width() as u16, t1.width,
                "Text width mismatch for {:?}: expected {}, got {}", t1.text, t1.width, t1.text.width());

            for t2 in model.fg_texts.iter().skip(i + 1) {
                if t1.y == t2.y {
                    prop_assert!(t1.x + t1.width <= t2.x || t2.x + t2.width <= t1.x,
                        "Overlapping FgTexts at y={}: [{}, {}] and [{}, {}]",
                        t1.y, t1.x, t1.x + t1.width, t2.x, t2.x + t2.width);
                }
            }
        }

        // 4. Verify Cell-by-Cell coverage
        for y in 0..height {
            let mut x = 0;
            while x < width {
                let cell = &buffer[(x, y)];
                let symbol = cell.symbol();
                let sw = symbol.width();
                let bg_hex = color_to_hex(cell.bg, "#000000");

                // Check background
                if bg_hex != "#000000" {
                    let matching_bg = model.bg_rects.iter()
                        .find(|r| y >= r.y && y < r.y + r.height && x >= r.x && x < r.x + r.width);
                    prop_assert!(matching_bg.is_some(), "Missing BgRect for cell ({}, {})", x, y);
                    prop_assert_eq!(&matching_bg.unwrap().color, &bg_hex);
                }

                // Check foreground
                if symbol != " " && sw > 0 {
                    let fg_hex = color_to_hex(cell.fg, "#ffffff");
                    let matching_fg = model.fg_texts.iter()
                        .find(|t| t.y == y && x >= t.x && x < t.x + t.width);
                    prop_assert!(matching_fg.is_some(), "Missing FgText for cell ({}, {}) symbol {:?}", x, y, symbol);
                    prop_assert_eq!(&matching_fg.unwrap().color, &fg_hex);
                }

                x += sw.max(1) as u16;
            }
        }

        // 5. Verify rendered SVG basics
        let svg = buffer_to_svg(&buffer);
        let expected_width = format!("width=\"{}\"", width * 10);
        let expected_height = format!("height=\"{}\"", height * 20);
        prop_assert!(svg.contains(&expected_width));
        prop_assert!(svg.contains(&expected_height));
    }
}
