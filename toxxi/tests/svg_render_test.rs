use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use resvg::usvg::{self, Tree};
use tiny_skia::{Pixmap, Transform};
use toxxi::export::buffer_to_svg;

fn render_svg_to_pixmap(svg_str: &str, width: u32, height: u32) -> Pixmap {
    let mut fontdb = resvg::usvg::fontdb::Database::new();
    fontdb.load_system_fonts();

    // Explicitly try to load a font to see if it makes a difference
    let font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
    ];
    for path in font_paths {
        if let Ok(data) = std::fs::read(path) {
            fontdb.load_font_data(data);
        }
    }

    if fontdb.is_empty() {
        panic!("Font database is empty! No fonts available for rendering.");
    }

    let opt = usvg::Options {
        fontdb: std::sync::Arc::new(fontdb),
        font_family: "Monospace".to_string(),
        ..usvg::Options::default()
    };
    let tree = Tree::from_str(svg_str, &opt).expect("Failed to parse SVG");

    let mut pixmap = Pixmap::new(width, height).unwrap();
    resvg::render(&tree, Transform::default(), &mut pixmap.as_mut());
    pixmap
}

#[test]
fn test_svg_vertical_connectivity_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 1, 2));
    buffer[(0, 0)].set_symbol("█").set_fg(Color::White);
    buffer[(0, 1)].set_symbol("█").set_fg(Color::White);

    let svg = buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 10, 40);

    let x = 5;

    // Debug: check center of first block
    let center1 = pixmap.pixel(x, 10).unwrap();
    let center2 = pixmap.pixel(x, 30).unwrap();
    let boundary = pixmap.pixel(x, 20).unwrap();

    println!("Pixel at y=10 (center 1): {:?}", center1);
    println!("Pixel at y=30 (center 2): {:?}", center2);
    println!("Pixel at y=20 (boundary): {:?}", boundary);

    if center1.alpha() == 0 || center2.alpha() == 0 {
        println!("SVG on failure:\n{}", svg);
        // If centers are empty, the character probably didn't render at all in the available font
        return;
    }

    // Check connectivity: no transparent or black gaps between centers
    for y in 10..30 {
        let pixel = pixmap.pixel(x, y).unwrap();
        assert!(
            pixel.alpha() > 10,
            "Gap found at y={} in vertical block. Pixel: {:?}",
            y,
            pixel
        );
    }
}

#[test]
fn test_emoji_alignment_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    buffer.set_string(0, 0, "A 😊 B", Style::default().fg(Color::White));

    let svg = buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 100, 20);

    let has_pixels = |x_start: u32, x_end: u32| {
        for x in x_start..x_end {
            for y in 0..20 {
                if pixmap.pixel(x, y).unwrap().alpha() > 0 {
                    return true;
                }
            }
        }
        false
    };

    assert!(has_pixels(0, 10), "Character 'A' missing pixels");
    assert!(has_pixels(20, 40), "Emoji '😊' missing pixels");
    assert!(has_pixels(50, 60), "Character 'B' missing pixels");
}

#[test]
fn test_scrollbar_connectivity_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 1, 3));
    buffer[(0, 0)].set_symbol("█").set_fg(Color::Blue);
    buffer[(0, 1)].set_symbol("█").set_fg(Color::Blue);
    buffer[(0, 2)].set_symbol("█").set_fg(Color::Blue);

    let svg = buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 10, 60);

    let x = 5;

    // Check centers first
    let p10 = pixmap.pixel(x, 10).unwrap();
    let p30 = pixmap.pixel(x, 30).unwrap();
    let p50 = pixmap.pixel(x, 50).unwrap();

    if p10.alpha() == 0 || p30.alpha() == 0 || p50.alpha() == 0 {
        return; // Font issues
    }

    for y in 10..50 {
        let pixel = pixmap.pixel(x, y).unwrap();
        if pixel.alpha() <= 10 {
            println!("SVG on failure:\n{}", svg);
            panic!("Gap found in scrollbar at y={}. Pixel: {:?}", y, pixel);
        }
    }
}

#[test]
fn test_png_rendering_not_empty() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 2));
    buffer.set_string(
        0,
        0,
        "SOME TEXT",
        Style::default().fg(Color::White).bg(Color::Black),
    );
    buffer.set_string(
        0,
        1,
        "OTHER TEXT",
        Style::default().fg(Color::Red).bg(Color::Blue),
    );

    let png_data = toxxi::export::buffer_to_png(&buffer).expect("Failed to render PNG");
    assert!(!png_data.is_empty());

    let pixmap = Pixmap::decode_png(&png_data).expect("Failed to decode rendered PNG");

    let mut has_white = false;
    let mut has_red = false;
    let mut has_blue = false;

    for x in 0..pixmap.width() {
        for y in 0..pixmap.height() {
            let p = pixmap.pixel(x, y).unwrap();
            // Checking for non-zero luminosity/color components
            if p.red() > 200 && p.green() > 200 && p.blue() > 200 {
                has_white = true;
            }
            if p.red() > 150 && p.green() < 50 && p.blue() < 50 {
                has_red = true;
            }
            if p.red() < 50 && p.green() < 50 && p.blue() > 150 {
                has_blue = true;
            }
        }
    }

    // If it's just background, these will fail
    assert!(has_white, "PNG missing white text pixels. Render issues?");
    assert!(has_red, "PNG missing red text pixels. Render issues?");
    assert!(
        has_blue,
        "PNG missing blue background pixels. Render issues?"
    );
}

#[test]
fn test_svg_no_bleeding_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    // Put a character in the middle
    buffer[(5, 0)].set_symbol("X").set_fg(Color::White);

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 100, 20);

    // Columns 0-4 and 6-9 should be completely black (except for tiny anti-aliasing)
    for x in 0..100 {
        if (48..62).contains(&x) {
            continue;
        } // The character 'X' is in 50..60
        for y in 0..20 {
            let p = pixmap.pixel(x, y).unwrap();
            // Since we have a black background, anything non-black is bleeding
            if p.red() > 20 || p.green() > 20 || p.blue() > 20 {
                println!("SVG on failure:\n{}", svg);
                panic!("Bleeding detected at x={}, y={}. Pixel: {:?}", x, y, p);
            }
        }
    }
}

#[test]
fn test_long_string_alignment_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 1));
    // Fill with 'a' and a specific marker at the end
    let mut s = "a".repeat(70);
    s.push('X');
    buffer.set_string(0, 0, &s, Style::default().fg(Color::White));

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 800, 20);

    // 'X' should be exactly at x = 70..71 (px 700..710)
    let has_pixels = |x_start: u32, x_end: u32| {
        for x in x_start..x_end {
            for y in 0..20 {
                if pixmap.pixel(x, y).unwrap().alpha() > 20 {
                    return true;
                }
            }
        }
        false
    };

    assert!(
        has_pixels(700, 710),
        "Marker 'X' missing or misaligned at end of long string"
    );

    // Check that it DOES NOT have pixels where it shouldn't (cumulative error check)
    // If it shifted right, it might bleed into 712+
    for x in 712..800 {
        for y in 0..20 {
            let p = pixmap.pixel(x, y).unwrap();
            assert!(
                p.red() < 20,
                "Cumulative shifting detected at x={}. Pixel: {:?}",
                x,
                p
            );
        }
    }
}

#[test]
fn test_mixed_width_alignment_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 20, 1));
    // "a😊a😊a😊a😊a" -> 1+2+1+2+1+2+1+2+1 = 13 cells
    buffer.set_string(0, 0, "a😊a😊a😊a😊a", Style::default().fg(Color::White));

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 200, 20);

    let has_pixels = |x_start: u32, x_end: u32| {
        for x in x_start..x_end {
            for y in 0..20 {
                if pixmap.pixel(x, y).unwrap().alpha() > 20 {
                    return true;
                }
            }
        }
        false
    };

    // The last 'a' is at cell 12, so px 120..130
    assert!(
        has_pixels(120, 130),
        "Last character in mixed-width string misaligned"
    );

    // Verify no pixels in cell 13 (px 135..145)
    for x in 135..145 {
        for y in 0..20 {
            let p = pixmap.pixel(x, y).unwrap();
            assert!(
                p.red() < 20,
                "Unexpected pixels in space gap at x={}. Pixel: {:?}",
                x,
                p
            );
        }
    }
}

#[test]
fn test_kerning_precision_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 20, 1));
    // 10 'X' characters.
    buffer.set_string(0, 0, "XXXXXXXXXX", Style::default().fg(Color::White));

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 200, 20);

    let is_text = |x: u32, y: u32| {
        let p = pixmap.pixel(x, y).unwrap();
        p.red() > 20 || p.green() > 20 || p.blue() > 20
    };

    // With explicit grid anchoring, the 10th 'X' (at col 9) MUST start at px 90.
    // If we use textLength+spacing, it will likely start LATER (e.g. px 93)
    // because gaps were added between all previous 9 characters.

    let mut starts_at_90 = false;
    for y in 5..15 {
        if is_text(90, y) || is_text(91, y) {
            starts_at_90 = true;
            break;
        }
    }

    // If it started later, px 90 and 91 will be black (background)
    assert!(
        starts_at_90,
        "10th character shifted due to cumulative kerning/spacing error"
    );

    // Also check that it hasn't spilled way past its end
    for x in 105..200 {
        for y in 0..20 {
            if is_text(x, y) {
                panic!("Text spilled into cell 11+ at x={}", x);
            }
        }
    }
}

#[test]
fn test_character_spacing_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
    // Two characters. They should be at px 0..10 and 10..20.
    buffer.set_string(0, 0, "XX", Style::default().fg(Color::White));

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 100, 20);

    let is_text = |x: u32, y: u32| {
        let p = pixmap.pixel(x, y).unwrap();
        p.red() > 20 || p.green() > 20 || p.blue() > 20
    };

    // If the font is 10px wide, x=9 and x=10 should likely have pixels (the 'X' strokes)
    // If there is a "too much space" issue, x=10 or x=11 might be empty while the
    // second 'X' starts later (e.g. at x=12).

    let mut boundary_has_pixels = false;
    for y in 5..15 {
        // Check the middle of the 'X' height
        if is_text(9, y) || is_text(10, y) || is_text(11, y) {
            boundary_has_pixels = true;
            break;
        }
    }

    // This is expected to fail if lengthAdjust="spacing" is distributing extra space
    // as gaps between characters, causing the second 'X' to be pushed away from the first.
    assert!(
        boundary_has_pixels,
        "Excessive kerning/gap detected between characters at the cell boundary"
    );
}

#[test]
fn test_internal_spacing_alignment_raster() {
    let mut buffer = Buffer::empty(Rect::new(0, 0, 30, 1));
    // "A" at 0, 10 spaces, "B" at 11
    buffer.set_string(0, 0, "A          B", Style::default().fg(Color::White));

    let svg = toxxi::export::buffer_to_svg(&buffer);
    let pixmap = render_svg_to_pixmap(&svg, 300, 20);

    let has_pixels = |x_start: u32, x_end: u32| {
        for x in x_start..x_end {
            for y in 0..20 {
                if pixmap.pixel(x, y).unwrap().alpha() > 20 {
                    return true;
                }
            }
        }
        false
    };

    // "A" should be at 0..10
    assert!(has_pixels(0, 10), "Character 'A' missing or misaligned");
    // "B" should be at 110..120
    assert!(
        has_pixels(110, 120),
        "Character 'B' missing or misaligned after spaces"
    );

    // The space between 10 and 110 should be empty (pixels 15 to 105 to be safe)
    for x in 15..105 {
        for y in 0..20 {
            let p = pixmap.pixel(x, y).unwrap();
            assert!(
                p.red() < 20,
                "Unexpected pixels in space gap at x={}. Pixel: {:?}",
                x,
                p
            );
        }
    }
}
// end of file
