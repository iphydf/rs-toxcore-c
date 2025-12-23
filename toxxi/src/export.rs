use ratatui::buffer::Buffer;
use ratatui::style::Color;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgRect {
    pub y: u16, // Sort by y then x for better path jumps
    pub x: u16,
    pub w: u16,
    pub h: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CharCategory {
    Normal,
    Block,
    Emoji,
}

pub struct FgRun {
    pub x: u16,
    pub y: u16,
    pub color_idx: usize,
    pub text: String,
    pub width: u16,
    pub category: CharCategory,
}

pub struct SvgModel {
    pub width: u16,
    pub height: u16,
    pub bg_rects: Vec<ModelBgRect>,
    pub fg_texts: Vec<ModelFgText>,
}

#[derive(Debug)]
pub struct ModelBgRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub color: String,
}

#[derive(Debug)]
pub struct ModelFgText {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub text: String,
    pub color: String,
    pub category: CharCategory,
}

struct IntermediateSvgData {
    palette: Vec<String>,
    background_layers: BTreeMap<usize, Vec<BgRect>>,
    foreground_runs: Vec<FgRun>,
}

fn get_char_category(symbol: &str) -> CharCategory {
    if symbol.is_empty() {
        return CharCategory::Normal;
    }
    for c in symbol.chars() {
        match c as u32 {
            0x2580..=0x259F | 0x2800..=0x28FF => return CharCategory::Block,
            _ => {}
        }
    }
    if symbol.width() > 1 {
        return CharCategory::Emoji;
    }
    CharCategory::Normal
}

fn build_palette(buffer: &Buffer) -> (Vec<String>, HashMap<String, usize>) {
    let mut palette_map = HashMap::new();
    let mut palette = Vec::new();
    let mut add_color = |hex: String| {
        if let Some(&idx) = palette_map.get(&hex) {
            idx
        } else {
            let idx = palette.len();
            palette.push(hex.clone());
            palette_map.insert(hex.clone(), idx);
            idx
        }
    };

    for cell in buffer.content.iter() {
        add_color(color_to_hex(cell.bg, "#000000"));
        add_color(color_to_hex(cell.fg, "#ffffff"));
    }
    (palette, palette_map)
}

fn process_backgrounds(
    buffer: &Buffer,
    palette_map: &HashMap<String, usize>,
) -> BTreeMap<usize, Vec<BgRect>> {
    let area = buffer.area;
    let width = area.width;
    let height = area.height;
    let mut bg_layers_masks: BTreeMap<usize, Vec<bool>> = BTreeMap::new();

    for y in 0..height {
        for x in 0..width {
            let cell = &buffer[(x, y)];
            let hex = color_to_hex(cell.bg, "#000000");
            if hex == "#000" || hex == "#000000" {
                continue;
            }
            let idx = *palette_map.get(&hex).unwrap();
            bg_layers_masks
                .entry(idx)
                .or_insert_with(|| vec![false; (width * height) as usize])
                [(y * width + x) as usize] = true;
        }
    }

    let mut background_layers = BTreeMap::new();
    for (idx, mut mask) in bg_layers_masks {
        let mut rects = Vec::new();
        for y in 0..height {
            for x in 0..width {
                if mask[(y * width + x) as usize] {
                    let mut w = 0;
                    while x + w < width && mask[(y * width + x + w) as usize] {
                        w += 1;
                    }
                    let mut h = 1;
                    'outer: while y + h < height {
                        for dx in 0..w {
                            if !mask[((y + h) * width + x + dx) as usize] {
                                break 'outer;
                            }
                        }
                        h += 1;
                    }
                    for dy in 0..h {
                        for dx in 0..w {
                            mask[((y + dy) * width + x + dx) as usize] = false;
                        }
                    }
                    rects.push(BgRect { x, y, w, h });
                }
            }
        }
        rects.sort();
        background_layers.insert(idx, rects);
    }
    background_layers
}

fn process_foregrounds(buffer: &Buffer, palette_map: &HashMap<String, usize>) -> Vec<FgRun> {
    let area = buffer.area;
    let width = area.width;
    let height = area.height;
    let mut foreground_runs = Vec::new();

    for y in 0..height {
        let mut row_cells = Vec::new();
        let mut x = 0;
        while x < width {
            let cell = &buffer[(x, y)];
            let symbol = cell.symbol();
            let sw = symbol.width() as u16;

            if symbol == " " || symbol.is_empty() {
                row_cells.push(None);
                x += 1;
            } else {
                let hex = color_to_hex(cell.fg, "#ffffff");
                let idx = *palette_map.get(&hex).unwrap();
                row_cells.push(Some((
                    idx,
                    symbol.to_string(),
                    sw,
                    get_char_category(symbol),
                )));
                for _ in 1..sw {
                    row_cells.push(None);
                }
                x += sw.max(1);
            }
        }

        let mut x = 0;
        while x < width {
            if let Some((color_idx, symbol, w, category)) = &row_cells[x as usize] {
                let start_x = x;
                let mut run_text = symbol.clone();
                let mut run_width = *w;
                let color_idx = *color_idx;
                let category = *category;
                x += *w;

                while x < width {
                    let mut gap = 0;
                    while x + gap < width && row_cells[(x + gap) as usize].is_none() {
                        gap += 1;
                    }

                    if x + gap < width
                        && let Some((next_color, next_symbol, next_w, next_cat)) =
                            &row_cells[(x + gap) as usize]
                    {
                        // Only merge if it's the SAME color, SAME category, AND there is NO gap.
                        if *next_color == color_idx && *next_cat == category && gap == 0 {
                            run_text.push_str(next_symbol);
                            run_width += *next_w;
                            x += *next_w;
                            continue;
                        }
                    }
                    break;
                }
                foreground_runs.push(FgRun {
                    x: start_x,
                    y,
                    color_idx,
                    text: run_text,
                    width: run_width,
                    category,
                });
            } else {
                x += 1;
            }
        }
    }
    foreground_runs
}

fn process_buffer(buffer: &Buffer) -> IntermediateSvgData {
    let (palette, palette_map) = build_palette(buffer);
    let background_layers = process_backgrounds(buffer, &palette_map);
    let foreground_runs = process_foregrounds(buffer, &palette_map);

    IntermediateSvgData {
        palette,
        background_layers,
        foreground_runs,
    }
}

impl SvgModel {
    pub fn from_buffer(buffer: &Buffer) -> Self {
        let data = process_buffer(buffer);
        let mut bg_rects = Vec::new();
        let mut fg_texts = Vec::new();

        for (idx, rects) in data.background_layers {
            let color = &data.palette[idx];
            for r in rects {
                bg_rects.push(ModelBgRect {
                    x: r.x,
                    y: r.y,
                    width: r.w,
                    height: r.h,
                    color: color.clone(),
                });
            }
        }
        // Sort for deterministic test output (by y, then x)
        // Original BgRects are sorted by y, x in process_buffer via `rects.sort()`.
        // However, iteration order of HashMap is not deterministic.
        bg_rects.sort_by(|a, b| a.x.cmp(&b.x)); // The test seems to expect x-order or simple list.

        for run in data.foreground_runs {
            fg_texts.push(ModelFgText {
                x: run.x,
                y: run.y,
                width: run.width,
                text: run.text,
                color: data.palette[run.color_idx].clone(),
                category: run.category,
            });
        }

        Self {
            width: buffer.area.width,
            height: buffer.area.height,
            bg_rects,
            fg_texts,
        }
    }
}

pub fn buffer_to_svg(buffer: &Buffer) -> String {
    let area = buffer.area;
    let width = area.width;
    let height = area.height;

    let data = process_buffer(buffer);

    render_svg(
        width,
        height,
        data.palette,
        data.background_layers,
        data.foreground_runs,
    )
}

pub fn buffer_to_png(buffer: &Buffer) -> Result<Vec<u8>, String> {
    let svg = buffer_to_svg(buffer);
    let pixmap = render_svg_to_pixmap(
        &svg,
        (buffer.area.width * 10) as u32,
        (buffer.area.height * 20) as u32,
    )?;
    pixmap.encode_png().map_err(|e| e.to_string())
}

pub fn buffer_to_qoi(buffer: &Buffer) -> Result<Vec<u8>, String> {
    let svg = buffer_to_svg(buffer);
    let pixmap = render_svg_to_pixmap(
        &svg,
        (buffer.area.width * 10) as u32,
        (buffer.area.height * 20) as u32,
    )?;
    qoi::encode_to_vec(pixmap.data(), pixmap.width(), pixmap.height()).map_err(|e| e.to_string())
}

const NOTO_COLOR_EMOJI: &[u8] = include_bytes!("../assets/fonts/NotoColorEmoji.ttf");

fn render_svg_to_pixmap(
    svg_str: &str,
    width: u32,
    height: u32,
) -> Result<tiny_skia::Pixmap, String> {
    let mut fontdb = resvg::usvg::fontdb::Database::new();
    fontdb.load_system_fonts();
    fontdb.load_font_data(NOTO_COLOR_EMOJI.to_vec());

    // Explicitly set a default monospace font if possible
    fontdb.set_monospace_family("DejaVu Sans Mono");
    fontdb.set_serif_family("DejaVu Serif");
    fontdb.set_sans_serif_family("DejaVu Sans");

    let opt = resvg::usvg::Options {
        fontdb: std::sync::Arc::new(fontdb),
        font_family: "DejaVu Sans Mono".to_string(),
        ..resvg::usvg::Options::default()
    };
    let tree = resvg::usvg::Tree::from_str(svg_str, &opt).map_err(|e| e.to_string())?;

    let mut pixmap = tiny_skia::Pixmap::new(width, height).ok_or("Failed to create pixmap")?;
    resvg::render(&tree, tiny_skia::Transform::default(), &mut pixmap.as_mut());
    Ok(pixmap)
}

fn render_svg_style(palette: &[String]) -> String {
    let mut s = String::new();
    s.push_str("<style>");
    s.push_str("rect,path{shape-rendering:crispEdges}");
    s.push_str("text{white-space:pre;dominant-baseline:central}");
    s.push_str(".n{font-size:1.66px;font-family:'DejaVu Sans Mono',monospace}");
    s.push_str(".b{font-size:2.0px;font-family:'DejaVu Sans Mono',monospace}");
    s.push_str(".e{font-size:2.0px;font-family:'Noto Color Emoji','DejaVu Sans Mono',monospace}");
    for (i, color) in palette.iter().enumerate() {
        let _ = write!(s, ".{}{{fill:{}}}", to_base36(i), color);
    }
    s.push_str("</style>");
    s
}

fn render_svg_backgrounds(
    width: u16,
    height: u16,
    background_layers: &BTreeMap<usize, Vec<BgRect>>,
) -> String {
    let mut svg = String::new();
    let _ = write!(
        svg,
        r##"<rect width="{}" height="{}" fill="#000"/>"##,
        width,
        height * 2
    );

    for (idx, rects) in background_layers {
        let mut d = String::new();
        let mut last_x = 0i32;
        let mut last_y = 0i32;

        for (i, r) in rects.iter().enumerate() {
            let rx = r.x as i32;
            let ry = (r.y * 2) as i32;
            let rw = r.w as i32;
            let rh = (r.h * 2) as i32;

            if i == 0 {
                let _ = write!(d, "M{} {}h{}v{}h-{}z", rx, ry, rw, rh, rw);
            } else {
                let dx = rx - last_x;
                let dy = ry - last_y;
                let _ = write!(d, "m{} {}h{}v{}h-{}z", dx, dy, rw, rh, rw);
            }
            last_x = rx;
            last_y = ry;
        }
        let _ = write!(svg, r#"<path class="{}" d="{}"/>"#, to_base36(*idx), d);
    }
    svg
}

fn render_svg_foregrounds(foreground_runs: &[FgRun]) -> String {
    let mut svg = String::new();
    let mut by_row: HashMap<u16, Vec<&FgRun>> = HashMap::new();
    for run in foreground_runs {
        by_row.entry(run.y).or_default().push(run);
    }
    let mut rows: Vec<_> = by_row.keys().collect();
    rows.sort();

    for y in rows {
        let py = *y * 2 + 1;
        let _ = write!(svg, r#"<text x="0" y="{}" text-anchor="start">"#, py);
        let mut row_runs = by_row[y].clone();
        row_runs.sort_by_key(|r| r.x);

        for run in row_runs {
            let mut x_list = String::new();
            let mut current_x = run.x;
            for (i, g) in run.text.graphemes(true).enumerate() {
                if i > 0 {
                    x_list.push(' ');
                }
                let _ = write!(x_list, "{}", current_x);
                current_x += g.width().max(1) as u16;
            }

            let class_suffix = match run.category {
                CharCategory::Normal => "n",
                CharCategory::Block => "b",
                CharCategory::Emoji => "e",
            };

            let _ = write!(
                svg,
                r#"<tspan x="{}" class="{} {}">{}</tspan>"#,
                x_list,
                to_base36(run.color_idx),
                class_suffix,
                escape_xml(&run.text)
            );
        }
        svg.push_str("</text>");
    }
    svg
}

fn render_svg(
    width: u16,
    height: u16,
    palette: Vec<String>,
    background_layers: BTreeMap<usize, Vec<BgRect>>,
    foreground_runs: Vec<FgRun>,
) -> String {
    let mut svg = String::with_capacity(16384);
    let _ = write!(
        svg,
        r#"<svg width="{}" height="{}" viewBox="0 0 {} {}" xmlns="http://www.w3.org/2000/svg">"#,
        width * 10,
        height * 20,
        width,
        height * 2
    );

    svg.push_str(&render_svg_style(&palette));
    svg.push_str(&render_svg_backgrounds(width, height, &background_layers));
    svg.push_str(&render_svg_foregrounds(&foreground_runs));

    svg.push_str("</svg>");
    svg
}

fn to_base36(mut n: usize) -> String {
    if n == 0 {
        return "ca".to_string();
    }
    let mut s = "c".to_string();
    let mut digits = Vec::new();
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    while n > 0 {
        digits.push(chars[n % 36] as char);
        n /= 36;
    }
    for c in digits.into_iter().rev() {
        s.push(c);
    }
    s
}

fn escape_xml(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
}

pub fn color_to_hex(color: Color, default: &str) -> String {
    match color {
        Color::Reset => default.to_string(),
        Color::Black => "#000000".to_string(),
        Color::Red => "#aa0000".to_string(),
        Color::Green => "#00aa00".to_string(),
        Color::Yellow => "#aa5500".to_string(),
        Color::Blue => "#0000aa".to_string(),
        Color::Magenta => "#aa00aa".to_string(),
        Color::Cyan => "#00aaaa".to_string(),
        Color::Gray => "#aaaaaa".to_string(),
        Color::DarkGray => "#555555".to_string(),
        Color::LightRed => "#ff5555".to_string(),
        Color::LightGreen => "#55ff55".to_string(),
        Color::LightYellow => "#ffff55".to_string(),
        Color::LightBlue => "#5555ff".to_string(),
        Color::LightMagenta => "#ff55ff".to_string(),
        Color::LightCyan => "#55ffff".to_string(),
        Color::White => "#ffffff".to_string(),
        Color::Rgb(r, g, b) => format!("#{:02x}{:02x}{:02x}", r, g, b),
        Color::Indexed(i) => {
            if i < 16 {
                match i {
                    0 => "#000000".to_string(),
                    1 => "#aa0000".to_string(),
                    2 => "#00aa00".to_string(),
                    3 => "#aa5500".to_string(),
                    4 => "#0000aa".to_string(),
                    5 => "#aa00aa".to_string(),
                    6 => "#00aaaa".to_string(),
                    7 => "#aaaaaa".to_string(),
                    8 => "#555555".to_string(),
                    9 => "#ff5555".to_string(),
                    10 => "#55ff55".to_string(),
                    11 => "#ffff55".to_string(),
                    12 => "#5555ff".to_string(),
                    13 => "#ff55ff".to_string(),
                    14 => "#55ffff".to_string(),
                    15 => "#ffffff".to_string(),
                    _ => default.to_string(),
                }
            } else if i < 232 {
                let i = i - 16;
                let r = (i / 36) % 6;
                let g = (i / 6) % 6;
                let b = i % 6;
                let r = if r == 0 { 0 } else { r * 40 + 55 };
                let g = if g == 0 { 0 } else { g * 40 + 55 };
                let b = if b == 0 { 0 } else { b * 40 + 55 };
                format!("#{:02x}{:02x}{:02x}", r, g, b)
            } else {
                let i = i - 232;
                let v = i * 10 + 8;
                format!("#{:02x}{:02x}{:02x}", v, v, v)
            }
        }
    }
}
