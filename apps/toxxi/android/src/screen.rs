//! The screen toxxi draws on: ratatui writes cells into it, the app's view
//! copies them out to draw them.

use std::io;
use std::sync::Mutex;

use ratatui::backend::{Backend, ClearType, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};
use ratatui::style::{Color, Modifier};
use unicode_width::UnicodeWidthStr;

/// A cell's look is its foreground and background as ARGB, then its style.
pub const LOOK_INTS: usize = 3;

// Style flags, as in Toxxi.kt. The cell's width in columns is above them.
const BOLD: i32 = 1;
const ITALIC: i32 = 2;
const UNDERLINE: i32 = 4;
const CROSSED_OUT: i32 = 8;
const CURSOR: i32 = 16;
const WIDTH_SHIFT: u32 = 8;

const FOREGROUND: u32 = 0xffd0d0d0;
const BACKGROUND: u32 = 0xff000000;

/// The 16 named colours.
const PALETTE: [u32; 16] = [
    0xff000000, 0xffcd3131, 0xff0dbc79, 0xffe5e510, 0xff2472c8, 0xffbc3fbc, 0xff11a8cd, 0xffe5e5e5,
    0xff666666, 0xfff14c4c, 0xff23d18b, 0xfff5f543, 0xff3b8eea, 0xffd670d6, 0xff29b8db, 0xffffffff,
];

struct Screen {
    cells: Vec<Cell>,
    size: Size,
    cursor: Position,
    cursor_shown: bool,
    /// Whether anything changed since the last frame was shown.
    changed: bool,
}

static SCREEN: Mutex<Screen> = Mutex::new(Screen {
    cells: Vec::new(),
    size: Size::ZERO,
    cursor: Position::ORIGIN,
    cursor_shown: false,
    changed: false,
});

impl Screen {
    fn show_cursor(&mut self, shown: bool) {
        self.changed |= self.cursor_shown != shown;
        self.cursor_shown = shown;
    }
}

fn screen() -> std::sync::MutexGuard<'static, Screen> {
    SCREEN.lock().unwrap_or_else(|e| e.into_inner())
}

/// Makes the screen `size` big and blank: toxxi draws all of it again.
pub fn resize(size: Size) {
    let mut screen = screen();
    screen.size = size;
    screen.cells = vec![Cell::default(); size.area() as usize];
    screen.changed = true;
}

/// Copies the screen as a `rows` × `cols` grid: each cell's look into
/// `looks`, and where its text starts in the returned string into `starts`
/// (in UTF-16 units, with the string's length last). A cell hidden by a wide
/// one before it has no text and width 0.
pub fn snapshot(rows: u16, cols: u16, looks: &mut Vec<i32>, starts: &mut Vec<i32>) -> String {
    let screen = screen();
    let blank = Cell::default();
    let mut text = String::new();
    let mut units = 0;
    looks.clear();
    starts.clear();

    for y in 0..rows {
        let mut hidden_until = 0;
        for x in 0..cols {
            let cell = if x < screen.size.width && y < screen.size.height {
                &screen.cells[usize::from(y) * usize::from(screen.size.width) + usize::from(x)]
            } else {
                &blank
            };
            starts.push(units);

            let width = if x < hidden_until {
                0
            } else {
                let symbol = match cell.symbol() {
                    "" => " ",
                    symbol => symbol,
                };
                text.push_str(symbol);
                units += symbol.encode_utf16().count() as i32;
                let width = symbol.width().clamp(1, usize::from(cols - x)) as u16;
                hidden_until = x + width;
                width
            };

            let cursor = screen.cursor_shown && screen.cursor == Position::new(x, y);
            looks.extend(look(cell, cursor, width));
        }
    }
    starts.push(units);
    text
}

fn look(cell: &Cell, cursor: bool, width: u16) -> [i32; LOOK_INTS] {
    let mut fg = colour(cell.fg, FOREGROUND);
    let mut bg = colour(cell.bg, BACKGROUND);
    let m = cell.modifier;
    if m.contains(Modifier::REVERSED) {
        (fg, bg) = (bg, fg);
    }
    if m.contains(Modifier::DIM) {
        fg = halfway(fg, bg);
    }
    if m.contains(Modifier::HIDDEN) {
        fg = bg;
    }

    let mut style = i32::from(width) << WIDTH_SHIFT;
    for (modifier, flag) in [
        (Modifier::BOLD, BOLD),
        (Modifier::ITALIC, ITALIC),
        (Modifier::UNDERLINED, UNDERLINE),
        (Modifier::CROSSED_OUT, CROSSED_OUT),
    ] {
        if m.contains(modifier) {
            style |= flag;
        }
    }
    if cursor {
        style |= CURSOR;
    }
    [fg as i32, bg as i32, style]
}

fn colour(colour: Color, default: u32) -> u32 {
    match colour {
        Color::Reset => default,
        Color::Black => PALETTE[0],
        Color::Red => PALETTE[1],
        Color::Green => PALETTE[2],
        Color::Yellow => PALETTE[3],
        Color::Blue => PALETTE[4],
        Color::Magenta => PALETTE[5],
        Color::Cyan => PALETTE[6],
        Color::Gray => PALETTE[7],
        Color::DarkGray => PALETTE[8],
        Color::LightRed => PALETTE[9],
        Color::LightGreen => PALETTE[10],
        Color::LightYellow => PALETTE[11],
        Color::LightBlue => PALETTE[12],
        Color::LightMagenta => PALETTE[13],
        Color::LightCyan => PALETTE[14],
        Color::White => PALETTE[15],
        Color::Rgb(r, g, b) => rgb(r, g, b),
        Color::Indexed(i) => indexed(i),
    }
}

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    0xff000000 | u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b)
}

/// The xterm 256-colour palette: the named colours, a 6×6×6 cube, then 24 greys.
fn indexed(i: u8) -> u32 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match i {
        0..16 => PALETTE[usize::from(i)],
        16..232 => {
            let i = usize::from(i - 16);
            rgb(LEVELS[i / 36], LEVELS[i / 6 % 6], LEVELS[i % 6])
        }
        _ => {
            let grey = 8 + 10 * (i - 232);
            rgb(grey, grey, grey)
        }
    }
}

fn halfway(a: u32, b: u32) -> u32 {
    let channel = |shift: u32| (((a >> shift & 0xff) + (b >> shift & 0xff)) / 2) << shift;
    0xff000000 | channel(16) | channel(8) | channel(0)
}

/// Draws on the screen and calls `flushed` when a frame changed it. toxxi
/// draws a frame every tick, mostly the same.
pub struct ScreenBackend {
    pub flushed: fn(),
}

impl Backend for ScreenBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut screen = screen();
        let size = screen.size;
        for (x, y, cell) in content {
            // A frame drawn for the size before a resize can be bigger.
            if x < size.width && y < size.height {
                screen.cells[usize::from(y) * usize::from(size.width) + usize::from(x)] =
                    cell.clone();
                screen.changed = true;
            }
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        screen().show_cursor(false);
        Ok(())
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        screen().show_cursor(true);
        Ok(())
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(screen().cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let mut screen = screen();
        let position = position.into();
        screen.changed |= screen.cursor != position;
        screen.cursor = position;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.clear_region(ClearType::All)
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        let mut screen = screen();
        let width = usize::from(screen.size.width);
        let cursor = usize::from(screen.cursor.y) * width + usize::from(screen.cursor.x);
        let line = cursor - cursor % width.max(1);
        let len = screen.cells.len();
        let range = match clear_type {
            ClearType::All => 0..len,
            ClearType::AfterCursor => cursor..len,
            ClearType::BeforeCursor => 0..cursor,
            ClearType::CurrentLine => line..line + width,
            ClearType::UntilNewLine => cursor..line + width,
        };
        let range = range.start.min(len)..range.end.min(len);
        screen.cells[range].fill(Cell::default());
        screen.changed = true;
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(screen().size)
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: screen().size,
            pixels: Size::ZERO,
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        if std::mem::take(&mut screen().changed) {
            (self.flushed)();
        }
        Ok(())
    }
}
