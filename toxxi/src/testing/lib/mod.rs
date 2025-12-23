use ratatui::buffer::Buffer;
use std::path::PathBuf;
use unicode_width::UnicodeWidthStr;

pub fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut s = String::new();
    // Add top border for clarity in snapshot
    s.push_str(&"─".repeat(area.width as usize));
    s.push('\n');

    for y in area.y..area.y + area.height {
        let mut x = area.x;
        while x < area.x + area.width {
            let cell = &buffer[(x, y)];
            let symbol = cell.symbol();
            s.push_str(symbol);
            let w = symbol.width();
            if w > 0 {
                x += w as u16;
            } else {
                x += 1;
            }
        }
        s.push('\n');
    }

    // Add bottom border
    s.push_str(&"─".repeat(area.width as usize));
    s.push('\n');
    s
}

pub fn configure_insta() -> insta::Settings {
    let mut settings = insta::Settings::clone_current();
    let path = if let Ok(workspace_dir) = std::env::var("BUILD_WORKSPACE_DIRECTORY") {
        let mut p = PathBuf::from(workspace_dir);
        p.push("rs-toxcore-c");
        p.push("toxxi");
        p.push("tests");
        p.push("snapshots");
        p
    } else {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let mut p = std::env::current_dir().unwrap();
        p.push(manifest_dir);
        p.push("tests");
        p.push("snapshots");
        p
    };
    settings.set_snapshot_path(path);
    settings
}
