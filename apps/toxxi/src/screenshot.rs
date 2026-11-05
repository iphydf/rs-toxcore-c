use crate::export;
use crate::model::{self, ConsoleMessageType, Model};
use crate::ui::draw;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::fs;
use std::path::{Path, PathBuf};

pub fn handle_screenshot(
    model: &mut Model,
    screenshots_dir: &Path,
    path_str: String,
    cols: Option<u16>,
    rows: Option<u16>,
    current_size: Option<ratatui::layout::Size>,
) {
    let path = PathBuf::from(&path_str);
    let final_path = if path.is_absolute() {
        path
    } else {
        screenshots_dir.join(path)
    };

    let extension = final_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("svg");

    let width = cols.or(current_size.map(|s| s.width)).unwrap_or(80);
    let height = rows.or(current_size.map(|s| s.height)).unwrap_or(24);

    let backend = TestBackend::new(width, height);
    let mut term = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            model.add_console_message(
                ConsoleMessageType::Error,
                format!("Failed to create screenshot terminal: {}", e),
            );
            return;
        }
    };

    if let Err(e) = term.draw(|f| draw(f, model)) {
        model.add_console_message(
            ConsoleMessageType::Error,
            format!("Failed to draw screenshot: {}", e),
        );
        return;
    }

    let buffer = term.backend().buffer();
    let res = match extension {
        "png" => export::buffer_to_png(buffer).map(|b| (b, "PNG")),
        "qoi" => export::buffer_to_qoi(buffer).map(|b| (b, "QOI")),
        _ => Ok((export::buffer_to_svg(buffer).into_bytes(), "SVG")),
    };

    match res {
        Ok((bytes, _format_name)) => {
            let size_bytes = bytes.len();
            if let Err(e) = fs::write(&final_path, &bytes) {
                model.add_console_message(
                    ConsoleMessageType::Error,
                    format!("Failed to save screenshot: {}", e),
                );
            } else {
                let display_path = if let Some(user_dirs) = directories::UserDirs::new() {
                    let home = user_dirs.home_dir();
                    if let Ok(suffix) = final_path.strip_prefix(home) {
                        format!("~/{}", suffix.display())
                    } else {
                        final_path.display().to_string()
                    }
                } else {
                    final_path.display().to_string()
                };

                let size_str = if size_bytes < 1024 {
                    format!("{} bytes", size_bytes)
                } else {
                    format!("{:.2} KB", size_bytes as f64 / 1024.0)
                };

                model.add_status_message(model::MessageContent::Text(format!(
                    "Screenshot saved to {} ({})",
                    display_path, size_str
                )));
            }
        }
        Err(e) => {
            model.add_console_message(
                ConsoleMessageType::Error,
                format!("Failed to render screenshot: {}", e),
            );
        }
    }
}
