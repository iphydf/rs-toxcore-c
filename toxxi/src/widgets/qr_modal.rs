use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Widget},
};
use unicode_width::UnicodeWidthStr;

pub struct QrCodeModal {
    data: String,
    title: String,
}

impl QrCodeModal {
    pub fn new(data: String) -> Self {
        Self {
            data,
            title: " Tox ID QR Code (Press any key to close) ".to_string(),
        }
    }

    pub fn title(mut self, title: String) -> Self {
        self.title = title;
        self
    }

    /// Returns the required size (width, height) to render the QR code
    pub fn required_size(&self) -> (u16, u16) {
        let code = match QrCode::new(&self.data) {
            Ok(c) => c,
            Err(_) => return (20, 5), // Fallback size
        };
        let image = code.render::<unicode::Dense1x2>().build();
        let lines: Vec<&str> = image.lines().collect();
        let height = lines.len() as u16;
        let width = lines.iter().map(|l| l.width()).max().unwrap_or(0) as u16;

        // +2 for borders
        (width + 2, height + 2)
    }
}

impl Widget for QrCodeModal {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let code = match QrCode::new(&self.data) {
            Ok(c) => c,
            Err(_) => {
                Paragraph::new("Error generating QR code")
                    .block(Block::default().borders(Borders::ALL).title(self.title))
                    .render(area, buf);
                return;
            }
        };

        let image = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();

        let lines: Vec<Line> = image.lines().map(Line::from).collect();

        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(self.title))
            .alignment(ratatui::layout::Alignment::Center)
            .render(area, buf);
    }
}
