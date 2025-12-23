use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::FileTransferCard;

#[test]
fn test_render_file_transfer_card() {
    let backend = TestBackend::new(40, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = FileTransferCard::new(
        "document.pdf".to_string(),
        5 * 1024 * 1024,
        0.3,
        "500 KB/s".to_string(),
    );

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 40, 3);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("file_transfer_card", rendered);
    });
}

#[test]
fn test_render_file_transfer_card_focused() {
    let backend = TestBackend::new(60, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = FileTransferCard::new(
        "document.pdf".to_string(),
        5 * 1024 * 1024,
        0.3,
        "500 KB/s".to_string(),
    )
    .focused(true);

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 60, 3);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("file_transfer_card_focused", rendered);
    });
}

#[test]
fn test_render_file_transfer_card_outgoing() {
    let backend = TestBackend::new(40, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let widget = FileTransferCard::new(
        "image.png".to_string(),
        2 * 1024 * 1024,
        0.5,
        "1 MB/s".to_string(),
    )
    .is_incoming(false);

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 40, 3);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("file_transfer_card_outgoing", rendered);
    });
}

// end of file
