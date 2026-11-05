use ratatui::{Terminal, backend::TestBackend};
use toxxi::ui::draw;
use toxxi::update::handle_command;
use toxxi_testing::create_test_model;

#[test]
fn test_qr_command_and_visibility() {
    let mut model = create_test_model();

    assert!(model.ui.qr.is_none());

    handle_command(&mut model, "/qr");
    assert!(model.ui.qr.is_some());

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let mut found_title = false;
    for y in 0..20 {
        let row: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("Tox ID QR Code") {
            found_title = true;
            break;
        }
    }
    assert!(
        found_title,
        "QR modal title should be visible in the terminal buffer"
    );
}
