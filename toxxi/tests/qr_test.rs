use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::ui::draw;
use toxxi::update::handle_command;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_qr_command_and_visibility() {
    let mut model = create_test_model();

    // 1. Initial state: show_qr is false
    assert!(!model.ui.show_qr);

    // 2. Run /qr command
    handle_command(&mut model, "/qr");
    assert!(model.ui.show_qr);

    // 3. Draw and check for QR modal indicators
    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Check if the title of the QR modal is present in the buffer
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
