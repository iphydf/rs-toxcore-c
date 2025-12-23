use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::{Config, SystemMessageType};
use toxxi::model::{DomainState, Model};
use toxxi::msg::Msg;
use toxxi::update::update;

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

fn send_command(model: &mut Model, command: &str) {
    for c in command.chars() {
        update(
            model,
            Msg::Input(CrosstermEvent::Key(KeyEvent::new(
                KeyCode::Char(c),
                KeyModifiers::empty(),
            ))),
        );
    }
    update(
        model,
        Msg::Input(CrosstermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );
}

#[test]
fn test_set_ipv6_enabled() {
    let mut model = create_test_model();
    assert!(model.config.ipv6_enabled); // Default true

    send_command(&mut model, "/set ipv6_enabled false");
    assert!(!model.config.ipv6_enabled);

    send_command(&mut model, "/set ipv6_enabled true");
    assert!(model.config.ipv6_enabled);
}

#[test]
fn test_set_udp_enabled() {
    let mut model = create_test_model();
    assert!(model.config.udp_enabled); // Default true

    send_command(&mut model, "/set udp_enabled false");
    assert!(!model.config.udp_enabled);
}

#[test]
fn test_set_system_messages() {
    let mut model = create_test_model();
    // Default enabled: Join, Leave, NickChange
    assert!(
        model
            .config
            .enabled_system_messages
            .contains(&SystemMessageType::Join)
    );

    // Disable Join
    send_command(&mut model, "/set system_messages Join");
    assert!(
        !model
            .config
            .enabled_system_messages
            .contains(&SystemMessageType::Join)
    );

    // Enable Join
    send_command(&mut model, "/set system_messages Join");
    assert!(
        model
            .config
            .enabled_system_messages
            .contains(&SystemMessageType::Join)
    );
}

#[test]
fn test_set_invalid_key() {
    let mut model = create_test_model();
    send_command(&mut model, "/set nonexistent_key val");
    let last_msg = model.domain.console_messages.last().unwrap();
    assert_eq!(last_msg.msg_type, toxxi::model::ConsoleMessageType::Error);
    assert!(
        last_msg
            .content
            .as_text()
            .unwrap()
            .contains("Unknown setting")
    );
}
