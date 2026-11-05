use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxxi::config::SystemMessageType;
use toxxi::model::Model;
use toxxi::msg::Msg;
use toxxi::update::update;
use toxxi_testing::create_test_model;

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
    // Join, Leave and NickChange are on by default.
    assert!(
        model
            .config
            .enabled_system_messages
            .contains(&SystemMessageType::Join)
    );

    // Hide joins.
    send_command(&mut model, "/set system_messages Join");
    assert!(
        !model
            .config
            .enabled_system_messages
            .contains(&SystemMessageType::Join)
    );

    // Show them again.
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
