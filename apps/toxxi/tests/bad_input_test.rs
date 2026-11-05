use toxxi::model::{ConsoleMessageType, Model};
use toxxi::update::handle_command;
use toxxi_testing::create_test_model;

// Each bad argument reports an error, so the user sees why nothing happened.
fn last_is_error(model: &Model) -> bool {
    model
        .domain
        .console_messages
        .last()
        .is_some_and(|m| m.msg_type == ConsoleMessageType::Error)
}

#[test]
fn test_non_numeric_ids_report_errors() {
    for cmd in ["/query abc", "/whois abc", "/win abc"] {
        let mut model = create_test_model();
        let before = model.domain.console_messages.len();
        handle_command(&mut model, cmd);
        assert!(
            model.domain.console_messages.len() > before && last_is_error(&model),
            "{cmd} should report an error"
        );
    }
}

#[test]
fn test_clear_with_unknown_argument_reports_error() {
    let mut model = create_test_model();
    handle_command(&mut model, "/clear nonsense");
    assert!(
        last_is_error(&model),
        "/clear nonsense should report an error"
    );
}
