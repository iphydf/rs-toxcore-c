use toxcore::tox::ToxUserStatus;
use toxcore::types::{Address, ChatId, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "iphy".to_string(),
        "I am iphy".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_should_highlight() {
    let mut model = create_test_model();
    let window_id = WindowId::Console;

    // Direct match
    assert!(model.should_highlight(window_id, "hello iphy"));
    assert!(model.should_highlight(window_id, "iphy: hello"));
    assert!(model.should_highlight(window_id, "hello @iphy"));
    assert!(model.should_highlight(window_id, "iphy's cat"));

    // Case insensitive
    assert!(model.should_highlight(window_id, "HELLO IPHY"));

    // Negative matches
    assert!(!model.should_highlight(window_id, "hello giphy"));
    assert!(!model.should_highlight(window_id, "hello iphyria"));

    // Additional highlight strings
    model.config.highlight_strings.push("rust".to_string());
    assert!(model.should_highlight(window_id, "rust is cool"));
    assert!(!model.should_highlight(window_id, "trust me"));

    // Group specific nick
    let chat_id = ChatId([1u8; 32]);
    model.ensure_group_window(chat_id);
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.self_name = Some("iph".to_string());
    }
    assert!(model.should_highlight(WindowId::Group(chat_id), "hello iph"));
    assert!(model.should_highlight(WindowId::Group(chat_id), "hello iphy")); // still highlights global nick
}
