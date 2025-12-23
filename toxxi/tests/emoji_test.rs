use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::completion::{complete_text, get_replacement};
use toxxi::config::Config;
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

#[test]
fn test_emoji_completion() {
    let model = create_test_model();

    // Test prefix completion
    let candidates = complete_text(":smil", &model);
    assert!(candidates.contains(&"😊".to_string()));
    assert!(candidates.contains(&"😃".to_string()));

    // Test replacement
    let replacement = get_replacement(":smile:", "😊");
    assert_eq!(replacement, "😊");

    // Test multiple words
    let candidates = complete_text("Hello :smil", &model);
    assert!(candidates.contains(&"😊".to_string()));

    let replacement = get_replacement("Hello :smile:", "😊");
    assert_eq!(replacement, "Hello 😊");
}

#[test]
fn test_emoji_exact_match() {
    let model = create_test_model();
    let candidates = complete_text(":smile:", &model);
    assert_eq!(candidates, vec!["😊".to_string()]);
}

#[test]
fn test_short_form_emoji() {
    let model = create_test_model();

    // Test :)
    let candidates = complete_text(":)", &model);
    assert!(candidates.contains(&"😊".to_string()));

    // Test ;)
    let candidates = complete_text(";)", &model);
    assert!(candidates.contains(&"😉".to_string()));
}

#[test]
fn test_emoji_grid_navigation() {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    let mut model = create_test_model();

    // Trigger emoji completion
    model.ui.input_state.set_value(":".to_string());
    model.ui.input_state.set_cursor(0, 1);
    let candidates = complete_text(":", &model);
    model.ui.completion.active = true;
    model.ui.completion.candidates = candidates;
    model.ui.completion.index = 0;

    let event = |code| {
        Msg::Input(crossterm::event::Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }))
    };

    // Move Right
    update(&mut model, event(KeyCode::Right));
    assert_eq!(model.ui.completion.index, 1);

    // Move Down (should be +10)
    update(&mut model, event(KeyCode::Down));
    assert_eq!(model.ui.completion.index, 11);

    // Move Left
    update(&mut model, event(KeyCode::Left));
    assert_eq!(model.ui.completion.index, 10);

    // Move Up
    update(&mut model, event(KeyCode::Up));
    assert_eq!(model.ui.completion.index, 0);
}

#[test]
fn test_emoji_prioritization() {
    let model = create_test_model();

    // Trigger completion with ":"
    let candidates = complete_text(":", &model);

    // Check that faces (early in the list) come before animals (later in the list)
    let index_smile = candidates.iter().position(|c| c == "😊").unwrap();
    let index_cat = candidates.iter().position(|c| c == "🐱").unwrap();

    assert!(
        index_smile < index_cat,
        "😊 should come before 🐱 in the completion list"
    );
}
