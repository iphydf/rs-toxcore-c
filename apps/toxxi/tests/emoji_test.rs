use toxxi::completion::{complete_text, get_replacement};
use toxxi::msg::Msg;
use toxxi::update::update;
use toxxi_testing::create_test_model;

#[test]
fn test_emoji_completion() {
    let model = create_test_model();

    // Prefix completion.
    let candidates = complete_text(":smil", &model);
    assert!(candidates.contains(&"😊".to_string()));
    assert!(candidates.contains(&"😃".to_string()));

    // Replacement.
    let replacement = get_replacement(":smile:", "😊");
    assert_eq!(replacement, "😊");

    // Several words.
    let candidates = complete_text("Hello :smil", &model);
    assert!(candidates.contains(&"😊".to_string()));

    let replacement = get_replacement("Hello :smile:", "😊");
    assert_eq!(replacement, "Hello 😊");
}

#[test]
fn test_emoji_exact_match() {
    let model = create_test_model();
    let candidates = complete_text(":smile:", &model);
    assert_eq!(candidates, vec!["😊".to_string(), "😀".to_string()]);
}

#[test]
fn test_short_form_emoji() {
    let model = create_test_model();

    let candidates = complete_text(":)", &model);
    assert!(candidates.contains(&"😊".to_string()));

    let candidates = complete_text(";)", &model);
    assert!(candidates.contains(&"😉".to_string()));
}

#[test]
fn test_emoji_grid_navigation() {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    let mut model = create_test_model();

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

    update(&mut model, event(KeyCode::Right));
    assert_eq!(model.ui.completion.index, 1);

    // Down moves 10.
    update(&mut model, event(KeyCode::Down));
    assert_eq!(model.ui.completion.index, 11);

    update(&mut model, event(KeyCode::Left));
    assert_eq!(model.ui.completion.index, 10);

    update(&mut model, event(KeyCode::Up));
    assert_eq!(model.ui.completion.index, 0);
}

#[test]
fn test_emoji_prioritization() {
    let model = create_test_model();

    let candidates = complete_text(":", &model);

    // Faces (early in the table) come before animals (later).
    let index_smile = candidates.iter().position(|c| c == "😊").unwrap();
    let index_cat = candidates.iter().position(|c| c == "🐱").unwrap();

    assert!(
        index_smile < index_cat,
        "😊 should come before 🐱 in the completion list"
    );
}

/// A smiley's shorthand offers the faces it may mean first, the usual one
/// first of all. `:D` is also how `:dog:` starts.
#[test]
fn a_smiley_offers_its_faces() {
    let model = toxxi_testing::create_test_model();
    for (typed, faces) in [
        (":)", &["😊", "🙂", "☺️"][..]),
        (":-)", &["😊", "🙂", "☺️"]),
        (":(", &["😞", "🙁", "☹️"]),
        (":-(", &["😞", "🙁", "☹️"]),
        (":D", &["😃", "😄", "😁"]),
        (":P", &["😛", "😜", "😝"]),
    ] {
        let offered = toxxi::completion::complete_text(typed, &model);
        assert_eq!(&offered[..faces.len()], faces, "{typed}");
    }
}
