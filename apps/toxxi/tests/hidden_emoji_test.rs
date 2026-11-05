use crossterm::event::{KeyCode, KeyModifiers};
use toxxi::completion::complete_text;
use toxxi::model::Model;
use toxxi::msg::{Cmd, IOAction};
use toxxi_testing::{create_test_model, send_key};

fn picker() -> Model {
    let mut model = create_test_model();
    send_key(&mut model, KeyCode::Char('e'), KeyModifiers::CONTROL);
    model
}

fn shown(model: &Model) -> Vec<String> {
    let state = model.ui.emoji_picker.as_ref().unwrap();
    state.filtered_emojis(&model.config.hidden_emojis)
}

fn saved(cmds: &[Cmd]) -> bool {
    cmds.iter()
        .any(|cmd| matches!(cmd, Cmd::IO(IOAction::SaveConfig(config)) if config.hidden_emojis == ["😊"]))
}

/// An emoji the terminal draws badly can be hidden from the picker and from
/// completion, and put back from the Hidden tab.
#[test]
fn backspace_hides_an_emoji_and_the_hidden_tab_puts_it_back() {
    let mut model = picker();
    assert_eq!(shown(&model)[0], "😊");

    // It's shown on its own first, framed, to see whether it breaks the frame.
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    let state = model.ui.emoji_picker.as_ref().unwrap();
    assert_eq!(state.confirming.as_deref(), Some("😊"));
    assert!(model.config.hidden_emojis.is_empty());

    let cmds = send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    assert!(saved(&cmds), "{cmds:?}");
    assert!(!shown(&model).contains(&"😊".to_owned()));
    assert!(!complete_text(":)", &model).contains(&"😊".to_owned()));

    send_key(&mut model, KeyCode::Tab, KeyModifiers::empty());
    assert_eq!(shown(&model), ["😊"]);
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    assert!(model.config.hidden_emojis.is_empty());
    assert!(shown(&model).is_empty());

    send_key(&mut model, KeyCode::Tab, KeyModifiers::empty());
    assert_eq!(shown(&model)[0], "😊");
}

#[test]
fn backspace_in_a_search_edits_the_search() {
    let mut model = picker();
    for c in "heart".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());

    let state = model.ui.emoji_picker.as_ref().unwrap();
    assert_eq!(state.input_state.text, "hear");
    assert!(model.config.hidden_emojis.is_empty());
}

#[test]
fn escape_keeps_the_emoji_and_the_picker() {
    let mut model = picker();
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Esc, KeyModifiers::empty());

    let state = model.ui.emoji_picker.as_ref().expect("the picker closed");
    assert_eq!(state.confirming, None);
    assert!(model.config.hidden_emojis.is_empty());
}

/// What Backspace shows first: the emoji alone on a line of a frame.
#[test]
fn the_emoji_to_hide_is_shown_framed() {
    use ratatui::{Terminal, backend::TestBackend};
    use toxxi_testing::{buffer_to_string, configure_insta};

    let clock =
        toxxi::time::FakeTimeProvider::new(std::time::Instant::now(), std::time::UNIX_EPOCH);
    let mut model = create_test_model().with_time_provider(std::sync::Arc::new(clock));
    send_key(&mut model, KeyCode::Char('e'), KeyModifiers::CONTROL);
    send_key(&mut model, KeyCode::Right, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Right, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());

    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| toxxi::ui::draw(f, &mut model)).unwrap();
    let screen = buffer_to_string(terminal.backend().buffer());
    configure_insta().bind(|| insta::assert_snapshot!("confirm_hide", screen));
}

fn hidden(model: &Model, emoji: &str) -> bool {
    model.config.hidden_emojis.iter().any(|e| e == emoji)
}

/// The groups some terminals draw badly can be hidden at once, and shown again
/// without showing what was hidden on its own.
#[test]
fn emoji_groups_hide_and_show_at_once() {
    let mut model = create_test_model();
    model.config.hidden_emojis.push("😊".to_owned());

    let cmds = toxxi::update::handle_enter(&mut model, "/emoji hide symbols");
    assert!(
        cmds.iter()
            .any(|cmd| matches!(cmd, Cmd::IO(IOAction::SaveConfig(_))))
    );
    for emoji in ["❤️", "☺️", "✌️", "1️⃣", "❤️‍🩹"] {
        assert!(hidden(&model, emoji), "{emoji}");
    }
    // Wide without the selector, or a real emoji first: they're drawn right.
    for emoji in ["㊙️", "🙅‍♂️", "🇩🇪", "🫪"] {
        assert!(!hidden(&model, emoji), "{emoji}");
    }

    toxxi::update::handle_enter(&mut model, "/emoji hide flags");
    toxxi::update::handle_enter(&mut model, "/emoji hide newest");
    for emoji in ["🇩🇪", "🏴󠁧󠁢󠁥󠁮󠁧󠁿", "🫪"] {
        assert!(hidden(&model, emoji), "{emoji}");
    }

    toxxi::update::handle_enter(&mut model, "/emoji show symbols");
    assert!(!hidden(&model, "❤️"));
    assert!(hidden(&model, "😊"));
    assert!(hidden(&model, "🇩🇪"));
}
