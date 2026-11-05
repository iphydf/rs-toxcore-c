use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::PublicKey;
use toxxi::model::{Model, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

/// Friends whose keys sort the other way round from their names.
fn friends() -> Model {
    let mut model = create_test_model();
    for (key, name) in [(1, "Zed"), (2, "bob"), (3, "Alice")] {
        let pk = PublicKey([key; 32]);
        add_test_friend(&mut model, pk);
        update(
            &mut model,
            Msg::Tox(ToxEvent::FriendName(pk, name.to_owned())),
        );
    }
    model
}

fn friend_names(windows: impl Iterator<Item = (Option<WindowId>, String)>) -> Vec<String> {
    windows
        .filter(|(window, _)| matches!(window, Some(WindowId::Friend(_))))
        .map(|(_, name)| name)
        .collect()
}

#[test]
fn the_sidebar_lists_friends_by_name() {
    let mut model = friends();
    let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let items = model.ui.sidebar_cache.clone().unwrap();
    assert_eq!(
        friend_names(items.into_iter().map(|item| (item.window, item.name))),
        ["Alice", "bob", "Zed"]
    );
}

#[test]
fn the_quick_switcher_lists_friends_by_name() {
    let mut model = friends();
    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);

    let items = model.ui.quick_switcher.as_ref().unwrap().items.clone();
    assert_eq!(
        friend_names(items.into_iter().map(|item| (Some(item.window), item.name))),
        ["Alice", "bob", "Zed"]
    );
}

#[test]
fn groups_and_conferences_are_listed_by_name() {
    use toxcore::types::{ConferenceId, GroupChatId};
    let mut model = create_test_model();
    for (key, name) in [(1, "zoo"), (2, "Bar"), (3, "art")] {
        for window in [
            WindowId::Group(GroupChatId([key; 32])),
            WindowId::Conference(ConferenceId([key; 32])),
        ] {
            model.ensure_window(window);
            model.domain.conversations.get_mut(&window).unwrap().name = name.to_owned();
        }
    }
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let sidebar: Vec<_> = model
        .ui
        .sidebar_cache
        .clone()
        .unwrap()
        .into_iter()
        .filter(|item| {
            matches!(
                item.window,
                Some(WindowId::Group(_) | WindowId::Conference(_))
            )
        })
        .map(|item| item.name)
        .collect();
    assert_eq!(sidebar, ["art", "Bar", "zoo", "art", "Bar", "zoo"]);

    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);
    let switcher: Vec<_> = model
        .ui
        .quick_switcher
        .as_ref()
        .unwrap()
        .items
        .iter()
        .filter(|item| item.prefix != ">")
        .map(|item| format!("{}{}", item.prefix, item.name))
        .collect();
    assert_eq!(switcher, ["gart", "gBar", "gzoo", "cart", "cBar", "czoo"]);
}
