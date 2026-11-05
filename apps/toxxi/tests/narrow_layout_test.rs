use ratatui::{Terminal, backend::TestBackend};
use std::collections::HashSet;
use toxcore::tox::{Address, UserStatus};
use toxcore::types::{GroupChatId, GroupRole, PublicKey};
use toxxi::config::Config;
use toxxi::model::{Conversation, DomainState, Model, PeerId, PeerInfo, WindowId};
use toxxi::ui::draw;
use toxxi_testing::buffer_to_string;

/// A model showing a group with Alice in it.
fn group_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address::from_public_key(PublicKey([0; 32]), 0),
        "Tester".to_owned(),
        String::new(),
        UserStatus::None,
    );
    let mut model = Model::new(domain, config.clone(), config);
    let window = WindowId::Group(GroupChatId([1; 32]));
    model.domain.conversations.insert(
        window,
        Conversation {
            name: "Test Group".to_owned(),
            messages: Vec::new(),
            topic: None,
            peers: vec![PeerInfo {
                id: PeerId(PublicKey([1; 32])),
                name: "Alice".to_owned(),
                role: Some(GroupRole::User),
                status: UserStatus::None,
                is_ignored: false,
                seen_online: true,
            }],
            self_role: Some(GroupRole::Founder),
            self_name: Some("Tester".to_owned()),
            ignored_peers: HashSet::new(),
        },
    );
    model.ui.window_ids = vec![WindowId::Console, window];
    model.ui.active_window_index = 1;
    model
}

/// Which of the chat list and the member list a `width` wide screen shows.
fn panes(width: u16) -> (bool, bool) {
    let mut model = group_model();
    let mut terminal = Terminal::new(TestBackend::new(width, 20)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let screen = buffer_to_string(terminal.backend().buffer());
    (screen.contains("Contacts"), screen.contains("Alice"))
}

#[test]
fn wide_screens_show_both_lists() {
    assert_eq!(panes(85), (true, true));
}

#[test]
fn the_member_list_goes_first_when_the_chat_would_get_narrow() {
    assert_eq!(panes(70), (true, false));
}

#[test]
fn phones_held_upright_show_only_the_chat() {
    assert_eq!(panes(50), (false, false));
}
