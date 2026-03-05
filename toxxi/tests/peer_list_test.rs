use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, GroupNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId};
use toxxi::ui::draw;

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
fn test_peer_list_shows_when_empty() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    // Create a group window
    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "Joined group".to_string(),
        None,
    );
    model.set_active_window(1);

    // Enable peer list
    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Check for the border at x=55
    let border_char = buffer[(55u16, 2u16)].symbol();
    assert_eq!(
        border_char, "│",
        "Peer list border should be visible at x=55"
    );

    // Check that self_name "Tester" is in the peer list (x > 55)
    // InfoPane list starts at y=1 (y=0 is border). Scan a range for the name.
    let mut found_tester = false;
    for y in 1..10 {
        let row: String = (56..80)
            .map(|x| buffer[(x as u16, y as u16)].symbol())
            .collect();
        if row.contains("Tester") {
            found_tester = true;
            break;
        }
    }
    assert!(found_tester, "Peer list should contain self name 'Tester'");
}

#[test]
fn test_peer_list_namesake_distinction() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "Joined group".to_string(),
        None,
    );
    model.set_active_window(1);

    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Tester".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let mut found_styles = Vec::new();

    for y in 1..10 {
        let row_str: String = (56..80).map(|x| buffer[(x, y)].symbol()).collect();
        if let Some(idx) = row_str.find("Tester") {
            let t_x = 56 + idx as u16;
            let style = buffer[(t_x, y)].style();
            found_styles.push(format!(
                "Row {}: FG={:?} Mod={:?}",
                y, style.fg, style.add_modifier
            ));
        }
    }

    assert_eq!(
        found_styles.len(),
        2,
        "Should have found 2 Testers. Found: {:?}",
        found_styles
    );
}

#[test]
fn test_peer_list_status_colors() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    model.ensure_group_window(chat_id);
    model.set_active_window(1);

    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        // Away peer
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "AwayPeer".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_AWAY,
            is_ignored: false,
            seen_online: true,
        });
        // Busy peer
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([2u8; 32])),
            name: "BusyPeer".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_BUSY,
            is_ignored: false,
            seen_online: true,
        });
    }

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let find_peer_color = |name_start: &str| {
        for y in 1..20 {
            let mut row_str = String::new();
            for x in 56..80 {
                row_str.push_str(buffer[(x as u16, y as u16)].symbol());
            }
            if let Some(pos) = row_str.find(name_start) {
                return Some(buffer[((56 + pos) as u16, y as u16)].style().fg);
            }
        }
        None
    };

    assert_eq!(
        find_peer_color("AwayPeer"),
        Some(Some(ratatui::style::Color::Yellow))
    );
    assert_eq!(
        find_peer_color("BusyPeer"),
        Some(Some(ratatui::style::Color::Red))
    );
    assert_eq!(
        find_peer_color("Tester"),
        Some(Some(ratatui::style::Color::White))
    );
}

#[test]
fn test_peer_list_roles_and_ignore() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    model.ensure_group_window(chat_id);
    model.set_active_window(1);

    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    use toxcore::types::ToxGroupRole;

    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        // Founder
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([11u8; 32])),
            name: "FounderPeer".to_string(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
        // Ignored Moderator
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([12u8; 32])),
            name: "IgnoredMod".to_string(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: true,
            seen_online: true,
        });
    }

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Find FounderPeer and check for '&' in Blue
    let mut founder_found = false;
    for y in 1..10 {
        let row_str: String = (56..80)
            .map(|x| buffer[(x as u16, y as u16)].symbol())
            .collect();
        if row_str.contains("FounderPeer") {
            let sig_pos = row_str.find('&').unwrap();
            assert_eq!(
                buffer[((56 + sig_pos) as u16, y as u16)].style().fg,
                Some(ratatui::style::Color::Blue)
            );
            founder_found = true;
        }
    }
    assert!(founder_found);

    // Find IgnoredMod and check for CROSSED_OUT modifier and '+' in Green
    let mut ignored_mod_found = false;
    for y in 1..10 {
        let row_str: String = (56..80)
            .map(|x| buffer[(x as u16, y as u16)].symbol())
            .collect();
        if row_str.contains("IgnoredMod") {
            // Check Name style for CROSSED_OUT
            let name_pos = row_str.find("IgnoredMod").unwrap();
            let name_cell = &buffer[((56 + name_pos) as u16, y as u16)];
            assert!(
                name_cell
                    .style()
                    .add_modifier
                    .contains(ratatui::style::Modifier::CROSSED_OUT),
                "Ignored user should have CROSSED_OUT modifier"
            );

            // Check Role '+'
            let plus_pos = row_str.find('+').unwrap();
            assert_eq!(
                buffer[((56 + plus_pos) as u16, y as u16)].style().fg,
                Some(ratatui::style::Color::Green)
            );
            ignored_mod_found = true;
        }
    }
    assert!(ignored_mod_found);
}

#[test]
fn test_peer_list_not_shown_in_friend_window() {
    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(0);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);

    // Create a friend window
    model.ensure_friend_window(pk);
    // Find the window index for the friend
    let window_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == toxxi::model::WindowId::Friend(pk))
        .unwrap();
    model.set_active_window(window_idx);

    // Try to enable peer list (even though Ctrl-b should prevent it, we test the UI layer here)
    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Check that there is NO border at x=55
    let border_char = buffer[(55u16, 2u16)].symbol();
    assert_ne!(
        border_char, "│",
        "Peer list border should NOT be visible for friend window"
    );

    // Check that self_name "Tester" is NOT in the peer list area (x > 55)
    let mut found_tester = false;
    for y in 1..10 {
        let row: String = (56..80)
            .map(|x| buffer[(x as u16, y as u16)].symbol())
            .collect();
        if row.contains("Tester") {
            found_tester = true;
            break;
        }
    }
    assert!(
        !found_tester,
        "Peer list should NOT contain self name 'Tester' for friend window"
    );
}

// end of tests
