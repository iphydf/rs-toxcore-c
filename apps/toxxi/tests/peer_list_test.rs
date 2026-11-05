use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{GroupNumber, UserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::model::PeerId;
use toxxi::ui::draw;
use toxxi_testing::create_test_model;

#[test]
fn test_peer_list_shows_when_empty() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::Normal,
        "System".to_string(),
        "Joined group".to_string(),
        None,
    );
    model.set_active_window(1);

    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let border_char = buffer[(55u16, 2u16)].symbol();
    assert_eq!(
        border_char, "│",
        "Peer list border should be visible at x=55"
    );

    // Our name is in the peer list (x > 55),
    // somewhere from y=1 (y=0 is the border).
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
        MessageType::Normal,
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
            status: UserStatus::None,
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
            status: UserStatus::Away,
            is_ignored: false,
            seen_online: true,
        });
        // Busy peer
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([2u8; 32])),
            name: "BusyPeer".to_string(),
            role: None,
            status: UserStatus::Busy,
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

    use toxcore::types::GroupRole;

    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        // Founder
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([11u8; 32])),
            name: "FounderPeer".to_string(),
            role: Some(GroupRole::Founder),
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
        // Ignored Moderator
        conv.peers.push(toxxi::model::PeerInfo {
            id: PeerId(PublicKey([12u8; 32])),
            name: "IgnoredMod".to_string(),
            role: Some(GroupRole::Moderator),
            status: UserStatus::None,
            is_ignored: true,
            seen_online: true,
        });
    }

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // The founder has a blue '&'.
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

    // The ignored moderator is crossed out, with a green '+'.
    let mut ignored_mod_found = false;
    for y in 1..10 {
        let row_str: String = (56..80)
            .map(|x| buffer[(x as u16, y as u16)].symbol())
            .collect();
        if row_str.contains("IgnoredMod") {
            let name_pos = row_str.find("IgnoredMod").unwrap();
            let name_cell = &buffer[((56 + name_pos) as u16, y as u16)];
            assert!(
                name_cell
                    .style()
                    .add_modifier
                    .contains(ratatui::style::Modifier::CROSSED_OUT),
                "Ignored user should have CROSSED_OUT modifier"
            );

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
    let pk = PublicKey([1u8; 32]);

    model.ensure_friend_window(pk);
    let window_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == toxxi::model::WindowId::Friend(pk))
        .unwrap();
    model.set_active_window(window_idx);

    // Ctrl+B doesn't do this in a friend's window, but we test the drawing here.
    let window_id = model.active_window_id();
    let state = model.ui.window_state.entry(window_id).or_default();
    state.show_peers = true;

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let border_char = buffer[(55u16, 2u16)].symbol();
    assert_ne!(
        border_char, "│",
        "Peer list border should NOT be visible for friend window"
    );

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
