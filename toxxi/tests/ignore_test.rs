use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{Address, GroupNumber, GroupPeerNumber, ToxUserStatus};
use toxcore::types::{GroupChatId, PublicKey, ToxGroupRole};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId, WindowId};
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

fn add_test_group(model: &mut Model, gnum: GroupNumber, chat_id: GroupChatId) {
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
}

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
fn test_ignore_unignore_flow() {
    let mut model = create_test_model();
    let group_num = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    let peer_pk = PublicKey([5u8; 32]);
    let peer_id = PeerId(peer_pk);

    // 1. Setup Group with a peer
    add_test_group(&mut model, group_num, chat_id);
    // Populate session mapping for peer
    model
        .session
        .group_peer_numbers
        .insert((group_num, GroupPeerNumber(1)), peer_pk);

    let win_id = WindowId::Group(chat_id);

    if let Some(conv) = model.domain.conversations.get_mut(&win_id) {
        conv.peers.push(toxxi::model::PeerInfo {
            id: peer_id,
            name: "AnnoyingUser".to_string(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    // Switch to group window
    model.set_active_window(1); // 0 is Console, 1 is Group 1

    // 2. Ignore the user
    send_command(&mut model, "/ignore AnnoyingUser");

    // Verify
    let conv = model.domain.conversations.get(&win_id).unwrap();
    let peer = conv
        .peers
        .iter()
        .find(|p| p.name == "AnnoyingUser")
        .unwrap();

    assert!(peer.is_ignored, "Peer should be marked as ignored");
    assert!(
        conv.ignored_peers.contains(&peer_pk),
        "Peer PK should be in ignored_peers set"
    );

    // Check conversation output (system message)
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.sender, "System");
    assert!(
        last_msg
            .content
            .as_text()
            .unwrap()
            .contains("Now ignoring AnnoyingUser")
    );

    // 3. Unignore the user
    send_command(&mut model, "/unignore AnnoyingUser");

    // Verify
    let conv = model.domain.conversations.get(&win_id).unwrap();
    let peer = conv
        .peers
        .iter()
        .find(|p| p.name == "AnnoyingUser")
        .unwrap();

    assert!(!peer.is_ignored, "Peer should NOT be marked as ignored");
    assert!(
        !conv.ignored_peers.contains(&peer_pk),
        "Peer PK should NOT be in ignored_peers set"
    );

    // Check conversation output
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.sender, "System");
    assert!(
        last_msg
            .content
            .as_text()
            .unwrap()
            .contains("Stopped ignoring AnnoyingUser")
    );
}

#[test]
fn test_ignore_by_peer_id() {
    let mut model = create_test_model();
    let group_num = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    let peer_pk = PublicKey([5u8; 32]);
    let peer_num = GroupPeerNumber(10);
    let peer_id = PeerId(peer_pk);

    add_test_group(&mut model, group_num, chat_id);
    model
        .session
        .group_peer_numbers
        .insert((group_num, peer_num), peer_pk);
    let win_id = WindowId::Group(chat_id);

    if let Some(conv) = model.domain.conversations.get_mut(&win_id) {
        conv.peers.push(toxxi::model::PeerInfo {
            id: peer_id,
            name: "SomeUser".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    model.set_active_window(1);

    // Ignore by PK Hex
    let pk_hex = toxxi::utils::encode_hex(&peer_pk.0);
    send_command(&mut model, &format!("/ignore {}", pk_hex));

    let conv = model.domain.conversations.get(&win_id).unwrap();
    let peer = conv.peers.iter().find(|p| p.name == "SomeUser").unwrap();
    assert!(peer.is_ignored);
    assert!(conv.ignored_peers.contains(&peer_pk));
}

#[test]
fn test_ignore_not_found() {
    let mut model = create_test_model();
    let group_num = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1);
    let win_id = WindowId::Group(chat_id);

    send_command(&mut model, "/ignore Ghost");

    let conv = model.domain.conversations.get(&win_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.sender, "System");
    assert!(
        last_msg
            .content
            .as_text()
            .unwrap()
            .contains("Peer not found")
    );
}
