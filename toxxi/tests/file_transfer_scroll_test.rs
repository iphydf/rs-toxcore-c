use ratatui::{Terminal, backend::TestBackend};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::{ChatId, MessageType, PublicKey, ToxGroupRole};
use toxxi::config::Config;
use toxxi::model::{
    Conversation, DomainState, InternalMessageId, Message, MessageContent, MessageStatus, Model,
    WindowId,
};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::time::FakeTimeProvider;
use toxxi::ui::draw;

fn setup_clipping_model(trailing_messages: usize) -> (Model, ChatId) {
    let config = Config::default();
    let self_pk = PublicKey([0u8; 32]);
    let domain = DomainState::new(
        Address::from_public_key(self_pk, 0),
        self_pk,
        "Tester".to_string(),
        "".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let fixed_system_time = UNIX_EPOCH + Duration::from_secs(1672574400);
    let fixed_instant = Instant::now();
    let tp = Arc::new(FakeTimeProvider::new(fixed_instant, fixed_system_time));

    let mut model = Model::new(domain, config.clone(), config).with_time_provider(tp);

    let group_id = ChatId([1u8; 32]);
    let window_id = WindowId::Group(group_id);

    let mut conversation = Conversation {
        name: "Test Group".to_string(),
        messages: Vec::new(),
        topic: None,
        peers: Vec::new(),
        self_role: Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
        self_name: Some("Tester".to_string()),
        ignored_peers: HashSet::new(),
    };

    let friend_pk = PublicKey([1u8; 32]);
    conversation.peers.push(toxxi::model::PeerInfo {
        id: toxxi::model::PeerId(friend_pk),
        name: "Alice".to_string(),
        role: Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
        status: ToxUserStatus::TOX_USER_STATUS_NONE,
        is_ignored: false,
        seen_online: true,
    });

    model.domain.conversations.insert(window_id, conversation);
    model.ui.window_ids = vec![WindowId::Console, window_id];
    model.ui.active_window_index = 1;

    // Initial messages (above FT)
    for i in 0..40 {
        model.add_group_message(
            group_id,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "Alice".to_string(),
            format!("Initial {:02}", i),
            Some(friend_pk),
        );
    }

    // File transfer
    let ft_msg = Message {
        internal_id: InternalMessageId(100),
        sender: "Alice".to_string(),
        sender_pk: Some(friend_pk),
        is_self: false,
        content: MessageContent::FileTransfer {
            file_id: None,
            name: "clipping_test.bin".to_string(),
            size: 1024 * 1024,
            progress: 0.5,
            speed: "100 KB/s".to_string(),
            is_incoming: true,
        },
        timestamp: model.time_provider.now_local(),
        status: MessageStatus::Incoming,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };
    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        conv.messages.push(ft_msg);
    }

    // Trailing messages (below FT)
    for i in 0..trailing_messages {
        model.add_group_message(
            group_id,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "Alice".to_string(),
            format!("Trailing {:02}", i),
            Some(friend_pk),
        );
    }

    (model, group_id)
}

fn run_test(mut model: Model, scroll: usize, snapshot_name: &str) {
    let window_id = model.active_window_id();
    let width = 120;
    let height = 20;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    let state = model.ui.window_state.entry(window_id).or_default();
    state.msg_list_state.scroll = scroll;

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn test_file_transfer_clip_top_1() {
    // Only Bottom and Middle visible, Top clipped
    let (model, _) = setup_clipping_model(20);
    run_test(model, 7, "file_transfer_clip_top_1");
}

#[test]
fn test_file_transfer_clip_top_2() {
    // Only Bottom visible, Middle and Top clipped
    let (model, _) = setup_clipping_model(20);
    run_test(model, 6, "file_transfer_clip_top_2");
}

#[test]
fn test_file_transfer_clip_bottom_1() {
    // Only Top and Middle visible, Bottom clipped
    let (model, _) = setup_clipping_model(20);
    run_test(model, 21, "file_transfer_clip_bottom_1");
}

#[test]
fn test_file_transfer_clip_bottom_2() {
    // Only Top visible, Middle and Bottom clipped
    let (model, _) = setup_clipping_model(20);
    run_test(model, 22, "file_transfer_clip_bottom_2");
}

#[test]
fn test_file_transfer_full_visible() {
    // Fully visible in the middle
    let (model, _) = setup_clipping_model(20);
    run_test(model, 10, "file_transfer_full_visible");
}

#[test]
fn test_game_card_full_visible() {
    let config = Config::default();
    let self_pk = PublicKey([0u8; 32]);
    let domain = DomainState::new(
        Address::from_public_key(self_pk, 0),
        self_pk,
        "Tester".to_string(),
        "".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let fixed_system_time = UNIX_EPOCH + Duration::from_secs(1672574400);
    let fixed_instant = Instant::now();
    let tp = Arc::new(FakeTimeProvider::new(fixed_instant, fixed_system_time));

    let mut model = Model::new(domain, config.clone(), config).with_time_provider(tp);

    let group_id = ChatId([1u8; 32]);
    let window_id = WindowId::Group(group_id);

    let conversation = Conversation {
        name: "Test Group".to_string(),
        messages: Vec::new(),
        topic: None,
        peers: Vec::new(),
        self_role: Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
        self_name: Some("Tester".to_string()),
        ignored_peers: HashSet::new(),
    };

    let friend_pk = PublicKey([1u8; 32]);
    model.domain.conversations.insert(window_id, conversation);
    model.ui.window_ids = vec![WindowId::Console, window_id];
    model.ui.active_window_index = 1;

    let game_msg = Message {
        internal_id: InternalMessageId(101),
        sender: "Alice".to_string(),
        sender_pk: Some(friend_pk),
        is_self: false,
        content: MessageContent::GameInvite {
            game_type: "Chess".to_string(),
            challenger: "Alice".to_string(),
        },
        timestamp: model.time_provider.now_local(),
        status: MessageStatus::Incoming,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };
    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        conv.messages.push(game_msg);
    }

    run_test(model, 0, "game_card_full_visible");
}
