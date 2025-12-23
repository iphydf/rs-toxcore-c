use toxcore::tox::{GroupNumber, ToxGroupRole, ToxUserStatus};
use toxcore::types::{ChatId, PublicKey};
use toxxi::model::{Conversation, PeerId, PeerInfo, WindowId};
use toxxi::testing::TestContext;

#[test]
fn test_reboot_persistence_peers_offline() {
    let ctx = TestContext::new();
    let chat_id = ChatId([1u8; 32]);
    let _group_number = GroupNumber(1);
    let peer_pk = PublicKey([2u8; 32]);
    let peer_id = PeerId(peer_pk);

    // 1. Simulate a previous session state where a peer was online
    let mut conversation = Conversation {
        name: "Test Group".to_string(),
        messages: Vec::new(),
        topic: None,
        peers: Vec::new(),
        self_role: None,
        self_name: None,
        ignored_peers: std::collections::HashSet::new(),
    };

    conversation.peers.push(PeerInfo {
        id: peer_id,
        name: "Alice".to_string(),
        role: Some(ToxGroupRole::TOX_GROUP_ROLE_USER),
        status: ToxUserStatus::TOX_USER_STATUS_NONE,
        is_ignored: false,
        seen_online: true, // They were online last time
    });

    // Save this state to disk
    let mut model = ctx.create_model();
    model
        .domain
        .conversations
        .insert(WindowId::Group(chat_id), conversation);
    model.ui.window_ids.push(WindowId::Group(chat_id)); // Ensure it's in the window list

    toxxi::model::save_state(&ctx.config_dir, &model).expect("Failed to save state");

    // 2. Simulate a "Reboot" (Load state into a NEW model)
    // We pass empty reconcile lists as if we just connected and haven't fetched anything yet
    let new_model = toxxi::model::load_or_initialize(
        &ctx.config_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: model.domain.tox_id,
            public_key: model.domain.self_public_key,
            name: model.domain.self_name.clone(),
            status_msg: model.domain.self_status_message.clone(),
            status_type: model.domain.self_status_type,
        },
        vec![], // No friends reconciled yet
        vec![], // No groups reconciled yet
        vec![],
        model.saved_config.clone(),
        model.config.clone(),
    );

    // 3. Verify the peer exists but is marked as NOT seen_online
    let new_conv = new_model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .expect("Conversation should persist");

    let peer = new_conv
        .peers
        .iter()
        .find(|p| p.id == peer_id)
        .expect("Peer should persist in list");

    assert_eq!(peer.name, "Alice");
    assert!(
        !peer.seen_online,
        "Peer should be marked offline (gray) after reboot until they re-announce"
    );
}
