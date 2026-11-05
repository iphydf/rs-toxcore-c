use toxcore::tox::{GroupNumber, GroupRole, UserStatus};
use toxcore::types::{GroupChatId, PublicKey};
use toxxi::model::{Conversation, PeerId, PeerInfo, WindowId};
use toxxi_testing::TestContext;

#[test]
fn test_reboot_persistence_peers_offline() {
    let ctx = TestContext::new();
    let chat_id = GroupChatId([1u8; 32]);
    let _group_number = GroupNumber(1);
    let peer_pk = PublicKey([2u8; 32]);
    let peer_id = PeerId(peer_pk);

    // A peer that was online in the last session.
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
        role: Some(GroupRole::User),
        status: UserStatus::None,
        is_ignored: false,
        seen_online: true,
    });

    let mut model = ctx.create_model();
    model
        .domain
        .conversations
        .insert(WindowId::Group(chat_id), conversation);
    model.ui.window_ids.push(WindowId::Group(chat_id));

    toxxi::model::save_state(&ctx.config_dir, &model).expect("Failed to save state");

    // Restart: load the state into a new model, before Tox has told us anything.
    let new_model = toxxi::model::load_or_initialize(
        &ctx.config_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: model.domain.tox_id,
            name: model.domain.self_name.clone(),
            status_msg: model.domain.self_status_message.clone(),
            status_type: model.domain.self_status_type,
        },
        vec![],
        vec![],
        vec![],
        model.saved_config.clone(),
        model.config.clone(),
    );

    // The peer is there, but not seen online.
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
