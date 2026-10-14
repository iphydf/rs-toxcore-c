use toxcore::tox::{FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{Address, PublicKey};
use toxxi::config::Config;
use toxxi::model::{FriendInfo, Model, ToxSelfInfo, WindowId, load_or_initialize, save_state};

fn start(config_dir: &std::path::Path, friends: &[PublicKey]) -> Model {
    let self_info = ToxSelfInfo {
        tox_id: Address([0u8; 38]),
        public_key: PublicKey([0u8; 32]),
        name: "Me".to_owned(),
        status_msg: String::new(),
        status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
    };
    let friends = friends
        .iter()
        .enumerate()
        .map(|(i, &pk)| {
            (
                FriendNumber(i as u32),
                FriendInfo {
                    name: format!("Friend {}", i),
                    public_key: Some(pk),
                    status_message: String::new(),
                    connection: ToxConnection::TOX_CONNECTION_NONE,
                    last_sent_message_id: None,
                    last_read_receipt: None,
                    is_typing: false,
                },
            )
        })
        .collect();
    load_or_initialize(
        config_dir,
        self_info,
        friends,
        vec![],
        vec![],
        Config::default(),
        Config::default(),
    )
}

#[test]
fn test_closed_friend_windows_stay_closed_after_restart() {
    let temp_dir = tempfile::tempdir().unwrap();
    let alice = PublicKey([1u8; 32]);
    let bob = PublicKey([2u8; 32]);

    let mut model = start(temp_dir.path(), &[alice, bob]);
    assert!(model.ui.window_ids.contains(&WindowId::Friend(alice)));
    assert!(model.ui.window_ids.contains(&WindowId::Friend(bob)));

    model.ui.window_ids.retain(|&w| w != WindowId::Friend(bob));
    save_state(temp_dir.path(), &model).unwrap();

    let model = start(temp_dir.path(), &[alice, bob]);
    assert!(model.ui.window_ids.contains(&WindowId::Friend(alice)));
    assert!(!model.ui.window_ids.contains(&WindowId::Friend(bob)));
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(bob))
    );
}
