use toxcore::types::PublicKey;
use toxxi::model::{WindowId, save_state};
use toxxi_testing::start;

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
