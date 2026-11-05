use toxcore::types::PublicKey;
use toxxi::model::{MAX_PENDING_ITEMS, PendingItem};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;
use toxxi_testing::create_test_model;

fn request(n: u32, message: &str) -> Msg {
    let mut key = [0; 32];
    key[..4].copy_from_slice(&n.to_be_bytes());
    Msg::Tox(ToxEvent::FriendRequest(PublicKey(key), message.to_owned()))
}

/// A stranger asking again replaces their request.
#[test]
fn a_key_has_one_request() {
    let mut model = create_test_model();
    update(&mut model, request(1, "hi"));
    update(&mut model, request(1, "hi again"));
    assert!(matches!(
        &model.domain.pending_items[..],
        [PendingItem::FriendRequest { message, .. }] if message == "hi again"
    ));
}

/// Strangers can send requests from as many keys as they like.
#[test]
fn requests_stop_at_the_limit() {
    let mut model = create_test_model();
    for n in 0..=MAX_PENDING_ITEMS as u32 {
        update(&mut model, request(n, "hi"));
    }
    assert_eq!(model.domain.pending_items.len(), MAX_PENDING_ITEMS);
}
