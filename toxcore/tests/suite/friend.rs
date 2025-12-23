use super::setup::TestHarness;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub fn subtest_friend_info(harness: &mut TestHarness) {
    println!("Running subtest_friend_info...");
    struct InfoHandler {
        typing: Arc<AtomicBool>,
        status: Arc<Mutex<Option<ToxUserStatus>>>,
        status_msg: Arc<Mutex<Option<Vec<u8>>>>,
    }
    impl ToxHandler for InfoHandler {
        fn on_friend_typing(&mut self, _: FriendNumber, is_typing: bool) {
            if is_typing {
                self.typing.store(true, Ordering::SeqCst);
            }
        }
        fn on_friend_status(&mut self, _: FriendNumber, status: ToxUserStatus) {
            *self.status.lock().unwrap() = Some(status);
        }
        fn on_friend_status_message(&mut self, _: FriendNumber, message: &[u8]) {
            *self.status_msg.lock().unwrap() = Some(message.to_vec());
        }
    }

    let typing = Arc::new(AtomicBool::new(false));
    let status = Arc::new(Mutex::new(None));
    let status_msg = Arc::new(Mutex::new(None));
    let mut handler = InfoHandler {
        typing: typing.clone(),
        status: status.clone(),
        status_msg: status_msg.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    // Test Typing
    f0.set_typing(true).unwrap();
    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        if typing.load(Ordering::SeqCst) {
            break;
        }
    }
    assert!(typing.load(Ordering::SeqCst), "Typing status not received");

    // Test Status
    harness.toxes[0]
        .tox
        .set_status(ToxUserStatus::TOX_USER_STATUS_BUSY);
    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        if *status.lock().unwrap() == Some(ToxUserStatus::TOX_USER_STATUS_BUSY) {
            break;
        }
    }
    assert_eq!(
        *status.lock().unwrap(),
        Some(ToxUserStatus::TOX_USER_STATUS_BUSY),
        "Status change not received"
    );

    // Test Status Message
    harness.toxes[0]
        .tox
        .set_status_message(b"Busy coding")
        .unwrap();
    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        if *status_msg.lock().unwrap() == Some(b"Busy coding".to_vec()) {
            break;
        }
    }
    assert_eq!(
        *status_msg.lock().unwrap(),
        Some(b"Busy coding".to_vec()),
        "Status message not received"
    );
}
