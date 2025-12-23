use super::setup::TestHarness;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub fn subtest_send_message(harness: &mut TestHarness) {
    println!("Running subtest_send_message...");
    struct MsgHandler {
        received: Arc<AtomicBool>,
        receipt: Arc<Mutex<Option<MessageId>>>,
    }
    impl ToxHandler for MsgHandler {
        fn on_friend_message(&mut self, _: FriendNumber, _: MessageType, message: &[u8]) {
            if message == b"Hello World" {
                self.received.store(true, Ordering::SeqCst);
            }
        }
        fn on_friend_read_receipt(&mut self, _: FriendNumber, message_id: FriendMessageId) {
            *self.receipt.lock().unwrap() = Some(MessageId(message_id.0));
        }
    }

    let received = Arc::new(AtomicBool::new(false));
    let receipt = Arc::new(Mutex::new(None));
    let mut handler = MsgHandler {
        received: received.clone(),
        receipt: receipt.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    let sent_id = f0
        .send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, b"Hello World")
        .unwrap();

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    while Instant::now().duration_since(start) < timeout {
        harness.iterate(&mut handler);
        if received.load(Ordering::SeqCst) && receipt.lock().unwrap().is_some() {
            break;
        }
    }

    assert!(received.load(Ordering::SeqCst), "Message not received");
    let r_id = receipt.lock().unwrap().expect("Read receipt not received");
    assert_eq!(r_id.0, sent_id.0, "Read receipt ID mismatch");
}
