use super::setup::TestHarness;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub fn subtest_conference(harness: &mut TestHarness) {
    println!("Running subtest_conference...");

    type ConfInvite = (FriendNumber, ToxConferenceType, Vec<u8>);

    struct ConfHandler {
        invites: Arc<Mutex<Vec<ConfInvite>>>,
        messages: Arc<Mutex<Vec<Vec<u8>>>>,
        title_changed: Arc<Mutex<Option<Vec<u8>>>>,
        peer_list_changed: Arc<AtomicBool>,
    }
    impl ToxHandler for ConfHandler {
        fn on_conference_invite(
            &mut self,
            friend: FriendNumber,
            c_type: ToxConferenceType,
            cookie: &[u8],
        ) {
            self.invites
                .lock()
                .unwrap()
                .push((friend, c_type, cookie.to_vec()));
        }
        fn on_conference_message(
            &mut self,
            _conference: ConferenceNumber,
            _peer: ConferencePeerNumber,
            _type: MessageType,
            message: &[u8],
        ) {
            self.messages.lock().unwrap().push(message.to_vec());
        }
        fn on_conference_title(
            &mut self,
            _conference: ConferenceNumber,
            _peer: ConferencePeerNumber,
            title: &[u8],
        ) {
            *self.title_changed.lock().unwrap() = Some(title.to_vec());
        }
        fn on_conference_peer_list_changed(&mut self, _conference: ConferenceNumber) {
            self.peer_list_changed.store(true, Ordering::SeqCst);
        }
    }

    let invites = Arc::new(Mutex::new(Vec::new()));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let title_changed = Arc::new(Mutex::new(None));
    let peer_list_changed = Arc::new(AtomicBool::new(false));

    let mut handler = ConfHandler {
        invites: invites.clone(),
        messages: messages.clone(),
        title_changed: title_changed.clone(),
        peer_list_changed: peer_list_changed.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    // 1. Alice creates conference
    let c0 = harness.toxes[0].tox.conference_new().unwrap();
    c0.invite(&f0).unwrap();

    // 2. Wait for Bob invite
    let start = Instant::now();
    let mut bob_cookie: Option<Vec<u8>> = None;
    let mut bob_friend: Option<FriendNumber> = None;

    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        let mut inv = invites.lock().unwrap();
        if !inv.is_empty() {
            let (f, _, cookie) = inv.remove(0);
            bob_friend = Some(f);
            bob_cookie = Some(cookie);
            break;
        }
    }
    let bob_friend = bob_friend.expect("Bob did not receive conference invite");
    let bob_cookie = bob_cookie.expect("No cookie");

    // 3. Bob joins
    let bob_friend_obj = harness.toxes[1].tox.friend(bob_friend);
    let c1 = harness.toxes[1]
        .tox
        .conference_join(&bob_friend_obj, &bob_cookie)
        .unwrap();

    // 4. Wait for connection (approximate by sending messages until received)
    // There is on_conference_peer_list_changed but simplest is just to try sending
    let start = Instant::now();
    let mut received_msg = false;

    while Instant::now().duration_since(start) < Duration::from_secs(10) {
        harness.iterate(&mut handler);

        // Alice sends message periodically
        let _ = c0.send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, b"ConfHello");

        let msgs = messages.lock().unwrap();
        if msgs.iter().any(|m| m == b"ConfHello") {
            received_msg = true;
            break;
        }
        drop(msgs); // unlock
    }

    assert!(received_msg, "Conference message not received");

    // Verify peer list changed event occurred during join
    assert!(
        peer_list_changed.load(Ordering::SeqCst),
        "Peer list changed event not received"
    );

    // 5. Test Title Change
    println!("Testing conference title...");
    let new_title = b"Rust Conference";
    c0.set_title(new_title).unwrap();

    let start = Instant::now();
    let mut title_received = false;
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        if *title_changed.lock().unwrap() == Some(new_title.to_vec()) {
            title_received = true;
            break;
        }
    }
    assert!(title_received, "Conference title update not received");

    // Cleanup
    c0.delete().unwrap();
    c1.delete().unwrap();
}
