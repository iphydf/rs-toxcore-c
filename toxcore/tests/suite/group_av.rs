use super::setup::TestHarness;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;
use toxcore::toxav::*;

pub fn subtest_group_av(harness: &mut TestHarness) {
    println!("Running subtest_group_av (Conference)...");

    struct ConfAvHandler {
        received_audio: Arc<Mutex<bool>>,
    }
    impl ToxAVConferenceHandler for ConfAvHandler {
        fn on_conference_audio_receive_frame(
            &self,
            _conference: ConferenceNumber,
            _peer: u32,
            _pcm: &[i16],
            _channels: u8,
            _sample_rate: u32,
        ) {
            *self.received_audio.lock().unwrap() = true;
        }
    }

    type ConfInvite = (FriendNumber, Vec<u8>);

    struct InviteHandler {
        invites: Arc<Mutex<Vec<ConfInvite>>>,
    }
    impl ToxHandler for InviteHandler {
        fn on_conference_invite(
            &mut self,
            friend: FriendNumber,
            _type: ToxConferenceType,
            cookie: &[u8],
        ) {
            self.invites.lock().unwrap().push((friend, cookie.to_vec()));
        }
    }

    let invites = Arc::new(Mutex::new(Vec::new()));
    let mut invite_handler = InviteHandler {
        invites: invites.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    // 2. Enable AV (Create AV Conference using legacy API)
    // Initialize ToxAV for both (required for audio backend)
    struct DummyHandler;
    impl ToxAVHandler for DummyHandler {}
    let _av0 = ToxAV::new(&harness.toxes[0].tox, DummyHandler).unwrap();
    let _av1 = ToxAV::new(&harness.toxes[1].tox, DummyHandler).unwrap();

    let received_audio_bob = Arc::new(Mutex::new(false));
    let av_handler_bob = ConfAvHandler {
        received_audio: received_audio_bob.clone(),
    };

    let received_audio_alice = Arc::new(Mutex::new(false));
    let av_handler_alice = ConfAvHandler {
        received_audio: received_audio_alice.clone(),
    };

    // Alice creates AV groupchat
    let (c0, _scope_alice) = harness.toxes[0]
        .tox
        .add_av_groupchat(&av_handler_alice)
        .expect("Failed to add AV groupchat for Alice");

    // Invite Bob
    c0.invite(&f0).unwrap();

    // Wait for invite
    let start = Instant::now();
    let mut bob_cookie = None;
    let mut bob_friend = None;
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut invite_handler);
        let mut inv = invites.lock().unwrap();
        if !inv.is_empty() {
            let (f, cookie) = inv.remove(0);
            bob_friend = Some(f);
            bob_cookie = Some(cookie);
            break;
        }
    }
    let bob_friend = bob_friend.expect("Bob did not receive conference invite");
    let bob_cookie = bob_cookie.expect("No invite cookie");

    // Bob joins AV groupchat
    let bob_friend_obj = harness.toxes[1].tox.friend(bob_friend);
    let (c1, _scope_bob) = harness.toxes[1]
        .tox
        .join_av_groupchat(&bob_friend_obj, &bob_cookie, &av_handler_bob)
        .expect("Failed to join AV groupchat for Bob");

    assert!(c0.av_enabled());
    assert!(c1.av_enabled());

    // 3. Send Audio
    // Wait for peers to connect in the conference (check peer count > 0 for both?)
    let start = Instant::now();
    let mut connected = false;
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut invite_handler);
        let count0 = c0.peer_count().unwrap_or(0);
        let count1 = c1.peer_count().unwrap_or(0);
        if count0 >= 1 && count1 >= 1 {
            connected = true;
            break;
        }
    }
    assert!(connected, "Peers did not connect in conference");

    let pcm = vec![0i16; 960];
    let start = Instant::now();

    while Instant::now().duration_since(start) < Duration::from_secs(10) {
        harness.iterate(&mut invite_handler);

        let _ = c0.send_audio(&pcm, 960, 1, 48000);

        if *received_audio_bob.lock().unwrap() {
            break;
        }
    }

    assert!(
        *received_audio_bob.lock().unwrap(),
        "Bob did not receive conference audio"
    );
}
