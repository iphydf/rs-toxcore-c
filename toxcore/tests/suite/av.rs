use super::setup::TestHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use toxcore::tox::*;
use toxcore::toxav::events::Frame;
use toxcore::toxav::*;

pub fn subtest_toxav_call(harness: &mut TestHarness) {
    println!("Running subtest_toxav_call...");

    struct CallHandler {
        received_call: Arc<AtomicBool>,
        received_audio: Arc<AtomicBool>,
        received_video: Arc<AtomicBool>,
    }
    impl ToxAVHandler for CallHandler {
        fn on_call(&mut self, _: FriendNumber, _: bool, _: bool) {
            self.received_call.store(true, Ordering::SeqCst);
        }
        fn on_audio_receive_frame(&mut self, _: FriendNumber, _: &[i16], _: u8, _: u32) {
            self.received_audio.store(true, Ordering::SeqCst);
        }
        fn on_video_receive_frame(
            &mut self,
            _: FriendNumber,
            width: u16,
            height: u16,
            y: &[u8],
            u: &[u8],
            v: &[u8],
            ystride: i32,
            ustride: i32,
            vstride: i32,
        ) {
            let frame = Frame::packed(width, height, y, u, v, ystride, ustride, vstride);
            // An odd height's last chroma row is there too.
            let chroma = usize::from(width).div_ceil(2) * usize::from(height).div_ceil(2);
            if frame.u.len() == chroma && frame.v.len() == chroma {
                self.received_video.store(true, Ordering::SeqCst);
            }
        }
    }

    struct SenderHandler;
    impl ToxAVHandler for SenderHandler {}

    struct IdleHandler;
    impl ToxHandler for IdleHandler {}
    let mut core_handler = IdleHandler;

    let received_call = Arc::new(AtomicBool::new(false));
    let received_audio = Arc::new(AtomicBool::new(false));
    let received_video = Arc::new(AtomicBool::new(false));

    let av_handler = CallHandler {
        received_call: received_call.clone(),
        received_audio: received_audio.clone(),
        received_video: received_video.clone(),
    };
    let sender_handler = SenderHandler;

    let mut av0 = ToxAV::new(&harness.toxes[0].tox, sender_handler).unwrap();
    let mut av1 = ToxAV::new(&harness.toxes[1].tox, av_handler).unwrap();

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    av0.call(f0.get_number(), 48, 2000).expect("Call failed");

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    while Instant::now().duration_since(start) < timeout {
        av0.iterate();
        av1.iterate();
        harness.iterate(&mut core_handler);

        if received_call.load(Ordering::SeqCst) {
            break;
        }
    }

    assert!(received_call.load(Ordering::SeqCst), "Call not received");

    // Answer call
    let pk0 = harness.toxes[0].tox.public_key();
    let f1 = harness.toxes[1].tox.lookup_friend(&pk0).unwrap();
    av1.answer(f1.get_number(), 48, 2000)
        .expect("Answer failed");

    // Send Media
    let pcm = vec![0i16; 960]; // 20ms of audio at 48kHz mono
    let width = 100;
    let height = 99;
    let y = vec![0u8; width * height];
    let u = vec![0u8; width * height / 4];
    let v = vec![0u8; width * height / 4];

    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut core_handler);
        av0.iterate();
        av1.iterate();

        let _ = av0.audio_send_frame(f0.get_number(), &pcm, 1, 48000);
        let _ = av0.video_send_frame(f0.get_number(), width as u16, height as u16, &y, &u, &v);

        if received_audio.load(Ordering::SeqCst) && received_video.load(Ordering::SeqCst) {
            break;
        }
    }

    assert!(received_audio.load(Ordering::SeqCst), "Audio not received");
    assert!(received_video.load(Ordering::SeqCst), "Video not received");
}

/// Calls that end at both ends at once, or that both ends place at once,
/// leave nothing behind to end the next call.
pub fn subtest_toxav_crossed_calls(harness: &mut TestHarness) {
    println!("Running subtest_toxav_crossed_calls...");

    #[derive(Default)]
    struct States {
        rang: bool,
        failed: bool,
        answered: bool,
    }
    impl ToxAVHandler for States {
        fn on_call(&mut self, _: FriendNumber, _: bool, _: bool) {
            self.rang = true;
        }
        fn on_call_state(&mut self, _: FriendNumber, state: u32) {
            if ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_ERROR.is_in(state) {
                self.failed = true;
            } else if !ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_FINISHED.is_in(state) {
                self.answered = true;
            }
        }
    }

    struct IdleHandler;
    impl ToxHandler for IdleHandler {}

    let mut av0 = ToxAV::new(&harness.toxes[0].tox, States::default()).unwrap();
    let mut av1 = ToxAV::new(&harness.toxes[1].tox, States::default()).unwrap();
    let f0 = harness.toxes[0]
        .tox
        .lookup_friend(&harness.toxes[1].tox.public_key())
        .unwrap()
        .get_number();
    let f1 = harness.toxes[1]
        .tox
        .lookup_friend(&harness.toxes[0].tox.public_key())
        .unwrap()
        .get_number();

    // Runs both until [done], or for [limit].
    let run = |av0: &mut ToxAV<States>,
               av1: &mut ToxAV<States>,
               limit: Duration,
               done: &dyn Fn(&States, &States) -> bool| {
        let start = Instant::now();
        while start.elapsed() < limit && !done(av0.handler_mut(), av1.handler_mut()) {
            av0.iterate();
            av1.iterate();
            harness.iterate(&mut IdleHandler);
        }
    };
    let wait = Duration::from_secs(5);
    // Long enough for what's left of a call to reach the other end.
    let settle = Duration::from_secs(1);
    // Calls 1 from 0, answering it, and keeps it up a while.
    let call = |av0: &mut ToxAV<States>, av1: &mut ToxAV<States>| {
        *av0.handler_mut() = States::default();
        *av1.handler_mut() = States::default();
        av0.call(f0, 48, 0).expect("Call failed");
        run(av0, av1, wait, &|_, b| b.rang);
        av1.answer(f1, 48, 0).expect("Answer failed");
        run(av0, av1, settle, &|a, b| a.failed || b.failed);
        assert!(av0.handler_mut().answered, "Call not answered");
        assert!(
            !av0.handler_mut().failed && !av1.handler_mut().failed,
            "Call failed"
        );
    };
    let hang_up = |av: &ToxAV<States>, friend| {
        av.call_control(friend, ToxavCallControl::TOXAV_CALL_CONTROL_CANCEL)
            .unwrap();
    };

    // What's left of the calls before.
    run(&mut av0, &mut av1, settle, &|_, _| false);
    call(&mut av0, &mut av1);
    hang_up(&av0, f0);
    hang_up(&av1, f1);
    run(&mut av0, &mut av1, settle, &|_, _| false);
    call(&mut av0, &mut av1);

    hang_up(&av0, f0);
    run(&mut av0, &mut av1, settle, &|_, _| false);
    av0.call(f0, 48, 0).expect("Call failed");
    av1.call(f1, 48, 0).expect("Call failed");
    run(&mut av0, &mut av1, wait, &|a, b| a.failed && b.failed);
    run(&mut av0, &mut av1, settle, &|_, _| false);
    call(&mut av0, &mut av1);
}
