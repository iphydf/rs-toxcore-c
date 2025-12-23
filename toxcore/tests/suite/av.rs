use super::setup::TestHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use toxcore::tox::*;
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
            _: u16,
            _: u16,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: i32,
            _: i32,
            _: i32,
        ) {
            self.received_video.store(true, Ordering::SeqCst);
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
    let height = 100;
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
