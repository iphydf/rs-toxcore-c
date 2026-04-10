use std::thread;
use std::time::{Duration, Instant};
use toxcore::tox::*;
use toxcore::toxav::*;

mod panic_test;
mod suite;

#[test]
fn integration_suite() {
    let mut harness = suite::setup::TestHarness::new();
    harness.add_tox();
    harness.add_tox();
    harness.add_tox();

    // Connect 0-1, 0-2 and 1-2 to ensure full connectivity without LAN discovery.
    harness.connect(0, 1);
    harness.connect(0, 2);
    harness.connect(1, 2);

    harness.wait_for_connection(0, 1);
    harness.wait_for_connection(1, 0);
    harness.wait_for_connection(0, 2);
    harness.wait_for_connection(2, 0);
    harness.wait_for_connection(1, 2);
    harness.wait_for_connection(2, 1);

    harness.setup_groups();

    // Run independent tests on the same connection
    suite::message::subtest_send_message(&mut harness);
    suite::friend::subtest_friend_info(&mut harness);
    suite::custom_packet::subtest_friend_custom_packets(&mut harness);
    suite::custom_packet::subtest_group_custom_packets(&mut harness);
    suite::file::subtest_file_transfer(&mut harness);
    suite::conference::subtest_conference(&mut harness);
    suite::group::subtest_groups(&mut harness);
    suite::group::subtest_group_management(&mut harness);
    suite::group_av::subtest_group_av(&mut harness);
    suite::av::subtest_toxav_call(&mut harness);
    suite::dht::subtest_dht_nodes(&mut harness);
    suite::persistence::subtest_persistence();
    suite::encryptsave::subtest_encryptsave();
}

// Standalone unit tests (fast)

#[test]
fn test_version() {
    let (major, minor, _patch) = version();
    assert_eq!(major, 0);
    assert!(minor >= 2);
}

#[test]
fn test_tox_lifecycle() {
    let mut opts = Options::new().unwrap();
    opts.set_local_discovery_enabled(false);
    let tox = Tox::new(opts).expect("Failed to create Tox instance");
    let addr = tox.address();
    assert_ne!(addr.0, [0u8; ADDRESS_SIZE]);

    tox.set_name(b"RustTox").expect("Failed to set name");
    assert_eq!(tox.name(), b"RustTox");
}

#[test]
fn test_toxav_lifecycle() {
    let mut opts = Options::new().unwrap();
    opts.set_local_discovery_enabled(false);
    let tox = Tox::new(opts).expect("Failed to create Tox instance");
    struct DummyHandler;
    impl ToxAVHandler for DummyHandler {}
    let _av = ToxAV::new(&tox, DummyHandler).expect("Failed to create ToxAV instance");
}

#[test]
fn test_group_lifecycle() {
    let mut opts = Options::new().unwrap();
    opts.set_local_discovery_enabled(false);
    let tox = Tox::new(opts).expect("Failed to create Tox instance");
    let group = tox
        .group_new(
            ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE,
            b"TestGroup",
            b"PeerName",
        )
        .expect("Failed to create group");
    group
        .send_message(MessageType::TOX_MESSAGE_TYPE_NORMAL, b"Hello World")
        .expect("Failed to send group message");
    group
        .leave(Some(b"Goodbye"))
        .expect("Failed to leave group");
}

#[test]
fn test_events_lifecycle() {
    let mut opts = Options::new().unwrap();
    opts.set_local_discovery_enabled(false);
    let tox = Tox::new(opts).expect("Failed to create Tox instance");

    // Iterate a few times to ensure stability
    for _ in 0..5 {
        let events = tox.events().expect("Failed to iterate events");
        for event in &events {
            if let toxcore::tox::events::Event::SelfConnectionStatus(status) = event {
                println!(
                    "Got self connection status: {:?}",
                    status.connection_status()
                );
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    struct DummyHandler;
    impl ToxHandler for DummyHandler {}
    let mut handler = DummyHandler;
    tox.iterate(&mut handler);
}

// =============================================================================
// Native toxcore file transfer throughput measurement
// =============================================================================
//
// These tests use the toxcore native file transfer API (`tox_file_send` /
// `file_send_chunk` / `file_recv_chunk`) between two Tox nodes on loopback.
// They exist to provide a directly comparable substrate baseline against
// merkle-tox-tox's blob transfer e2e tests (see
// rs-toxcore-c/merkle-tox-tox/tests/integration_test.rs::run_blob_transfer):
// same machine, same loopback path, same TestHarness-style iteration cadence.
// The only thing that differs is the protocol stack on top.
//
// E2E_RESULT lines are emitted in the same format the merkle-tox e2e tests use,
// so the two can be compared side-by-side without further post-processing:
//
//     E2E_RESULT size_mb=10 elapsed_s=4.123 mbps=19.4 status=OK
//
// Marked `#[ignore]` so they only run when explicitly requested via
// `--test_arg=--ignored`. They are measurement, not pass/fail.

#[test]
#[ignore = "Slow real-Tox file transfer measurement; run via --test_arg=--ignored"]
fn test_native_tox_file_transfer_1mb() {
    run_native_tox_file_transfer(1024 * 1024, Duration::from_secs(60));
}

#[test]
#[ignore = "Slow real-Tox file transfer measurement; run via --test_arg=--ignored"]
fn test_native_tox_file_transfer_10mb() {
    run_native_tox_file_transfer(10 * 1024 * 1024, Duration::from_secs(120));
}

fn run_native_tox_file_transfer(size_bytes: u64, timeout: Duration) {
    use toxcore::tox::events::Event;

    // Two Tox nodes on loopback, no group setup, no other subtests.
    let mut harness = suite::setup::TestHarness::new();
    harness.add_tox();
    harness.add_tox();
    harness.connect(0, 1);
    harness.wait_for_connection(0, 1);
    harness.wait_for_connection(1, 0);

    // Synthetic file payload — same shape as the merkle-tox e2e blob test.
    let file_data: Vec<u8> = (0..size_bytes as usize).map(|i| (i % 251) as u8).collect();

    let pk1 = harness.toxes[1].tox.public_key();
    let alice_friend = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    // 1. Alice issues file_send for the synthetic blob.
    let _alice_file = harness.toxes[0]
        .tox
        .file_send(
            &alice_friend,
            ToxFileKind::TOX_FILE_KIND_DATA as u32,
            size_bytes,
            None,
            format!("native_{}mb.bin", size_bytes / (1024 * 1024)).as_bytes(),
        )
        .expect("Alice file_send failed");

    // We use the events-based iteration path (`tox.events()`) rather than
    // the callback-based `tox.iterate()` because the latter has shown
    // significant chunk-delivery latency in this isolated 2-node test
    // setup. The events path is the same one merkle-tox-tox uses for its
    // blob transfer e2e tests, so the comparison stays apples-to-apples.
    //
    // Important: each `tox.events()` call returns a `ToxEvents<'_>` whose
    // event references borrow from the underlying ffi buffer. The buffer
    // is freed when `ToxEvents` is dropped, so events MUST be processed
    // in the same scope where `events()` is called — never collected into
    // a longer-lived container or returned from a helper function.

    // 2. Wait for Bob to see the file_recv event.
    let request_deadline = Instant::now() + Duration::from_secs(5);
    let (bob_friend, bob_file) = loop {
        // Drain alice's events too so the connection keeps progressing.
        let _ = harness.toxes[0].tox.events();
        let bob_events = harness.toxes[1].tox.events().expect("bob events failed");
        let mut found: Option<(FriendNumber, FileNumber)> = None;
        for ev in &bob_events {
            if let Event::FileRecv(e) = ev {
                eprintln!(
                    "[file] FileRecv friend={:?} file={:?} size={}",
                    e.friend_number(),
                    e.file_number(),
                    e.file_size()
                );
                found = Some((e.friend_number(), e.file_number()));
                break;
            }
        }
        drop(bob_events);
        if let Some(pair) = found {
            break pair;
        }
        thread::sleep(Duration::from_millis(20));
        assert!(
            Instant::now() < request_deadline,
            "Bob never received the file_send request"
        );
    };

    // 3. Bob accepts (RESUME). The actual transfer starts now.
    let bob_friend_obj = harness.toxes[1].tox.friend(bob_friend);
    harness.toxes[1]
        .tox
        .file(&bob_friend_obj, bob_file)
        .control(ToxFileControl::TOX_FILE_CONTROL_RESUME)
        .unwrap();

    let transfer_start = Instant::now();
    let mut received_bytes: u64 = 0;
    let mut completed = false;

    // 4. Drive the transfer: each iteration, poll BOTH toxes for events.
    //    Alice's events include FileChunkRequest (we feed her chunks).
    //    Bob's events include FileRecvChunk (we tally bytes).
    while transfer_start.elapsed() < timeout {
        // Drain alice's events: handle any pending chunk requests.
        // Each iteration of this inner block processes one tox.events()
        // call and lets the ToxEvents drop at the closing brace, freeing
        // the buffer before we move on.
        {
            let alice_events =
                harness.toxes[0].tox.events().expect("alice events failed");
            for ev in &alice_events {
                if let Event::FileChunkRequest(e) = ev {
                    let position = e.position();
                    let length = e.length();
                    if length == 0 {
                        continue;
                    }
                    let friend_obj = harness.toxes[0].tox.friend(e.friend_number());
                    let file_obj = harness.toxes[0].tox.file(&friend_obj, e.file_number());
                    let pos = position as usize;
                    if pos >= file_data.len() {
                        let _ = file_obj.send_chunk(position, &[]);
                    } else {
                        let end = std::cmp::min(pos + length, file_data.len());
                        let _ = file_obj.send_chunk(position, &file_data[pos..end]);
                    }
                }
            }
        }

        // Drain bob's events: tally received chunks, watch for EOF.
        {
            let bob_events =
                harness.toxes[1].tox.events().expect("bob events failed");
            for ev in &bob_events {
                if let Event::FileRecvChunk(e) = ev {
                    let data = e.data();
                    if data.is_empty() {
                        completed = true;
                    } else {
                        received_bytes += data.len() as u64;
                    }
                }
            }
        }

        if completed {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let transfer_time = transfer_start.elapsed();
    let size_mb = size_bytes as f64 / (1024.0 * 1024.0);

    if !completed {
        println!(
            "E2E_RESULT size_mb={} elapsed_s={:.3} mbps=0 status=TIMEOUT received_bytes={}",
            size_mb,
            transfer_time.as_secs_f64(),
            received_bytes,
        );
        panic!(
            "Native tox file transfer of {} MB did not complete within {:?}",
            size_mb, timeout
        );
    }

    let throughput_mbps = (size_mb * 8.0) / transfer_time.as_secs_f64();
    println!(
        "E2E_RESULT size_mb={} elapsed_s={:.3} mbps={:.3} status=OK",
        size_mb,
        transfer_time.as_secs_f64(),
        throughput_mbps,
    );
}
