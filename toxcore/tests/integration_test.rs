use std::thread;
use std::time::Duration;
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
