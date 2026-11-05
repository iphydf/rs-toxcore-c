use std::fs;

use toxcore::types::PublicKey;
use toxxi::sync::event::EventId;
use toxxi::sync::protocol::SessionMessage;
use toxxi::sync::trace::SyncTrace;

#[test]
fn records_each_message_with_its_kind_and_ids_but_not_its_content() {
    let dir = tempfile::tempdir().unwrap();
    let device = PublicKey([0xab; 32]);
    let mut trace = SyncTrace::new(dir.path());
    let event = b"secret text".to_vec();
    trace.record(
        "in",
        &device,
        &SessionMessage::Want(vec![EventId([1; 32])]).encode(),
    );
    trace.record(
        "out",
        &device,
        &SessionMessage::Events(vec![event.clone()]).encode(),
    );
    let log = fs::read_to_string(dir.path().join("sync-trace.log")).unwrap();
    let lines: Vec<Vec<&str>> = log
        .lines()
        .map(|l| l.split(' ').skip(1).collect())
        .collect();
    let event_id = &toxxi::utils::encode_hex(&EventId::of(&event).0)[..8];
    assert_eq!(lines[0], ["in", "abababab", "Want", "1", "[01010101]"]);
    assert_eq!(
        lines[1],
        [
            "out",
            "abababab",
            "Events",
            "11",
            "bytes",
            "1",
            &format!("[{event_id}]")
        ]
    );
    assert!(!log.contains("secret"));
}

#[test]
fn starts_a_new_file_when_full_and_keeps_one_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let device = PublicKey([0; 32]);
    let mut trace = SyncTrace::new(dir.path());
    let message = SessionMessage::Want(vec![EventId([2; 32]); 1000]).encode();
    for _ in 0..30000 {
        trace.record("in", &device, &message);
    }
    let current = fs::metadata(dir.path().join("sync-trace.log"))
        .unwrap()
        .len();
    let old = fs::metadata(dir.path().join("sync-trace.log.1"))
        .unwrap()
        .len();
    assert!(current <= 1024 * 1024 && old <= 1024 * 1024 && old > 1000 * 1000);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}
