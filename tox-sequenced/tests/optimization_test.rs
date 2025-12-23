use std::time::{Duration, Instant};
use tox_sequenced::outgoing::OutgoingMessage;
use tox_sequenced::protocol::{FragmentIndex, MessageType};

#[test]
fn test_on_ack_with_retransmission_in_flight() {
    let now = Instant::now();
    let expected_size = 100;
    let mut msg =
        OutgoingMessage::new(MessageType::MerkleNode, vec![0; expected_size], 100, now).unwrap();

    let (_, _, is_retrans, was_in_flight) =
        msg.prepare_fragment_for_send(FragmentIndex(0), now, 0, now, false);
    assert!(!is_retrans);
    assert!(!was_in_flight);

    // Prepare again (retransmission)
    let later = now + Duration::from_millis(100);
    let (_, _, is_retrans, was_in_flight) =
        msg.prepare_fragment_for_send(FragmentIndex(0), later, 0, now, false);
    assert!(is_retrans);
    assert!(was_in_flight);

    assert_eq!(msg.in_flight_queue.len(), 2);
    assert_eq!(msg.in_flight_queue[0].0, FragmentIndex(0));
    assert_eq!(msg.in_flight_queue[1].0, FragmentIndex(0));

    // ACK for fragment 0. It should remove both entries from in-flight queue if implemented efficiently.
    let ack_time = later + Duration::from_millis(100);
    let res = msg.on_ack(FragmentIndex(1), 0, ack_time, 0);

    assert_eq!(res.newly_delivered_bytes, expected_size);

    // The important part:
    // We sent it twice (initial + TLP), but since SequenceSession tracks
    // unique bytes in flight, only unique bytes should be reported as removed.
    assert_eq!(
        res.newly_completed_in_flight_bytes, expected_size,
        "Should have reported unique bytes for the fragment"
    );
    assert_eq!(
        msg.in_flight_queue.len(),
        0,
        "In-flight queue should be cleared"
    );
    assert!(msg.fragment_states[0].last_sent.is_none());
}

// end of tests
