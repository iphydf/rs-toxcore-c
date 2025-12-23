use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::{MessageType, SequenceSession};

#[test]
fn test_bidirectional_stress() {
    let start_time = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(start_time, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(start_time, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(start_time, tp, &mut rng);
    let mut now = start_time;

    let data_to_bob = vec![1u8; 100_000]; // 100KB
    let data_to_alice = vec![2u8; 100_000]; // 100KB

    alice
        .send_message_at(MessageType::MerkleNode, &data_to_bob, now)
        .unwrap();
    bob.send_message_at(MessageType::MerkleNode, &data_to_alice, now)
        .unwrap();

    let mut alice_completed = false;
    let mut bob_completed = false;

    // Simulation loop
    for _ in 0..10000 {
        now += Duration::from_millis(1);

        // Alice -> Bob
        let a_to_b = alice.get_packets_to_send(now, 0);
        for p in a_to_b {
            let replies = bob.handle_packet(p, now);
            while let Some(event) = bob.poll_event() {
                if let tox_sequenced::SessionEvent::MessageCompleted(_id, _, data) = event {
                    assert_eq!(data, data_to_bob);
                    bob_completed = true;
                }
            }
            for r in replies {
                alice.handle_packet(r, now);
            }
        }

        // Bob -> Alice
        let b_to_a = bob.get_packets_to_send(now, 0);
        for p in b_to_a {
            let replies = alice.handle_packet(p, now);
            while let Some(event) = alice.poll_event() {
                if let tox_sequenced::SessionEvent::MessageCompleted(_id, _, data) = event {
                    assert_eq!(data, data_to_alice);
                    alice_completed = true;
                }
            }
            for r in replies {
                bob.handle_packet(r, now);
            }
        }

        if alice_completed && bob_completed && alice.in_flight() == 0 && bob.in_flight() == 0 {
            break;
        }
    }

    assert!(alice_completed, "Alice did not receive her message");
    assert!(bob_completed, "Bob did not receive his message");

    // Ensure both sessions converge to 0 in-flight
    assert_eq!(alice.in_flight(), 0);
    assert_eq!(bob.in_flight(), 0);
}
