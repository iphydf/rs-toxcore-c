use rand::SeedableRng;
use std::time::Instant;
use tox_sequenced::protocol::{
    FragmentCount, FragmentIndex, MessageId, MessageType, OutboundEnvelope, serialize,
};
use tox_sequenced::quota::ReassemblyQuota;
use tox_sequenced::session::SequenceSession;

#[test]
fn test_quota_priority_isolation() {
    // 100KB total quota
    let quota = ReassemblyQuota::new(100 * 1024);
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut session = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // Helper to create valid serialized data for a message type
    let make_data = |mtype: MessageType, size: usize| {
        let env = OutboundEnvelope {
            message_type: mtype,
            payload: &vec![0u8; size],
        };
        serialize(&env).unwrap()
    };

    // 1. Fill 75% of the quota with Bulk data (Threshold is 70% for new Bulk)
    let bulk_data_full = make_data(MessageType::BlobData, 75 * 1024);

    // Attempt to start a 75KB Bulk message.
    // It should fail because 75KB > 70KB (70% threshold).
    let _res = session.handle_packet(
        tox_sequenced::protocol::Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(60),
            data: bulk_data_full[0..1000].to_vec(),
        },
        now,
    );

    assert!(
        session.find_incoming(MessageId(1)).is_none(),
        "Bulk message exceeding 70% threshold should be rejected"
    );

    // 2. Start a 60KB Bulk message (under 70% threshold).
    let bulk_data_ok = make_data(MessageType::BlobData, 60 * 1024);
    session.handle_packet(
        tox_sequenced::protocol::Packet::Data {
            message_id: MessageId(2),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(50),
            data: bulk_data_ok[0..1000].to_vec(),
        },
        now,
    );
    assert!(
        session.find_incoming(MessageId(2)).is_some(),
        "Bulk message under threshold should be accepted"
    );

    // 3. Now quota used is ~65KB (reserved based on planned size).
    // Try another Bulk message. Must be >= 32KB to be Priority::Bulk.
    let bulk_data_fail = make_data(MessageType::BlobData, 35 * 1024);
    session.handle_packet(
        tox_sequenced::protocol::Packet::Data {
            message_id: MessageId(3),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(30),
            data: bulk_data_fail[0..1000].to_vec(),
        },
        now,
    );
    assert!(
        session.find_incoming(MessageId(3)).is_none(),
        "Additional Bulk should be rejected when over 70%"
    );

    // 4. Try a Standard message (Threshold 90%).
    let std_data = make_data(MessageType::MerkleNode, 10 * 1024);
    session.handle_packet(
        tox_sequenced::protocol::Packet::Data {
            message_id: MessageId(4),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(10),
            data: std_data[0..1000].to_vec(),
        },
        now,
    );
    assert!(
        session.find_incoming(MessageId(4)).is_some(),
        "Standard multi-fragment message should be in reassembly"
    );

    // 5. Try a Critical message (Threshold 99%).
    let crit_data = make_data(MessageType::CapsAnnounce, 100);
    session.handle_packet(
        tox_sequenced::protocol::Packet::Data {
            message_id: MessageId(5),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(1),
            data: crit_data,
        },
        now,
    );

    let mut completed = false;
    while let Some(event) = session.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, _, _) = event
            && id == MessageId(5)
        {
            completed = true;
        }
    }
    assert!(completed, "Critical message should have completed");
}
