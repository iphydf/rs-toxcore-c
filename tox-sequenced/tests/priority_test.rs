use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;
use tox_sequenced::protocol::{
    ESTIMATED_PAYLOAD_SIZE, FragmentCount, FragmentIndex, MessageId, Packet,
};
use tox_sequenced::quota::{Priority, ReassemblyQuota};
use tox_sequenced::session::SequenceSession;
use tox_sequenced::time::ManualTimeProvider;

#[test]
fn test_message_priority_identification() {
    let now = Instant::now();
    let time_provider = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    // Total quota = 100 * ESTIMATED_PAYLOAD_SIZE
    let quota_size = 100 * ESTIMATED_PAYLOAD_SIZE;
    let quota = ReassemblyQuota::new(quota_size);

    // Reserve 60% of quota.
    // Bulk threshold: 70%. (60 + 20 = 80 > 70, should be REJECTED if correctly identified as Bulk)
    // Standard threshold: 90%. (60 + 20 = 80 < 90, will be ACCEPTED if misidentified as Standard)
    let reserve_amount = 60 * ESTIMATED_PAYLOAD_SIZE;
    assert!(quota.reserve(reserve_amount, Priority::Critical));

    let mut session =
        SequenceSession::with_quota_at(quota.clone(), now, time_provider.clone(), &mut rng);

    // BlobData (index 0x09) should have priority Bulk.
    // Message must be > 16KB to exceed FAIR_SHARE_GUARANTEE and trigger priority check.
    // And it must be multi-fragment to trigger reservation of (data_len * total_fragments).
    let total_fragments = 20;
    let mut payload = vec![0x92, 0x09]; // 0x92 is fixarray(2) prefix, 0x09 is BlobData discriminant
    payload.extend(vec![0u8; ESTIMATED_PAYLOAD_SIZE - 2]);

    let packet = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(total_fragments),
        data: payload,
    };

    let responses = session.handle_packet(packet, now);

    // Verify if it was rejected. A rejection results in a SelectiveAck with bitmask 0 and base_index 0.
    let mut rejected = false;
    for resp in responses {
        if let Packet::Ack(ack) = resp
            && ack.message_id == MessageId(1)
            && ack.base_index == FragmentIndex(0)
            && ack.bitmask == 0
        {
            rejected = true;
        }
    }

    // Correct behavior: should be rejected (Bulk > 70% used).
    // Buggy behavior: will be accepted (Standard < 90% used).
    assert!(
        rejected,
        "BlobData should be rejected as Bulk priority when 80% of quota is used"
    );
}
