//! TDD anchor for sampling RTT from regular data ACKs.
//!
//! Background: the SRTT estimator was being fed *only* by Ping/Pong
//! exchanges, which run on a 10-second active interval. For any flow
//! that completes within a few seconds, this means the SRTT was
//! anchored to `INITIAL_SRTT` (200 ms) plus at most a single sample,
//! producing srtt ≈ 175 ms even on a 1 ms physical link. BBRv2 then
//! used that stale figure as the floor of `min_rtt`, ballooning its
//! BDP estimate and choking pacing/cwnd growth.
//!
//! After the fix, every ACK that resolves a previously-unresolved
//! datagram contributes one RTT sample (`now - sent_time` of the
//! freshest newly-resolved datagram). This test pins that behaviour
//! by sending a stream of packets, advancing the clock by a known
//! offset, ACKing them, and asserting that the smoothed RTT collapses
//! toward the sample value rather than remaining stuck near the
//! initial 200 ms.

use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{MessageType, Packet};
use tox_sequenced::rtt::INITIAL_SRTT;
use tox_sequenced::time::ManualTimeProvider;
use tox_sequenced::SequenceSession;

fn make_session(now: Instant) -> (SequenceSession, Arc<ManualTimeProvider>) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let session = SequenceSession::new_at(now, tp.clone(), &mut rng);
    (session, tp)
}

/// Drains all queued DATA packets from `session` into `out`. Returns
/// the seqs in order.
fn drain_data(session: &mut SequenceSession, now: Instant) -> Vec<u32> {
    let mut seqs = Vec::new();
    for _ in 0..1000 {
        let mut emitted = 0;
        session.flush(now, 0, &mut |packet| {
            if let Packet::Data { seq, .. } = &packet {
                seqs.push(*seq);
                emitted += 1;
            }
            true
        });
        if session.outgoing_count() == 0 {
            break;
        }
        if emitted == 0 {
            break;
        }
    }
    seqs
}

#[test]
fn srtt_collapses_toward_per_ack_sample() {
    // Sample RTT we want to inject on every ACK round.
    const SAMPLE_RTT: Duration = Duration::from_millis(5);
    const ROUNDS: usize = 200;
    const PKTS_PER_ROUND: usize = 4;

    let start = Instant::now();
    let (mut alice, _tp) = make_session(start);

    let initial_srtt = alice.current_srtt();
    assert_eq!(
        initial_srtt, INITIAL_SRTT,
        "session should start at INITIAL_SRTT"
    );

    let mut clock = start;
    for _round in 0..ROUNDS {
        // Send a small burst, drain, advance clock by SAMPLE_RTT,
        // then ACK them all cumulatively.
        for i in 0..PKTS_PER_ROUND {
            alice
                .send(MessageType::MerkleNode, &[i as u8; 64], clock)
                .expect("send");
        }
        let seqs = drain_data(&mut alice, clock);
        assert_eq!(
            seqs.len(),
            PKTS_PER_ROUND,
            "drain should yield exactly the seqs we just sent"
        );
        let max_seq = *seqs.iter().max().unwrap();

        clock += SAMPLE_RTT;

        let ack = Packet::Ack {
            base_seq: tox_proto::Untrusted::new(max_seq.wrapping_add(1)),
            recv_bytes: tox_proto::Untrusted::new(0),
            sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![]),
        };
        alice.handle_packet(ack, clock);
    }

    let final_srtt = alice.current_srtt();

    // After 200 ACK rounds with SAMPLE_RTT=5 ms samples, the smoothed
    // RTT must have collapsed well below INITIAL_SRTT toward the
    // sample.  A loose upper bound (15 ms) is enough to distinguish
    // "samples were ingested at all" from "estimator is stuck near
    // 200 ms".  Today (no per-ACK sampling) this assertion fails:
    // srtt remains at INITIAL_SRTT.
    assert!(
        final_srtt < Duration::from_millis(15),
        "expected smoothed RTT to converge toward {:?}, but got {:?} \
         (likely indicates per-ACK RTT sampling is missing)",
        SAMPLE_RTT, final_srtt
    );
    assert!(
        final_srtt >= SAMPLE_RTT,
        "smoothed RTT cannot be below the sample {:?}, but got {:?}",
        SAMPLE_RTT, final_srtt
    );
}
