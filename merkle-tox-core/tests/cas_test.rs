use merkle_tox_core::cas::{BlobStatus, CHUNK_SIZE, FETCH_TIMEOUT, SwarmSync};
use merkle_tox_core::dag::{NodeHash, PhysicalDevicePk};
use merkle_tox_core::testing::create_blob_info;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[test]
fn test_swarm_sync_requests() {
    let hash = NodeHash::from([1u8; 32]);
    let info = create_blob_info(hash, CHUNK_SIZE * 3);

    let mut sync = SwarmSync::new(info);
    let peer1 = PhysicalDevicePk::from([0x11u8; 32]);
    let peer2 = PhysicalDevicePk::from([0x22u8; 32]);

    sync.add_seeder(peer1);
    sync.add_seeder(peer2);

    let reqs = sync.next_requests(2, Instant::now());
    assert_eq!(reqs.len(), 2);

    // Check that different chunks were requested
    assert_ne!(reqs[0].1.offset, reqs[1].1.offset);
    // Check that both peers were utilized
    assert_ne!(reqs[0].0, reqs[1].0);
}

#[test]
fn test_swarm_sync_timeout() {
    let hash = NodeHash::from([1u8; 32]);
    let info = create_blob_info(hash, CHUNK_SIZE * 10);

    let mut sync = SwarmSync::new(info);
    let peer1 = PhysicalDevicePk::from([0x11u8; 32]);
    sync.add_seeder(peer1);

    let now = Instant::now();
    let reqs = sync.next_requests(1, now);
    assert_eq!(reqs.len(), 1);
    assert_eq!(sync.active_fetches.len(), 1);

    // Request the remaining 9 chunks (all 10 chunks now in-flight)
    let reqs = sync.next_requests(9, now);
    assert_eq!(reqs.len(), 9);
    assert_eq!(sync.active_fetches.len(), 10);

    // Request again, should be empty because all chunks are in-flight
    let reqs = sync.next_requests(1, now);
    assert_eq!(reqs.len(), 0);

    // Advance time past timeout
    let later = now + FETCH_TIMEOUT + Duration::from_secs(1);
    sync.clear_stalled_fetches(later);
    assert_eq!(sync.active_fetches.len(), 0);

    // Should be able to request again
    let reqs = sync.next_requests(1, later);
    assert_eq!(reqs.len(), 1);
}

#[test]
fn test_swarm_sync_completion() {
    let hash = NodeHash::from([1u8; 32]);
    let info = create_blob_info(hash, CHUNK_SIZE);

    let mut sync = SwarmSync::new(info);
    sync.add_seeder(PhysicalDevicePk::from([0x11u8; 32]));

    assert!(!sync.tracker.is_complete());

    sync.mark_chunk_received(0);
    assert!(sync.tracker.is_complete());
}

// Note: `test_bao_verification_*`, `test_swarm_sync_corrupted_bao_proof`,
// `test_seeder_removal_on_failure`, and `test_swarm_sync_all_seeders_failed`
// used to live here. They tested per-piece Bao slice verification, which
// has been replaced by the domain-separated ChunkMerkleTree scheme (see
// `doc/merkle-tox-cas.md` §3). Equivalent coverage for the new scheme lives
// in `merkle-tox-core/src/cas/merkle.rs` (unit tests for the Merkle tree
// itself) and `tests/cas_push_test.rs` (engine-level security properties:
// rejects tampered chunks, rejects invalid proofs, blacklists seeders).

#[test]
fn test_swarm_sync_multiple_seeders() {
    let hash = NodeHash::from([1u8; 32]);
    let info = create_blob_info(hash, CHUNK_SIZE * 10);

    let mut sync = SwarmSync::new(info);
    let p1 = PhysicalDevicePk::from([0x11u8; 32]);
    let p2 = PhysicalDevicePk::from([0x22u8; 32]);
    let p3 = PhysicalDevicePk::from([0x33u8; 32]);

    sync.add_seeder(p1);
    sync.add_seeder(p2);
    sync.add_seeder(p3);

    // Request 8 chunks.
    // Load balancing should spread them: p1:3, p2:3, p3:2
    let reqs = sync.next_requests(8, Instant::now());
    assert_eq!(reqs.len(), 8);

    let mut counts = HashMap::new();
    for (peer, _) in &reqs {
        *counts.entry(*peer).or_insert(0) += 1;
    }

    // With 8 chunks and 3 seeders, load should be 3, 3, 2 in any order
    let mut distribution: Vec<usize> = counts.values().cloned().collect();
    distribution.sort_unstable();
    assert_eq!(distribution, vec![2, 3, 3]);

    // Receive one chunk from p1, now p1 should have 2 in-flight, p2: 3, p3: 2
    // Next request should go to either p1 or p3 (both have 2 in-flight)
    let p1_offset = *reqs
        .iter()
        .find(|(p, _)| p == &p1)
        .unwrap()
        .1
        .offset
        .expose_unchecked();
    sync.mark_chunk_received(p1_offset / CHUNK_SIZE);

    let more_reqs = sync.next_requests(1, Instant::now());
    assert_eq!(more_reqs.len(), 1);
    let chosen_peer = more_reqs[0].0;
    assert!(
        chosen_peer == p1 || chosen_peer == p3,
        "Should pick a peer with the least in-flight requests (p1 or p3)"
    );
}

#[test]
fn test_zero_byte_blob() {
    let hash = NodeHash::from([1u8; 32]);
    let info = create_blob_info(hash, 0);

    let sync = SwarmSync::new(info);
    assert!(sync.tracker.is_complete());
}

#[test]
fn test_swarm_sync_resumption() {
    let hash = NodeHash::from([1u8; 32]);
    let mut info = create_blob_info(hash, CHUNK_SIZE * 10);
    info.status = BlobStatus::Downloading;

    let mut sync = SwarmSync::new(info);

    // Partially download
    sync.tracker.mark_received(0);
    sync.tracker.mark_received(5);

    // Verify next missing
    assert_eq!(sync.tracker.next_missing(0), Some(1));
    assert_eq!(sync.tracker.next_missing(6), Some(6));
}

// end of file
