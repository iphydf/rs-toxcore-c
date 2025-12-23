use merkle_tox_core::cas::{BlobStatus, CHUNK_SIZE, FETCH_TIMEOUT, SwarmSync};
use merkle_tox_core::dag::{NodeHash, PhysicalDevicePk};
use merkle_tox_core::testing::{create_blob_data, create_blob_info};
use std::collections::HashMap;
use std::io::Read;
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

    // Request 3 more, should still use the same seeder (up to 4 in-flight)
    let reqs = sync.next_requests(3, now);
    assert_eq!(reqs.len(), 3);
    assert_eq!(sync.active_fetches.len(), 4);

    // Request again, should be empty because peer is busy (limit reached)
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

    let data = create_blob_data(hash, 0, vec![0u8; CHUNK_SIZE as usize]);

    sync.on_chunk_received(&data);
    assert!(sync.tracker.is_complete());
}

#[test]
fn test_bao_verification_failure() {
    let hash = NodeHash::from([1u8; 32]);
    let bao_root = [0xEEu8; 32];
    let mut info = create_blob_info(hash, CHUNK_SIZE);
    info.bao_root = Some(bao_root);

    let mut sync = SwarmSync::new(info);

    let mut data = create_blob_data(hash, 0, vec![0u8; CHUNK_SIZE as usize]);
    data.proof = vec![0xAAu8; 32]; // Invalid non-zero proof

    let res = sync.on_chunk_received(&data);
    assert!(!res, "Should fail Bao verification");
    assert!(!sync.tracker.is_received(0));
    assert!(
        !sync.active_fetches.contains_key(&0),
        "Active fetch should be cleared even on failure"
    );
}

#[test]
fn test_bao_verification_success() {
    let data = vec![0x42u8; 1024];
    let (bao_outboard, bao_root) = bao::encode::outboard(&data);
    let mut hash_inner = [0u8; 32];
    hash_inner.copy_from_slice(bao_root.as_bytes());
    let hash = NodeHash::from(hash_inner);

    let mut info = create_blob_info(hash, 1024);
    info.bao_root = Some(hash_inner);

    let mut sync = SwarmSync::new(info);
    sync.add_seeder(PhysicalDevicePk::from([0x11u8; 32]));

    // Request the chunk
    let _ = sync.next_requests(1, Instant::now());

    // Generate a real proof for this slice
    let mut encoder = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(&data),
        std::io::Cursor::new(&bao_outboard),
        0,
        1024,
    );
    let mut proof = Vec::new();
    encoder.read_to_end(&mut proof).unwrap();

    let blob_data = merkle_tox_core::cas::BlobData {
        hash,
        offset: 0,
        data,
        proof,
    };

    sync.on_chunk_received(&blob_data);
    assert!(sync.tracker.is_complete());
}

#[test]
fn test_swarm_sync_corrupted_bao_proof() {
    let data = vec![0x42u8; 1024];
    let (bao_outboard, bao_root) = bao::encode::outboard(&data);
    let mut hash_inner = [0u8; 32];
    hash_inner.copy_from_slice(bao_root.as_bytes());
    let hash = NodeHash::from(hash_inner);

    let mut info = create_blob_info(hash, 1024);
    info.bao_root = Some(hash_inner);

    let mut sync = SwarmSync::new(info);
    let peer = PhysicalDevicePk::from([0x11u8; 32]);
    sync.add_seeder(peer);

    // Request the chunk
    let _ = sync.next_requests(1, Instant::now());

    // Generate a real proof for this slice
    let mut encoder = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(&data),
        std::io::Cursor::new(&bao_outboard),
        0,
        1024,
    );
    let mut proof = Vec::new();
    encoder.read_to_end(&mut proof).unwrap();

    // CORRUPT the proof
    proof[0] ^= 0xFF;

    let blob_data = merkle_tox_core::cas::BlobData {
        hash,
        offset: 0,
        data,
        proof,
    };

    // Receiving corrupted data should fail
    let res = sync.on_chunk_received(&blob_data);
    assert!(!res, "Should fail on corrupted Bao proof");
    assert!(!sync.tracker.is_received(0));

    // We should simulate seeder removal if it failed (matching Engine behavior)
    sync.remove_seeder(&peer);
    assert!(!sync.seeders.contains(&peer));
}

#[test]
fn test_seeder_removal_on_failure() {
    let hash = NodeHash::from([1u8; 32]);
    let mut info = create_blob_info(hash, CHUNK_SIZE);
    info.bao_root = Some([0u8; 32]);

    let mut sync = SwarmSync::new(info);
    let peer = PhysicalDevicePk::from([0x11u8; 32]);
    sync.add_seeder(peer);

    // Simulate a failure and removal (as the Engine would do)
    let mut data = create_blob_data(hash, 0, vec![0u8; CHUNK_SIZE as usize]);
    data.proof = vec![1u8; 32];

    if !sync.on_chunk_received(&data) {
        sync.remove_seeder(&peer);
    }

    assert!(!sync.seeders.contains(&peer));
    assert!(sync.active_fetches.is_empty());

    // Ensure no more requests are made to this peer
    let next_reqs = sync.next_requests(1, Instant::now());
    assert!(
        next_reqs.is_empty(),
        "Should not request from removed seeder"
    );
}

#[test]
fn test_swarm_sync_all_seeders_failed() {
    let hash = NodeHash::from([1u8; 32]);
    let mut info = create_blob_info(hash, CHUNK_SIZE);
    info.bao_root = Some([0u8; 32]);

    let mut sync = SwarmSync::new(info);
    let peer = PhysicalDevicePk::from([0x11u8; 32]);
    sync.add_seeder(peer);

    // Request chunk
    let _ = sync.next_requests(1, Instant::now());

    // Fail chunk
    let mut data = create_blob_data(hash, 0, vec![0u8; CHUNK_SIZE as usize]);
    data.proof = vec![1u8; 32]; // Invalid proof

    if !sync.on_chunk_received(&data) {
        sync.remove_seeder(&peer);
    }

    assert!(sync.seeders.is_empty());
    assert!(sync.next_requests(1, Instant::now()).is_empty());
}

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
    let data = create_blob_data(
        hash,
        reqs.iter().find(|(p, _)| p == &p1).unwrap().1.offset,
        vec![0u8; CHUNK_SIZE as usize],
    );
    sync.on_chunk_received(&data);

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
