use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk};
use merkle_tox_core::engine::session::active::solve_challenge;
use merkle_tox_core::engine::session::{Handshake, SyncSession};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::time::Instant;

#[test]
fn test_pow_solve_and_verify() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = Instant::now();
    let store = InMemoryStore::new();
    let mut session =
        SyncSession::<Handshake>::new(ConversationId::from([0; 32]), &store, false, now)
            .activate(0);

    // Set a reasonable difficulty
    session.common.effective_difficulty = 10; // ~1024 hashes

    let sketch = tox_reconcile::SyncSketch {
        conversation_id: ConversationId::from([0; 32]),
        cells: Vec::new(),
        range: tox_reconcile::SyncRange {
            epoch: 0,
            min_rank: 0,
            max_rank: 0,
        },
    };

    let nonce = session.generate_challenge(sketch, now, &mut rng);

    let solution = solve_challenge(nonce, 10);

    assert!(
        session.verify_solution(nonce, solution, now),
        "PoW verification failed!"
    );
}

#[test]
fn test_pow_incorrect_solution() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = Instant::now();
    let store = InMemoryStore::new();
    let mut session =
        SyncSession::<Handshake>::new(ConversationId::from([0; 32]), &store, false, now)
            .activate(0);
    session.common.effective_difficulty = 10;

    let sketch = tox_reconcile::SyncSketch {
        conversation_id: ConversationId::from([0; 32]),
        cells: Vec::new(),
        range: tox_reconcile::SyncRange {
            epoch: 0,
            min_rank: 0,
            max_rank: 0,
        },
    };

    let nonce = session.generate_challenge(sketch, now, &mut rng);

    assert!(
        !session.verify_solution(nonce, 0, now),
        "PoW verified incorrect solution!"
    );
}

#[test]
fn test_pow_expired_challenge() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = Instant::now();
    let store = InMemoryStore::new();
    let mut session =
        SyncSession::<Handshake>::new(ConversationId::from([0; 32]), &store, false, now)
            .activate(0);
    session.common.effective_difficulty = 5;

    let sketch = tox_reconcile::SyncSketch {
        conversation_id: ConversationId::from([0; 32]),
        cells: Vec::new(),
        range: tox_reconcile::SyncRange {
            epoch: 0,
            min_rank: 0,
            max_rank: 0,
        },
    };

    let nonce = session.generate_challenge(sketch, now, &mut rng);
    let solution = solve_challenge(nonce, 5);

    let later = now + std::time::Duration::from_secs(61);
    assert!(
        !session.verify_solution(nonce, solution, later),
        "PoW verified expired challenge!"
    );
}

#[test]
fn test_difficulty_consensus_median() {
    let now = Instant::now();
    let store = InMemoryStore::new();
    let mut session =
        SyncSession::<Handshake>::new(ConversationId::from([0; 32]), &store, false, now)
            .activate(0);

    // Initial default
    assert_eq!(session.common.effective_difficulty, 12); // DEFAULT_RECON_DIFFICULTY is 12

    // Add some votes
    session.update_difficulty_consensus(PhysicalDevicePk::from([1; 32]), 10);
    session.update_difficulty_consensus(PhysicalDevicePk::from([2; 32]), 30);
    session.update_difficulty_consensus(PhysicalDevicePk::from([3; 32]), 25);

    // Sorted votes: [10, 25, 30]. Median is 25.
    assert_eq!(session.common.effective_difficulty, 25);

    // Add another vote
    session.update_difficulty_consensus(PhysicalDevicePk::from([4; 32]), 5);
    // Sorted votes: [5, 10, 25, 30]. Median (at index 2) is 25.
    assert_eq!(session.common.effective_difficulty, 25);
}
