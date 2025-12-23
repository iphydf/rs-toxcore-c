use proptest::prelude::*;
use rand::{RngCore, thread_rng};
use tox_proto::{ConversationId, NodeHash, deserialize, serialize};
use tox_reconcile::{IbltCell, IbltSketch, SyncRange, SyncSketch, Tier};

#[test]
fn test_iblt_simple() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut sketch_a = IbltSketch::new(Tier::Small.cell_count());
    let mut sketch_b = IbltSketch::new(Tier::Small.cell_count());

    let mut ids = Vec::new();
    for _ in 0..100 {
        let mut id = [0u8; 32];
        thread_rng().fill_bytes(&mut id);
        ids.push(NodeHash::from(id));
    }

    // Both have first 90 IDs
    for id in &ids[0..90] {
        sketch_a.insert(id.as_ref());
        sketch_b.insert(id.as_ref());
    }

    // A has 90..95
    for id in &ids[90..95] {
        sketch_a.insert(id.as_ref());
    }

    // B has 95..100
    for id in &ids[95..100] {
        sketch_b.insert(id.as_ref());
    }

    sketch_a.subtract(&sketch_b).unwrap();
    let (in_a, in_b, _) = sketch_a.decode().unwrap();

    assert_eq!(in_a.len(), 5);
    assert_eq!(in_b.len(), 5);

    for id in &ids[90..95] {
        assert!(in_a.contains(id));
    }
    for id in &ids[95..100] {
        assert!(in_b.contains(id));
    }
}

#[test]
fn test_iblt_identical() {
    let mut sketch_a = IbltSketch::new(Tier::Small.cell_count());
    let mut sketch_b = IbltSketch::new(Tier::Small.cell_count());

    let mut id = [0u8; 32];
    thread_rng().fill_bytes(&mut id);
    let id = NodeHash::from(id);

    sketch_a.insert(id.as_ref());
    sketch_b.insert(id.as_ref());

    sketch_a.subtract(&sketch_b).unwrap();
    let (in_a, in_b, _) = sketch_a.decode().unwrap();

    assert!(in_a.is_empty());
    assert!(in_b.is_empty());
}

#[test]
fn test_iblt_overflow() {
    let mut sketch_a = IbltSketch::new(Tier::Tiny.cell_count());
    let sketch_b = IbltSketch::new(Tier::Tiny.cell_count());

    // Insert 50 differences into a Tiny sketch (capacity ~10)
    for _ in 0..50 {
        let mut id_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut id_bytes);
        let id = NodeHash::from(id_bytes);
        sketch_a.insert(id.as_ref());
    }

    sketch_a.subtract(&sketch_b).unwrap();
    let res = sketch_a.decode();
    assert!(res.is_err());
}

#[test]
fn test_iblt_tiers_capacity() {
    let tiers = [
        (Tier::Tiny, 5),
        (Tier::Small, 35),
        (Tier::Medium, 150),
        (Tier::Large, 600),
    ];

    for (tier, diff_count) in tiers {
        let mut sketch_a = IbltSketch::new(tier.cell_count());
        let sketch_b = IbltSketch::new(tier.cell_count());
        let mut ids = Vec::new();

        for _ in 0..diff_count {
            let mut id = [0u8; 32];
            thread_rng().fill_bytes(&mut id);
            ids.push(NodeHash::from(id));
            sketch_a.insert(&id);
        }

        sketch_a.subtract(&sketch_b).unwrap();
        let (in_a, in_b, _) = sketch_a
            .decode()
            .unwrap_or_else(|_| panic!("Failed to decode tier {:?}", tier));
        assert_eq!(in_a.len(), diff_count);
        assert!(in_b.is_empty());
    }
}

#[test]
fn test_iblt_remove() {
    let mut sketch = IbltSketch::new(Tier::Small.cell_count());
    let mut id = [0u8; 32];
    thread_rng().fill_bytes(&mut id);
    let id = NodeHash::from(id);

    sketch.insert(id.as_ref());
    sketch.remove(id.as_ref());

    let (in_a, in_b, _) = sketch.decode().unwrap();
    assert!(in_a.is_empty());
    assert!(in_b.is_empty());
}

#[test]
fn test_iblt_mismatched_sizes() {
    let mut sketch_a = IbltSketch::new(Tier::Small.cell_count());
    let sketch_b = IbltSketch::new(Tier::Tiny.cell_count());

    let res = sketch_a.subtract(&sketch_b);
    assert!(matches!(
        res,
        Err(tox_reconcile::iblt::ReconciliationError::InvalidSketch)
    ));
}

#[test]
fn test_iblt_conversion() {
    let mut sketch = IbltSketch::new(Tier::Tiny.cell_count());
    let mut id = [0u8; 32];
    thread_rng().fill_bytes(&mut id);
    let id = NodeHash::from(id);
    sketch.insert(id.as_ref());

    let cells = sketch.into_cells();
    assert_eq!(cells.len(), Tier::Tiny.cell_count());

    let mut sketch_rebuilt = IbltSketch::from_cells(cells);
    // To verify it works, we should be able to decode it (finding the inserted element)
    // But decode returns diffs.
    // If we subtract an empty sketch from it, we should find the element.
    let empty_sketch = IbltSketch::new(Tier::Tiny.cell_count());
    sketch_rebuilt.subtract(&empty_sketch).unwrap();
    let (in_a, in_b, _) = sketch_rebuilt.decode().unwrap();

    assert_eq!(in_a.len(), 1);
    assert!(in_b.is_empty());
    assert_eq!(in_a[0], id);
}

#[test]
fn test_sync_sketch_serialization() {
    let mut cells = vec![IbltCell::default(); Tier::Tiny.cell_count()];
    // Modify one cell to make it interesting
    cells[0].count = 1;
    cells[0].hash_sum = 123456789;

    let sketch = SyncSketch {
        conversation_id: ConversationId::from([1u8; 32]),
        cells: cells.clone(),
        range: SyncRange {
            epoch: 10,
            min_rank: 100,
            max_rank: 200,
        },
    };

    let serialized = serialize(&sketch).expect("Serialization failed");
    let deserialized: SyncSketch = deserialize(&serialized).expect("Deserialization failed");

    assert_eq!(sketch, deserialized);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn test_iblt_proptest(
        common in prop::collection::vec(prop::array::uniform32(0u8..), 0..50),
        a_only in prop::collection::vec(prop::array::uniform32(0u8..), 0..10),
        b_only in prop::collection::vec(prop::array::uniform32(0u8..), 0..10),
    ) {
        let mut sketch_a = IbltSketch::new(Tier::Medium.cell_count());
        let mut sketch_b = IbltSketch::new(Tier::Medium.cell_count());

        // Ensure all IDs are unique for the test logic
        let mut all_ids = std::collections::HashSet::new();
        let a_only_filtered: Vec<_> = a_only.into_iter().filter(|id| all_ids.insert(*id)).collect();
        let b_only_filtered: Vec<_> = b_only.into_iter().filter(|id| all_ids.insert(*id)).collect();
        let _common_filtered: Vec<_> = common.into_iter().filter(|id| all_ids.insert(*id)).collect();

        for id in &_common_filtered {
            sketch_a.insert(id);
            sketch_b.insert(id);
        }

        for id in &a_only_filtered {
            sketch_a.insert(id);
        }

        for id in &b_only_filtered {
            sketch_b.insert(id);
        }

        sketch_a.subtract(&sketch_b).unwrap();
        let (in_a, in_b, _) = sketch_a.decode().unwrap();

        prop_assert_eq!(in_a.len(), a_only_filtered.len());
        prop_assert_eq!(in_b.len(), b_only_filtered.len());

        for id in &a_only_filtered {
            prop_assert!(in_a.contains(&NodeHash::from(*id)));
        }
        for id in &b_only_filtered {
            prop_assert!(in_b.contains(&NodeHash::from(*id)));
        }
    }
}
