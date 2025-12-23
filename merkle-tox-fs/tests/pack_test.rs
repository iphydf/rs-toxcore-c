use merkle_tox_core::dag::NodeHash;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::pack::{DEFAULT_FANOUT_BITS, IndexRecord, PackIndex};
use tempfile::TempDir;

#[test]
fn test_pack_index_build_lookup() {
    let mut records = Vec::new();
    let h1 = NodeHash::from([0x00u8; 32]);
    let h2 = NodeHash::from([0x01u8; 32]);
    let h3 = NodeHash::from([0xFFu8; 32]);

    records.push(IndexRecord {
        hash: h2,
        offset: 200,
        rank: 1,
        payload_length: 60,
        node_type: 2,
        status: 1,
        flags: 0,
    });
    records.push(IndexRecord {
        hash: h1,
        offset: 100,
        rank: 0,
        payload_length: 50,
        node_type: 1,
        status: 1,
        flags: 0,
    });
    records.push(IndexRecord {
        hash: h3,
        offset: 300,
        rank: 2,
        payload_length: 70,
        node_type: 2,
        status: 1,
        flags: 0,
    });

    let index = PackIndex::build(records, 8, 2);

    assert_eq!(index.records.len(), 3);
    assert_eq!(index.records[0].hash, h1);
    assert_eq!(index.records[1].hash, h2);
    assert_eq!(index.records[2].hash, h3);

    let r1 = index.lookup(&h1).unwrap();
    assert_eq!(r1.offset, 100);
    assert_eq!(r1.payload_length, 50);

    let r2 = index.lookup(&h2).unwrap();
    assert_eq!(r2.offset, 200);
    assert_eq!(r2.payload_length, 60);

    let r3 = index.lookup(&h3).unwrap();
    assert_eq!(r3.offset, 300);
    assert_eq!(r3.payload_length, 70);

    assert!(index.lookup(&NodeHash::from([0x77u8; 32])).is_none());
}

#[test]
fn test_pack_index_save_load() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = StdFileSystem;
    let path = tmp_dir.path().join("test.idx");

    let h1 = NodeHash::from([1u8; 32]);
    let h2 = NodeHash::from([2u8; 32]);
    let records = vec![
        IndexRecord {
            hash: h1,
            offset: 10,
            rank: 0,
            payload_length: 100,
            node_type: 1,
            status: 1,
            flags: 0,
        },
        IndexRecord {
            hash: h2,
            offset: 20,
            rank: 1,
            payload_length: 200,
            node_type: 2,
            status: 1,
            flags: 0,
        },
    ];

    let index = PackIndex::build(records, DEFAULT_FANOUT_BITS, 2);
    index.save(&fs, &path).unwrap();

    let loaded = PackIndex::load(&fs, &path).unwrap();
    assert_eq!(loaded.records.len(), 2);
    assert_eq!(loaded.fanout_bits, index.fanout_bits);
    assert_eq!(loaded.bloom_k, index.bloom_k);
    assert_eq!(loaded.records[0].hash, h1);
    assert_eq!(loaded.records[0].payload_length, 100);
    assert_eq!(loaded.records[1].hash, h2);
    assert_eq!(loaded.records[1].payload_length, 200);
}
