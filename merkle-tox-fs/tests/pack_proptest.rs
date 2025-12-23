use merkle_tox_core::dag::NodeHash;
use merkle_tox_fs::pack::{IndexRecord, RECORD_SIZE};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_index_record_serialization(
        hash in prop::array::uniform32(0u8..),
        offset in 0u64..,
        rank in 0u64..,
        payload_length in 0u32..,
        node_type in 0u8..2,
        status in 0u8..2,
        flags in 0u8..
    ) {
        let record = IndexRecord {
            hash: NodeHash::from(hash),
            offset,
            rank,
            payload_length,
            node_type,
            status,
            flags,
        };

        let mut buf = [0u8; RECORD_SIZE];
        record.to_bytes(&mut buf);
        let decoded = IndexRecord::from_bytes(&buf);

        assert_eq!(record, decoded);
    }
}
