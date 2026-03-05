//! Adversarial coverage for over-cap wire arrays on the merkle-tox
//! sync surface.
//!
//! `SyncHeads.heads` (cap `MAX_HEADS_SYNC = 64`),
//! `FetchBatchReq.hashes` (cap `MAX_BATCH_SIZE = 64`), and
//! `ProtocolMessage::SyncShardChecksums.shards`
//! (cap `MAX_SYNC_SHARDS = 4096`) are all peer-controlled wire arrays
//! with documented caps that, prior to the BoundedVec migration, were
//! enforced only at the *writer* side (`truncate(MAX_*)` after the
//! fact) or at the *handler* side (post-deserialise reject of the
//! whole packet). The wire deserialiser itself accepted any length.
//!
//! That left a privilege-amplification surface: an authenticated peer
//! can craft a packet whose array claims thousands of entries, the
//! deserialiser allocates and parses every one of them, then either
//! the writer-side truncate silently drops the surplus (heads /
//! hashes) or the handler-side check rejects the whole packet
//! (shards). In both cases the receiver has already paid the
//! per-element parse cost — a 4 KB inbound packet can demand tens of
//! ms of allocation + per-entry deserialise + checksum work, then be
//! discarded.
//!
//! After migrating these fields to `BoundedVec<T, N>`, the
//! `ToxDeserialize` impl rejects any array whose declared length
//! exceeds `N` *before* allocating or parsing a single element.
//! These tests pin that boundary by serialising oversize wire bytes
//! through "forge" structs that mirror the real types' wire shape but
//! use unbounded `Vec`, then asserting deserialisation as the real
//! type errors out.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobFetch, BlobProgress, MAX_BLOB_PROGRESS_RANGES};
use merkle_tox_core::dag::{ConversationId, NodeHash, ShardHash};
use merkle_tox_core::sync::{FetchBatchReq, SyncHeads};
use tox_proto::ToxProto;
use tox_proto::constants::{MAX_BATCH_SIZE, MAX_HEADS_SYNC, MAX_SYNC_SHARDS};
use tox_reconcile::SyncRange;

/// Wire-shape twin of `SyncHeads` using an unbounded `Vec` so we can
/// craft over-cap payloads at serialise time. Field order, types, and
/// ToxProto derive must match `merkle_tox_core::sync::SyncHeads`
/// byte-for-byte, otherwise the deserialiser would fail for the wrong
/// reason.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct SyncHeadsForge {
    conversation_id: ConversationId,
    heads: Vec<NodeHash>,
    flags: u64,
    anchor_hash: Option<NodeHash>,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct FetchBatchReqForge {
    conversation_id: ConversationId,
    hashes: Vec<NodeHash>,
}

/// Wire-shape twin of the `SyncShardChecksums` variant of
/// `ProtocolMessage`. We serialise the variant by wrapping in our own
/// enum that uses identical encoding.
#[derive(Debug, Clone, ToxProto, PartialEq)]
enum ProtocolMessageForge {
    /// Pad the variant index to match `ProtocolMessage::SyncShardChecksums`
    /// at offset 4 in the original enum (CapsAnnounce, CapsAck, SyncHeads,
    /// SyncSketch, SyncShardChecksums). We don't actually need to send
    /// the earlier variants — we just need the *index* to line up so the
    /// real deserialiser routes our bytes to the right arm. This means
    /// the test pins both the variant's array cap and the enum's wire
    /// discrimination simultaneously.
    Variant0,
    Variant1,
    Variant2,
    Variant3,
    SyncShardChecksums {
        conversation_id: ConversationId,
        shards: Vec<(SyncRange, ShardHash)>,
    },
}

#[test]
fn sync_heads_with_oversize_heads_array_is_rejected_at_deserialize() {
    let forge = SyncHeadsForge {
        conversation_id: ConversationId::from([0u8; 32]),
        heads: (0..200u32).map(|i| NodeHash::from([i as u8; 32])).collect(),
        flags: 0,
        anchor_hash: None,
    };
    assert!(forge.heads.len() > MAX_HEADS_SYNC);

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<SyncHeads> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of SyncHeads with {} heads (cap {}) must fail; \
         pre-fix it succeeds via the unbounded Vec deserialiser, \
         turning every authorised peer into a CPU/allocation \
         amplification primitive.",
        forge.heads.len(),
        MAX_HEADS_SYNC,
    );
}

#[test]
fn fetch_batch_req_with_oversize_hashes_array_is_rejected_at_deserialize() {
    let forge = FetchBatchReqForge {
        conversation_id: ConversationId::from([0u8; 32]),
        hashes: (0..200u32).map(|i| NodeHash::from([i as u8; 32])).collect(),
    };
    assert!(forge.hashes.len() > MAX_BATCH_SIZE);

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<FetchBatchReq> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of FetchBatchReq with {} hashes (cap {}) must fail",
        forge.hashes.len(),
        MAX_BATCH_SIZE,
    );
}

#[test]
fn sync_shard_checksums_with_oversize_shards_array_is_rejected_at_deserialize() {
    // Build 8000 shard entries — twice the cap. Each entry is a
    // (SyncRange, ShardHash) tuple.
    let shards: Vec<(SyncRange, ShardHash)> = (0..8000u64)
        .map(|i| {
            (
                SyncRange {
                    min_rank: i,
                    max_rank: i + 1,
                },
                ShardHash::from([0u8; 32]),
            )
        })
        .collect();
    assert!(shards.len() > MAX_SYNC_SHARDS);

    let forge = ProtocolMessageForge::SyncShardChecksums {
        conversation_id: ConversationId::from([0u8; 32]),
        shards: shards.clone(),
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<ProtocolMessage> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of SyncShardChecksums with {} shards (cap {}) must fail",
        shards.len(),
        MAX_SYNC_SHARDS,
    );
}

// Forge mirrors of `BlobFetch` / `BlobProgress` for oversize wire tests.
// Same wire shape, unbounded `Vec` so we can craft over-cap payloads at
// serialise time.

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct BlobFetchForge {
    hash: NodeHash,
    completed_ranges: Option<Vec<(tox_proto::Untrusted<u64>, tox_proto::Untrusted<u64>)>>,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct BlobProgressForge {
    hash: NodeHash,
    completed_ranges: Vec<(tox_proto::Untrusted<u64>, tox_proto::Untrusted<u64>)>,
    incomplete_chunks: Vec<(tox_proto::Untrusted<u64>, Vec<u8>)>,
}

#[test]
fn blob_fetch_with_oversize_completed_ranges_is_rejected_at_deserialize() {
    let forge = BlobFetchForge {
        hash: NodeHash::from([0u8; 32]),
        completed_ranges: Some(
            (0..(MAX_BLOB_PROGRESS_RANGES as u64 * 2))
                .map(|i| {
                    (
                        tox_proto::Untrusted::new(i),
                        tox_proto::Untrusted::new(i + 1),
                    )
                })
                .collect(),
        ),
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<BlobFetch> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of BlobFetch with {} completed_ranges (cap {}) must fail",
        forge.completed_ranges.as_ref().unwrap().len(),
        MAX_BLOB_PROGRESS_RANGES,
    );
}

#[test]
fn blob_progress_with_oversize_completed_ranges_is_rejected_at_deserialize() {
    let ranges: Vec<(tox_proto::Untrusted<u64>, tox_proto::Untrusted<u64>)> = (0
        ..(MAX_BLOB_PROGRESS_RANGES as u64 * 2))
        .map(|i| {
            (
                tox_proto::Untrusted::new(i),
                tox_proto::Untrusted::new(i + 1),
            )
        })
        .collect();
    let forge = BlobProgressForge {
        hash: NodeHash::from([0u8; 32]),
        completed_ranges: ranges.clone(),
        incomplete_chunks: vec![],
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<BlobProgress> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of BlobProgress with {} completed_ranges (cap {}) must fail",
        ranges.len(),
        MAX_BLOB_PROGRESS_RANGES,
    );
}

#[test]
fn blob_progress_with_oversize_incomplete_chunks_is_rejected_at_deserialize() {
    let chunks: Vec<(tox_proto::Untrusted<u64>, Vec<u8>)> = (0..(MAX_BLOB_PROGRESS_RANGES as u64
        * 2))
        .map(|i| (tox_proto::Untrusted::new(i), vec![0xFFu8]))
        .collect();
    let forge = BlobProgressForge {
        hash: NodeHash::from([0u8; 32]),
        completed_ranges: vec![],
        incomplete_chunks: chunks.clone(),
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<BlobProgress> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of BlobProgress with {} incomplete_chunks (cap {}) must fail",
        chunks.len(),
        MAX_BLOB_PROGRESS_RANGES,
    );
}

// `SyncSketch.cells` is the IBLT cell array driving symmetric-difference
// reconciliation. The handler at `merkle-tox-core/src/engine/handlers/
// mod.rs:193` classifies tiers by `Tier::from_cell_count(cells.len())`,
// gates Medium/Large on PoW, and at `:216` charges CPU budget at
// `0.01 * cells.len()`. The wire format had no upper bound on cell
// count, so a 100 000-cell sketch deserialises into a ~5.6 MB
// `Vec<IbltCell>` and runs `O(cells.len())` work BEFORE the PoW gate
// can drop the packet. The fix caps `cells` at `Tier::Large.cell_count()
// = 1024` (the largest legitimate tier) at the type level via
// `BoundedVec<IbltCell, MAX_SKETCH_CELLS>`, so over-cap payloads are
// rejected at the length-prefix check before any cell allocation.

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct SyncSketchForge {
    conversation_id: ConversationId,
    cells: Vec<tox_reconcile::IbltCell>,
    range: SyncRange,
}

#[test]
fn sync_sketch_with_oversize_cells_array_is_rejected_at_deserialize() {
    use tox_reconcile::{IbltCell, MAX_SKETCH_CELLS, SyncSketch};

    // 4096 = 4× the largest legitimate tier (Large = 1024 cells).
    let attack_cell_count: usize = MAX_SKETCH_CELLS * 4;
    let cells: Vec<IbltCell> = (0..attack_cell_count)
        .map(|_| IbltCell::default())
        .collect();
    assert!(cells.len() > MAX_SKETCH_CELLS);

    let forge = SyncSketchForge {
        conversation_id: ConversationId::from([0u8; 32]),
        cells: cells.clone(),
        range: SyncRange {
            min_rank: 0,
            max_rank: 0,
        },
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<SyncSketch> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of SyncSketch with {} cells (cap {}) must fail; \
         pre-fix this is the smoking gun: an authenticated peer can ship \
         100 K-cell sketches that allocate ~5 MB and run O(cells.len()) \
         decode work BEFORE the Tier-based PoW gate at \
         handlers/mod.rs:193 can drop the packet.",
        cells.len(),
        MAX_SKETCH_CELLS,
    );
}

// -- Forward-compat: ProtocolMessage::Unknown catches future variants.
//
// `ProtocolMessage` carries a `#[tox(catch_all)] Unknown` variant so a
// build receiving a wire payload from a newer peer (whose protocol
// added a variant we don't recognise) routes the packet to `Unknown`
// rather than failing deserialisation outright. Without this,
// every old peer drops the entire packet on encountering a single
// unknown discriminant — turning every protocol addition into a
// SemVer-major break for in-flight upgrades.
//
// This test pins the round-trip:
//   1. Construct `Unknown { discriminant: 99, data: <payload> }`.
//   2. Serialise — produces wire bytes whose leading discriminant is
//      99 (not the compile-time index of `Unknown`).
//   3. Deserialise — discriminant 99 is not a known variant, so the
//      catch-all path captures it as `Unknown { discriminant: 99,
//      data: <captured> }`.
//   4. Re-serialise — bit-identical to step 2.
//
// A regression that drops `#[tox(catch_all)]` would make step 3 fail
// (deserialise returns Err on an unknown discriminant), failing this
// test loudly.

#[test]
fn protocol_message_unknown_round_trips_under_catch_all() {
    let payload_bytes = tox_proto::serialize(&42u32).expect("serialize inner payload");
    let original = ProtocolMessage::Unknown {
        discriminant: 99,
        data: payload_bytes.clone(),
    };

    let bytes = tox_proto::serialize(&original).expect("serialize ProtocolMessage::Unknown");
    let restored: ProtocolMessage = tox_proto::deserialize(&bytes).expect(
        "deserialise must accept unknown discriminant via catch_all — \
         a build that errors here has lost forward-compat for newer-peer \
         protocol additions",
    );

    match &restored {
        ProtocolMessage::Unknown { discriminant, data } => {
            assert_eq!(
                *discriminant, 99,
                "catch_all must preserve the wire discriminant"
            );
            assert_eq!(
                data, &payload_bytes,
                "catch_all must preserve the wire payload bytes"
            );
        }
        other => panic!("expected ProtocolMessage::Unknown, got {:?}", other),
    }

    // Bit-identical re-serialisation guarantees a relay can forward
    // an unrecognised packet without distorting it. Not strictly
    // required for our peer-to-peer model, but tightens the
    // round-trip contract for any future relay/proxy code.
    let reserialised = tox_proto::serialize(&restored).expect("re-serialize");
    assert_eq!(
        reserialised, bytes,
        "Unknown serialise must be bit-identical to the original wire bytes"
    );
}

// -- Round 2 wire-cap migration: per-recipient lists in `SnapshotData`,
// `Content::KeyWrap`, `Content::SenderKeyDistribution`,
// `Content::HistoryExport`, `ControlAction::Announcement`. Each is a
// peer-controlled `Vec<T>` whose natural cap is the per-conversation
// device limit (`MAX_GROUP_DEVICES = 4096`) or — for X3DH prekeys —
// the per-announcement handshake budget (`MAX_HANDSHAKES_PER_
// ANNOUNCEMENT = 100`). Pre-fix none of them was bounded at
// deserialise; a malicious admin or peer could ship a node carrying
// an arbitrarily large list and force every recipient through that
// many decrypt / verify / store operations before any signature
// check could reject the node.

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
struct SnapshotDataForge {
    basis_hash: NodeHash,
    members: Vec<merkle_tox_core::dag::MemberInfo>,
    last_seq_numbers: Vec<(merkle_tox_core::dag::PhysicalDevicePk, u64)>,
}

#[test]
fn snapshot_data_with_oversize_members_is_rejected_at_deserialize() {
    use merkle_tox_core::dag::{LogicalIdentityPk, MemberInfo, SnapshotData};
    use tox_proto::constants::MAX_GROUP_DEVICES;

    let attack_count = MAX_GROUP_DEVICES + 1;
    let members: Vec<MemberInfo> = (0..attack_count as u32)
        .map(|i| MemberInfo {
            public_key: LogicalIdentityPk::from([i as u8; 32]),
            role: 0,
            joined_at: 0,
        })
        .collect();

    let forge = SnapshotDataForge {
        basis_hash: NodeHash::from([0u8; 32]),
        members: members.clone(),
        last_seq_numbers: vec![],
    };

    let bytes = tox_proto::serialize(&forge).expect("forge serialise");
    let result: tox_proto::Result<SnapshotData> = tox_proto::deserialize(&bytes);

    assert!(
        result.is_err(),
        "deserialise of SnapshotData with {} members (cap {}) must fail",
        members.len(),
        MAX_GROUP_DEVICES,
    );
}
