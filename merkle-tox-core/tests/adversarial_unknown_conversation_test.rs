//! Adversarial coverage for handlers that create per-conversation
//! state on receipt of a peer-supplied `conversation_id`.
//!
//! Without a `conversations.contains_key(&conv_id)` gate, any
//! authenticated friend can ship messages naming arbitrary 32-byte
//! conv_ids and force the local node to allocate fresh state per
//! packet. The worst offender is `MerkleNode`: its handler emits
//! `Effect::WriteWireNode(conv_id, hash, node)` which the runner
//! dispatches to the fs-backed store, and `merkle-tox-fs::ensure_conversation`
//! creates a fresh `conversations/<hex>/` tree (3× `create_dir_all`
//! plus `permissions.bin`/`state.bin`/`journal.bin`/`ratchet.bin`/
//! `.lock` opens) for any unseen `conv_id` — disk amplification at
//! line rate.
//!
//! `SyncHeads`/`SyncSketch`/`SyncShardChecksums` and `HandshakeError`
//! share the same structural flaw via `entry((sender, conv_id)).or_insert_with`
//! / `handshake_retry_state.entry((conv_id, sender))` — memory-only
//! OOM, slower but unbounded.
//!
//! All five close on the same gate: drop the message early when
//! `self.conversations` does not contain the peer-supplied `conv_id`.
//! The legitimate flow is unaffected — peers send these messages
//! only inside conversations both sides have explicitly joined
//! (start_sync / load_conversation_state populates the local map).

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ConversationId, Ed25519Signature, KConv, NodeAuth, NodeHash, PhysicalDevicePk, WireFlags,
    WireNode,
};
use merkle_tox_core::engine::{Conversation, Effect, MerkleToxEngine};
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::sync::SyncHeads;
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

struct Fixture {
    engine: MerkleToxEngine,
    store: InMemoryStore,
    sender: PhysicalDevicePk,
    /// A conversation we *have* joined locally (in `engine.conversations`).
    known_conv: ConversationId,
    /// A conversation we have *not* joined — this is the attacker's
    /// vector; messages naming it must be dropped before per-conv
    /// state is allocated.
    unknown_conv: ConversationId,
}

fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let self_pk = PhysicalDevicePk::from([0x01u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        StdRng::seed_from_u64(0xC0FFEE),
        tp,
    );
    let store = InMemoryStore::new();

    let known_conv = ConversationId::from([0xAAu8; 32]);
    let unknown_conv = ConversationId::from([0xBBu8; 32]);

    let established = ConversationData::<Established>::new(
        known_conv,
        KConv::from([0x11u8; 32]),
        1000,
    );
    engine
        .conversations
        .insert(known_conv, Conversation::Established(established));

    Fixture {
        engine,
        store,
        sender: PhysicalDevicePk::from([0x02u8; 32]),
        known_conv,
        unknown_conv,
    }
}

fn empty_wire_node() -> WireNode {
    WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: vec![],
        payload_data: vec![],
        topological_rank: 0,
        flags: WireFlags::ENCRYPTED,
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
    }
}

/// §UC-1 — `MerkleNode` for an unknown `conversation_id` must not
/// emit `WriteWireNode`. Without this gate the runner's fs store
/// runs `ensure_conversation`, creating a fresh on-disk conversation
/// tree per peer-supplied conv_id — single-friend at line rate
/// drives unbounded inode/file growth and the
/// `inner.conversations` HashMap.
#[test]
fn test_merkle_node_for_unknown_conv_does_not_emit_disk_write() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.sender,
            ProtocolMessage::MerkleNode {
                conversation_id: f.unknown_conv,
                hash: NodeHash::from([0xDEu8; 32]),
                node: empty_wire_node(),
            },
            &f.store,
            None,
        )
        .unwrap();

    let write_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteWireNode(_, _, _)))
        .count();
    assert_eq!(
        write_count, 0,
        "MerkleNode for unknown conv_id must not emit WriteWireNode \
         — that effect lands in the fs store and runs \
         ensure_conversation, creating a full conversation tree on \
         disk per peer-supplied 32-byte hash",
    );
}

/// §UC-2 — `MerkleNode` for the known conv_id is the regression
/// guard: the gate must NOT degenerate to "drop everything".
#[test]
fn test_merkle_node_for_known_conv_still_emits_write() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.sender,
            ProtocolMessage::MerkleNode {
                conversation_id: f.known_conv,
                hash: NodeHash::from([0xCDu8; 32]),
                node: empty_wire_node(),
            },
            &f.store,
            None,
        )
        .unwrap();

    let write_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteWireNode(_, _, _)))
        .count();
    assert!(
        write_count > 0,
        "MerkleNode for a known conv_id must still emit \
         WriteWireNode — the fix must not regress to blanket \
         rejection",
    );
}

/// §UC-3 — `SyncHeads` for an unknown `conversation_id` must not
/// create a session entry. Without the gate, `entry((sender,
/// conv_id)).or_insert_with(PeerSession::Handshake(...))` allocates
/// per-peer-supplied conv_id session state (with `remote_heads`,
/// `missing_nodes_*`, etc.) — slower than #1 but unbounded memory.
#[test]
fn test_sync_heads_for_unknown_conv_does_not_create_session() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.sender,
            ProtocolMessage::SyncHeads(SyncHeads {
                conversation_id: f.unknown_conv,
                heads: tox_proto::BoundedVec::new(),
                flags: 0,
                anchor_hash: None,
            }),
            &f.store,
            None,
        )
        .unwrap();

    assert!(
        !f.engine.sessions.contains_key(&(f.sender, f.unknown_conv)),
        "SyncHeads for unknown conv_id must not allocate a session \
         entry — that's the per-peer per-fake-conv memory growth leg",
    );
}

/// §UC-4 — `HandshakeError` for an unknown `conversation_id` must
/// not insert into `handshake_retry_state`. The map grows
/// unboundedly per (peer-supplied conv_id, sender) pair without the
/// gate.
#[test]
fn test_handshake_error_for_unknown_conv_does_not_insert_retry_state() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.sender,
            ProtocolMessage::HandshakeError {
                conversation_id: f.unknown_conv,
                reason: "spam".to_string(),
            },
            &f.store,
            None,
        )
        .unwrap();

    assert!(
        !f.engine
            .handshake_retry_state
            .contains_key(&(f.unknown_conv, f.sender)),
        "HandshakeError for unknown conv_id must not insert into \
         handshake_retry_state — that's a per-fake-conv memory \
         growth vector",
    );
}

/// §UC-5 — Honest `HandshakeError` for the known conv_id still
/// records retry state. Regression guard.
#[test]
fn test_handshake_error_for_known_conv_records_retry_state() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.sender,
            ProtocolMessage::HandshakeError {
                conversation_id: f.known_conv,
                reason: "rotation".to_string(),
            },
            &f.store,
            None,
        )
        .unwrap();

    assert!(
        f.engine
            .handshake_retry_state
            .contains_key(&(f.known_conv, f.sender)),
        "HandshakeError for a known conv_id must still record \
         retry state — the fix must not regress to blanket \
         rejection",
    );
}
