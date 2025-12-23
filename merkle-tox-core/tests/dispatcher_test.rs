use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::session::{Handshake, PeerSession, SyncSession};
use merkle_tox_core::engine::{Conversation, ConversationData, MerkleToxEngine};
use merkle_tox_core::sync::SyncHeads;
use merkle_tox_core::testing::InMemoryStore;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_sync_heads_dispatcher() {
    let alice_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_pk,
        alice_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();

    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0xBBu8; 32]);
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<
            merkle_tox_core::engine::conversation::Established,
        >::new(conv_id, k_conv, 0)),
    );
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, Instant::now());
    // Explicitly activate for dispatcher test to process SyncHeads
    engine
        .sessions
        .insert((bob_pk, conv_id), PeerSession::Active(session.activate(0)));

    // Receive SyncHeads from Bob
    let heads = SyncHeads {
        conversation_id: conv_id,
        heads: vec![NodeHash::from([0xCCu8; 32])],
        flags: 0,
    };

    let result = engine
        .handle_message(bob_pk, ProtocolMessage::SyncHeads(heads), &store, None)
        .unwrap();
    let responses: Vec<_> = result
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    // Alice should respond with a FetchBatchReq for the missing head
    assert_eq!(responses.len(), 1);
    if let ProtocolMessage::FetchBatchReq(req) = &responses[0] {
        assert_eq!(req.conversation_id, conv_id);
        assert_eq!(req.hashes, vec![NodeHash::from([0xCCu8; 32])]);
    } else {
        panic!("Expected FetchBatchReq");
    }
}
