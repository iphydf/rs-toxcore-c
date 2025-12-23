use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::dag::{ConversationId, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::engine::session::PeerSession;
use merkle_tox_core::testing::InMemoryStore;
use proptest::prelude::*;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

fn arb_protocol_message() -> impl Strategy<Value = ProtocolMessage> {
    prop_oneof![
        any::<u32>().prop_map(|v| ProtocolMessage::CapsAnnounce {
            version: v,
            features: 0
        }),
        any::<u32>().prop_map(|v| ProtocolMessage::CapsAck {
            version: v,
            features: 0
        }),
        any::<Vec<[u8; 32]>>().prop_map(|heads| ProtocolMessage::SyncHeads(
            merkle_tox_core::sync::SyncHeads {
                conversation_id: ConversationId::from([0; 32]),
                heads: heads.into_iter().map(NodeHash::from).collect(),
                flags: 0,
            }
        )),
        any::<[u8; 32]>().prop_map(|hash| ProtocolMessage::BlobQuery(NodeHash::from(hash))),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_engine_robustness(messages in prop::collection::vec(arb_protocol_message(), 1..20)) {
        let tp = Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(Instant::now(), 0));
        let self_pk = PhysicalDevicePk::from([1; 32]);
        let mut engine = MerkleToxEngine::new(self_pk, self_pk.to_logical(), rand::rngs::StdRng::seed_from_u64(0), tp);
        let store = InMemoryStore::new();
        let conv_id = ConversationId::from([0; 32]);

        let sender_pk = PhysicalDevicePk::from([2; 32]);
        engine.start_sync(conv_id, Some(sender_pk), &store);

        for msg in messages {
            let _ = engine.handle_message(sender_pk, msg, &store, None);
        }
    }

    #[test]
    fn test_handshake_transition_property(
        has_announce in any::<bool>(),
        has_ack in any::<bool>(),
        other_messages in prop::collection::vec(arb_protocol_message(), 0..10)
    ) {
        let tp = Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(Instant::now(), 0));
        let self_pk = PhysicalDevicePk::from([1; 32]);
        let mut engine = MerkleToxEngine::new(self_pk, self_pk.to_logical(), rand::rngs::StdRng::seed_from_u64(0), tp);
        let store = InMemoryStore::new();
        let conv_id = ConversationId::from([0; 32]);

        let sender_pk = PhysicalDevicePk::from([2; 32]);
        engine.start_sync(conv_id, Some(sender_pk), &store);

        let mut transitioned = false;

        if has_announce {
            let _ = engine.handle_message(sender_pk, ProtocolMessage::CapsAnnounce { version: 1, features: 0 }, &store, None);
            transitioned = true;
        }
        if has_ack {
            let _ = engine.handle_message(sender_pk, ProtocolMessage::CapsAck { version: 1, features: 0 }, &store, None);
            transitioned = true;
        }

        for msg in other_messages {
            println!("Handling message: {:?}", msg);
            if matches!(msg, ProtocolMessage::CapsAnnounce { .. }
                | ProtocolMessage::CapsAck { .. }
                | ProtocolMessage::SyncHeads(_)
                | ProtocolMessage::SyncSketch(_)
                | ProtocolMessage::SyncShardChecksums { .. }
            ) {
                println!("  Message triggers transition");
                transitioned = true;
            }
            let _ = engine.handle_message(sender_pk, msg, &store, None);
        }

        let session = engine.sessions.get(&(sender_pk, conv_id)).unwrap();
        if transitioned {
            prop_assert!(matches!(session, PeerSession::Active(_)));
        } else {
            prop_assert!(matches!(session, PeerSession::Handshake(_)));
        }
    }
}
// end of file
