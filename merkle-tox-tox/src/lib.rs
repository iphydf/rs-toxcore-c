use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk};
use merkle_tox_core::error::MerkleToxResult;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::{ProtocolMessage, Transport, TransportError};
use parking_lot::ReentrantMutex;
use std::sync::Arc;
use std::time::Instant;
use toxcore::tox::Tox;
use toxcore::tox::events::Event;
use toxcore::types::PublicKey as ToxPublicKey;
use tracing::info;

pub const TOX_CUSTOM_PACKET_ID: u8 = 200;

/// A transport implementation that uses real Tox custom packets.
#[derive(Clone)]
pub struct ToxTransport {
    pub tox: Arc<ReentrantMutex<Tox>>,
}

impl Transport for ToxTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        PhysicalDevicePk::from(self.tox.lock().public_key().0)
    }

    fn send_raw(&self, to: PhysicalDevicePk, mut data: Vec<u8>) -> Result<(), TransportError> {
        let tox = self.tox.lock();
        let friend = tox
            .lookup_friend(&ToxPublicKey(*to.as_bytes()))
            .map_err(|_| TransportError::PeerNotFound(hex::encode(to.as_bytes())))?;

        data.insert(0, TOX_CUSTOM_PACKET_ID);
        friend
            .send_lossy_packet(&data)
            .map_err(|e| TransportError::Other(format!("{:?}", e)))?;
        Ok(())
    }
}

/// A bridge between the Tox network and the Merkle-Tox engine.
pub struct ToxMerkleBridge<S: NodeStore + BlobStore> {
    pub node: MerkleToxNode<ToxTransport, S>,
}

impl<S: NodeStore + BlobStore> ToxMerkleBridge<S> {
    pub fn new(tox: Tox, store: S) -> Self {
        let self_pk = PhysicalDevicePk::from(tox.public_key().0);
        let transport = ToxTransport {
            tox: Arc::new(ReentrantMutex::new(tox)),
        };
        let engine = merkle_tox_core::engine::MerkleToxEngine::new(
            self_pk,
            self_pk.to_logical(),
            rand::SeedableRng::from_entropy(),
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        let node = MerkleToxNode::new(
            engine,
            transport,
            store,
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        Self { node }
    }

    /// Initiates history synchronization for a conversation with a specific friend.
    pub fn start_sync(
        &mut self,
        friend_pk: PhysicalDevicePk,
        conversation_id: ConversationId,
    ) -> MerkleToxResult<()> {
        let effects =
            self.node
                .engine
                .start_sync(conversation_id, Some(friend_pk), &self.node.store);

        let now = self.node.time_provider.now_instant();
        let now_ms = self.node.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            let _ = self
                .node
                .process_effect(effect, now, now_ms, &mut dummy_wakeup);
        }

        Ok(())
    }

    /// Offers a single Tox event to the bridge for processing.
    /// Returns true if the bridge handled the event.
    pub fn handle_event(&mut self, event: &Event) -> bool {
        match event {
            Event::FriendConnectionStatus(e) => {
                let status = e.connection_status();
                if status != toxcore::tox::ToxConnection::TOX_CONNECTION_NONE {
                    let pk = {
                        let tox = self.node.transport.tox.lock();
                        tox.friend(e.friend_number()).public_key().ok().map(|p| p.0)
                    };
                    if let Some(pk) = pk {
                        info!("Tox friend connected, initiating MT handshake");
                        let caps = ProtocolMessage::CapsAnnounce {
                            version: 1,
                            features: 0,
                        };
                        self.node.send_message(PhysicalDevicePk::from(pk), caps);
                        return true;
                    }
                }
            }
            Event::FriendLossyPacket(e) => {
                let data = e.data();
                if data.first() == Some(&TOX_CUSTOM_PACKET_ID) {
                    let pk = {
                        let tox = self.node.transport.tox.lock();
                        tox.friend(e.friend_number()).public_key().ok().map(|p| p.0)
                    };
                    if let Some(pk) = pk {
                        self.node
                            .handle_packet(PhysicalDevicePk::from(pk), &data[1..]);
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Background polling for retransmissions and pacing.
    /// Returns the next scheduled wakeup time.
    pub fn poll(&mut self) -> Instant {
        self.node.poll()
    }
}
