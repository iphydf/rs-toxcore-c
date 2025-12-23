use crate::Transport;
use crate::dag::PhysicalDevicePk;
use crate::testing::hub::VirtualHub;
use crossbeam::channel::Receiver;
use std::sync::Arc;
use tracing::{debug, error};

pub const TOX_BRIDGED_PACKET_ID: u8 = 201;

/// A bridge between a VirtualHub simulation and a real-world Transport.
pub struct MerkleToxGateway<T: Transport> {
    pub hub: Arc<VirtualHub>,
    pub real_transport: T,
    promotion_rx: Receiver<(PhysicalDevicePk, PhysicalDevicePk, Vec<u8>)>,
}

impl<T: Transport> MerkleToxGateway<T> {
    pub fn new(hub: Arc<VirtualHub>, real_transport: T) -> Self {
        let promotion_rx = hub.register_gateway();
        Self {
            hub,
            real_transport,
            promotion_rx,
        }
    }

    /// Processes pending packets in both directions.
    /// This should be called regularly in the simulation loop.
    pub fn poll(&self) {
        // 1. Promotion: Hub -> Real World
        while let Ok((from, to, data)) = self.promotion_rx.try_recv() {
            debug!("Gateway Promoting: {:?} -> {:?}", from, to);

            // Wrap in a bridged packet so the recipient knows who it's for
            let mut bridged = vec![TOX_BRIDGED_PACKET_ID];
            bridged.extend_from_slice(to.as_bytes());
            bridged.extend_from_slice(&data);

            if let Err(e) = self.real_transport.send_raw(to, bridged) {
                error!("Gateway promotion failed: {}", e);
            }
        }
    }

    /// Handles an incoming bridged packet from the real world.
    pub fn handle_bridged_packet(&self, from: PhysicalDevicePk, data: &[u8]) {
        if data.len() < 32 {
            return;
        }
        let mut to = [0u8; 32];
        to.copy_from_slice(&data[..32]);
        let inner_data = &data[32..];

        debug!("Gateway Bridged Demote: {:?} -> {:?}", from, to);
        self.hub
            .inject(from, PhysicalDevicePk::from(to), inner_data.to_vec());
    }

    /// Demotes a packet from the real world into the virtual hub.
    pub fn demote(&self, from: PhysicalDevicePk, to: PhysicalDevicePk, data: Vec<u8>) {
        debug!("Gateway Demoting: {:?} -> {:?}", from, to);
        self.hub.inject(from, to, data);
    }
}
