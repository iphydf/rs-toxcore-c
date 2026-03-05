use crate::state::ChatState;
use merkle_tox_core::dag::{PhysicalDevicePk, PublicKey};
use std::time::Duration;

pub trait PolicyHandler: Send + Sync {
    /// Decide whether to automatically authorize a device.
    fn should_authorize(&self, author_pk: &PublicKey, device_pk: &PublicKey) -> bool;

    /// Decide when to perform proactive key rotations.
    fn should_rotate_keys(&self, state: &ChatState) -> bool;

    /// Decide whether to respond to a HandshakePulse by announcing new keys.
    fn should_respond_to_pulse(&self, sender_pk: &PublicKey) -> bool;

    /// Interval between periodic full-sync sweeps with all reachable peers.
    fn full_sync_interval(&self) -> Duration {
        Duration::from_secs(300)
    }

    /// Whether a specific peer should be included in sync operations.
    fn should_sync_with(&self, _peer_pk: &PhysicalDevicePk) -> bool {
        true
    }
}

pub struct DefaultPolicy;

impl PolicyHandler for DefaultPolicy {
    fn should_authorize(&self, author_pk: &PublicKey, device_pk: &PublicKey) -> bool {
        // By default, only auto-authorize if the device PK matches the logical author PK.
        // This is useful for bootstrapping a second device if it's using the same key
        // temporarily, or if the user explicitly configured it.
        author_pk == device_pk
    }

    fn should_rotate_keys(&self, _state: &ChatState) -> bool {
        // Let the engine handle the standard triggers (msg count/time).
        false
    }

    fn should_respond_to_pulse(&self, _sender_pk: &PublicKey) -> bool {
        // By default, always respond to pulse requests to ensure forward secrecy
        // when peers want to initiate a new session.
        true
    }
}
