use std::fmt::Debug;
use std::time::{Duration, Instant};
pub use tox_proto::{SystemTimeProvider, TimeProvider};

use tox_proto::ToxProto;

/// A manual time provider for deterministic simulations.
#[derive(Debug, ToxProto)]
pub struct ManualTimeProvider {
    instant: std::sync::RwLock<Instant>,
    system_ms: std::sync::RwLock<i64>,
}

impl ManualTimeProvider {
    pub fn new(instant: Instant, system_ms: i64) -> Self {
        Self {
            instant: std::sync::RwLock::new(instant),
            system_ms: std::sync::RwLock::new(system_ms),
        }
    }

    pub fn set_time(&self, instant: Instant, system_ms: i64) {
        *self.instant.write().unwrap() = instant;
        *self.system_ms.write().unwrap() = system_ms;
    }

    pub fn advance(&self, duration: Duration) {
        *self.instant.write().unwrap() += duration;
        *self.system_ms.write().unwrap() += duration.as_millis() as i64;
    }
}

impl TimeProvider for ManualTimeProvider {
    fn now_instant(&self) -> Instant {
        *self.instant.read().unwrap()
    }

    fn now_system_ms(&self) -> i64 {
        *self.system_ms.read().unwrap()
    }
}
