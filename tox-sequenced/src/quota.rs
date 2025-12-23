pub use crate::protocol::Priority;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tox_proto::ToxProto;

/// Manages a shared memory budget for message reassembly across multiple sessions.
///
/// This provides global bounds on memory usage and proportional back-pressure
/// by allowing sessions to calculate their receive window based on global availability.
///
/// Admission control is based on a **Priority** system:
/// - `Critical` messages can use up to 99% of the quota.
/// - `Standard` messages are capped at 90%.
/// - `Bulk` transfers (like large files) are capped at 70%.
///
/// This ensures that a large file download cannot block small, critical chat messages
/// or protocol handshakes.
#[derive(Debug, ToxProto)]
pub struct ReassemblyQuota {
    max_bytes: usize,
    #[tox(skip)]
    used_bytes: Arc<AtomicUsize>,
}

impl ReassemblyQuota {
    /// Creates a new quota with the specified maximum total bytes.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            used_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Attempts to reserve `amount` bytes with a specific priority.
    ///
    /// Higher priority requests have higher thresholds for admission.
    pub fn reserve(&self, amount: usize, priority: Priority) -> bool {
        let threshold = match priority {
            Priority::Bulk => self.max_bytes * 70 / 100,
            Priority::Low => self.max_bytes * 80 / 100,
            Priority::Standard => self.max_bytes * 90 / 100,
            Priority::High => self.max_bytes * 95 / 100,
            Priority::Critical => self.max_bytes * 99 / 100,
        };

        loop {
            let current = self.used_bytes.load(Ordering::Relaxed);
            if current + amount > threshold {
                return false;
            }
            if self
                .used_bytes
                .compare_exchange(
                    current,
                    current + amount,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Attempts to reserve `amount` bytes, bypassing priority thresholds but
    /// still respecting the hard maximum capacity.
    ///
    /// Used for "Fair-Share" guarantees to ensure basic connectivity even under load.
    pub fn reserve_guaranteed(&self, amount: usize) -> bool {
        loop {
            let current = self.used_bytes.load(Ordering::Relaxed);
            if current + amount > self.max_bytes {
                return false;
            }
            if self
                .used_bytes
                .compare_exchange(
                    current,
                    current + amount,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Releases `amount` bytes back to the quota.
    pub fn release(&self, amount: usize) {
        loop {
            let current = self.used_bytes.load(Ordering::Relaxed);
            let new = current.saturating_sub(amount);
            if self
                .used_bytes
                .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Returns the number of bytes currently available in the global pool.
    pub fn available(&self) -> usize {
        self.max_bytes
            .saturating_sub(self.used_bytes.load(Ordering::Relaxed))
    }

    /// Returns the total capacity of the quota.
    pub fn capacity(&self) -> usize {
        self.max_bytes
    }

    /// Returns the number of bytes currently used.
    pub fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Relaxed)
    }
}

impl Clone for ReassemblyQuota {
    fn clone(&self) -> Self {
        Self {
            max_bytes: self.max_bytes,
            used_bytes: Arc::clone(&self.used_bytes),
        }
    }
}
