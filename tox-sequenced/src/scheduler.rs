use std::collections::VecDeque;
use tox_proto::ToxProto;

/// Number of priority levels (0=Highest, 4=Lowest).
const NUM_PRIORITIES: usize = 5;

/// Default quantums for each priority level.
const DEFAULT_QUANTUMS: [i32; NUM_PRIORITIES] = [
    4096, // P0: Caps (Critical)
    2048, // P1: Sync/Sketch
    1500, // P2: MerkleNode
    1024, // P3: Blob Metadata
    512,  // P4: Blob Data (Bulk)
];

/// A Deficit Round Robin (DRR) scheduler for prioritized packet transmission.
#[derive(Debug, Clone, ToxProto)]
pub struct PriorityScheduler {
    /// Deficit counters for each priority level.
    deficits: [i32; NUM_PRIORITIES],
    /// Configured quantums (weights) for each level.
    quantums: [i32; NUM_PRIORITIES],
    /// Which message IDs are active in each priority level.
    active_queues: [VecDeque<u32>; NUM_PRIORITIES],
    /// Priority levels that have messages and are ready for serving.
    active_levels: VecDeque<usize>,
    /// Whether a level needs a quantum added on its next visit.
    needs_quantum: [bool; NUM_PRIORITIES],
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityScheduler {
    pub fn new() -> Self {
        Self {
            deficits: [0; NUM_PRIORITIES],
            quantums: DEFAULT_QUANTUMS,
            active_queues: Default::default(),
            active_levels: VecDeque::new(),
            needs_quantum: [true; NUM_PRIORITIES],
        }
    }

    pub fn update_message(&mut self, message_id: u32, priority: u8) {
        let p = (priority as usize).min(NUM_PRIORITIES - 1);
        if !self.active_levels.contains(&p) {
            // High priority levels (P0: Caps, P1: Sync) are pushed to the front
            // of the queue to ensure they pre-empt lower priority ones in the
            // DRR cycle, minimizing protocol reconciliation latency.
            if p <= 1 {
                self.active_levels.push_front(p);
            } else {
                self.active_levels.push_back(p);
            }
            self.needs_quantum[p] = true;
        }
        for (i, queue) in self.active_queues.iter_mut().enumerate() {
            if i != p {
                queue.retain(|&id| id != message_id);
            }
        }
        if !self.active_queues[p].contains(&message_id) {
            self.active_queues[p].push_back(message_id);
        }
    }

    pub fn remove_message(&mut self, message_id: u32) {
        for (p, queue) in self.active_queues.iter_mut().enumerate() {
            queue.retain(|&id| id != message_id);
            if queue.is_empty() {
                self.deficits[p] = 0;
                self.active_levels.retain(|&level| level != p);
                self.needs_quantum[p] = true;
            }
        }
    }

    /// Picks the next message ID to send a fragment from.
    ///
    /// The caller provides a closure `is_ready` that returns the size of the
    /// next fragment if the message is ready to send, or `None` otherwise.
    pub fn next_message<F>(&mut self, mut is_ready: F) -> Option<u32>
    where
        F: FnMut(u32) -> Option<usize>,
    {
        let num_active = self.active_levels.len();
        for _ in 0..num_active {
            let p = self.active_levels.pop_front()?;
            let queue = &mut self.active_queues[p];

            if queue.is_empty() {
                self.deficits[p] = 0;
                self.needs_quantum[p] = true;
                continue;
            }

            if self.needs_quantum[p] {
                self.deficits[p] += self.quantums[p];
                self.deficits[p] = self.deficits[p].min(16384);
                self.needs_quantum[p] = false;
            }

            let num_messages = queue.len();
            let mut found_ready = false;
            for _ in 0..num_messages {
                let mid = queue.front().copied().unwrap();
                if let Some(size) = is_ready(mid) {
                    found_ready = true;
                    if self.deficits[p] >= size as i32 {
                        self.deficits[p] -= size as i32;
                        queue.rotate_left(1);

                        if self.deficits[p] > 0 {
                            self.active_levels.push_front(p);
                        } else {
                            self.active_levels.push_back(p);
                            self.needs_quantum[p] = true;
                        }
                        return Some(mid);
                    } else {
                        // Deficit exhausted. Try next level.
                        self.active_levels.push_back(p);
                        self.needs_quantum[p] = true;
                        break;
                    }
                } else {
                    queue.rotate_left(1);
                }
            }

            if !found_ready {
                // Nothing ready in this level, move to back.
                self.active_levels.push_back(p);
                self.needs_quantum[p] = true;
            }
        }
        None
    }
}
