use criterion::{Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::VecDeque;
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tox_sequenced::protocol::{MessageType, Packet};
use tox_sequenced::{Algorithm, AlgorithmType, SequenceSession, SessionEvent};

struct NetSim {
    latency: Duration,
    loss_rate: f32,
    jitter: Duration,
    rng: StdRng,
    wire: VecDeque<(Instant, Packet)>,
}

impl NetSim {
    fn new(latency: Duration, loss_rate: f32, jitter: Duration) -> Self {
        Self {
            latency,
            loss_rate,
            jitter,
            rng: StdRng::seed_from_u64(42),
            wire: VecDeque::new(),
        }
    }

    fn send(&mut self, packet: Packet, now: Instant) {
        if self.loss_rate > 0.0 && self.rng.r#gen::<f32>() < self.loss_rate {
            return;
        }

        let mut delivery_time = now + self.latency;
        if !self.jitter.is_zero() {
            let j = self.rng.gen_range(0..self.jitter.as_micros() as u64);
            delivery_time += Duration::from_micros(j);
        }

        self.wire.push_back((delivery_time, packet));
    }

    fn receive(&mut self, now: Instant) -> Vec<Packet> {
        let mut ready = Vec::new();
        let mut i = 0;
        while i < self.wire.len() {
            if self.wire[i].0 <= now {
                ready.push(self.wire.remove(i).unwrap().1);
            } else {
                i += 1;
            }
        }
        ready
    }
}

fn run_session_transfer(
    data_size: usize,
    messages_count: usize,
    latency: Duration,
    loss_rate: f32,
    jitter: Duration,
    algo: AlgorithmType,
) {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::SystemTimeProvider);
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rng.clone()),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let mut a_to_b = NetSim::new(latency, loss_rate, jitter);
    let mut b_to_a = NetSim::new(latency, 0.0, Duration::ZERO);

    let msg_data = vec![0u8; data_size / messages_count.max(1)];
    for _ in 0..messages_count {
        alice
            .send_auto(MessageType::MerkleNode, &msg_data, now)
            .unwrap();
    }

    let start = now;
    let mut now = now;
    let timeout = Duration::from_secs(10);
    let mut completed = 0;

    while completed < messages_count && now.duration_since(start) < timeout {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Alice flushes outgoing
        alice.flush(now, now_ms, &mut |packet| {
            a_to_b.send(packet, now);
            true
        });

        // Bob receives from Alice
        for p in a_to_b.receive(now) {
            let replies = bob.handle_packet(p, now);
            for r in replies {
                b_to_a.send(r, now);
            }
        }

        // Bob flushes (ACKs)
        bob.flush(now, now_ms, &mut |packet| {
            b_to_a.send(packet, now);
            true
        });

        // Count received messages
        while let Some(event) = bob.poll_event() {
            match event {
                SessionEvent::DataReceived(..) | SessionEvent::MessageCompleted(..) => {
                    completed += 1;
                }
                _ => {}
            }
        }

        // Alice receives ACKs
        for p in b_to_a.receive(now) {
            let _replies = alice.handle_packet(p, now);
        }

        alice.cleanup(now);
        bob.cleanup(now);

        now += Duration::from_millis(1);
    }

    if completed < messages_count {
        panic!(
            "Benchmark timed out: completed {}/{}",
            completed, messages_count
        );
    }
}

fn bench_session_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_transfer");

    for &algo in AlgorithmType::ALL_TYPES {
        // Small single-packet DATA transfers
        group.bench_function(format!("data_1kb_clean_{}", algo), |b| {
            b.iter(|| {
                run_session_transfer(
                    black_box(1000),
                    black_box(10),
                    Duration::from_millis(10),
                    0.0,
                    Duration::ZERO,
                    black_box(algo),
                )
            })
        });

        // Fragmented transfer
        group.bench_function(format!("frag_100kb_clean_{}", algo), |b| {
            b.iter(|| {
                run_session_transfer(
                    black_box(100_000),
                    black_box(1),
                    Duration::from_millis(10),
                    0.0,
                    Duration::ZERO,
                    black_box(algo),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_session_scenarios);
criterion_main!(benches);
