use crossbeam::channel::{Sender, unbounded};
use rand::{Rng, SeedableRng, thread_rng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, IsTerminal};
use std::panic;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tox_sequenced::{
    Algorithm, AlgorithmType, CongestionControl, MessageType, Packet, SequenceSession, SessionEvent,
};

use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{
        Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row, Sparkline, Table, TableState,
    },
};

/// Benchmark for Tox Sequenced congestion control algorithms.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Duration to run in headless mode (seconds).
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Run in non-interactive mode and print results.
    #[arg(long)]
    headless: bool,

    /// Save final scores to a baseline file.
    #[arg(long)]
    save: Option<String>,

    /// Load baseline scores from a file to compare.
    #[arg(long)]
    load: Option<String>,
}

/// Metrics for a single simulation run.
#[derive(Clone, Default)]
struct RunMetrics {
    duration: Duration,
    total_data_bytes: usize,
    lost_datagrams: usize,
    rtt_samples: Vec<Duration>,
    message_latencies: Vec<Duration>,
    is_completed: bool,
    debug_state: String,
}

impl RunMetrics {
    fn throughput_mbps(&self) -> f32 {
        if self.duration.is_zero() {
            return 0.0;
        }
        (self.total_data_bytes as f32 * 8.0) / self.duration.as_secs_f32() / 1_000_000.0
    }

    fn loss_rate(&self) -> f32 {
        let total = self.total_data_bytes + self.lost_datagrams;
        if total == 0 {
            return 0.0;
        }
        (self.lost_datagrams as f32 / total as f32) * 100.0
    }

    fn rtt_percentiles(&self) -> (Duration, Duration) {
        if self.rtt_samples.is_empty() {
            return (Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = self.rtt_samples.clone();
        sorted.sort();
        let p50 = sorted[sorted.len() / 2];
        let p99 = sorted[(sorted.len() * 99 / 100).min(sorted.len() - 1)];
        (p50, p99)
    }

    fn msg_lat_percentiles(&self) -> (Duration, Duration) {
        if self.message_latencies.is_empty() {
            return (Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = self.message_latencies.clone();
        sorted.sort();
        let p50 = sorted[sorted.len() / 2];
        let p99 = sorted[(sorted.len() * 99 / 100).min(sorted.len() - 1)];
        (p50, p99)
    }

    fn calculate_score(&self, s: &Scenario) -> f32 {
        let (_rtt_p50, rtt_p99) = self.rtt_percentiles();

        // 1. Goodput (Actual useful data rate)
        let goodput = self.throughput_mbps().max(0.0);
        // We define a "good enough" sync speed target (e.g. 2Mbps)
        let target_bw = s.bandwidth.map(|b| b / 1_000_000.0).unwrap_or(2.0);

        // Goodput Score: Logarithmic utility. Diminishing returns after target_bw.
        let goodput_score = (1.0 + goodput).ln() / (1.0 + target_bw).ln() * 100.0;

        // 2. Bufferbloat Penalty (p99 RTT)
        // Chat apps need to remain responsive. If p99 RTT >> base RTT, penalize.
        let base_rtt = (s.latency * 2).as_secs_f32();
        let bloat_factor = rtt_p99.as_secs_f32() / base_rtt.max(0.01);

        // Bloat penalty: 1.0 multiplier if bloat < 1.5x base, decaying as bloat increases.
        // Penalty starts becoming significant after 2x bloat.
        let bloat_penalty = 1.0 / (1.0 + (bloat_factor - 1.5).max(0.0).powi(2) / 4.0);

        // 3. Combine Goodput and Bloat
        let mut final_score = goodput_score * bloat_penalty;

        // 4. INTERACTIVE Scenario (Message Latency Focus)
        if s.messages_count > 1 {
            let (_msg_p50, msg_p99) = self.msg_lat_percentiles();
            if msg_p99.is_zero() {
                final_score = 0.0;
            } else {
                // For chat, we care about the worst-case (p99) message delivery time.
                // Target: < 300ms for "snappy" feel.
                let lat_score = 100.0 / (1.0 + (msg_p99.as_secs_f32() / 0.3).powi(2));
                // Interactive score is a weighted blend favoring latency (70%) over goodput (30%)
                final_score = (final_score * 0.3) + (lat_score * 0.7);
            }
        }

        // 5. Penalize incomplete runs (e.g. stalled or timed out)
        let data_ratio = (self.total_data_bytes as f32 / s.data_size as f32).min(1.0);
        final_score *= data_ratio;

        final_score
    }
}

/// Aggregated metrics for multiple runs.
struct AggregatedMetrics {
    scenario_index: usize,
    algo: AlgorithmType,
    runs: usize,
    total_duration: Duration,
    total_data_bytes: usize,
    total_lost_datagrams: usize,
    rtt_samples: VecDeque<Duration>,
    msg_lat_samples: VecDeque<Duration>,
    last_score: f32,
    avg_score: f32,
    last_update_time: Instant,
    debug_state: String,
}

impl AggregatedMetrics {
    fn new(scenario_index: usize, algo: AlgorithmType) -> Self {
        Self {
            scenario_index,
            algo,
            runs: 0,
            total_duration: Duration::ZERO,
            total_data_bytes: 0,
            total_lost_datagrams: 0,
            rtt_samples: VecDeque::with_capacity(1000),
            msg_lat_samples: VecDeque::with_capacity(1000),
            last_score: 0.0,
            avg_score: 0.0,
            last_update_time: Instant::now(),
            debug_state: "Starting...".to_string(),
        }
    }

    fn update(&mut self, m: RunMetrics, s: &Scenario) {
        self.last_score = m.calculate_score(s);
        self.runs += 1;
        self.total_duration += m.duration;
        self.total_data_bytes += m.total_data_bytes;
        self.total_lost_datagrams += m.lost_datagrams;

        for rtt in m.rtt_samples {
            if self.rtt_samples.len() >= 1000 {
                self.rtt_samples.pop_front();
            }
            self.rtt_samples.push_back(rtt);
        }
        for lat in m.message_latencies {
            if self.msg_lat_samples.len() >= 1000 {
                self.msg_lat_samples.pop_front();
            }
            self.msg_lat_samples.push_back(lat);
        }

        self.avg_score =
            (self.avg_score * (self.runs - 1) as f32 + self.last_score) / self.runs as f32;
        self.last_update_time = Instant::now();
        self.debug_state = m.debug_state;
    }

    fn current_metrics(&self) -> RunMetrics {
        RunMetrics {
            duration: self.total_duration,
            total_data_bytes: self.total_data_bytes,
            lost_datagrams: self.total_lost_datagrams,
            rtt_samples: self.rtt_samples.iter().cloned().collect(),
            message_latencies: self.msg_lat_samples.iter().cloned().collect(),
            is_completed: true,
            debug_state: self.debug_state.clone(),
        }
    }
}

/// Simulation scenario parameters.
#[derive(Clone)]
struct Scenario {
    name: &'static str,
    loss_rate: f32,
    burst_length: f32,
    blackout: Option<(Duration, Duration)>,
    latency: Duration,
    jitter: Duration,
    bandwidth: Option<f32>,
    data_size: usize,
    messages_count: usize,
    router_buffer_size: Option<usize>,
    bidirectional: bool,
    bandwidth_profile: Option<BandwidthProfile>,
}

#[derive(Clone, Copy)]
enum BandwidthProfile {
    Elevator {
        initial: f32,
        drop_at: Duration,
        drop_dur: Duration,
        drop_to: f32,
        recover_to: f32,
    },
}

impl Scenario {
    fn reliable_return(latency: Duration) -> Self {
        Self {
            name: "ACK Return",
            loss_rate: 0.0,
            burst_length: 1.0,
            blackout: None,
            latency,
            jitter: Duration::ZERO,
            bandwidth: None,
            data_size: 0,
            messages_count: 0,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        }
    }
}

/// A simulated network link with impairments.
struct NetworkLink {
    scenario: Scenario,
    /// Packets waiting in the router buffer to be serialized.
    buffer: VecDeque<Packet>,
    buffer_bytes: usize,
    /// Packets currently on the wire (propagation).
    wire: VecDeque<(Instant, Packet)>,
    /// When the transmitter will be free to send the next packet.
    next_tx_avail: Instant,
    in_burst: bool,
    max_queue_size: usize,
}

const ROUTER_BUFFER_SIZE: usize = 100 * 1024; // 100KB

impl NetworkLink {
    fn new(scenario: Scenario) -> Self {
        let max_queue_size = scenario.router_buffer_size.unwrap_or(ROUTER_BUFFER_SIZE);
        Self {
            scenario,
            buffer: VecDeque::new(),
            buffer_bytes: 0,
            wire: VecDeque::new(),
            next_tx_avail: Instant::now(),
            in_burst: false,
            max_queue_size,
        }
    }

    fn get_current_bandwidth(&self, now: Instant, start_time: Instant) -> Option<f32> {
        if let Some(profile) = self.scenario.bandwidth_profile {
            let elapsed = now.duration_since(start_time);
            match profile {
                BandwidthProfile::Elevator {
                    initial,
                    drop_at,
                    drop_dur,
                    drop_to,
                    recover_to,
                } => {
                    if elapsed < drop_at {
                        Some(initial)
                    } else if elapsed < drop_at + drop_dur {
                        Some(drop_to)
                    } else {
                        Some(recover_to)
                    }
                }
            }
        } else {
            self.scenario.bandwidth
        }
    }

    fn transmit(&mut self, packet: Packet, _now: Instant, start_time: Instant) {
        let elapsed = _now.duration_since(start_time);

        // Check for blackout
        if let Some((start, dur)) = self.scenario.blackout
            && elapsed >= start
            && elapsed < start + dur
        {
            return;
        }

        let size = match &packet {
            Packet::Data { data, .. } | Packet::Fragment { data, .. } => data.len() + 20,
            _ => 40,
        };

        // Router Buffer Limit (Tail Drop)
        if self.buffer_bytes + size > self.max_queue_size {
            return;
        }

        // Random/Burst Loss (Packet dropped before entering buffer)
        if self.roll_loss() {
            return;
        }

        self.buffer_bytes += size;
        self.buffer.push_back(packet);
    }

    /// Progresses the link state by one tick.
    /// - Drains buffer onto the wire if bandwidth allows.
    /// - Returns packets that have arrived at the destination.
    fn tick(&mut self, now: Instant, start_time: Instant) -> Vec<Packet> {
        // 1. Serialize packets from Buffer -> Wire
        while self.buffer.front().is_some() {
            // If the transmitter is busy, we can't send yet.
            if now < self.next_tx_avail {
                break;
            }

            // Take packet from buffer
            let packet = self.buffer.pop_front().unwrap();
            let size = match &packet {
                Packet::Data { data, .. } | Packet::Fragment { data, .. } => data.len() + 20,
                _ => 40,
            };
            self.buffer_bytes -= size;

            // Calculate serialization delay
            let bw = self.get_current_bandwidth(now, start_time);
            let tx_delay = if let Some(bps) = bw {
                Duration::from_secs_f32((size as f32 * 8.0) / bps)
            } else {
                Duration::ZERO
            };

            // Schedule when the wire will be free next
            self.next_tx_avail = self.next_tx_avail.max(now) + tx_delay;

            // Calculate arrival time (Serialization finish + Propagation + Jitter)
            let mut delivery_time = self.next_tx_avail + self.scenario.latency;
            if !self.scenario.jitter.is_zero() {
                let j = thread_rng().gen_range(0..self.scenario.jitter.as_micros() as u64);
                delivery_time += Duration::from_micros(j);
            }

            self.wire.push_back((delivery_time, packet));
        }

        // 2. Deliver packets from Wire -> Receiver
        let mut ready = Vec::new();

        // Optimization: Avoid O(N^2) removal from VecDeque.
        // We iterate and keep only packets that are NOT ready.
        // Since we need to inspect all packets (due to jitter reordering),
        // we can rotate the deque: pop front, check, push back if not ready.
        let count = self.wire.len();
        for _ in 0..count {
            let (t, p) = self.wire.pop_front().unwrap();
            if t <= now {
                ready.push(p);
            } else {
                self.wire.push_back((t, p));
            }
        }

        ready
    }

    fn roll_loss(&mut self) -> bool {
        let roll = thread_rng().r#gen::<f32>();
        if self.in_burst {
            if roll < (1.0 / self.scenario.burst_length.max(1.0)) {
                self.in_burst = false;
            }
        } else if roll < (self.scenario.loss_rate / self.scenario.burst_length.max(1.0)) {
            self.in_burst = true;
        }
        self.in_burst
    }
}

/// Runs a single simulation between Alice and Bob.
struct SimulationRunner<C: CongestionControl> {
    alice: SequenceSession<C>,
    bob: SequenceSession<Algorithm>,
    forward_link: NetworkLink,
    backward_link: NetworkLink,
    metrics: RunMetrics,
    /// Track send time for each seq to measure RTT from DatagramDelivered events.
    seq_send_times: HashMap<u32, Instant>,
    /// Track send time for each message (identified by first seq/frag_id) for message latency.
    msg_send_times: HashMap<u32, Instant>,
    /// Set of seq/frag_ids we have sent (to track messages).
    pending_messages: HashSet<u32>,
    /// Track data sizes sent per seq for throughput measurement.
    seq_data_sizes: HashMap<u32, usize>,
}

impl<C: CongestionControl + 'static> SimulationRunner<C> {
    fn execute(
        scenario: Scenario,
        cc: C,
        tx: Option<(Sender<Message>, usize, AlgorithmType)>,
    ) -> RunMetrics {
        let wall_start = Instant::now();
        let start_time = Instant::now();
        let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(start_time, 0));
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let mut runner = Self {
            alice: SequenceSession::with_congestion_control_at(
                cc,
                start_time,
                tp.clone(),
                &mut rng,
            ),
            bob: SequenceSession::new_at(start_time, tp, &mut rng),
            forward_link: NetworkLink::new(scenario.clone()),
            backward_link: NetworkLink::new(Scenario::reliable_return(scenario.latency)),
            metrics: RunMetrics::default(),
            seq_send_times: HashMap::new(),
            msg_send_times: HashMap::new(),
            pending_messages: HashSet::new(),
            seq_data_sizes: HashMap::new(),
        };

        let msg_data = vec![0u8; scenario.data_size / scenario.messages_count.max(1)];
        for _ in 0..scenario.messages_count {
            if let Ok(id) =
                runner
                    .alice
                    .send_auto(MessageType::MerkleNode, &msg_data, start_time)
            {
                runner.msg_send_times.insert(id, start_time);
                runner.pending_messages.insert(id);
            }
        }

        if scenario.bidirectional {
            for _ in 0..scenario.messages_count {
                let _ = runner
                    .bob
                    .send_auto(MessageType::MerkleNode, &msg_data, start_time);
            }
            // Use full scenario for backward link too
            runner.backward_link = NetworkLink::new(scenario.clone());
        }

        let mut virtual_now = start_time;
        let mut completed = 0;
        let timeout = Duration::from_secs(60);

        let mut last_report = Instant::now();

        while runner.metrics.message_latencies.len() < scenario.messages_count
            && virtual_now.duration_since(start_time) < timeout
        {
            runner.process_step(virtual_now, start_time, &mut completed);
            virtual_now += Duration::from_millis(1);

            // Report progress every 500ms wall clock
            if let Some((ref tx, s_idx, algo)) = tx
                && last_report.elapsed() > Duration::from_millis(500)
            {
                runner.update_debug_state(virtual_now, start_time);
                // Send clone of current metrics
                let _ = tx.send(Message::Progress {
                    scenario_idx: s_idx,
                    algo,
                    metrics: runner.metrics.clone(),
                });
                last_report = Instant::now();
            }
        }

        runner.metrics.duration = virtual_now.duration_since(start_time);
        runner.metrics.is_completed =
            runner.metrics.message_latencies.len() == scenario.messages_count;

        let wall_duration = wall_start.elapsed();
        if wall_duration > Duration::from_secs(1) {
            eprintln!(
                "Slow simulation run: {} ({}ms wall, {}s virtual)",
                scenario.name,
                wall_duration.as_millis(),
                runner.metrics.duration.as_secs_f32()
            );
        }

        runner.metrics
    }

    fn update_debug_state(&mut self, now: Instant, start: Instant) {
        let elapsed = now.duration_since(start);
        self.metrics.debug_state = format!(
            "T={:.2}s | InFlight={} | Cwnd={} | Pending={}",
            elapsed.as_secs_f32(),
            self.alice.in_flight(),
            self.alice.cwnd(),
            self.pending_messages.len()
        );
    }

    fn process_step(&mut self, now: Instant, start: Instant, completed: &mut usize) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Alice -> Bob: flush paced packets onto the forward link.
        // We collect into a buffer to avoid borrow conflicts.
        let mut alice_outgoing = Vec::new();
        self.alice.flush(now, now_ms, &mut |packet| {
            alice_outgoing.push(packet);
            true
        });
        for p in alice_outgoing {
            Self::track_outgoing_packet_static(
                &mut self.seq_send_times,
                &mut self.seq_data_sizes,
                &p,
                now,
            );
            self.forward_link.transmit(p, now, start);
        }

        // Advance links
        let forward_packets = self.forward_link.tick(now, start);
        let backward_packets = self.backward_link.tick(now, start);

        for p in forward_packets {
            let replies = self.bob.handle_packet(p, now);
            while let Some(event) = self.bob.poll_event() {
                if let SessionEvent::MessageCompleted(..) = event {
                    *completed += 1;
                }
            }
            for r in replies {
                self.backward_link.transmit(r, now, start);
            }
        }

        // Bob Internal (flush ACKs and any outgoing data)
        let mut bob_outgoing = Vec::new();
        self.bob.flush(now, now_ms, &mut |packet| {
            bob_outgoing.push(packet);
            true
        });
        for p in bob_outgoing {
            self.backward_link.transmit(p, now, start);
        }

        // Bob -> Alice: process incoming packets from backward link
        for p in backward_packets {
            let replies = self.alice.handle_packet(p, now);
            for r in replies {
                Self::track_outgoing_packet_static(
                    &mut self.seq_send_times,
                    &mut self.seq_data_sizes,
                    &r,
                    now,
                );
                self.forward_link.transmit(r, now, start);
            }
        }

        // Process Alice's events (delivery confirmations, losses, completions)
        while let Some(event) = self.alice.poll_event() {
            match event {
                SessionEvent::DatagramDelivered(seq) => {
                    // Record RTT from send time to delivery confirmation
                    if let Some(sent_time) = self.seq_send_times.remove(&seq) {
                        self.metrics.rtt_samples.push(now.duration_since(sent_time));
                    }
                    if let Some(size) = self.seq_data_sizes.remove(&seq) {
                        self.metrics.total_data_bytes += size;
                    }
                    // For single-packet messages, delivery = message completion
                    if self.pending_messages.remove(&seq)
                        && let Some(msg_sent_time) = self.msg_send_times.remove(&seq)
                    {
                        self.metrics
                            .message_latencies
                            .push(now.duration_since(msg_sent_time));
                    }
                }
                SessionEvent::DatagramLost(seq) => {
                    self.seq_send_times.remove(&seq);
                    self.seq_data_sizes.remove(&seq);
                    self.metrics.lost_datagrams += 1;
                }
                SessionEvent::MessageCompleted(frag_id, _msg_type, _data) => {
                    // This fires on the receiver side; for Alice as sender we
                    // track completion via DatagramDelivered. But if Alice also
                    // receives (bidirectional), count it.
                    let _ = (frag_id, _msg_type, _data);
                }
                SessionEvent::MessageDropped(frag_id) => {
                    // A fragmented message we were receiving was dropped
                    self.pending_messages.remove(&frag_id);
                    self.msg_send_times.remove(&frag_id);
                }
                _ => {}
            }
        }

        self.alice.cleanup(now);
        self.bob.cleanup(now);
    }

    /// Track outgoing packets from Alice for RTT and throughput measurement.
    fn track_outgoing_packet_static(
        seq_send_times: &mut HashMap<u32, Instant>,
        seq_data_sizes: &mut HashMap<u32, usize>,
        p: &Packet,
        now: Instant,
    ) {
        match p {
            Packet::Data { seq, data, .. } => {
                seq_send_times.entry(*seq).or_insert(now);
                seq_data_sizes.entry(*seq).or_insert(data.len());
            }
            Packet::Fragment {
                frag_id, data, ..
            } => {
                // Track fragment data for throughput; use frag_id for message-level tracking
                seq_send_times.entry(*frag_id).or_insert(now);
                seq_data_sizes
                    .entry(*frag_id)
                    .and_modify(|s| *s += data.len())
                    .or_insert(data.len());
            }
            _ => {}
        }
    }
}

enum Message {
    Result {
        scenario_idx: usize,
        algo: AlgorithmType,
        metrics: RunMetrics,
    },
    Progress {
        scenario_idx: usize,
        algo: AlgorithmType,
        metrics: RunMetrics,
    },
    Error(String),
}

fn worker(scenario_idx: usize, algo: AlgorithmType, scenario: Scenario, tx: Sender<Message>) {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        loop {
            let worker_rng = rand::SeedableRng::seed_from_u64(0);
            let metrics = SimulationRunner::<Algorithm>::execute(
                scenario.clone(),
                Algorithm::new(algo, worker_rng),
                Some((tx.clone(), scenario_idx, algo)),
            );
            if tx
                .send(Message::Result {
                    scenario_idx,
                    algo,
                    metrics,
                })
                .is_err()
            {
                break;
            }
            // Small sleep to not absolutely peg the CPU if simulations are too fast
            thread::sleep(Duration::from_millis(10));
        }
    }));

    if let Err(e) = result {
        let msg = format!(
            "Worker panicked for Scenario {} Algo {:?}: {:?}",
            scenario_idx, algo, e
        );
        let _ = tx.send(Message::Error(msg));
    }
}

#[derive(Serialize, Deserialize, Default)]
struct BaselineData {
    /// Map of (ScenarioName, AlgorithmName) -> Score
    scores: HashMap<String, HashMap<String, f32>>,
}

struct App {
    scenarios: Vec<Scenario>,
    results: Vec<AggregatedMetrics>,
    table_state: TableState,
    baseline: Option<BaselineData>,
    focused_scenario_idx: Option<usize>,
    last_error: Option<String>,
    start_time: Instant,
}

impl App {
    fn new(scenarios: Vec<Scenario>, baseline: Option<BaselineData>) -> Self {
        let mut results = Vec::new();
        for i in 0..scenarios.len() {
            for &algo in AlgorithmType::ALL_TYPES {
                results.push(AggregatedMetrics::new(i, algo));
            }
        }
        Self {
            scenarios,
            results,
            table_state: TableState::default(),
            baseline,
            focused_scenario_idx: None,
            last_error: None,
            start_time: Instant::now(),
        }
    }

    fn update(&mut self, msg: Message) {
        match msg {
            Message::Result {
                scenario_idx,
                algo,
                metrics,
            }
            | Message::Progress {
                scenario_idx,
                algo,
                metrics,
            } => {
                if let Some(res) = self
                    .results
                    .iter_mut()
                    .find(|r| r.scenario_index == scenario_idx && r.algo == algo)
                {
                    res.update(metrics, &self.scenarios[scenario_idx]);
                }
            }
            Message::Error(err) => {
                self.last_error = Some(err);
            }
        }
    }
}

fn run_headless(scenarios: Vec<Scenario>, args: &Args) {
    let timeout = Duration::from_secs(args.timeout);
    let (tx, rx) = unbounded();
    for (i, s) in scenarios.iter().enumerate() {
        for &algo in AlgorithmType::ALL_TYPES {
            let tx_algo = tx.clone();
            let s_algo = s.clone();
            thread::spawn(move || worker(i, algo, s_algo, tx_algo));
        }
    }

    println!("Benchmarking for {:?}...", timeout);
    let start = Instant::now();
    let baseline = args.load.as_ref().and_then(|path| {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str::<BaselineData>(&content).ok())
    });
    let mut app = App::new(scenarios.clone(), baseline);

    while start.elapsed() < timeout {
        while let Ok(msg) = rx.try_recv() {
            app.update(msg);
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Final drain
    while let Ok(msg) = rx.try_recv() {
        app.update(msg);
    }

    println!(
        "\n{:<25} | {:<10} | {:<6} | {:<10} | {:<10} | {:<10} | {:<8} | {:<8}",
        "Scenario", "Algo", "Runs", "Thr/MLat", "p50RTT", "p99RTT", "Loss%", "Score"
    );
    println!(
        "{:-<25}-|-{:-<10}-|-{:-<6}-|-{:-<10}-|-{:-<10}-|-{:-<10}-|-{:-<8}-|-{:-<8}",
        "", "", "", "", "", "", "", ""
    );

    let mut last_scenario_was_lab = true;
    for item in &app.results {
        let s = &scenarios[item.scenario_index];
        let is_lab = !matches!(
            s.name,
            "Interactive Chat (10msg)"
                | "Starlink Bloat (600ms/1MB)"
                | "Asymmetric DSL (512k up)"
                | "Bi-di Contention (1Mbps)"
                | "Elevator (Mobile)"
        );

        if last_scenario_was_lab && !is_lab {
            println!(
                "{:-<25}-+-{:-<10}-+-{:-<6}-+-{:-<10}-+-{:-<10}-+-{:-<10}-+-{:-<8}-+-{:-<8}",
                "", "", "", "", "", "", "", ""
            );
            println!(
                "{:<25} | {:<10} | {:<6} | {:<10} | {:<10} | {:<10} | {:<8} | {:<8}",
                "REALISTIC SCENARIOS", "", "", "", "", "", "", ""
            );
            println!(
                "{:-<25}-+-{:-<10}-+-{:-<6}-+-{:-<10}-+-{:-<10}-+-{:-<10}-+-{:-<8}-+-{:-<8}",
                "", "", "", "", "", "", "", ""
            );
            last_scenario_was_lab = false;
        }

        let m = item.current_metrics();
        let (rtt_p50, rtt_p99) = m.rtt_percentiles();
        let (msg_p50, _) = m.msg_lat_percentiles();

        let speed_col = if s.messages_count > 1 {
            format!("{:.1}ms", msg_p50.as_secs_f32() * 1000.0)
        } else {
            format!("{:.3}", m.throughput_mbps())
        };

        let score = item.avg_score;
        let diff_str = if let Some(bl) = &app.baseline {
            bl.scores
                .get(s.name)
                .and_then(|algos| algos.get(&item.algo.to_string()))
                .map(|&base_score| {
                    let diff = score - base_score;
                    if diff > 0.1 {
                        format!(" (+{:.1})", diff)
                    } else if diff < -0.1 {
                        format!(" ({:.1})", diff)
                    } else {
                        "".to_string()
                    }
                })
                .unwrap_or_default()
        } else {
            "".to_string()
        };

        println!(
            "{:<25} | {:<10} | {:<6} | {:<10} | {:<10.1} | {:<10.1} | {:<7.1}% | {:<8.1}{}",
            s.name,
            item.algo.to_string(),
            item.runs,
            speed_col,
            rtt_p50.as_secs_f32() * 1000.0,
            rtt_p99.as_secs_f32() * 1000.0,
            m.loss_rate(),
            score,
            diff_str
        );
    }

    if let Some(path) = &args.save {
        let mut bl = BaselineData::default();
        for item in &app.results {
            let s = &scenarios[item.scenario_index];
            bl.scores
                .entry(s.name.to_string())
                .or_default()
                .insert(item.algo.to_string(), item.avg_score);
        }
        if let Ok(json) = serde_json::to_string_pretty(&bl) {
            let _ = fs::write(path, json);
            println!("\nBaseline saved to {}", path);
        }
    }

    println!("\nPROTOCOL FITNESS SUMMARY");
    println!("{:-<25}", "");
    let mut fitness = HashMap::new();
    for res in &app.results {
        *fitness.entry(res.algo).or_insert(0.0) += res.avg_score;
    }
    let mut sorted_fitness: Vec<_> = fitness.into_iter().collect();
    sorted_fitness.sort_by_key(|(a, _)| *a);
    for (algo, total_score) in sorted_fitness {
        let avg_score = total_score / scenarios.len() as f32;
        let diff_str = if let Some(bl) = &app.baseline {
            let mut base_total = 0.0;
            let mut count = 0;
            for s in &scenarios {
                if let Some(algos) = bl.scores.get(s.name)
                    && let Some(&base_score) = algos.get(&algo.to_string())
                {
                    base_total += base_score;
                    count += 1;
                }
            }
            if count > 0 {
                let base_avg = base_total / count as f32;
                let diff = avg_score - base_avg;
                if diff > 0.1 {
                    format!(" (+{:.1})", diff)
                } else if diff < -0.1 {
                    format!(" ({:.1})", diff)
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        println!(
            "{:<10} | Score: {:.1}{}",
            algo.to_string(),
            avg_score,
            diff_str
        );
    }
}

fn run_tui(scenarios: Vec<Scenario>, args: &Args) -> Result<(), io::Error> {
    let (tx, rx) = unbounded();

    let algos = AlgorithmType::ALL_TYPES;
    for (i, s) in scenarios.iter().enumerate() {
        for &algo in algos {
            let tx_algo = tx.clone();
            let s_algo = s.clone();
            thread::spawn(move || worker(i, algo, s_algo, tx_algo));
        }
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let baseline = args.load.as_ref().and_then(|path| {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str::<BaselineData>(&content).ok())
    });
    let mut app = App::new(scenarios, baseline);
    // Select first row by default so details/sparkline show up immediately
    app.table_state.select(Some(0));

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Esc => {
                    if let Some(focus_idx) = app.focused_scenario_idx {
                        app.focused_scenario_idx = None;
                        // Find the first row in the full list corresponding to this scenario
                        if let Some(idx) = app
                            .results
                            .iter()
                            .position(|r| r.scenario_index == focus_idx)
                        {
                            app.table_state.select(Some(idx));
                        } else {
                            app.table_state.select(Some(0));
                        }
                    }
                }
                KeyCode::Enter => {
                    if let Some(selected) = app.table_state.selected() {
                        let scenario_idx = if let Some(focus) = app.focused_scenario_idx {
                            focus
                        } else {
                            app.results[selected].scenario_index
                        };
                        app.focused_scenario_idx = Some(scenario_idx);
                        app.table_state.select(Some(0));
                    }
                }
                KeyCode::Down => {
                    let count = if app.focused_scenario_idx.is_some() {
                        AlgorithmType::ALL_TYPES.len()
                    } else {
                        app.results.len()
                    };

                    app.table_state.select(Some(
                        app.table_state.selected().map_or(0, |i| (i + 1) % count),
                    ));
                }
                KeyCode::Up => {
                    let count = if app.focused_scenario_idx.is_some() {
                        AlgorithmType::ALL_TYPES.len()
                    } else {
                        app.results.len()
                    };

                    app.table_state.select(Some(
                        app.table_state
                            .selected()
                            .map_or(0, |i| (i + count - 1) % count),
                    ));
                }
                _ => {}
            }
        }

        while let Ok(msg) = rx.try_recv() {
            app.update(msg);
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Some(path) = &args.save {
        let mut bl = BaselineData::default();
        for item in &app.results {
            let s = &app.scenarios[item.scenario_index];
            bl.scores
                .entry(s.name.to_string())
                .or_default()
                .insert(item.algo.to_string(), item.avg_score);
        }
        if let Ok(json) = serde_json::to_string_pretty(&bl) {
            let _ = fs::write(path, json);
            println!("\nBaseline saved to {}", path);
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(0),     // Table + Dashboard
                Constraint::Length(10), // Sparkline + Details
                Constraint::Length(3),  // Summary
                Constraint::Length(1),  // Help
            ]
            .as_ref(),
        )
        .split(f.area());

    // Dynamic Split for Focus Mode
    let (table_area, dashboard_area) = if app.focused_scenario_idx.is_some() {
        let table_height = (AlgorithmType::ALL_TYPES.len() + 5) as u16;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(table_height),
                    Constraint::Min(0), // Deep Dive Dashboard
                ]
                .as_ref(),
            )
            .split(rects[0]);
        (chunks[0], Some(chunks[1]))
    } else {
        (rects[0], None)
    };

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let normal_style = Style::default().bg(Color::Blue);
    let header_cells = [
        "Scenario", " ", "Algo", "Runs", "Thr/MLat", "p50RTT", "p99RTT", "Loss%", "AvgScore",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let header = Row::new(header_cells)
        .style(normal_style)
        .height(1)
        .bottom_margin(1);

    // Pre-calculate winners
    let mut best_scores = HashMap::new();
    for item in &app.results {
        let entry = best_scores.entry(item.scenario_index).or_insert(0.0f32);
        if item.avg_score > *entry {
            *entry = item.avg_score;
        }
    }

    // Filter results if focused
    let display_results: Vec<&AggregatedMetrics> = if let Some(focus_idx) = app.focused_scenario_idx
    {
        app.results
            .iter()
            .filter(|r| r.scenario_index == focus_idx)
            .collect()
    } else {
        app.results.iter().collect()
    };

    let rows = display_results.iter().map(|item| {
        let s = &app.scenarios[item.scenario_index];
        let m = item.current_metrics();
        let (rtt_p50, rtt_p99) = m.rtt_percentiles();
        let (msg_p50, _) = m.msg_lat_percentiles();

        let speed_col = if s.messages_count > 1 {
            format!("{:.1}ms", msg_p50.as_secs_f32() * 1000.0)
        } else {
            format!("{:.3}", m.throughput_mbps())
        };

        let mut color = match item.algo {
            AlgorithmType::Bbrv2 => Color::Cyan,
            AlgorithmType::Bbrv1 => Color::Magenta,
            AlgorithmType::Cubic => Color::Green,
            AlgorithmType::Aimd => Color::White,
        };

        let score = item.avg_score;
        let mut score_text = format!("{:.1}", score);
        let mut row_style = Style::default();
        let algo_text = item.algo.to_string();
        let mut winner_icon = "";

        // Check for Zombie (stuck > 1s)
        if item.last_update_time.elapsed() > Duration::from_secs(1) {
            row_style = row_style.fg(Color::DarkGray);
            color = Color::DarkGray;
        }

        // Highlight Winner
        if let Some(&best) = best_scores.get(&item.scenario_index)
            && (score - best).abs() < f32::EPSILON
            && score > 0.0
        {
            winner_icon = "🏆";
            row_style = row_style.add_modifier(Modifier::BOLD);
            color = Color::Yellow;
        }

        if let Some(bl) = &app.baseline
            && let Some(base_score) = bl
                .scores
                .get(s.name)
                .and_then(|algos| algos.get(&item.algo.to_string()))
        {
            let diff = score - base_score;
            if diff > 0.1 {
                score_text.push_str(&format!(" (+{:.1})", diff));
            } else if diff < -0.1 {
                score_text.push_str(&format!(" ({:.1})", diff));
            }
        }

        Row::new(vec![
            Cell::from(s.name),
            Cell::from(winner_icon),
            Cell::from(algo_text).style(Style::default().fg(color)),
            Cell::from(item.runs.to_string()),
            Cell::from(speed_col),
            Cell::from(format!("{:.1}ms", rtt_p50.as_secs_f32() * 1000.0)),
            Cell::from(format!("{:.1}ms", rtt_p99.as_secs_f32() * 1000.0)),
            Cell::from(format!("{:.1}%", m.loss_rate())),
            Cell::from(score_text),
        ])
        .style(row_style)
    });

    let elapsed = app.start_time.elapsed();
    let timer = format!(
        "{:02}:{:02}",
        elapsed.as_secs() / 60,
        elapsed.as_secs() % 60
    );

    let t = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Length(2), // Winner Icon
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(format!(
        "Tox Sequenced Congestion Control Benchmark ({})",
        timer
    )))
    .row_highlight_style(selected_style)
    .highlight_symbol(">> ");

    f.render_stateful_widget(t, table_area, &mut app.table_state);

    // Render Deep Dive Dashboard if active
    if let Some(area) = dashboard_area {
        render_deep_dive(f, app, area);
    }

    // Selected Row Details & Sparkline
    if let Some(selected_idx) = app.table_state.selected()
        && let Some(item) = display_results.get(selected_idx)
    {
        let s = &app.scenarios[item.scenario_index];

        let details_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Percentage(30), // Text Details
                    Constraint::Percentage(35), // RTT Sparkline
                    Constraint::Percentage(35), // Comparison Chart
                ]
                .as_ref(),
            )
            .split(rects[1]);

        // Left: Text Details
        let m = item.current_metrics();
        let mut details_text = format!(
            "Scenario: {}\nAlgo: {}\nBytes: {}\nLost: {} ({:.1}%)\nTime: {:.2}s\nScore: {:.1}",
            s.name,
            item.algo,
            m.total_data_bytes,
            m.lost_datagrams,
            m.loss_rate(),
            m.duration.as_secs_f32(),
            item.avg_score
        );

        if !item.debug_state.is_empty() {
            details_text.push_str(&format!("\nDEBUG: {}", item.debug_state));
        }

        let details = Paragraph::new(details_text)
            .block(Block::default().borders(Borders::ALL).title("Details"));
        f.render_widget(details, details_layout[0]);

        // Right: RTT Sparkline
        let data: Vec<u64> = item
            .rtt_samples
            .iter()
            .map(|d| d.as_millis() as u64)
            .rev()
            .take(100)
            .collect();
        let data: Vec<u64> = data.into_iter().rev().collect();

        let sparkline = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("RTT History (Last 100 samples)"),
            )
            .data(&data)
            .style(Style::default().fg(Color::Cyan));
        f.render_widget(sparkline, details_layout[1]);

        // Right: Comparison Bar Chart
        let mut barchart = BarChart::default()
            .block(
                Block::default()
                    .title("Scenario Score Comparison (x10)")
                    .borders(Borders::ALL),
            )
            .bar_width(8)
            .bar_gap(1)
            .group_gap(3)
            .value_style(Style::default().add_modifier(Modifier::BOLD));

        for r in app
            .results
            .iter()
            .filter(|r| r.scenario_index == item.scenario_index)
        {
            let color = match r.algo {
                AlgorithmType::Bbrv2 => Color::Cyan,
                AlgorithmType::Bbrv1 => Color::Magenta,
                AlgorithmType::Cubic => Color::Green,
                AlgorithmType::Aimd => Color::White,
            };
            let label = match r.algo {
                AlgorithmType::Aimd => "AIMD",
                AlgorithmType::Bbrv1 => "BBRv1",
                AlgorithmType::Bbrv2 => "BBRv2",
                AlgorithmType::Cubic => "CUBIC",
            };
            barchart = barchart.data(
                BarGroup::default().label(label).bars(&[Bar::default()
                    .value((r.avg_score * 10.0) as u64)
                    .style(Style::default().fg(color))]),
            );
        }

        f.render_widget(barchart, details_layout[2]);
    }

    // Protocol Fitness Summary
    let mut fitness = HashMap::new();
    for res in &app.results {
        let entry = fitness.entry(res.algo).or_insert(0.0);
        *entry += res.avg_score;
    }

    let mut sorted_fitness: Vec<_> = fitness.into_iter().collect();
    sorted_fitness.sort_by_key(|(algo, _)| *algo);

    let summary_spans: Vec<_> = sorted_fitness
        .iter()
        .flat_map(|(algo, score)| {
            let avg = score / app.scenarios.len() as f32;
            let color = match *algo {
                AlgorithmType::Bbrv1 => Color::Magenta,
                AlgorithmType::Bbrv2 => Color::Cyan,
                AlgorithmType::Cubic => Color::Green,
                AlgorithmType::Aimd => Color::White,
            };

            let mut text = format!("{:.1}", avg);
            if let Some(bl) = &app.baseline {
                let mut base_total = 0.0;
                let mut count = 0;
                for s in &app.scenarios {
                    if let Some(algos) = bl.scores.get(s.name)
                        && let Some(&base_score) = algos.get(&algo.to_string())
                    {
                        base_total += base_score;
                        count += 1;
                    }
                }
                if count > 0 {
                    let base_avg = base_total / count as f32;
                    let diff = avg - base_avg;
                    if diff > 0.1 {
                        text.push_str(&format!(" (+{:.1})", diff));
                    } else if diff < -0.1 {
                        text.push_str(&format!(" ({:.1})", diff));
                    }
                }
            }

            vec![
                ratatui::text::Span::raw(format!("{:<6}: ", algo)),
                ratatui::text::Span::styled(
                    format!("{}  ", text),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]
        })
        .collect();

    let summary = Paragraph::new(ratatui::text::Line::from(summary_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Global Protocol Fitness Summary (Avg Score)"),
    );
    // If focused, replace Summary with Deep Diagnostics
    if let Some(focus_idx) = app.focused_scenario_idx {
        let scenario_results: Vec<&AggregatedMetrics> = app
            .results
            .iter()
            .filter(|r| r.scenario_index == focus_idx)
            .collect();

        // 1. Throughput vs Goodput Bar Chart (Grouped)
        let mut barchart = BarChart::default()
            .block(
                Block::default()
                    .title("Throughput [Mbps x100]")
                    .borders(Borders::ALL),
            )
            .bar_width(5)
            .bar_gap(1)
            .group_gap(2);

        for res in &scenario_results {
            let m = res.current_metrics();
            let label = match res.algo {
                AlgorithmType::Aimd => "AIMD",
                AlgorithmType::Bbrv1 => "BBR1",
                AlgorithmType::Bbrv2 => "BBR2",
                AlgorithmType::Cubic => "CUBC",
            };

            let total_mbps = m.throughput_mbps();

            barchart = barchart.data(
                BarGroup::default().label(label).bars(&[Bar::default()
                    .value((total_mbps * 100.0) as u64)
                    .label("Thr")
                    .style(Style::default().fg(Color::Blue))]),
            );
        }

        f.render_widget(barchart, rects[2]);
    } else {
        f.render_widget(summary, rects[2]);
    }

    let help_text = if let Some(err) = &app.last_error {
        format!("ERROR: {} (Press 'q' to quit)", err)
    } else if app.focused_scenario_idx.is_some() {
        "Esc: Back to Overview, q: Quit".to_string()
    } else {
        "Enter: Focus Scenario, q: Quit, Up/Down: Scroll".to_string()
    };

    let help_style = if app.last_error.is_some() {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let help = Paragraph::new(help_text).style(help_style);
    f.render_widget(help, rects[3]);
}

fn render_deep_dive(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if let Some(focus_idx) = app.focused_scenario_idx {
        let results: Vec<&AggregatedMetrics> = app
            .results
            .iter()
            .filter(|r| r.scenario_index == focus_idx)
            .collect();

        if results.is_empty() {
            return;
        }

        let algos_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                ]
                .as_ref(),
            )
            .split(area);

        for (i, res) in results.iter().enumerate() {
            if i >= 3 {
                break;
            } // Support up to 3 algorithms concurrently.

            let m = res.current_metrics();
            let mut samples: Vec<u64> =
                m.rtt_samples.iter().map(|d| d.as_millis() as u64).collect();
            samples.sort();

            if samples.is_empty() {
                continue;
            }

            // Create buckets
            let min = samples[0];
            let max = samples[samples.len() - 1];
            let range = max - min;
            let bucket_count = 10;
            let bucket_width = (range / bucket_count).max(1);

            let mut buckets = vec![0u64; bucket_count as usize];
            for &s in &samples {
                let idx = ((s - min) / bucket_width).min(bucket_count - 1) as usize;
                buckets[idx] += 1;
            }

            // Prepare BarChart data
            let bar_data: Vec<(String, u64)> = buckets
                .iter()
                .enumerate()
                .map(|(idx, &count)| {
                    let start = min + (idx as u64 * bucket_width);
                    (format!("{}ms", start), count)
                })
                .collect();

            let str_data: Vec<(&str, u64)> =
                bar_data.iter().map(|(s, c)| (s.as_str(), *c)).collect();

            let color = match res.algo {
                AlgorithmType::Bbrv1 => Color::Magenta,
                AlgorithmType::Bbrv2 => Color::Cyan,
                AlgorithmType::Cubic => Color::Green,
                AlgorithmType::Aimd => Color::White,
            };

            let barchart = BarChart::default()
                .block(
                    Block::default()
                        .title(format!("Latency Dist: {}", res.algo))
                        .borders(Borders::ALL),
                )
                .data(&str_data)
                .bar_width(5)
                .bar_style(Style::default().fg(color))
                .value_style(Style::default().bg(color).add_modifier(Modifier::BOLD));

            f.render_widget(barchart, algos_layout[i]);
        }
    }
}

fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    let scenarios = vec![
        Scenario {
            name: "1% Loss, 50ms RTT",
            loss_rate: 0.01,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::ZERO,
            bandwidth: None,
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Bottleneck 1Mbps, 50ms",
            loss_rate: 0.0,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::ZERO,
            bandwidth: Some(1_000_000.0),
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Bursty 5% Loss (Len 10)",
            loss_rate: 0.05,
            burst_length: 10.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::ZERO,
            bandwidth: None,
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "3s Blackout @ 1s",
            loss_rate: 0.0,
            burst_length: 1.0,
            blackout: Some((Duration::from_secs(1), Duration::from_secs(3))),
            latency: Duration::from_millis(25),
            jitter: Duration::ZERO,
            bandwidth: Some(5_000_000.0),
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Mobile (Btl/Jit/Burst)",
            loss_rate: 0.02,
            burst_length: 5.0,
            blackout: None,
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(20),
            bandwidth: Some(2_000_000.0),
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Extreme Loss (20%)",
            loss_rate: 0.20,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::ZERO,
            bandwidth: None,
            data_size: 500_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Satellite (600ms RTT)",
            loss_rate: 0.0,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(300),
            jitter: Duration::from_millis(20),
            bandwidth: Some(2_000_000.0),
            data_size: 500_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Interactive Chat (10msg)",
            loss_rate: 0.01,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(50),
            jitter: Duration::from_millis(10),
            bandwidth: None,
            data_size: 10_000,
            messages_count: 10,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Starlink Bloat (600ms/1MB)",
            loss_rate: 0.0,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(300),
            jitter: Duration::from_millis(50),
            bandwidth: Some(10_000_000.0), // 10Mbps
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: Some(1024 * 1024), // 1MB Buffer (Bloat!)
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Asymmetric DSL (512k up)",
            loss_rate: 0.01,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::from_millis(5),
            bandwidth: Some(512_000.0), // 512Kbps Upload
            data_size: 500_000,
            messages_count: 1,
            router_buffer_size: Some(64 * 1024),
            bidirectional: false,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Bi-di Contention (1Mbps)",
            loss_rate: 0.01,
            burst_length: 1.0,
            blackout: None,
            latency: Duration::from_millis(25),
            jitter: Duration::from_millis(10),
            bandwidth: Some(1_000_000.0),
            data_size: 500_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: true,
            bandwidth_profile: None,
        },
        Scenario {
            name: "Elevator (Mobile)",
            loss_rate: 0.02,
            burst_length: 2.0,
            blackout: None,
            latency: Duration::from_millis(40),
            jitter: Duration::from_millis(20),
            bandwidth: Some(5_000_000.0),
            data_size: 1_000_000,
            messages_count: 1,
            router_buffer_size: None,
            bidirectional: false,
            bandwidth_profile: Some(BandwidthProfile::Elevator {
                initial: 5_000_000.0,
                drop_at: Duration::from_secs(1),
                drop_dur: Duration::from_secs(2),
                drop_to: 100_000.0,
                recover_to: 2_000_000.0,
            }),
        },
    ];

    let headless = args.headless || !io::stdout().is_terminal();

    if headless {
        run_headless(scenarios, &args);
        Ok(())
    } else {
        run_tui(scenarios, &args)
    }
}

// end of file
