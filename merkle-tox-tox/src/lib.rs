use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk};
use merkle_tox_core::error::MerkleToxResult;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::{ProtocolMessage, Transport, TransportError};
use parking_lot::ReentrantMutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tox_proto::PhysicalDeviceSk;
use toxcore::tox::Tox;
use toxcore::tox::events::Event;
use toxcore::types::{
    PublicKey as ToxPublicKey, Tox_Err_Friend_Custom_Packet, ToxConnection, ToxError,
};
use tracing::debug;

use tokio::sync::Mutex;

pub const TOX_CUSTOM_PACKET_ID: u8 = 200;

/// A transport implementation that uses real Tox custom packets.
///
/// `send_ok` / `send_err` / `recv_count` are permanent observability
/// counters: they tally lossy custom packets at the Tox boundary so
/// callers can compare engine-level message rates against the actual
/// network rate. Read via [`ToxTransport::stats`].
#[derive(Clone)]
pub struct ToxTransport {
    pub tox: Arc<ReentrantMutex<Tox>>,
    pub send_ok: Arc<AtomicU64>,
    pub send_err: Arc<AtomicU64>,
    /// Bucketed `send_err` by the `Tox_Err_Friend_Custom_Packet` variant
    /// returned by `friend.send_lossy_packet`. Distinguishes a SENDQ
    /// rejection (toxcore queue full) from FRIEND_NOT_CONNECTED (no path
    /// to peer) from other errors. The sum equals `send_err`.
    pub send_err_sendq: Arc<AtomicU64>,
    pub send_err_not_connected: Arc<AtomicU64>,
    pub send_err_other: Arc<AtomicU64>,
    pub recv_count: Arc<AtomicU64>,
    /// Per-layer timing breakdowns in nanoseconds. Cumulative since
    /// session start; used to identify where wall-clock time goes
    /// during high-throughput transfers.
    ///
    /// Send path:
    /// - `send_lock_wait_ns`: time spent acquiring `tox.lock()` in `send_raw`
    /// - `send_lookup_ns`: time spent in `lookup_friend` (FFI)
    /// - `send_ffi_ns`: time spent in `friend.send_lossy_packet` (FFI + NaCl encrypt + sendto)
    pub send_lock_wait_ns: Arc<AtomicU64>,
    pub send_lookup_ns: Arc<AtomicU64>,
    pub send_ffi_ns: Arc<AtomicU64>,
}

/// Snapshot of [`ToxTransport`] counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ToxTransportStats {
    pub send_ok: u64,
    pub send_err: u64,
    pub send_err_sendq: u64,
    pub send_err_not_connected: u64,
    pub send_err_other: u64,
    pub recv_count: u64,
    pub send_lock_wait_ns: u64,
    pub send_lookup_ns: u64,
    pub send_ffi_ns: u64,
}

impl ToxTransport {
    pub fn stats(&self) -> ToxTransportStats {
        ToxTransportStats {
            send_ok: self.send_ok.load(Ordering::Relaxed),
            send_err: self.send_err.load(Ordering::Relaxed),
            send_err_sendq: self.send_err_sendq.load(Ordering::Relaxed),
            send_err_not_connected: self.send_err_not_connected.load(Ordering::Relaxed),
            send_err_other: self.send_err_other.load(Ordering::Relaxed),
            recv_count: self.recv_count.load(Ordering::Relaxed),
            send_lock_wait_ns: self.send_lock_wait_ns.load(Ordering::Relaxed),
            send_lookup_ns: self.send_lookup_ns.load(Ordering::Relaxed),
            send_ffi_ns: self.send_ffi_ns.load(Ordering::Relaxed),
        }
    }

    /// Query the friend's current connection status (UDP-direct, TCP-relay,
    /// or none). Acquires the tox lock; cheap.
    pub fn friend_connection_status(&self, peer: PhysicalDevicePk) -> Option<ToxConnection> {
        let tox = self.tox.lock();
        tox.lookup_friend(&ToxPublicKey(*peer.as_bytes()))
            .ok()
            .and_then(|f| f.connection_status().ok())
    }
}

impl Transport for ToxTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        PhysicalDevicePk::from(self.tox.lock().public_key().0)
    }

    fn send_raw(&self, to: PhysicalDevicePk, mut data: Vec<u8>) -> Result<(), TransportError> {
        let lock_start = Instant::now();
        let tox = self.tox.lock();
        self.send_lock_wait_ns
            .fetch_add(lock_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

        let lookup_start = Instant::now();
        let friend = tox
            .lookup_friend(&ToxPublicKey(*to.as_bytes()))
            .map_err(|_| TransportError::PeerNotFound(hex::encode(to.as_bytes())))?;
        self.send_lookup_ns
            .fetch_add(lookup_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

        data.insert(0, TOX_CUSTOM_PACKET_ID);
        let ffi_start = Instant::now();
        let result = friend.send_lossy_packet(&data);
        self.send_ffi_ns
            .fetch_add(ffi_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        match result {
            Ok(()) => {
                self.send_ok.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.send_err.fetch_add(1, Ordering::Relaxed);
                use Tox_Err_Friend_Custom_Packet::*;
                let variant = match &e {
                    ToxError::FriendCustomPacket(v) => Some(*v),
                    _ => None,
                };
                match variant {
                    Some(TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ) => {
                        self.send_err_sendq.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED) => {
                        self.send_err_not_connected.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        self.send_err_other.fetch_add(1, Ordering::Relaxed);
                        // Log the first 5 we see so we can identify the
                        // actual variant when "other" is non-zero.
                        let prev = self.send_err_other.load(Ordering::Relaxed);
                        if prev <= 5 {
                            tracing::warn!(
                                "send_lossy_packet error variant #{}: {:?}",
                                prev, e
                            );
                        }
                    }
                }
                Err(TransportError::Other(format!("{:?}", e)))
            }
        }
    }
}

/// A bridge between the Tox network and the Merkle-Tox engine.
pub struct ToxMerkleBridge<S: NodeStore + BlobStore> {
    pub node: Arc<Mutex<MerkleToxNode<ToxTransport, S>>>,
}

/// Combined transport + engine + per-session telemetry, used by tests and
/// observability tooling to characterize an in-progress transfer in one
/// snapshot. All fields are cheap atomics or quick struct reads.
#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    pub transport: ToxTransportStats,
    pub engine: merkle_tox_core::engine::EngineStatsSnapshot,
    /// Number of active push streams on this node.
    pub push_streams: usize,
    /// Push-stream credits for the first stream (0 if none).
    pub push_credits: usize,
    /// Next piece offset for the first push stream (0 if none).
    pub push_offset: u64,
    /// Number of distinct sessions.
    pub sessions: usize,
    /// Aggregate session metrics — summed across sessions when there are
    /// multiple, but in the common 1:1 transfer case this is the single
    /// session's snapshot. Bytes, not packets.
    pub session_cwnd_bytes: usize,
    pub session_in_flight_bytes: usize,
    pub session_outgoing_count: usize,
    pub session_pacing_bytes_per_sec: f32,
    /// Cumulative flush-loop diagnostic counters for the first session.
    pub session_flush_diag: tox_sequenced::FlushDiag,
    /// Cumulative ACK packets the sender has processed.
    pub session_acks_received: u64,
    /// Cumulative DatagramLost events emitted by the sender.
    pub session_losses_emitted: u64,
    /// Total payload bytes the sender has transmitted.
    pub session_bytes_sent: u64,
    /// Peer-reported cumulative recv counter (what the peer has acked).
    pub session_bytes_acked: u64,
    /// Sent datagrams still awaiting resolution (not acked, not marked lost).
    pub session_unresolved_sent: usize,
    /// Milliseconds since the last ACK was processed; saturates if none.
    pub session_last_ack_age_ms: u64,
    /// Milliseconds since this side last emitted an ACK to the peer.
    pub session_last_ack_sent_age_ms: u64,
    /// Whether an ACK is pending emission on this side.
    pub session_ack_pending: bool,
    /// Cumulative bytes this side has received (receiver-side counter).
    pub session_recv_bytes: u64,
    /// Current retransmit timeout in milliseconds.
    pub session_rto_ms: u64,
    /// Connection status of the first peer (UDP-direct, TCP-relay, or none).
    /// `None` if there are no sessions yet.
    pub peer_connection: Option<ToxConnection>,
}

impl<S: NodeStore + BlobStore> ToxMerkleBridge<S> {
    pub fn new(tox: Tox, store: S) -> Self {
        let tox_sk = tox.secret_key();
        // Derive an Ed25519 identity from the Tox X25519 secret key.
        // MerkleTox uses Ed25519 for protocol identity (signing), while Tox
        // uses X25519 for transport. The transport address (Tox PK) and the
        // protocol identity (Ed25519 PK) are independent.
        let self_pk = PhysicalDevicePk::from(
            merkle_tox_core::crypto::ed25519_public_key_from_seed(&tox_sk),
        );
        let transport = ToxTransport {
            tox: Arc::new(ReentrantMutex::new(tox)),
            send_ok: Arc::new(AtomicU64::new(0)),
            send_err: Arc::new(AtomicU64::new(0)),
            send_err_sendq: Arc::new(AtomicU64::new(0)),
            send_err_not_connected: Arc::new(AtomicU64::new(0)),
            send_err_other: Arc::new(AtomicU64::new(0)),
            recv_count: Arc::new(AtomicU64::new(0)),
            send_lock_wait_ns: Arc::new(AtomicU64::new(0)),
            send_lookup_ns: Arc::new(AtomicU64::new(0)),
            send_ffi_ns: Arc::new(AtomicU64::new(0)),
        };
        let engine = merkle_tox_core::engine::MerkleToxEngine::with_sk(
            self_pk,
            self_pk.to_logical(),
            PhysicalDeviceSk::from(tox_sk),
            rand::SeedableRng::from_entropy(),
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        let node = MerkleToxNode::new(
            engine,
            transport,
            store,
            Arc::new(merkle_tox_core::clock::SystemTimeProvider),
        );
        Self {
            node: Arc::new(Mutex::new(node)),
        }
    }

    pub fn with_node(node: Arc<Mutex<MerkleToxNode<ToxTransport, S>>>) -> Self {
        Self { node }
    }

    /// Take a single combined snapshot of transport, engine, and session
    /// counters. Acquires the node lock once. Cheap; safe to call from
    /// observability loops.
    pub async fn transfer_stats(&self) -> TransferStats {
        let lock = self.node.lock().await;
        let stream = lock.engine.push_streams.values().next();
        let peer_pk = lock.sessions.keys().next().copied();
        let session = lock.sessions.values().next();
        let now = lock.time_provider.now_instant();
        let peer_connection = peer_pk.and_then(|pk| lock.transport.friend_connection_status(pk));
        TransferStats {
            transport: lock.transport.stats(),
            engine: lock.engine.stats_snapshot(),
            push_streams: lock.engine.push_streams.len(),
            push_credits: stream.map(|s| s.credits).unwrap_or(0),
            push_offset: stream.map(|s| s.next_piece_offset).unwrap_or(0),
            sessions: lock.sessions.len(),
            session_cwnd_bytes: session
                .map(|s| s.cwnd() * tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE)
                .unwrap_or(0),
            session_in_flight_bytes: session.map(|s| s.in_flight()).unwrap_or(0),
            session_outgoing_count: session.map(|s| s.outgoing_count()).unwrap_or(0),
            session_pacing_bytes_per_sec: session.map(|s| s.pacing_rate()).unwrap_or(0.0),
            session_flush_diag: session
                .map(|s| s.flush_diag())
                .unwrap_or_default(),
            session_acks_received: session.map(|s| s.acks_received()).unwrap_or(0),
            session_losses_emitted: session.map(|s| s.losses_emitted()).unwrap_or(0),
            session_bytes_sent: session.map(|s| s.bytes_sent()).unwrap_or(0),
            session_bytes_acked: session.map(|s| s.bytes_acked()).unwrap_or(0),
            session_unresolved_sent: session.map(|s| s.unresolved_sent()).unwrap_or(0),
            session_last_ack_age_ms: session
                .map(|s| s.last_ack_age(now).as_millis() as u64)
                .unwrap_or(0),
            session_last_ack_sent_age_ms: session
                .map(|s| s.last_ack_sent_age(now).as_millis() as u64)
                .unwrap_or(0),
            session_ack_pending: session.map(|s| s.ack_pending()).unwrap_or(false),
            session_recv_bytes: session.map(|s| s.recv_bytes()).unwrap_or(0),
            session_rto_ms: session
                .map(|s| s.current_rto().as_millis() as u64)
                .unwrap_or(0),
            peer_connection,
        }
    }

    /// Initiates history synchronization for a conversation with a specific friend.
    pub async fn start_sync(
        &self,
        friend_pk: PhysicalDevicePk,
        conversation_id: ConversationId,
    ) -> MerkleToxResult<()> {
        let mut node_lock = self.node.lock().await;
        let MerkleToxNode {
            ref mut engine,
            ref store,
            ..
        } = *node_lock;

        let effects = engine.start_sync(conversation_id, Some(friend_pk), store);

        let now = node_lock.time_provider.now_instant();
        let now_ms = node_lock.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            let _ = node_lock.process_effect(effect, now, now_ms, &mut dummy_wakeup);
        }

        Ok(())
    }

    /// Offers a single Tox event to the bridge for processing.
    /// Returns Some(pk) if the bridge handled the event as a Merkle-Tox protocol event.
    pub async fn handle_event(&self, event: &Event<'_>) -> Option<ToxPublicKey> {
        let mut node = self.node.lock().await;
        Self::handle_event_locked(&mut node, event)
    }

    /// Internal version of handle_event that works on an already-locked node.
    pub fn handle_event_locked(
        node: &mut MerkleToxNode<ToxTransport, S>,
        event: &Event<'_>,
    ) -> Option<ToxPublicKey> {
        match event {
            Event::FriendConnectionStatus(e) => {
                let status = e.connection_status();
                let pk = node
                    .transport
                    .tox
                    .lock()
                    .friend(e.friend_number())
                    .public_key()
                    .ok();

                if let Some(pk) = pk {
                    let peer_pk = PhysicalDevicePk::from(pk.0);
                    if status != toxcore::tox::ToxConnection::TOX_CONNECTION_NONE {
                        debug!(
                            "Tox friend {:?} connected, initiating MT handshake",
                            peer_pk
                        );
                        node.set_peer_available(peer_pk, true);
                        let caps = ProtocolMessage::CapsAnnounce {
                            version: 1,
                            features: 0,
                        };
                        node.send_message(peer_pk, caps);
                    } else {
                        debug!("Tox friend {:?} disconnected", peer_pk);
                        node.set_peer_available(peer_pk, false);
                    }
                    return Some(pk);
                }
            }
            Event::FriendLossyPacket(e) => {
                let data = e.data();
                if data.first() == Some(&TOX_CUSTOM_PACKET_ID) {
                    node.transport
                        .recv_count
                        .fetch_add(1, Ordering::Relaxed);
                    let pk = node
                        .transport
                        .tox
                        .lock()
                        .friend(e.friend_number())
                        .public_key()
                        .ok();
                    if let Some(pk) = pk {
                        node.handle_packet(PhysicalDevicePk::from(pk.0), &data[1..]);
                        return Some(pk);
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// Background polling for retransmissions and pacing.
    /// Returns the next scheduled wakeup time.
    pub async fn poll(&self) -> Instant {
        self.node.lock().await.poll()
    }
}
