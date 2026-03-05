pub mod policy;
pub mod state;

use crate::policy::{DefaultPolicy, PolicyHandler};
use crate::state::{ChatMessage, ChatState, ClientEvent, MemberInfo, MemberRole};
use ed25519_dalek::SigningKey;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EmojiSource, InviteAction, LogicalIdentityPk,
    MerkleNode, NodeHash, NodeType, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::engine::Effect;
use merkle_tox_core::error::{MerkleToxError, MerkleToxResult};
use merkle_tox_core::identity::sign_delegation;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::{NodeEvent, NodeEventHandler, Transport};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, watch};
use tracing::{debug, error, info};

/// Bridges MerkleToxNode events into a tokio channel.
struct ClientEventBridge {
    tx: mpsc::UnboundedSender<NodeEvent>,
}

impl NodeEventHandler for ClientEventBridge {
    fn handle_event(&self, event: NodeEvent) {
        let _ = self.tx.send(event);
    }
}

/// A high-level client for Merkle-Tox conversations.
/// Manages the materialized view and automated orchestration policies.
pub struct MerkleToxClient<T: Transport + 'static, S: NodeStore + BlobStore + 'static> {
    node: Arc<Mutex<MerkleToxNode<T, S>>>,
    policy: Arc<dyn PolicyHandler>,
    state: Arc<RwLock<ChatState>>,
    conversation_id: ConversationId,
    event_tx: broadcast::Sender<ClientEvent>,
    reachable_peers: Arc<RwLock<HashSet<PhysicalDevicePk>>>,
    shutdown: watch::Sender<bool>,
}

impl<T: Transport + 'static, S: NodeStore + BlobStore + 'static> MerkleToxClient<T, S> {
    /// Creates a new client for a specific conversation.
    pub fn new(node: Arc<Mutex<MerkleToxNode<T, S>>>, conversation_id: ConversationId) -> Self {
        let state = Arc::new(RwLock::new(ChatState {
            conversation_id,
            ..Default::default()
        }));
        let (event_tx, _) = broadcast::channel(256);
        let (shutdown, _) = watch::channel(false);
        Self {
            node,
            policy: Arc::new(DefaultPolicy),
            state,
            conversation_id,
            event_tx,
            reachable_peers: Arc::new(RwLock::new(HashSet::new())),
            shutdown,
        }
    }

    /// Creates a new client with a custom policy handler.
    pub fn with_policy(
        node: Arc<Mutex<MerkleToxNode<T, S>>>,
        conversation_id: ConversationId,
        policy: Arc<dyn PolicyHandler>,
    ) -> Self {
        let state = Arc::new(RwLock::new(ChatState {
            conversation_id,
            ..Default::default()
        }));
        let (event_tx, _) = broadcast::channel(256);
        let (shutdown, _) = watch::channel(false);
        Self {
            node,
            policy,
            state,
            conversation_id,
            event_tx,
            reachable_peers: Arc::new(RwLock::new(HashSet::new())),
            shutdown,
        }
    }

    /// Subscribe to application-level client events.
    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.event_tx.subscribe()
    }

    /// Signal the orchestration loop to stop.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Update peer reachability. Emits connect/disconnect events and triggers sync on connect.
    pub async fn set_peer_available(&self, peer_pk: PhysicalDevicePk, available: bool) {
        {
            let mut node_lock = self.node.lock().await;
            node_lock.set_peer_available(peer_pk, available);
        }

        let mut peers = self.reachable_peers.write().await;
        if available {
            if peers.insert(peer_pk) {
                self.emit_event(ClientEvent::PeerConnected { peer_pk });
            }
        } else if peers.remove(&peer_pk) {
            self.emit_event(ClientEvent::PeerDisconnected { peer_pk });
        }
        drop(peers);

        // Trigger sync on connect
        if available {
            self.trigger_sync_with_peer(peer_pk).await;
        }
    }

    /// Forward a raw packet to the underlying node.
    pub async fn handle_packet(&self, from: PhysicalDevicePk, data: &[u8]) {
        let mut node_lock = self.node.lock().await;
        node_lock.handle_packet(from, data);
    }

    /// Starts the orchestration loop with polling, sync, and event handling.
    pub async fn start(self: Arc<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        {
            let mut node = self.node.lock().await;
            node.set_event_handler(Arc::new(ClientEventBridge { tx }));
        }

        // Initial state refresh from the Admin track.
        if let Err(e) = self.refresh_state().await {
            error!("Failed to refresh initial state: {}", e);
        }

        let mut shutdown_rx = self.shutdown.subscribe();

        // Initial poll to get first wakeup time
        let initial_wakeup = {
            let mut node_lock = self.node.lock().await;
            node_lock.poll()
        };
        let mut poll_deadline = tokio::time::Instant::from_std(initial_wakeup);

        let sync_interval = self.policy.full_sync_interval();

        let client = self.clone();
        tokio::spawn(async move {
            info!("MerkleToxClient orchestration loop started");
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(ev) => {
                                if let Err(e) = client.handle_event(ev).await {
                                    error!("Error in orchestration loop: {}", e);
                                }
                            }
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep_until(poll_deadline) => {
                        let next = {
                            let mut node_lock = client.node.lock().await;
                            node_lock.poll()
                        };
                        poll_deadline = tokio::time::Instant::from_std(next);
                    }
                    _ = tokio::time::sleep(sync_interval) => {
                        client.trigger_full_sync().await;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("MerkleToxClient shutting down");
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Processes a single node event.
    pub async fn handle_event(&self, event: NodeEvent) -> MerkleToxResult<()> {
        debug!("Client handling event: {:?}", event);
        match event {
            NodeEvent::NodeVerified {
                conversation_id,
                hash,
                node,
            } => {
                if conversation_id == self.conversation_id {
                    debug!("Applying node {} to state", hex::encode(hash.as_bytes()));
                    // Promote speculative/pending messages with the same hash
                    {
                        let mut state = self.state.write().await;
                        state.speculative_messages.retain(|m| m.hash != hash);
                        state.identity_pending_messages.retain(|m| m.hash != hash);
                    }
                    self.apply_node_to_state(&hash, &node).await?;
                    self.emit_client_events_for_node(conversation_id, &hash, &node);
                    debug!(
                        "Orchestrating actions for node {}",
                        hex::encode(hash.as_bytes())
                    );
                    self.orchestrate_actions(&node).await?;
                }
            }
            NodeEvent::NodeSpeculative {
                conversation_id,
                hash,
                node,
            } => {
                if conversation_id == self.conversation_id {
                    let mut state = self.state.write().await;
                    state.speculative_messages.push(ChatMessage {
                        hash,
                        author_pk: node.author_pk,
                        timestamp: node.network_timestamp,
                        content: node.content.clone(),
                        reactions: Default::default(),
                        is_redacted: false,
                    });
                    self.emit_event(ClientEvent::SpeculativeMessage {
                        conversation_id,
                        hash,
                        author_pk: node.author_pk,
                        content: node.content,
                    });
                }
            }
            NodeEvent::NodeIdentityPending {
                conversation_id,
                hash,
                node,
            } => {
                if conversation_id == self.conversation_id {
                    let mut state = self.state.write().await;
                    state.identity_pending_messages.push(ChatMessage {
                        hash,
                        author_pk: node.author_pk,
                        timestamp: node.network_timestamp,
                        content: node.content.clone(),
                        reactions: Default::default(),
                        is_redacted: false,
                    });
                    self.emit_event(ClientEvent::IdentityPendingMessage {
                        conversation_id,
                        hash,
                        author_pk: node.author_pk,
                        content: node.content,
                    });
                }
            }
            NodeEvent::NodeInvalidated {
                conversation_id,
                hash,
            } => {
                if conversation_id == self.conversation_id {
                    let mut state = self.state.write().await;
                    state.messages.retain(|m| m.hash != hash);
                    state.speculative_messages.retain(|m| m.hash != hash);
                    state.identity_pending_messages.retain(|m| m.hash != hash);
                    state.heads.retain(|h| *h != hash);
                    self.emit_event(ClientEvent::NodeInvalidated {
                        conversation_id,
                        hash,
                    });
                }
            }
            NodeEvent::PeerHandshakeComplete { peer_pk } => {
                debug!("Checking auto-authorize for peer {:?}", peer_pk);
                self.emit_event(ClientEvent::PeerConnected { peer_pk });
                self.check_auto_authorize(&peer_pk).await?;
            }
            NodeEvent::BlobAvailable { hash } => {
                self.emit_event(ClientEvent::BlobAvailable { hash });
            }
            NodeEvent::EquivocationDetected {
                conversation_id,
                device_pk,
                seq,
                existing_hash,
                conflicting_hash,
            } => {
                self.emit_event(ClientEvent::EquivocationDetected {
                    conversation_id,
                    device_pk,
                    seq,
                    existing_hash,
                    conflicting_hash,
                });
            }
            NodeEvent::HistorySnapshotNeeded { conversation_id } => {
                self.emit_event(ClientEvent::HistorySnapshotNeeded { conversation_id });
            }
        }
        debug!("Client handled event");
        Ok(())
    }

    /// Emit typed ClientEvents based on verified node content.
    fn emit_client_events_for_node(
        &self,
        conversation_id: ConversationId,
        hash: &NodeHash,
        node: &MerkleNode,
    ) {
        match &node.content {
            Content::Text(_)
            | Content::Blob { .. }
            | Content::Location { .. }
            | Content::Custom { .. } => {
                self.emit_event(ClientEvent::MessageReceived {
                    conversation_id,
                    hash: *hash,
                    author_pk: node.author_pk,
                    timestamp: node.network_timestamp,
                    content: node.content.clone(),
                });
            }
            Content::Reaction { target_hash, emoji } => {
                let emoji_str = match emoji {
                    EmojiSource::Unicode(s) => s.clone(),
                    EmojiSource::Custom { shortcode, .. } => shortcode.clone(),
                };
                self.emit_event(ClientEvent::ReactionAdded {
                    conversation_id,
                    target_hash: *target_hash,
                    emoji: emoji_str,
                    reactor_pk: node.author_pk,
                });
            }
            Content::Redaction { target_hash, .. } => {
                self.emit_event(ClientEvent::MessageRedacted {
                    conversation_id,
                    target_hash: *target_hash,
                });
            }
            Content::Control(action) => match action {
                ControlAction::SetTitle(title) => {
                    self.emit_event(ClientEvent::TitleChanged {
                        conversation_id,
                        title: title.clone(),
                    });
                }
                ControlAction::SetTopic(topic) => {
                    self.emit_event(ClientEvent::TopicChanged {
                        conversation_id,
                        topic: topic.clone(),
                    });
                }
                ControlAction::Invite(invite) => {
                    let role = if invite.role == 1 {
                        MemberRole::Admin
                    } else {
                        MemberRole::Member
                    };
                    self.emit_event(ClientEvent::MemberJoined {
                        conversation_id,
                        member_pk: invite.invitee_pk,
                        role,
                    });
                }
                ControlAction::AuthorizeDevice { cert } => {
                    self.emit_event(ClientEvent::DeviceAuthorized {
                        conversation_id,
                        device_pk: cert.device_pk,
                    });
                }
                ControlAction::RevokeDevice {
                    target_device_pk, ..
                } => {
                    self.emit_event(ClientEvent::DeviceRevoked {
                        conversation_id,
                        device_pk: *target_device_pk,
                    });
                }
                _ => {}
            },
            _ => {}
        }
    }

    async fn apply_node_to_state(&self, hash: &NodeHash, node: &MerkleNode) -> MerkleToxResult<()> {
        let mut state = self.state.write().await;
        self.apply_node_internal(&mut state, hash, node);
        Ok(())
    }

    fn apply_node_internal(&self, state: &mut ChatState, hash: &NodeHash, node: &MerkleNode) {
        // Update heads and rank
        state.heads.retain(|h| !node.parents.contains(h));
        if !state.heads.contains(hash) {
            state.heads.push(*hash);
        }
        state.max_verified_rank = state.max_verified_rank.max(node.topological_rank);

        match &node.content {
            Content::Text(_)
            | Content::Blob { .. }
            | Content::Location { .. }
            | Content::Custom { .. } => {
                state.messages.push(ChatMessage {
                    hash: *hash,
                    author_pk: node.author_pk,
                    timestamp: node.network_timestamp,
                    content: node.content.clone(),
                    reactions: Default::default(),
                    is_redacted: false,
                });
            }
            Content::Reaction { target_hash, emoji } => {
                if let Some(msg) = state.messages.iter_mut().find(|m| m.hash == *target_hash) {
                    let emoji_str = match emoji {
                        merkle_tox_core::dag::EmojiSource::Unicode(s) => s.clone(),
                        merkle_tox_core::dag::EmojiSource::Custom { shortcode, .. } => {
                            shortcode.clone()
                        }
                    };
                    msg.reactions
                        .entry(emoji_str)
                        .or_default()
                        .insert(node.author_pk);
                }
            }
            Content::Redaction { target_hash, .. } => {
                if let Some(msg) = state.messages.iter_mut().find(|m| m.hash == *target_hash) {
                    msg.is_redacted = true;
                }
            }
            Content::Control(action) => match action {
                ControlAction::SetTitle(title) => {
                    state.title = title.clone();
                }
                ControlAction::SetTopic(topic) => {
                    state.topic = topic.clone();
                }
                ControlAction::AuthorizeDevice { cert } => {
                    let member =
                        state
                            .members
                            .entry(node.author_pk)
                            .or_insert_with(|| MemberInfo {
                                public_key: node.author_pk,
                                role: MemberRole::Member,
                                joined_at: node.network_timestamp,
                                devices: Default::default(),
                            });
                    member.devices.insert(cert.device_pk);
                    state.authorized_devices.insert(cert.device_pk);
                }
                ControlAction::RevokeDevice {
                    target_device_pk, ..
                } => {
                    state.authorized_devices.remove(target_device_pk);
                    for member in state.members.values_mut() {
                        member.devices.remove(target_device_pk);
                    }
                }
                ControlAction::Invite(invite) => {
                    state
                        .members
                        .entry(invite.invitee_pk)
                        .or_insert_with(|| MemberInfo {
                            public_key: invite.invitee_pk,
                            role: if invite.role == 1 {
                                MemberRole::Admin
                            } else {
                                MemberRole::Member
                            },
                            joined_at: node.network_timestamp,
                            devices: Default::default(),
                        });
                }
                ControlAction::Announcement {
                    pre_keys,
                    last_resort_key,
                } => {
                    state
                        .announcements
                        .insert(node.sender_pk, (pre_keys.clone(), last_resort_key.clone()));
                }
                ControlAction::HandshakePulse => {
                    // HandshakePulse is ephemeral/action-oriented,
                    // usually doesn't need to be in materialized state.
                }
                _ => {}
            },
            Content::HistoryExport { .. }
            | Content::LegacyBridge { .. }
            | Content::SenderKeyDistribution { .. } => {
                // Not for UI state.
            }
            _ => {}
        }
    }

    async fn orchestrate_actions(&self, node: &MerkleNode) -> MerkleToxResult<()> {
        // Auto-Key Exchange and Automated Onboarding logic
        let mut node_lock = self.node.lock().await;
        let now = node_lock.engine.clock.network_time_ms();
        let self_pk = node_lock.engine.self_pk;
        let cid = self.conversation_id;

        match &node.content {
            Content::Control(ControlAction::AuthorizeDevice { .. })
            | Content::Control(ControlAction::RevokeDevice { .. })
            | Content::Control(ControlAction::Invite(_))
            | Content::Control(ControlAction::Leave(_)) => {
                let ctx = merkle_tox_core::identity::CausalContext::global();
                if node_lock.engine.identity_manager.is_admin(
                    &ctx,
                    cid,
                    &self_pk,
                    &self_pk.to_logical(),
                    now,
                    u64::MAX,
                ) && (self.policy.should_rotate_keys(&*self.state.read().await)
                    || node_lock
                        .engine
                        .check_rotation_triggers(self.conversation_id))
                {
                    let node_ref = &mut *node_lock;
                    let effects = node_ref
                        .engine
                        .rotate_conversation_key(self.conversation_id, &node_ref.store)?;
                    let now_inst = node_ref.time_provider.now_instant();
                    let now_ms = node_ref.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now_inst;
                    for effect in effects {
                        node_ref.process_effect(effect, now_inst, now_ms, &mut dummy_wakeup)?;
                    }
                }
            }
            Content::Control(ControlAction::Announcement { pre_keys, .. }) => {
                // A peer has published their ephemeral keys.
                // If we are an admin and have the conversation key, we should share it with them.
                let ctx = merkle_tox_core::identity::CausalContext::global();
                if node_lock.engine.identity_manager.is_admin(
                    &ctx,
                    cid,
                    &self_pk,
                    &self_pk.to_logical(),
                    now,
                    u64::MAX,
                ) {
                    // Use the first valid pre-key; K_conv_0 is derived internally per spec §2.C.
                    if let Some(spk) = pre_keys.iter().find(|k| k.expires_at > now) {
                        info!(
                            "Automatically sharing conversation key with {:?} via X3DH",
                            node.sender_pk
                        );
                        let node_ref = &mut *node_lock;
                        let effects = node_ref.engine.author_x3dh_key_exchange(
                            cid,
                            node.sender_pk,
                            spk.public_key,
                            &node_ref.store,
                        )?;
                        let now_inst = node_ref.time_provider.now_instant();
                        let now_ms = node_ref.time_provider.now_system_ms() as u64;
                        let mut dummy_wakeup = now_inst;
                        for effect in effects {
                            node_ref.process_effect(effect, now_inst, now_ms, &mut dummy_wakeup)?;
                        }
                    }
                }
            }
            Content::Control(ControlAction::HandshakePulse) => {
                if self
                    .policy
                    .should_respond_to_pulse(node.sender_pk.as_bytes())
                {
                    info!(
                        "Responding to HandshakePulse from {:?} with fresh Announcement",
                        node.sender_pk
                    );
                    let node_ref = &mut *node_lock;
                    let effects = node_ref.engine.author_announcement(cid, &node_ref.store)?;
                    let now_inst = node_ref.time_provider.now_instant();
                    let now_ms = node_ref.time_provider.now_system_ms() as u64;
                    let mut dummy_wakeup = now_inst;
                    for effect in effects {
                        node_ref.process_effect(effect, now_inst, now_ms, &mut dummy_wakeup)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_auto_authorize(&self, peer_pk: &PhysicalDevicePk) -> MerkleToxResult<()> {
        let self_pk = {
            let node_lock = self.node.lock().await;
            node_lock.engine.self_pk
        };

        if self
            .policy
            .should_authorize(self_pk.as_bytes(), peer_pk.as_bytes())
        {
            info!("Policy allows auto-authorization of {:?}", peer_pk);
            // Check if we are admin to perform authorization
            let state = self.state.read().await;
            if let Some(member) = state.members.get(&self_pk.to_logical())
                && member.role == MemberRole::Admin
            {
                self.authorize_device(*peer_pk, Permissions::ALL, i64::MAX)
                    .await?;
            }
        }
        Ok(())
    }

    /// Trigger a full sync with all reachable peers (filtered by policy).
    async fn trigger_full_sync(&self) {
        let peers: Vec<PhysicalDevicePk> = {
            let peers = self.reachable_peers.read().await;
            peers
                .iter()
                .filter(|pk| self.policy.should_sync_with(pk))
                .copied()
                .collect()
        };

        for peer in peers {
            self.trigger_sync_with_peer(peer).await;
        }
    }

    async fn trigger_sync_with_peer(&self, peer_pk: PhysicalDevicePk) {
        let mut node_lock = self.node.lock().await;
        let cid = self.conversation_id;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .start_sync(cid, Some(peer_pk), &node_ref.store);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            if let Err(e) = node_ref.process_effect(effect, now, now_ms, &mut dummy_wakeup) {
                error!("Error processing sync effect: {}", e);
            }
        }
    }

    fn emit_event(&self, event: ClientEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Appends a text message to the history.
    pub async fn send_message(&self, text: String) -> MerkleToxResult<NodeHash> {
        self.author_node(Content::Text(text), Vec::new()).await
    }

    /// Reacts to a previous message with an emoji.
    pub async fn send_reaction(
        &self,
        target_hash: NodeHash,
        emoji: EmojiSource,
    ) -> MerkleToxResult<NodeHash> {
        self.author_node(Content::Reaction { target_hash, emoji }, Vec::new())
            .await
    }

    /// Redacts a previous message.
    pub async fn send_redaction(
        &self,
        target_hash: NodeHash,
        reason: String,
    ) -> MerkleToxResult<NodeHash> {
        self.author_node(
            Content::Redaction {
                target_hash,
                reason,
            },
            Vec::new(),
        )
        .await
    }

    /// Sends a geo-location.
    pub async fn send_location(
        &self,
        latitude: f64,
        longitude: f64,
        title: Option<String>,
    ) -> MerkleToxResult<NodeHash> {
        self.author_node(
            Content::Location {
                latitude,
                longitude,
                title,
            },
            Vec::new(),
        )
        .await
    }

    /// Sets the room title.
    pub async fn set_title(&self, title: String) -> MerkleToxResult<NodeHash> {
        self.author_node(Content::Control(ControlAction::SetTitle(title)), Vec::new())
            .await
    }

    /// Sets the room topic.
    pub async fn set_topic(&self, topic: String) -> MerkleToxResult<NodeHash> {
        self.author_node(Content::Control(ControlAction::SetTopic(topic)), Vec::new())
            .await
    }

    /// Invites a new member to the conversation.
    pub async fn invite(
        &self,
        invitee_pk: LogicalIdentityPk,
        role: MemberRole,
    ) -> MerkleToxResult<NodeHash> {
        let role_u8 = if role == MemberRole::Admin { 1 } else { 0 };
        self.author_node(
            Content::Control(ControlAction::Invite(InviteAction {
                invitee_pk,
                role: role_u8,
            })),
            Vec::new(),
        )
        .await
    }

    /// Revokes a device's access.
    pub async fn revoke_device(
        &self,
        target_device_pk: PhysicalDevicePk,
        reason: String,
    ) -> MerkleToxResult<NodeHash> {
        self.author_node(
            Content::Control(ControlAction::RevokeDevice {
                target_device_pk,
                reason,
            }),
            Vec::new(),
        )
        .await
    }

    /// Manually authorize a device.
    pub async fn authorize_device(
        &self,
        device_pk: PhysicalDevicePk,
        permissions: Permissions,
        expires_at: i64,
    ) -> MerkleToxResult<NodeHash> {
        let mut node_lock = self.node.lock().await;
        let cid = self.conversation_id;

        let cert = if let Some(sk_bytes) = &node_lock.engine.self_sk {
            let signing_key = SigningKey::from_bytes(sk_bytes.as_bytes());
            sign_delegation(&signing_key, device_pk, permissions, expires_at, cid)
        } else {
            return Err(MerkleToxError::Crypto("Missing signing key".to_string()));
        };

        let node_ref = &mut *node_lock;
        let effects = node_ref.engine.author_node(
            cid,
            Content::Control(ControlAction::AuthorizeDevice { cert }),
            Vec::new(),
            &node_ref.store,
        )?;

        let mut node_hash = NodeHash::from([0u8; 32]);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            if let Effect::WriteStore(_, ref n, _) = effect {
                node_hash = n.hash();
            }
            node_ref.process_effect(effect, now, now_ms, &mut dummy_wakeup)?;
        }

        Ok(node_hash)
    }

    /// Leaves the conversation.
    pub async fn leave(&self) -> MerkleToxResult<NodeHash> {
        let self_pk = {
            let node_lock = self.node.lock().await;
            node_lock.engine.self_pk.to_logical()
        };
        self.author_node(Content::Control(ControlAction::Leave(self_pk)), Vec::new())
            .await
    }

    /// Authors a HandshakePulse node to request fresh pre-keys from peers.
    pub async fn send_pulse(&self) -> MerkleToxResult<NodeHash> {
        self.author_node(Content::Control(ControlAction::HandshakePulse), Vec::new())
            .await
    }

    /// Authors an Announcement node with fresh pre-keys.
    pub async fn announce_keys(&self) -> MerkleToxResult<NodeHash> {
        let mut node_lock = self.node.lock().await;
        let cid = self.conversation_id;
        let node_ref = &mut *node_lock;
        let effects = node_ref.engine.author_announcement(cid, &node_ref.store)?;

        let mut node_hash = NodeHash::from([0u8; 32]);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            if let Effect::WriteStore(_, ref n, _) = effect {
                node_hash = n.hash();
            }
            node_ref.process_effect(effect, now, now_ms, &mut dummy_wakeup)?;
        }

        Ok(node_hash)
    }

    /// Sends a large binary asset.
    pub async fn send_blob(
        &self,
        name: String,
        mime_type: String,
        data: Vec<u8>,
    ) -> MerkleToxResult<NodeHash> {
        let blob_hash = NodeHash::from(*blake3::hash(&data).as_bytes());
        let size = data.len() as u64;

        {
            let node_lock = self.node.lock().await;
            let info = merkle_tox_core::cas::BlobInfo {
                hash: blob_hash,
                size,
                bao_root: None, // Simplified: no outboard proof for small/medium blobs
                status: merkle_tox_core::cas::BlobStatus::Available,
                received_mask: None,
                decryption_key: None,
            };
            node_lock.store.put_blob_info(info)?;

            // Write chunks to store
            let chunk_size = 64 * 1024;
            for (i, chunk) in data.chunks(chunk_size).enumerate() {
                node_lock.store.put_chunk(
                    &self.conversation_id,
                    &blob_hash,
                    (i * chunk_size) as u64,
                    chunk,
                    None,
                )?;
            }
        }

        self.author_node(
            Content::Blob {
                hash: blob_hash,
                name,
                mime_type,
                size,
                metadata: Vec::new(),
            },
            Vec::new(),
        )
        .await
    }

    async fn author_node(&self, content: Content, metadata: Vec<u8>) -> MerkleToxResult<NodeHash> {
        let mut node_lock = self.node.lock().await;
        let cid = self.conversation_id;
        let node_ref = &mut *node_lock;
        let effects = node_ref
            .engine
            .author_node(cid, content, metadata, &node_ref.store)?;

        let mut node_hash = NodeHash::from([0u8; 32]);
        let now = node_ref.time_provider.now_instant();
        let now_ms = node_ref.time_provider.now_system_ms() as u64;
        let mut dummy_wakeup = now;
        for effect in effects {
            if let Effect::WriteStore(_, ref n, _) = effect {
                node_hash = n.hash();
            }
            node_ref.process_effect(effect, now, now_ms, &mut dummy_wakeup)?;
        }

        Ok(node_hash)
    }

    /// Returns the current materialized state of the conversation.
    pub async fn state(&self) -> ChatState {
        self.state.read().await.clone()
    }

    /// Performs a full rebuild of the materialized state from the Admin Track.
    pub async fn refresh_state(&self) -> MerkleToxResult<()> {
        let node_lock = self.node.lock().await;
        let admin_nodes = node_lock
            .store
            .get_verified_nodes_by_type(&self.conversation_id, NodeType::Admin)?;
        let content_nodes = node_lock
            .store
            .get_verified_nodes_by_type(&self.conversation_id, NodeType::Content)?;

        let mut new_state = ChatState {
            conversation_id: self.conversation_id,
            ..Default::default()
        };

        for n in admin_nodes {
            self.apply_node_internal(&mut new_state, &n.hash(), &n);
        }
        for n in content_nodes {
            self.apply_node_internal(&mut new_state, &n.hash(), &n);
        }

        let mut all_heads = node_lock.store.get_heads(&self.conversation_id);
        for h in node_lock.store.get_admin_heads(&self.conversation_id) {
            if !all_heads.contains(&h) {
                all_heads.push(h);
            }
        }
        new_state.heads = all_heads;

        let mut state = self.state.write().await;
        *state = new_state;

        Ok(())
    }
}
