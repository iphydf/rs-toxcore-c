pub mod policy;
pub mod state;

use crate::policy::{DefaultPolicy, PolicyHandler};
use crate::state::{ChatState, MemberInfo, MemberRole};
use ed25519_dalek::SigningKey;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EmojiSource, InviteAction, LogicalIdentityPk,
    MerkleNode, NodeHash, NodeType, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::engine::{Conversation, Effect};
use merkle_tox_core::error::{MerkleToxError, MerkleToxResult};
use merkle_tox_core::identity::sign_delegation;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::{NodeEvent, NodeEventHandler, Transport};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
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
}

impl<T: Transport + 'static, S: NodeStore + BlobStore + 'static> MerkleToxClient<T, S> {
    /// Creates a new client for a specific conversation.
    pub fn new(node: Arc<Mutex<MerkleToxNode<T, S>>>, conversation_id: ConversationId) -> Self {
        let state = Arc::new(RwLock::new(ChatState {
            conversation_id,
            ..Default::default()
        }));
        Self {
            node,
            policy: Arc::new(DefaultPolicy),
            state,
            conversation_id,
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
        Self {
            node,
            policy,
            state,
            conversation_id,
        }
    }

    /// Starts the orchestration loop and performs initial state refresh.
    pub async fn start(self: Arc<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        {
            let mut node = self.node.lock().await;
            node.set_event_handler(Arc::new(ClientEventBridge { tx }));
        }

        let client = self.clone();
        tokio::spawn(async move {
            info!("MerkleToxClient orchestration loop started");
            while let Some(event) = rx.recv().await {
                if let Err(e) = client.handle_event(event).await {
                    error!("Error in orchestration loop: {}", e);
                }
            }
        });

        // Initial state refresh from the Admin track.
        if let Err(e) = self.refresh_state().await {
            error!("Failed to refresh initial state: {}", e);
        }
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
                    self.apply_node_to_state(&hash, &node).await?;
                    debug!(
                        "Orchestrating actions for node {}",
                        hex::encode(hash.as_bytes())
                    );
                    self.orchestrate_actions(&node).await?;
                }
            }
            NodeEvent::PeerHandshakeComplete { peer_pk } => {
                debug!("Checking auto-authorize for peer {:?}", peer_pk);
                self.check_auto_authorize(&peer_pk).await?;
            }
            _ => {}
        }
        debug!("Client handled event");
        Ok(())
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
            | Content::Other { .. } => {
                state.messages.push(crate::state::ChatMessage {
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
            Content::RatchetSnapshot { .. } => {
                // RatchetSnapshot is for self-recovery, not for the UI.
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
                if node_lock.engine.identity_manager.is_admin(
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
                if node_lock.engine.identity_manager.is_admin(
                    cid,
                    &self_pk,
                    &self_pk.to_logical(),
                    now,
                    u64::MAX,
                ) && let Some(Conversation::Established(em)) =
                    node_lock.engine.conversations.get(&cid)
                    && let Some(keys) = em.get_keys(em.current_epoch())
                {
                    let k_conv = keys.k_conv.clone();
                    // Use the first valid pre-key
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
                            k_conv,
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
            sign_delegation(&signing_key, device_pk, permissions, expires_at)
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

        let mut new_state = ChatState {
            conversation_id: self.conversation_id,
            ..Default::default()
        };

        for n in admin_nodes {
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
