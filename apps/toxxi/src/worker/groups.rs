use crate::utils::Tell;
use std::sync::mpsc;

use toxcore::tox::events::{
    EventGroupInvite, EventGroupMessage, EventGroupModeration, EventGroupPeerExit,
    EventGroupPeerJoin, EventGroupPeerName, EventGroupPrivateMessage, EventGroupSelfJoin,
    EventGroupTopic,
};
use toxcore::tox::{GroupNumber, GroupPrivacyState, Tox};
use toxcore::types::{GroupChatId, GroupRole, GroupTopicLock, MessageType, PublicKey};

use super::{Session, find_friend, log_error, send_failure};
use crate::model::{GroupSettings, InternalMessageId, WindowId};
use crate::msg::{GroupSetting, LogContext, Msg, SendFailure, ToxEvent};
use crate::sync::event::ChatId;
use crate::sync::fact::Privacy;

/// Unlike the group list, this finds groups that are still joining.
fn find_group(tox: &Tox, chat_id: &GroupChatId) -> Option<GroupNumber> {
    tox.group_by_id(chat_id).ok().map(|group| group.number())
}

fn group_settings(tox: &Tox, gnum: GroupNumber) -> Option<GroupSettings> {
    let group = tox.group(gnum);
    Some(GroupSettings {
        privacy: group.privacy_state().ok()?,
        peer_limit: group.peer_limit().ok()?,
        password: String::from_utf8_lossy(&group.password().ok()?).into_owned(),
        topic_lock: group.topic_lock().ok()? == GroupTopicLock::Enabled,
        voice_state: group.voice_state().ok()?,
        self_pk: group.self_public_key().ok()?,
    })
}

/// Sends toxxi the name, topic and our role of each group in the profile.
pub(super) fn announce(tox: &Tox, tx: &mpsc::Sender<Msg>) {
    for group in tox.group_list() {
        let gnum = group.number();
        let name = group.name().ok().and_then(|n| String::from_utf8(n).ok());
        tx.tell(Msg::Tox(ToxEvent::GroupName(
            gnum,
            name.unwrap_or_default(),
        )));
        if let Ok(topic_bytes) = group.topic() {
            let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
            tx.tell(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, None)));
        }
        if let Ok(role) = group.self_role() {
            tx.tell(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
        }
    }
}

impl Session<'_> {
    pub(super) fn send_group_settings(&self, gnum: GroupNumber) {
        if let Some(settings) = group_settings(self.tox, gnum) {
            self.tx
                .tell(Msg::Tox(ToxEvent::GroupSettings(gnum, settings)));
        }
    }

    fn group_created(&self, gnum: GroupNumber, chat_id: GroupChatId, name: Option<String>) {
        self.tx
            .tell(Msg::Tox(ToxEvent::GroupCreated(gnum, chat_id, name)));
    }

    fn group_sent(
        &self,
        chat_id: GroupChatId,
        internal_id: InternalMessageId,
        sent: Result<GroupNumber, SendFailure>,
    ) {
        self.tx.tell(Msg::Tox(match sent {
            Ok(group) => ToxEvent::GroupMessageSent(group, internal_id),
            Err(failure) => {
                ToxEvent::MessageSendFailed(WindowId::Group(chat_id), internal_id, failure)
            }
        }));
    }

    pub(super) fn send_group_message(
        &mut self,
        chat_id: GroupChatId,
        message_type: MessageType,
        msg: Vec<u8>,
        internal_id: InternalMessageId,
    ) {
        let sent = find_group(self.tox, &chat_id)
            .ok_or(SendFailure::Never)
            .and_then(|group| {
                self.tox
                    .group(group)
                    .send_message(message_type, &msg)
                    .map(|_| group)
                    .map_err(|e| send_failure(self.tx, LogContext::Group(chat_id), &e))
            });
        self.group_sent(chat_id, internal_id, sent);
    }

    pub(super) fn send_group_private_message(
        &mut self,
        chat_id: GroupChatId,
        pk: PublicKey,
        message_type: MessageType,
        msg: Vec<u8>,
        internal_id: InternalMessageId,
    ) {
        let sent = find_group(self.tox, &chat_id)
            .ok_or(SendFailure::Never)
            .and_then(|group| {
                // A member who's away may come back.
                let peer = self
                    .group_peers
                    .get(&group)
                    .and_then(|peers| peers.get(&pk))
                    .ok_or(SendFailure::Later)?;
                self.tox
                    .group(group)
                    .send_private_message(*peer, message_type, &msg)
                    .map(|_| group)
                    .map_err(|e| send_failure(self.tx, LogContext::Group(chat_id), &e))
            });
        self.group_sent(chat_id, internal_id, sent);
    }

    pub(super) fn create_group(&mut self, name: String) {
        match self
            .tox
            .group_new(GroupPrivacyState::Public, name.as_bytes(), &self.tox.name())
        {
            Ok(group) => {
                if let Ok(chat_id) = group.chat_id() {
                    self.group_created(group.number(), chat_id, Some(name));
                } else {
                    log_error(
                        self.tx,
                        LogContext::Global,
                        "Failed to get chat_id for created group",
                    );
                }
            }
            Err(e) => {
                log_error(
                    self.tx,
                    LogContext::Global,
                    format!("Failed to create group: {e:?}"),
                );
            }
        }
    }

    pub(super) fn make_group(&mut self, privacy: Privacy, name: String) -> Option<ChatId> {
        let privacy = if privacy == Privacy::Private {
            GroupPrivacyState::Private
        } else {
            GroupPrivacyState::Public
        };
        let group = self
            .tox
            .group_new(privacy, name.as_bytes(), &self.tox.name())
            .ok()?;
        let chat_id = group.chat_id().ok()?;
        self.group_created(group.number(), chat_id, Some(name));
        Some(ChatId::Group(chat_id))
    }

    pub(super) fn leave_group(&mut self, chat_id: GroupChatId) {
        if let Some(group_number) = find_group(self.tox, &chat_id) {
            let left = self.tox.group(group_number).leave(&[]);
            self.check(LogContext::Group(chat_id), "leaving the group", left);
        }
    }

    /// Also sends toxxi a `GroupCreated` for the group.
    fn join(&mut self, chat_id: GroupChatId, password: Option<String>) -> Result<(), String> {
        let group = self
            .tox
            .group_join(
                &chat_id,
                &self.tox.name(),
                password.as_deref().map(str::as_bytes),
            )
            // When rejoining a group it has, Tox returns 0, not its number.
            .and_then(|_| self.tox.group_by_id(&chat_id))
            .map_err(|e| format!("{e:?}"))?;
        let name = group.name().ok().and_then(|n| String::from_utf8(n).ok());
        self.group_created(group.number(), chat_id, name);
        Ok(())
    }

    pub(super) fn join_group(&mut self, chat_id: GroupChatId, password: Option<String>) {
        if let Err(e) = self.join(chat_id, password) {
            log_error(
                self.tx,
                LogContext::Global,
                format!("Failed to join group: {e}"),
            );
        }
    }

    pub(super) fn join_chat_by_id(
        &mut self,
        chat_id: GroupChatId,
        password: Option<String>,
    ) -> Option<ChatId> {
        self.join(chat_id, password)
            .ok()
            .map(|()| ChatId::Group(chat_id))
    }

    pub(super) fn accept_group_invite(
        &mut self,
        friend: PublicKey,
        invite: Vec<u8>,
        password: Option<String>,
    ) -> Option<ChatId> {
        let friend_number = find_friend(self.tox, &friend)?;
        match self.tox.group_invite_accept(
            &self.tox.friend(friend_number),
            &invite,
            &self.tox.name(),
            password.as_deref().map(str::as_bytes),
        ) {
            Ok(group) => {
                let name = group.name().ok().and_then(|n| String::from_utf8(n).ok());
                let chat_id = group.chat_id().ok()?;
                self.group_created(group.number(), chat_id, name);
                Some(ChatId::Group(chat_id))
            }
            Err(e) => {
                log_error(
                    self.tx,
                    LogContext::Global,
                    format!("Failed to accept group invite: {e:?}"),
                );
                None
            }
        }
    }

    pub(super) fn invite_friend_to_group(&mut self, chat_id: GroupChatId, pk: PublicKey) {
        if let Some(group_number) = find_group(self.tox, &chat_id)
            && let Some(friend_number) = find_friend(self.tox, &pk)
        {
            let invited = self
                .tox
                .group(group_number)
                .invite_friend(&self.tox.friend(friend_number));
            self.check(LogContext::Group(chat_id), "inviting to the group", invited);
        }
    }

    pub(super) fn set_group_peer_ignore(
        &mut self,
        chat_id: GroupChatId,
        pk: PublicKey,
        ignore: bool,
    ) {
        if let Some(group_number) = find_group(self.tox, &chat_id)
            && let Some(peers) = self.group_peers.get(&group_number)
            && let Some(peer_id) = peers.get(&pk)
        {
            let set = self.tox.group(group_number).set_ignore(*peer_id, ignore);
            self.check(LogContext::Group(chat_id), "ignoring the peer", set);
        }
    }

    pub(super) fn set_group_setting(&mut self, chat_id: GroupChatId, setting: GroupSetting) {
        let Some(gnum) = find_group(self.tox, &chat_id) else {
            return;
        };
        let group = self.tox.group(gnum);
        let result = match setting {
            GroupSetting::Privacy(privacy) => group
                .set_privacy_state(privacy)
                .map_err(|e| format!("{e:?}")),
            GroupSetting::PeerLimit(limit) => {
                group.set_peer_limit(limit).map_err(|e| format!("{e:?}"))
            }
            GroupSetting::Password(password) => group
                .set_password(password.as_bytes())
                .map_err(|e| format!("{e:?}")),
            GroupSetting::TopicLock(lock) => group
                .set_topic_lock(if lock {
                    GroupTopicLock::Enabled
                } else {
                    GroupTopicLock::Disabled
                })
                .map_err(|e| format!("{e:?}")),
            GroupSetting::VoiceState(voice_state) => group
                .set_voice_state(voice_state)
                .map_err(|e| format!("{e:?}")),
        };
        match result {
            Ok(()) => self.send_group_settings(gnum),
            Err(e) => {
                log_error(
                    self.tx,
                    LogContext::Group(chat_id),
                    format!("Error changing group settings: {e}"),
                );
            }
        }
    }

    pub(super) fn moderate_group_peer(
        &mut self,
        chat_id: GroupChatId,
        pk: PublicKey,
        role: Option<GroupRole>,
    ) {
        let Some(gnum) = find_group(self.tox, &chat_id) else {
            return;
        };
        let Some(peer_id) = self
            .group_peers
            .get(&gnum)
            .and_then(|peers| peers.get(&pk))
            .copied()
        else {
            return;
        };
        let group = self.tox.group(gnum);
        let result = match role {
            Some(role) => group.set_role(peer_id, role),
            None => group.kick_peer(peer_id),
        };
        match (result, role) {
            (Ok(()), Some(role)) => {
                let name = group
                    .peer_name(peer_id)
                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                    .unwrap_or_default();
                self.tx.tell(Msg::Tox(ToxEvent::GroupPeerName(
                    gnum, peer_id, name, role, pk,
                )));
            }
            (Ok(()), None) => {
                if let Some(peers) = self.group_peers.get_mut(&gnum) {
                    peers.remove(&pk);
                }
                self.tx
                    .tell(Msg::Tox(ToxEvent::GroupPeerLeave(gnum, peer_id)));
            }
            (Err(e), _) => {
                log_error(
                    self.tx,
                    LogContext::Group(chat_id),
                    format!("Error moderating a peer: {e:?}"),
                );
            }
        }
    }

    pub(super) fn set_group_nickname(&mut self, chat_id: GroupChatId, name: String) {
        let Some(group_number) = find_group(self.tox, &chat_id) else {
            log_error(
                self.tx,
                LogContext::Group(chat_id),
                format!("SetGroupNickname: Group not found for GroupChatId {chat_id:?}"),
            );
            return;
        };
        let group = self.tox.group(group_number);
        match group
            .self_set_name(name.as_bytes())
            .and_then(|()| Ok((group.self_peer_id()?, group.self_role()?)))
        {
            Err(e) => log_error(
                self.tx,
                LogContext::Group(chat_id),
                format!("Error setting group nickname: {e:?}"),
            ),
            Ok((peer_id, role)) => {
                self.tx.tell(Msg::Tox(ToxEvent::GroupPeerName(
                    group_number,
                    peer_id,
                    name,
                    role,
                    self.tox.public_key(),
                )));
            }
        }
    }

    pub(super) fn set_group_topic(&mut self, chat_id: GroupChatId, topic: String) {
        let Some(group_number) = find_group(self.tox, &chat_id) else {
            log_error(
                self.tx,
                LogContext::Global,
                format!("SetGroupTopic: Group not found for GroupChatId {chat_id:?}"),
            );
            return;
        };
        if let Err(e) = self.tox.group(group_number).set_topic(topic.as_bytes()) {
            log_error(
                self.tx,
                LogContext::Group(chat_id),
                format!("Error setting group topic: {e:?}"),
            );
        } else {
            self.tx.tell(Msg::Tox(ToxEvent::GroupTopic(
                group_number,
                topic,
                Some(self.tox.public_key()),
            )));
        }
    }

    pub(super) fn group_message(&mut self, e: &EventGroupMessage) {
        let pk = self
            .tox
            .group(e.group_number())
            .peer_public_key(e.peer_id())
            .ok();
        self.tx.tell(Msg::Tox(ToxEvent::GroupMessage(
            e.group_number(),
            e.peer_id(),
            e.message_type(),
            e.message().to_vec(),
            pk,
        )));
    }

    pub(super) fn group_private_message(&mut self, e: &EventGroupPrivateMessage) {
        if let Ok(pk) = self
            .tox
            .group(e.group_number())
            .peer_public_key(e.peer_id())
        {
            self.tx.tell(Msg::Tox(ToxEvent::GroupPrivateMessage(
                e.group_number(),
                e.peer_id(),
                e.message_type(),
                e.message().to_vec(),
                pk,
            )));
        }
    }

    pub(super) fn group_invite(&mut self, e: &EventGroupInvite) {
        self.friend_event(e.friend_number(), |friend| ToxEvent::GroupInvite {
            friend,
            invite: e.invite_data().to_vec(),
            name: String::from_utf8_lossy(e.group_name()).into_owned(),
        });
    }

    fn send_group_name_and_role(&self, gnum: GroupNumber) {
        let group = self.tox.group(gnum);
        if let Ok(name_bytes) = group.name() {
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            self.tx.tell(Msg::Tox(ToxEvent::GroupName(gnum, name)));
        }
        if let Ok(role) = group.self_role() {
            self.tx.tell(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
        }
    }

    pub(super) fn group_topic(&mut self, e: &EventGroupTopic) {
        let gnum = e.group_number();
        self.send_group_name_and_role(gnum);
        let topic = String::from_utf8_lossy(e.topic()).into_owned();
        let setter = self.tox.group(gnum).peer_public_key(e.peer_id()).ok();
        self.tx
            .tell(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, setter)));
    }

    pub(super) fn group_self_join(&mut self, e: &EventGroupSelfJoin) {
        let gnum = e.group_number();
        let group = self.tox.group(gnum);
        let set = group.self_set_status(self.tox.status());
        self.check(LogContext::Global, "setting the status in a group", set);
        self.tx.tell(Msg::Tox(ToxEvent::GroupSelfJoin(gnum)));
        self.send_group_settings(gnum);
        self.send_group_name_and_role(gnum);
        if let Ok(topic_bytes) = group.topic() {
            let topic = String::from_utf8_lossy(&topic_bytes).into_owned();
            self.tx
                .tell(Msg::Tox(ToxEvent::GroupTopic(gnum, topic, None)));
        }
    }

    pub(super) fn group_peer_join(&mut self, e: &EventGroupPeerJoin) {
        let group = self.tox.group(e.group_number());
        // A peer that already left has no key: its exit event comes next.
        let (Ok(pk), Ok(role)) = (
            group.peer_public_key(e.peer_id()),
            group.peer_role(e.peer_id()),
        ) else {
            return;
        };
        let name = group
            .peer_name(e.peer_id())
            .map(|n| String::from_utf8_lossy(&n).into_owned())
            .unwrap_or_else(|_| format!("Peer {}", e.peer_id().0));

        self.group_peers
            .entry(e.group_number())
            .or_default()
            .insert(pk, e.peer_id());

        self.tx.tell(Msg::Tox(ToxEvent::GroupPeerJoin(
            e.group_number(),
            e.peer_id(),
            name,
            role,
            pk,
        )));
    }

    pub(super) fn group_peer_name(&mut self, e: &EventGroupPeerName) {
        let group = self.tox.group(e.group_number());
        let (Ok(pk), Ok(role)) = (
            group.peer_public_key(e.peer_id()),
            group.peer_role(e.peer_id()),
        ) else {
            return;
        };
        let name = String::from_utf8_lossy(e.name()).into_owned();

        // Keep the mapping up to date, e.g. for ourselves, as we get no join
        // event at first.
        self.group_peers
            .entry(e.group_number())
            .or_default()
            .insert(pk, e.peer_id());

        self.tx.tell(Msg::Tox(ToxEvent::GroupPeerName(
            e.group_number(),
            e.peer_id(),
            name,
            role,
            pk,
        )));
    }

    pub(super) fn group_peer_exit(&mut self, e: &EventGroupPeerExit) {
        if let Some(peers) = self.group_peers.get_mut(&e.group_number()) {
            peers.retain(|_, v| *v != e.peer_id());
        }
        self.tx.tell(Msg::Tox(ToxEvent::GroupPeerLeave(
            e.group_number(),
            e.peer_id(),
        )));
    }

    pub(super) fn group_moderation(&mut self, e: &EventGroupModeration) {
        let gnum = e.group_number();
        let group = self.tox.group(gnum);
        if let Ok(role) = group.peer_role(e.target_peer_id())
            && let Ok(name_bytes) = group.peer_name(e.target_peer_id())
            && let Ok(pk) = group.peer_public_key(e.target_peer_id())
        {
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            self.tx.tell(Msg::Tox(ToxEvent::GroupPeerName(
                gnum,
                e.target_peer_id(),
                name,
                role,
                pk,
            )));
        }
        if let Ok(role) = group.self_role() {
            self.tx.tell(Msg::Tox(ToxEvent::GroupSelfRole(gnum, role)));
        }
        self.tx.tell(Msg::Tox(ToxEvent::GroupModeration {
            group: gnum,
            source: e.source_peer_id(),
            target: e.target_peer_id(),
            event: e.mod_type(),
        }));
    }
}
