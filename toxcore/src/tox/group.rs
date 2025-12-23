use crate::types::*;
use std::fmt;

#[derive(Clone, Copy)]
pub struct Group<'a> {
    pub(crate) tox: &'a super::Tox,
    pub(crate) number: GroupNumber,
}

impl<'a> std::fmt::Debug for Group<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("number", &self.number)
            .finish()
    }
}

impl<'a> From<Group<'a>> for GroupNumber {
    fn from(g: Group<'a>) -> Self {
        g.number
    }
}

impl<'a> From<&Group<'a>> for GroupNumber {
    fn from(g: &Group<'a>) -> Self {
        g.number
    }
}

impl<'a> Group<'a> {
    pub fn get_number(&self) -> GroupNumber {
        self.number
    }

    pub fn name(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .group_get_name(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn topic(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .group_get_topic(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn chat_id(&self) -> Result<ChatId> {
        self.tox
            .inner
            .core
            .group_get_chat_id(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn send_message(
        &self,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<GroupMessageId> {
        self.tox
            .inner
            .core
            .group_send_message(self.number, message_type, message)
            .map_err(ToxError::GroupSendMessage)
    }

    pub fn leave(self, part_message: Option<&[u8]>) -> Result<()> {
        self.tox
            .inner
            .core
            .group_leave(self.number, part_message.unwrap_or(&[]))
            .map_err(ToxError::GroupLeave)
    }

    pub fn invite_friend(&self, friend: &crate::tox::friend::Friend) -> Result<()> {
        self.tox
            .inner
            .core
            .group_invite_friend(self.number, friend.get_number())
            .map_err(ToxError::GroupInviteFriend)
    }

    pub fn send_private_message(
        &self,
        peer_id: GroupPeerNumber,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<GroupMessageId> {
        self.tox
            .inner
            .core
            .group_send_private_message(self.number, peer_id, message_type, message)
            .map_err(ToxError::GroupSendPrivateMessage)
    }

    pub fn send_custom_packet(&self, lossless: bool, data: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .group_send_custom_packet(self.number, lossless, data)
            .map_err(ToxError::GroupSendCustomPacket)
    }

    pub fn send_custom_private_packet(
        &self,
        peer_id: GroupPeerNumber,
        lossless: bool,
        data: &[u8],
    ) -> Result<()> {
        self.tox
            .inner
            .core
            .group_send_custom_private_packet(self.number, peer_id, lossless, data)
            .map_err(ToxError::GroupSendCustomPrivatePacket)
    }

    pub fn set_password(&self, password: Option<&[u8]>) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_password(self.number, password.unwrap_or(&[]))
            .map_err(ToxError::GroupSetPassword)
    }

    pub fn set_topic_lock(&self, topic_lock: ToxGroupTopicLock) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_topic_lock(self.number, topic_lock)
            .map_err(ToxError::GroupSetTopicLock)
    }

    pub fn set_voice_state(&self, voice_state: ToxGroupVoiceState) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_voice_state(self.number, voice_state)
            .map_err(ToxError::GroupSetVoiceState)
    }

    pub fn set_privacy_state(&self, privacy_state: ToxGroupPrivacyState) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_privacy_state(self.number, privacy_state)
            .map_err(ToxError::GroupSetPrivacyState)
    }

    pub fn set_peer_limit(&self, peer_limit: u16) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_peer_limit(self.number, peer_limit)
            .map_err(ToxError::GroupSetPeerLimit)
    }

    pub fn set_ignore(&self, peer_id: GroupPeerNumber, ignore: bool) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_ignore(self.number, peer_id, ignore)
            .map_err(ToxError::GroupSetIgnore)
    }

    pub fn set_role(&self, peer_id: GroupPeerNumber, role: ToxGroupRole) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_role(self.number, peer_id, role)
            .map_err(ToxError::GroupSetRole)
    }

    pub fn kick_peer(&self, peer_id: GroupPeerNumber) -> Result<()> {
        self.tox
            .inner
            .core
            .group_kick_peer(self.number, peer_id)
            .map_err(ToxError::GroupKickPeer)
    }

    pub fn is_connected(&self) -> Result<bool> {
        self.tox
            .inner
            .core
            .group_is_connected(self.number)
            .map_err(ToxError::GroupIsConnected)
    }

    pub fn disconnect(&self) -> Result<()> {
        self.tox
            .inner
            .core
            .group_disconnect(self.number)
            .map_err(ToxError::GroupDisconnect)
    }

    pub fn self_set_name(&self, name: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .group_self_set_name(self.number, name)
            .map_err(ToxError::GroupSelfNameSet)
    }

    pub fn self_name(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .group_self_get_name(self.number)
            .map_err(ToxError::GroupSelfQuery)
    }

    pub fn self_set_status(&self, status: ToxUserStatus) -> Result<()> {
        self.tox
            .inner
            .core
            .group_self_set_status(self.number, status)
            .map_err(ToxError::GroupSelfStatusSet)
    }

    pub fn self_status(&self) -> Result<ToxUserStatus> {
        self.tox
            .inner
            .core
            .group_self_get_status(self.number)
            .map_err(ToxError::GroupSelfQuery)
    }

    pub fn self_role(&self) -> Result<ToxGroupRole> {
        self.tox
            .inner
            .core
            .group_self_get_role(self.number)
            .map_err(ToxError::GroupSelfQuery)
    }

    pub fn self_peer_id(&self) -> Result<GroupPeerNumber> {
        self.tox
            .inner
            .core
            .group_self_get_peer_id(self.number)
            .map_err(ToxError::GroupSelfQuery)
    }

    pub fn self_public_key(&self) -> Result<PublicKey> {
        self.tox
            .inner
            .core
            .group_self_get_public_key(self.number)
            .map_err(ToxError::GroupSelfQuery)
    }

    pub fn peer_name(&self, peer_id: GroupPeerNumber) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .group_peer_get_name(self.number, peer_id)
            .map_err(ToxError::GroupPeerQuery)
    }

    pub fn peer_status(&self, peer_id: GroupPeerNumber) -> Result<ToxUserStatus> {
        self.tox
            .inner
            .core
            .group_peer_get_status(self.number, peer_id)
            .map_err(ToxError::GroupPeerQuery)
    }

    pub fn peer_role(&self, peer_id: GroupPeerNumber) -> Result<ToxGroupRole> {
        self.tox
            .inner
            .core
            .group_peer_get_role(self.number, peer_id)
            .map_err(ToxError::GroupPeerQuery)
    }

    pub fn peer_connection_status(&self, peer_id: GroupPeerNumber) -> Result<ToxConnection> {
        self.tox
            .inner
            .core
            .group_peer_get_connection_status(self.number, peer_id)
            .map_err(ToxError::GroupPeerQuery)
    }

    pub fn peer_public_key(&self, peer_id: GroupPeerNumber) -> Result<PublicKey> {
        self.tox
            .inner
            .core
            .group_peer_get_public_key(self.number, peer_id)
            .map_err(ToxError::GroupPeerQuery)
    }

    pub fn privacy_state(&self) -> Result<ToxGroupPrivacyState> {
        self.tox
            .inner
            .core
            .group_get_privacy_state(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn voice_state(&self) -> Result<ToxGroupVoiceState> {
        self.tox
            .inner
            .core
            .group_get_voice_state(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn topic_lock(&self) -> Result<ToxGroupTopicLock> {
        self.tox
            .inner
            .core
            .group_get_topic_lock(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn peer_limit(&self) -> Result<u16> {
        self.tox
            .inner
            .core
            .group_get_peer_limit(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn password(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .group_get_password(self.number)
            .map_err(ToxError::GroupStateQuery)
    }

    pub fn set_topic(&self, topic: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .group_set_topic(self.number, topic)
            .map_err(ToxError::GroupTopicSet)
    }
}
