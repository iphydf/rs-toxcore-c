use crate::types::*;

#[derive(Clone, Copy)]
pub struct Friend<'a> {
    pub(crate) tox: &'a super::Tox,
    pub(crate) number: FriendNumber,
}

impl<'a> std::fmt::Debug for Friend<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Friend")
            .field("number", &self.number)
            .finish()
    }
}

impl<'a> From<Friend<'a>> for FriendNumber {
    fn from(f: Friend<'a>) -> Self {
        f.number
    }
}

impl<'a> From<&Friend<'a>> for FriendNumber {
    fn from(f: &Friend<'a>) -> Self {
        f.number
    }
}

impl<'a> Friend<'a> {
    pub fn get_number(&self) -> FriendNumber {
        self.number
    }

    pub fn name(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .friend_get_name(self.number)
            .map_err(ToxError::FriendQuery)
    }

    pub fn status_message(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .friend_get_status_message(self.number)
            .map_err(ToxError::FriendQuery)
    }

    pub fn status(&self) -> Result<ToxUserStatus> {
        self.tox
            .inner
            .core
            .friend_get_status(self.number)
            .map_err(ToxError::FriendQuery)
    }

    pub fn delete(self) -> Result<()> {
        self.tox
            .inner
            .core
            .friend_delete(self.number)
            .map_err(ToxError::FriendDelete)
    }

    pub fn connection_status(&self) -> Result<ToxConnection> {
        self.tox
            .inner
            .core
            .friend_get_connection_status(self.number)
            .map_err(ToxError::FriendQuery)
    }

    pub fn exists(&self) -> bool {
        self.tox.inner.core.friend_exists(self.number)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        self.tox
            .inner
            .core
            .friend_get_public_key(self.number)
            .map_err(ToxError::FriendGetPublicKey)
    }

    pub fn last_online(&self) -> Result<u64> {
        self.tox
            .inner
            .core
            .friend_get_last_online(self.number)
            .map_err(ToxError::FriendGetLastOnline)
    }

    pub fn set_typing(&self, typing: bool) -> Result<()> {
        self.tox
            .inner
            .core
            .self_set_typing(self.number, typing)
            .map_err(ToxError::SetTyping)
    }

    pub fn is_typing(&self) -> Result<bool> {
        self.tox
            .inner
            .core
            .friend_get_typing(self.number)
            .map_err(ToxError::FriendQuery)
    }

    pub fn send_message(
        &self,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<FriendMessageId> {
        self.tox
            .inner
            .core
            .friend_send_message(self.number, message_type, message)
            .map_err(ToxError::FriendSendMessage)
    }

    pub fn send_lossy_packet(&self, data: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .friend_send_lossy_packet(self.number, data)
            .map_err(ToxError::FriendCustomPacket)
    }

    pub fn send_lossless_packet(&self, data: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .friend_send_lossless_packet(self.number, data)
            .map_err(ToxError::FriendCustomPacket)
    }
}
