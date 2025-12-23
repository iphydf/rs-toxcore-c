use crate::tox::ConferenceAvScope;
use crate::tox::friend::Friend;
use crate::toxav::ToxAVConferenceHandler;
use crate::types::*;

#[derive(Clone, Copy)]
pub struct Conference<'a> {
    pub(crate) tox: &'a super::Tox,
    pub(crate) number: ConferenceNumber,
}

impl<'a> std::fmt::Debug for Conference<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conference")
            .field("number", &self.number)
            .finish()
    }
}

impl<'a> Conference<'a> {
    pub fn number(&self) -> ConferenceNumber {
        self.number
    }

    pub fn delete(self) -> Result<()> {
        self.tox
            .inner
            .core
            .conference_delete(self.number)
            .map_err(ToxError::ConferenceDelete)
    }

    pub fn peer_count(&self) -> Result<u32> {
        self.tox
            .inner
            .core
            .conference_peer_count(self.number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn peer_name(&self, peer_number: ConferencePeerNumber) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .conference_peer_get_name(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn peer_public_key(&self, peer_number: ConferencePeerNumber) -> Result<PublicKey> {
        self.tox
            .inner
            .core
            .conference_peer_get_public_key(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn peer_number_is_ours(&self, peer_number: ConferencePeerNumber) -> Result<bool> {
        self.tox
            .inner
            .core
            .conference_peer_number_is_ours(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn offline_peer_count(&self) -> Result<u32> {
        self.tox
            .inner
            .core
            .conference_offline_peer_count(self.number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn offline_peer_name(&self, peer_number: ConferenceOfflinePeerNumber) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .conference_offline_peer_get_name(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn offline_peer_public_key(
        &self,
        peer_number: ConferenceOfflinePeerNumber,
    ) -> Result<PublicKey> {
        self.tox
            .inner
            .core
            .conference_offline_peer_get_public_key(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn offline_peer_last_active(
        &self,
        peer_number: ConferenceOfflinePeerNumber,
    ) -> Result<u64> {
        self.tox
            .inner
            .core
            .conference_offline_peer_get_last_active(self.number, peer_number)
            .map_err(ToxError::ConferencePeerQuery)
    }

    pub fn set_max_offline(&self, max_offline: u32) -> Result<()> {
        self.tox
            .inner
            .core
            .conference_set_max_offline(self.number, max_offline)
            .map_err(ToxError::ConferenceSetMaxOffline)
    }

    pub fn invite(&self, friend: &Friend) -> Result<()> {
        self.tox
            .inner
            .core
            .conference_invite(friend.get_number(), self.number)
            .map_err(ToxError::ConferenceInvite)
    }

    pub fn send_message(&self, message_type: MessageType, message: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .conference_send_message(self.number, message_type.into(), message)
            .map_err(ToxError::ConferenceSendMessage)
    }

    pub fn title(&self) -> Result<Vec<u8>> {
        self.tox
            .inner
            .core
            .conference_get_title(self.number)
            .map_err(ToxError::ConferenceTitle)
    }

    pub fn set_title(&self, title: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .conference_set_title(self.number, title)
            .map_err(ToxError::ConferenceTitle)
    }

    pub fn enable_av<H: ToxAVConferenceHandler>(
        &self,
        handler: &H,
    ) -> Result<ConferenceAvScope<'a, H>> {
        if self
            .tox
            .inner
            .core
            .groupchat_enable_av_conference(self.number, handler)
        {
            Ok(ConferenceAvScope {
                inner: &self.tox.inner,
                conference: self.number,
                _marker: std::marker::PhantomData,
            })
        } else {
            Err(ToxError::AvGroupError)
        }
    }

    pub fn av_enabled(&self) -> bool {
        self.tox.inner.core.groupchat_av_enabled(self.number)
    }

    pub fn send_audio(
        &self,
        pcm: &[i16],
        samples: u32,
        channels: u8,
        sample_rate: u32,
    ) -> Result<()> {
        if self
            .tox
            .inner
            .core
            .group_send_audio(self.number, pcm, samples, channels, sample_rate)
        {
            Ok(())
        } else {
            Err(ToxError::AvGroupError)
        }
    }

    pub fn kind(&self) -> Result<ToxConferenceType> {
        self.tox
            .inner
            .core
            .conference_get_type(self.number)
            .map_err(ToxError::ConferenceGetType)
    }

    pub fn id(&self) -> Option<ConferenceId> {
        self.tox.inner.core.conference_get_id(self.number)
    }

    pub fn peer_list(&self) -> Result<Vec<ConferencePeerNumber>> {
        let count = self.peer_count()?;
        Ok((0..count).map(ConferencePeerNumber).collect())
    }
}
