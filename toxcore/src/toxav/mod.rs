use crate::core;
use crate::types::*;

// Re-export handlers from core
pub use crate::core::{ToxAVConferenceHandler, ToxAVHandler};

pub struct ToxAV<'a, H: ToxAVHandler> {
    pub(crate) inner: core::ToxAV<'a, H>,
    _parent: &'a crate::tox::Tox,
}

impl<'a, H: ToxAVHandler> ToxAV<'a, H> {
    pub fn new(tox: &'a crate::tox::Tox, handler: H) -> Result<Self> {
        // Tox wrapper has .inner which is Arc<Inner>, Inner has .core
        let inner = core::ToxAV::new(&tox.inner.core, handler).map_err(ToxError::AvNew)?;
        Ok(ToxAV {
            inner,
            _parent: tox,
        })
    }

    pub fn iterate(&mut self) {
        self.inner.iterate();
    }

    pub fn iteration_interval(&self) -> u32 {
        self.inner.iteration_interval()
    }

    pub fn audio_iterate(&mut self) {
        self.inner.audio_iterate();
    }

    pub fn audio_iteration_interval(&self) -> u32 {
        self.inner.audio_iteration_interval()
    }

    pub fn video_iterate(&mut self) {
        self.inner.video_iterate();
    }

    pub fn video_iteration_interval(&self) -> u32 {
        self.inner.video_iteration_interval()
    }

    pub fn call(
        &self,
        friend_number: FriendNumber,
        audio_bit_rate: u32,
        video_bit_rate: u32,
    ) -> Result<()> {
        self.inner
            .call(friend_number, audio_bit_rate, video_bit_rate)
            .map_err(ToxError::AvCall)
    }

    pub fn answer(
        &self,
        friend_number: FriendNumber,
        audio_bit_rate: u32,
        video_bit_rate: u32,
    ) -> Result<()> {
        self.inner
            .answer(friend_number, audio_bit_rate, video_bit_rate)
            .map_err(ToxError::AvAnswer)
    }

    pub fn call_control(
        &self,
        friend_number: FriendNumber,
        control: ToxavCallControl,
    ) -> Result<()> {
        self.inner
            .call_control(friend_number, control)
            .map_err(ToxError::AvCallControl)
    }

    pub fn audio_set_bit_rate(&self, friend_number: FriendNumber, bit_rate: u32) -> Result<()> {
        self.inner
            .audio_set_bit_rate(friend_number, bit_rate)
            .map_err(ToxError::AvBitRateSet)
    }

    pub fn video_set_bit_rate(&self, friend_number: FriendNumber, bit_rate: u32) -> Result<()> {
        self.inner
            .video_set_bit_rate(friend_number, bit_rate)
            .map_err(ToxError::AvBitRateSet)
    }

    pub fn audio_send_frame(
        &self,
        friend_number: FriendNumber,
        pcm: &[i16],
        channels: u8,
        sampling_rate: u32,
    ) -> Result<()> {
        // Core expects sample_count. pcm.len() / channels?
        // Original code took pcm slice.
        let sample_count = pcm.len() / (channels as usize);
        self.inner
            .audio_send_frame(friend_number, pcm, sample_count, channels, sampling_rate)
            .map_err(ToxError::AvSendFrame)
    }

    pub fn video_send_frame(
        &self,
        friend_number: FriendNumber,
        width: u16,
        height: u16,
        y: &[u8],
        u: &[u8],
        v: &[u8],
    ) -> Result<()> {
        self.inner
            .video_send_frame(friend_number, width, height, y, u, v)
            .map_err(ToxError::AvSendFrame)
    }
}
