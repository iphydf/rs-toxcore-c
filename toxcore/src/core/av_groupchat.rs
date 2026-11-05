// Hand-written A/V glue that apigen can't generate: the `ToxAv` iterate
// methods, and the toxav group chat API, which passes a C callback to a Rust
// handler trait.
use super::dispatch::ToxAvHandler;
use super::dispatch::register_tox_av_callbacks;
use super::tox::Tox;
use super::tox_av::ToxAv;
use crate::ffi;
use crate::types::*;
use std::os::raw::c_void;
use std::slice;

// Register the dispatch callbacks before each iteration, so the handler is
// called.
impl<'a, H: ToxAvHandler> ToxAv<'a, H> {
    pub fn iterate(&mut self) {
        let ptr = self.ptr;
        unsafe {
            register_tox_av_callbacks(ptr, &mut *self.handler);
            ffi::toxav_iterate(ptr);
        }
    }

    pub fn audio_iterate(&mut self) {
        let ptr = self.ptr;
        unsafe {
            register_tox_av_callbacks(ptr, &mut *self.handler);
            ffi::toxav_audio_iterate(ptr);
        }
    }

    pub fn video_iterate(&mut self) {
        let ptr = self.ptr;
        unsafe {
            register_tox_av_callbacks(ptr, &mut *self.handler);
            ffi::toxav_video_iterate(ptr);
        }
    }
}

pub trait ToxAvConferenceHandler: Sync + Send {
    fn on_conference_audio_receive_frame(
        &self,
        _conference: ConferenceNumber,
        _peer: u32,
        _pcm: &[i16],
        _channels: u8,
        _sample_rate: u32,
    ) {
    }
}

/// # Safety
///
/// This function is intended to be called by the C library.
/// `pcm` must be a valid pointer to at least `samples * channels` elements.
/// `user_data` must be a valid pointer to a `H: ToxAvConferenceHandler` if it is not null.
pub unsafe extern "C" fn dispatch_conference_audio<H: ToxAvConferenceHandler>(
    _tox: *mut c_void,
    group_number: u32,
    peer_number: u32,
    pcm: *const i16,
    samples: u32,
    channels: u8,
    sample_rate: u32,
    user_data: *mut c_void,
) {
    if !user_data.is_null() {
        let handler = unsafe { &*(user_data as *const H) };
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the panic has printed its message, and must not unwind into C"
        )]
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pcm_slice =
                unsafe { slice::from_raw_parts(pcm, samples as usize * channels as usize) };
            handler.on_conference_audio_receive_frame(
                crate::types::ConferenceNumber(group_number),
                peer_number,
                pcm_slice,
                channels,
                sample_rate,
            );
        }));
    }
}

impl Tox {
    /// Create an A/V group chat. Returns the new conference number, or a
    /// negative value on failure.
    pub fn add_av_groupchat<H: ToxAvConferenceHandler>(&self, handler: &H) -> i32 {
        unsafe {
            ffi::toxav_add_av_groupchat(
                self.ptr,
                Some(dispatch_conference_audio::<H>),
                handler as *const H as *mut c_void,
            )
        }
    }

    /// Join an A/V group chat via an invite. Returns the new conference number,
    /// or a negative value on failure.
    pub fn join_av_groupchat<H: ToxAvConferenceHandler>(
        &self,
        friend_number: FriendNumber,
        data: &[u8],
        handler: &H,
    ) -> i32 {
        unsafe {
            ffi::toxav_join_av_groupchat(
                self.ptr,
                friend_number.0,
                data.as_ptr(),
                data.len() as u16,
                Some(dispatch_conference_audio::<H>),
                handler as *const H as *mut c_void,
            )
        }
    }

    /// Send an audio frame to an A/V group chat. Returns true on success.
    pub fn group_send_audio(
        &self,
        conference_number: ConferenceNumber,
        pcm: &[i16],
        samples: u32,
        channels: u8,
        sample_rate: u32,
    ) -> bool {
        unsafe {
            ffi::toxav_group_send_audio(
                self.ptr,
                conference_number.0,
                pcm.as_ptr(),
                samples,
                channels,
                sample_rate,
            ) == 0
        }
    }

    /// Enable A/V in an existing (text) group chat. Returns true on success.
    pub fn groupchat_enable_av_conference<H: ToxAvConferenceHandler>(
        &self,
        conference_number: ConferenceNumber,
        handler: &H,
    ) -> bool {
        unsafe {
            ffi::toxav_groupchat_enable_av(
                self.ptr,
                conference_number.0,
                Some(dispatch_conference_audio::<H>),
                handler as *const H as *mut c_void,
            ) == 0
        }
    }
}
