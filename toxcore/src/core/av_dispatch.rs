use crate::ffi;
use crate::types::*;
use std::os::raw::c_void;
use std::slice;

pub trait ToxAVHandler {
    fn on_call(&mut self, _friend: FriendNumber, _audio_enabled: bool, _video_enabled: bool) {}
    fn on_call_state(&mut self, _friend: FriendNumber, _state: u32) {}
    fn on_audio_bit_rate(&mut self, _friend: FriendNumber, _bit_rate: u32) {}
    fn on_video_bit_rate(&mut self, _friend: FriendNumber, _bit_rate: u32) {}
    fn on_audio_receive_frame(
        &mut self,
        _friend: FriendNumber,
        _pcm: &[i16],
        _channels: u8,
        _sampling_rate: u32,
    ) {
    }
    #[allow(clippy::too_many_arguments)]
    fn on_video_receive_frame(
        &mut self,
        _friend: FriendNumber,
        _width: u16,
        _height: u16,
        _y: &[u8],
        _u: &[u8],
        _v: &[u8],
        _ystride: i32,
        _ustride: i32,
        _vstride: i32,
    ) {
    }
}

pub trait ToxAVConferenceHandler: Sync + Send {
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

pub(crate) unsafe fn register_av_callbacks<H: ToxAVHandler>(
    av_ptr: *mut ffi::ToxAV,
    handler: &mut H,
) {
    unsafe {
        ffi::toxav_callback_call(
            av_ptr,
            Some(dispatch_av_call::<H>),
            handler as *mut H as *mut c_void,
        );
        ffi::toxav_callback_call_state(
            av_ptr,
            Some(dispatch_av_call_state::<H>),
            handler as *mut H as *mut c_void,
        );
        ffi::toxav_callback_audio_bit_rate(
            av_ptr,
            Some(dispatch_av_audio_bit_rate::<H>),
            handler as *mut H as *mut c_void,
        );
        ffi::toxav_callback_video_bit_rate(
            av_ptr,
            Some(dispatch_av_video_bit_rate::<H>),
            handler as *mut H as *mut c_void,
        );
        ffi::toxav_callback_audio_receive_frame(
            av_ptr,
            Some(dispatch_av_audio_receive_frame::<H>),
            handler as *mut H as *mut c_void,
        );
        ffi::toxav_callback_video_receive_frame(
            av_ptr,
            Some(dispatch_av_video_receive_frame::<H>),
            handler as *mut H as *mut c_void,
        );
    }
}

// Access internal pointer. We need a trait or a way to get the pointer from generic ToxAV.
// core::ToxAV is a struct, defined in generated/av.rs or manually in toxav.rs.
use crate::core::av::ToxAV;

pub fn toxav_iterate<H: ToxAVHandler>(toxav: &mut ToxAV<'_, H>) {
    let ptr = toxav.ptr;
    unsafe {
        register_av_callbacks(ptr, &mut *toxav.handler);
        ffi::toxav_iterate(ptr);
    }
}

pub fn toxav_audio_iterate<H: ToxAVHandler>(toxav: &mut ToxAV<'_, H>) {
    let ptr = toxav.ptr;
    unsafe {
        register_av_callbacks(ptr, &mut *toxav.handler);
        ffi::toxav_audio_iterate(ptr);
    }
}

pub fn toxav_video_iterate<H: ToxAVHandler>(toxav: &mut ToxAV<'_, H>) {
    let ptr = toxav.ptr;
    unsafe {
        register_av_callbacks(ptr, &mut *toxav.handler);
        ffi::toxav_video_iterate(ptr);
    }
}

macro_rules! define_av_dispatch {
    ($func_name:ident, ($($arg_name:ident: $arg_type:ty),*), $body:expr) => {
        unsafe extern "C" fn $func_name<H: ToxAVHandler>(
            _av: *mut ffi::ToxAV,
            $($arg_name: $arg_type),*,
            user_data: *mut c_void,
        ) {
            if !user_data.is_null() {
                let handler = unsafe { &mut *(user_data as *mut H) };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    $body(handler)
                }));
            }
        }
    }
}

define_av_dispatch!(
    dispatch_av_call,
    (friend_number: u32, audio_enabled: bool, video_enabled: bool),
    |handler: &mut H| {
        handler.on_call(
            crate::types::FriendNumber(friend_number),
            audio_enabled,
            video_enabled,
        );
    }
);

define_av_dispatch!(
    dispatch_av_call_state,
    (friend_number: u32, state: u32),
    |handler: &mut H| {
        handler.on_call_state(crate::types::FriendNumber(friend_number), state);
    }
);

define_av_dispatch!(
    dispatch_av_audio_bit_rate,
    (friend_number: u32, audio_bit_rate: u32),
    |handler: &mut H| {
        handler.on_audio_bit_rate(crate::types::FriendNumber(friend_number), audio_bit_rate);
    }
);

define_av_dispatch!(
    dispatch_av_video_bit_rate,
    (friend_number: u32, video_bit_rate: u32),
    |handler: &mut H| {
        handler.on_video_bit_rate(crate::types::FriendNumber(friend_number), video_bit_rate);
    }
);

define_av_dispatch!(
    dispatch_av_audio_receive_frame,
    (friend_number: u32, pcm: *const i16, sample_count: usize, channels: u8, sampling_rate: u32),
    |handler: &mut H| {
        let pcm_slice = unsafe { slice::from_raw_parts(pcm, sample_count * channels as usize) };
        handler.on_audio_receive_frame(
            crate::types::FriendNumber(friend_number),
            pcm_slice,
            channels,
            sampling_rate,
        );
    }
);

define_av_dispatch!(
    dispatch_av_video_receive_frame,
    (friend_number: u32, width: u16, height: u16, y: *const u8, u: *const u8, v: *const u8, ystride: i32, ustride: i32, vstride: i32),
    |handler: &mut H| {
        let y_size = (width as i32).max(ystride.abs()) as usize * height as usize;
        let u_size = (width as i32 / 2).max(ustride.abs()) as usize * (height as usize / 2);
        let v_size = (width as i32 / 2).max(vstride.abs()) as usize * (height as usize / 2);

        let y_slice = unsafe { slice::from_raw_parts(y, y_size) };
        let u_slice = unsafe { slice::from_raw_parts(u, u_size) };
        let v_slice = unsafe { slice::from_raw_parts(v, v_size) };

        handler.on_video_receive_frame(
            crate::types::FriendNumber(friend_number),
            width,
            height,
            y_slice,
            u_slice,
            v_slice,
            ystride,
            ustride,
            vstride,
        );
    }
);

/// # Safety
///
/// This function is intended to be called by the C library.
/// `pcm` must be a valid pointer to at least `samples * channels` elements.
/// `user_data` must be a valid pointer to a `H: ToxAVConferenceHandler` if it is not null.
pub unsafe extern "C" fn dispatch_conference_audio<H: ToxAVConferenceHandler>(
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
