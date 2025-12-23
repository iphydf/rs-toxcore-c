use super::av_dispatch::{
    ToxAVConferenceHandler, ToxAVHandler, dispatch_conference_audio, register_av_callbacks,
};
use super::tox::Tox;
use crate::ffi;
use crate::types::*;
use std::marker::PhantomData;
use std::os::raw::c_void;

pub struct ToxAV<'tox, H: ToxAVHandler> {
    pub(crate) ptr: *mut ffi::ToxAV,
    pub handler: Box<H>,
    _tox: PhantomData<&'tox Tox>,
}

impl<'tox, H: ToxAVHandler> Drop for ToxAV<'tox, H> {
    fn drop(&mut self) {
        unsafe { ffi::toxav_kill(self.ptr) };
    }
}

impl<'tox, H: ToxAVHandler> ToxAV<'tox, H> {
    pub fn new(tox: &'tox Tox, handler: H) -> std::result::Result<Self, Toxav_Err_New> {
        ffi_call!(toxav_new, ffi::Toxav_Err_New::TOXAV_ERR_NEW_OK, tox.ptr)
            .map(|ptr| {
                let mut av = Self {
                    ptr,
                    handler: Box::new(handler),
                    _tox: PhantomData,
                };

                unsafe {
                    register_av_callbacks(av.ptr, &mut *av.handler);
                }

                av
            })
            .map_err(|e| e.into())
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe { ffi::toxav_iteration_interval(self.ptr) }
    }

    pub fn iterate(&mut self) {
        super::av_dispatch::toxav_iterate(self);
    }

    pub fn audio_iterate(&mut self) {
        super::av_dispatch::toxav_audio_iterate(self);
    }

    pub fn video_iterate(&mut self) {
        super::av_dispatch::toxav_video_iterate(self);
    }

    pub fn audio_iteration_interval(&self) -> u32 {
        unsafe { ffi::toxav_audio_iteration_interval(self.ptr) }
    }

    pub fn video_iteration_interval(&self) -> u32 {
        unsafe { ffi::toxav_video_iteration_interval(self.ptr) }
    }

    pub fn call(
        &self,
        friend_number: FriendNumber,
        audio_bit_rate: u32,
        video_bit_rate: u32,
    ) -> std::result::Result<(), Toxav_Err_Call> {
        ffi_call_unit!(
            toxav_call,
            ffi::Toxav_Err_Call::TOXAV_ERR_CALL_OK,
            self.ptr,
            friend_number.0,
            audio_bit_rate,
            video_bit_rate
        )
        .map_err(|e| e.into())
    }

    pub fn answer(
        &self,
        friend_number: FriendNumber,
        audio_bit_rate: u32,
        video_bit_rate: u32,
    ) -> std::result::Result<(), Toxav_Err_Answer> {
        ffi_call_unit!(
            toxav_answer,
            ffi::Toxav_Err_Answer::TOXAV_ERR_ANSWER_OK,
            self.ptr,
            friend_number.0,
            audio_bit_rate,
            video_bit_rate
        )
        .map_err(|e| e.into())
    }

    pub fn call_control(
        &self,
        friend_number: FriendNumber,
        control: ToxavCallControl,
    ) -> std::result::Result<(), Toxav_Err_Call_Control> {
        ffi_call_unit!(
            toxav_call_control,
            ffi::Toxav_Err_Call_Control::TOXAV_ERR_CALL_CONTROL_OK,
            self.ptr,
            friend_number.0,
            control.into()
        )
        .map_err(|e| e.into())
    }

    pub fn audio_set_bit_rate(
        &self,
        friend_number: FriendNumber,
        bit_rate: u32,
    ) -> std::result::Result<(), Toxav_Err_Bit_Rate_Set> {
        ffi_call_unit!(
            toxav_audio_set_bit_rate,
            ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK,
            self.ptr,
            friend_number.0,
            bit_rate
        )
        .map_err(|e| e.into())
    }

    pub fn video_set_bit_rate(
        &self,
        friend_number: FriendNumber,
        bit_rate: u32,
    ) -> std::result::Result<(), Toxav_Err_Bit_Rate_Set> {
        ffi_call_unit!(
            toxav_video_set_bit_rate,
            ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK,
            self.ptr,
            friend_number.0,
            bit_rate
        )
        .map_err(|e| e.into())
    }

    pub fn audio_send_frame(
        &self,
        friend_number: FriendNumber,
        pcm: &[i16],
        sample_count: usize,
        channels: u8,
        sampling_rate: u32,
    ) -> std::result::Result<(), Toxav_Err_Send_Frame> {
        ffi_call_unit!(
            toxav_audio_send_frame,
            ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK,
            self.ptr,
            friend_number.0,
            pcm.as_ptr(),
            sample_count,
            channels,
            sampling_rate
        )
        .map_err(|e| e.into())
    }

    pub fn video_send_frame(
        &self,
        friend_number: FriendNumber,
        width: u16,
        height: u16,
        y: &[u8],
        u: &[u8],
        v: &[u8],
    ) -> std::result::Result<(), Toxav_Err_Send_Frame> {
        ffi_call_unit!(
            toxav_video_send_frame,
            ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK,
            self.ptr,
            friend_number.0,
            width,
            height,
            y.as_ptr(),
            u.as_ptr(),
            v.as_ptr()
        )
        .map_err(|e| e.into())
    }
}

// Group AV methods on Tox
impl Tox {
    pub fn groupchat_enable_av_conference<H: ToxAVConferenceHandler>(
        &self,
        group_number: ConferenceNumber,
        handler: &H,
    ) -> bool {
        unsafe {
            ffi::toxav_groupchat_enable_av(
                self.ptr,
                group_number.0,
                Some(dispatch_conference_audio::<H>),
                handler as *const H as *mut c_void,
            ) != 0
        }
    }

    pub fn add_av_groupchat<H: ToxAVConferenceHandler>(&self, handler: &H) -> i32 {
        unsafe {
            ffi::toxav_add_av_groupchat(
                self.ptr,
                Some(dispatch_conference_audio::<H>),
                handler as *const H as *mut c_void,
            )
        }
    }

    pub fn join_av_groupchat<H: ToxAVConferenceHandler>(
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

    pub fn groupchat_disable_av(&self, group_number: ConferenceNumber) -> bool {
        unsafe { ffi::toxav_groupchat_disable_av(self.ptr, group_number.0) != 0 }
    }

    pub fn groupchat_av_enabled(&self, group_number: ConferenceNumber) -> bool {
        ffi_bool!(toxav_groupchat_av_enabled, self.ptr, group_number.0)
    }

    pub fn group_send_audio(
        &self,
        group_number: ConferenceNumber,
        pcm: &[i16],
        samples: u32,
        channels: u8,
        sample_rate: u32,
    ) -> bool {
        unsafe {
            ffi::toxav_group_send_audio(
                self.ptr,
                group_number.0,
                pcm.as_ptr(),
                samples,
                channels,
                sample_rate,
            ) != 0
        }
    }
}
