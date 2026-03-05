#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
use super::tox::Tox;
use crate::core::dispatch::ToxAVHandler;
pub struct ToxAV<'a, H: ToxAVHandler> {
    pub(crate) ptr: *mut ffi::ToxAV,
    pub handler: Box<H>,
    _tox: std::marker::PhantomData<&'a Tox>

}
impl<'a, H: ToxAVHandler> Drop for ToxAV<'a, H> {
    fn drop(&mut self) {
        unsafe {
            ffi::toxav_kill(self.ptr)
        }
    }
}
impl<'a, H: ToxAVHandler> ToxAV<'a, H> {
    pub fn new(tox: &Tox, handler: H) -> std::result::Result<Self, Toxav_Err_New> {
        ffi_call!(toxav_new, ffi::Toxav_Err_New::TOXAV_ERR_NEW_OK, tox.ptr).map(|val| Self { ptr: val, handler: Box::new(handler), _tox: std::marker::PhantomData })
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe {
            ffi::toxav_iteration_interval(self.ptr)
        }
    }

    pub fn audio_iteration_interval(&self) -> u32 {
        unsafe {
            ffi::toxav_audio_iteration_interval(self.ptr)
        }
    }

    pub fn video_iteration_interval(&self) -> u32 {
        unsafe {
            ffi::toxav_video_iteration_interval(self.ptr)
        }
    }

    pub fn call(&self, friend_number: FriendNumber, audio_bit_rate: u32, video_bit_rate: u32) -> std::result::Result<(), Toxav_Err_Call> {
        ffi_call_unit!(toxav_call, ffi::Toxav_Err_Call::TOXAV_ERR_CALL_OK, self.ptr, friend_number.0, audio_bit_rate, video_bit_rate)
    }

    pub fn answer(&self, friend_number: FriendNumber, audio_bit_rate: u32, video_bit_rate: u32) -> std::result::Result<(), Toxav_Err_Answer> {
        ffi_call_unit!(toxav_answer, ffi::Toxav_Err_Answer::TOXAV_ERR_ANSWER_OK, self.ptr, friend_number.0, audio_bit_rate, video_bit_rate)
    }

    pub fn call_control(&self, friend_number: FriendNumber, control: ToxavCallControl) -> std::result::Result<(), Toxav_Err_Call_Control> {
        ffi_call_unit!(toxav_call_control, ffi::Toxav_Err_Call_Control::TOXAV_ERR_CALL_CONTROL_OK, self.ptr, friend_number.0, control.into())
    }

    pub fn audio_send_frame(&self, friend_number: FriendNumber, pcm: &[i16], sample_count: usize, channels: u8, sampling_rate: u32) -> std::result::Result<(), Toxav_Err_Send_Frame> {
        ffi_call_unit!(toxav_audio_send_frame, ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK, self.ptr, friend_number.0, pcm.as_ptr(), sample_count, channels, sampling_rate)
    }

    pub fn audio_set_bit_rate(&self, friend_number: FriendNumber, bit_rate: u32) -> std::result::Result<(), Toxav_Err_Bit_Rate_Set> {
        ffi_call_unit!(toxav_audio_set_bit_rate, ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK, self.ptr, friend_number.0, bit_rate)
    }

    pub fn video_send_frame(&self, friend_number: FriendNumber, width: u16, height: u16, y: &[u8], u: &[u8], v: &[u8]) -> std::result::Result<(), Toxav_Err_Send_Frame> {
        ffi_call_unit!(toxav_video_send_frame, ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK, self.ptr, friend_number.0, width, height, y.as_ptr(), u.as_ptr(), v.as_ptr())
    }

    pub fn video_set_bit_rate(&self, friend_number: FriendNumber, bit_rate: u32) -> std::result::Result<(), Toxav_Err_Bit_Rate_Set> {
        ffi_call_unit!(toxav_video_set_bit_rate, ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK, self.ptr, friend_number.0, bit_rate)
    }
}
