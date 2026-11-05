use super::tox::Tox;
use crate::core::dispatch::ToxAvHandler;
use crate::ffi;
use crate::types::*;

pub struct ToxAv<'a, H: ToxAvHandler> {
    pub(crate) ptr: *mut ffi::ToxAV,
    pub handler: Box<H>,
    _marker: std::marker::PhantomData<&'a Tox>,
}

impl<'a, H: ToxAvHandler> Drop for ToxAv<'a, H> {
    fn drop(&mut self) {
        unsafe { ffi::toxav_kill(self.ptr) }
    }
}

impl<'a, H: ToxAvHandler> ToxAv<'a, H> {
    pub fn new(tox: &Tox, handler: H) -> std::result::Result<Self, AvNewError> {
        ffi_call!(toxav_new, ffi::Toxav_Err_New::TOXAV_ERR_NEW_OK, tox.ptr).map(|val| Self {
            ptr: val,
            handler: Box::new(handler),
            _marker: std::marker::PhantomData,
        })
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe { ffi::toxav_iteration_interval(self.ptr) }
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
        audio_bit_rate: AvBitRate,
        video_bit_rate: AvBitRate,
    ) -> std::result::Result<(), AvCallError> {
        ffi_call_unit!(
            toxav_call,
            ffi::Toxav_Err_Call::TOXAV_ERR_CALL_OK,
            self.ptr,
            friend_number.0,
            audio_bit_rate.0,
            video_bit_rate.0
        )
    }

    pub fn answer(
        &self,
        friend_number: FriendNumber,
        audio_bit_rate: AvBitRate,
        video_bit_rate: AvBitRate,
    ) -> std::result::Result<(), AvAnswerError> {
        ffi_call_unit!(
            toxav_answer,
            ffi::Toxav_Err_Answer::TOXAV_ERR_ANSWER_OK,
            self.ptr,
            friend_number.0,
            audio_bit_rate.0,
            video_bit_rate.0
        )
    }

    pub fn call_control(
        &self,
        friend_number: FriendNumber,
        control: AvCallControl,
    ) -> std::result::Result<(), AvCallControlError> {
        ffi_call_unit!(
            toxav_call_control,
            ffi::Toxav_Err_Call_Control::TOXAV_ERR_CALL_CONTROL_OK,
            self.ptr,
            friend_number.0,
            control.into()
        )
    }

    pub fn audio_send_frame(
        &self,
        friend_number: FriendNumber,
        pcm: &[i16],
        sample_count: usize,
        channels: AvChannels,
        sampling_rate: AvSamplingRate,
    ) -> std::result::Result<(), AvSendFrameError> {
        assert!(pcm.len() as i64 >= sample_count as i64 * channels.0 as i64);
        ffi_call_unit!(
            toxav_audio_send_frame,
            ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK,
            self.ptr,
            friend_number.0,
            pcm.as_ptr(),
            sample_count,
            channels.0,
            sampling_rate.0
        )
    }

    pub fn audio_set_bit_rate(
        &self,
        friend_number: FriendNumber,
        bit_rate: AvBitRate,
    ) -> std::result::Result<(), AvBitRateSetError> {
        ffi_call_unit!(
            toxav_audio_set_bit_rate,
            ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK,
            self.ptr,
            friend_number.0,
            bit_rate.0
        )
    }

    pub fn video_send_frame(
        &self,
        friend_number: FriendNumber,
        width: AvWidth,
        height: AvHeight,
        y: &[u8],
        u: &[u8],
        v: &[u8],
    ) -> std::result::Result<(), AvSendFrameError> {
        assert!(y.len() as i64 >= width.0 as i64 * height.0 as i64);
        assert!(u.len() as i64 >= ((width.0 as i64 / 2_i64) * height.0 as i64) / 2_i64);
        assert!(v.len() as i64 >= ((width.0 as i64 / 2_i64) * height.0 as i64) / 2_i64);
        ffi_call_unit!(
            toxav_video_send_frame,
            ffi::Toxav_Err_Send_Frame::TOXAV_ERR_SEND_FRAME_OK,
            self.ptr,
            friend_number.0,
            width.0,
            height.0,
            y.as_ptr(),
            u.as_ptr(),
            v.as_ptr()
        )
    }

    pub fn video_set_bit_rate(
        &self,
        friend_number: FriendNumber,
        bit_rate: AvBitRate,
    ) -> std::result::Result<(), AvBitRateSetError> {
        ffi_call_unit!(
            toxav_video_set_bit_rate,
            ffi::Toxav_Err_Bit_Rate_Set::TOXAV_ERR_BIT_RATE_SET_OK,
            self.ptr,
            friend_number.0,
            bit_rate.0
        )
    }
}
