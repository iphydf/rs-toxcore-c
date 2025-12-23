use super::tox::Tox;
use crate::ffi;
use crate::types::{
    self, FileId, FileNumber, FriendNumber, Tox_Err_File_Control, Tox_Err_File_Get,
    Tox_Err_File_Seek, Tox_Err_File_Send, Tox_Err_File_Send_Chunk, ToxFileControl,
};
use std::ptr;

impl Tox {
    pub fn file_send(
        &self,
        friend_number: FriendNumber,
        kind: u32,
        file_size: u64,
        file_id: Option<&FileId>,
        filename: &[u8],
    ) -> Result<FileNumber, Tox_Err_File_Send> {
        let file_id_ptr = file_id.map_or(ptr::null(), |id| id.0.as_ptr());
        ffi_call!(
            tox_file_send,
            ffi::Tox_Err_File_Send::TOX_ERR_FILE_SEND_OK,
            self.ptr,
            friend_number.0,
            kind,
            file_size,
            file_id_ptr,
            filename.as_ptr(),
            filename.len()
        )
        .map(FileNumber)
        .map_err(|e| e.into())
    }

    pub fn file_send_chunk(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        position: u64,
        data: &[u8],
    ) -> Result<(), Tox_Err_File_Send_Chunk> {
        ffi_call_unit!(
            tox_file_send_chunk,
            ffi::Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_OK,
            self.ptr,
            friend_number.0,
            file_number.0,
            position,
            data.as_ptr(),
            data.len()
        )
        .map_err(|e| e.into())
    }

    pub fn file_control(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        control: ToxFileControl,
    ) -> Result<(), Tox_Err_File_Control> {
        ffi_call_unit!(
            tox_file_control,
            ffi::Tox_Err_File_Control::TOX_ERR_FILE_CONTROL_OK,
            self.ptr,
            friend_number.0,
            file_number.0,
            control.into()
        )
        .map_err(|e| e.into())
    }

    pub fn file_seek(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        position: u64,
    ) -> Result<(), Tox_Err_File_Seek> {
        ffi_call_unit!(
            tox_file_seek,
            ffi::Tox_Err_File_Seek::TOX_ERR_FILE_SEEK_OK,
            self.ptr,
            friend_number.0,
            file_number.0,
            position
        )
        .map_err(|e| e.into())
    }

    pub fn file_get_file_id(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
    ) -> Result<FileId, Tox_Err_File_Get> {
        ffi_get_array!(
            tox_file_get_file_id,
            ffi::Tox_Err_File_Get::TOX_ERR_FILE_GET_OK,
            types::FILE_ID_LENGTH,
            self.ptr,
            friend_number.0,
            file_number.0
        )
        .map(FileId)
        .map_err(|e| e.into())
    }
}
