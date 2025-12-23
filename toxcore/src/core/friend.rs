use super::tox::Tox;
use crate::ffi;
use crate::types::{
    self, Address, FriendMessageId, FriendNumber, PublicKey, Tox_Err_Friend_Add,
    Tox_Err_Friend_By_Public_Key, Tox_Err_Friend_Custom_Packet, Tox_Err_Friend_Delete,
    Tox_Err_Friend_Get_Last_Online, Tox_Err_Friend_Get_Public_Key, Tox_Err_Friend_Query,
    Tox_Err_Friend_Send_Message, Tox_Err_Set_Typing,
};

impl Tox {
    pub fn friend_get_name(
        &self,
        friend_number: FriendNumber,
    ) -> Result<Vec<u8>, Tox_Err_Friend_Query> {
        ffi_get_vec!(
            tox_friend_get_name,
            tox_friend_get_name_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn friend_get_status_message(
        &self,
        friend_number: FriendNumber,
    ) -> Result<Vec<u8>, Tox_Err_Friend_Query> {
        ffi_get_vec!(
            tox_friend_get_status_message,
            tox_friend_get_status_message_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn friend_get_status(
        &self,
        friend_number: FriendNumber,
    ) -> Result<types::ToxUserStatus, Tox_Err_Friend_Query> {
        ffi_call!(
            tox_friend_get_status,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn friend_add(
        &self,
        address: &Address,
        message: &[u8],
    ) -> Result<FriendNumber, Tox_Err_Friend_Add> {
        ffi_call!(
            tox_friend_add,
            ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK,
            self.ptr,
            address.0.as_ptr(),
            message.as_ptr(),
            message.len()
        )
        .map(FriendNumber)
        .map_err(|e| e.into())
    }

    pub fn friend_add_norequest(
        &self,
        public_key: &PublicKey,
    ) -> Result<FriendNumber, Tox_Err_Friend_Add> {
        ffi_call!(
            tox_friend_add_norequest,
            ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK,
            self.ptr,
            public_key.0.as_ptr()
        )
        .map(FriendNumber)
        .map_err(|e| e.into())
    }

    pub fn friend_delete(&self, friend_number: FriendNumber) -> Result<(), Tox_Err_Friend_Delete> {
        ffi_call_unit!(
            tox_friend_delete,
            ffi::Tox_Err_Friend_Delete::TOX_ERR_FRIEND_DELETE_OK,
            self.ptr,
            friend_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn friend_by_public_key(
        &self,
        public_key: &PublicKey,
    ) -> Result<FriendNumber, Tox_Err_Friend_By_Public_Key> {
        ffi_call!(
            tox_friend_by_public_key,
            ffi::Tox_Err_Friend_By_Public_Key::TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK,
            self.ptr,
            public_key.0.as_ptr()
        )
        .map(FriendNumber)
        .map_err(|e| e.into())
    }

    pub fn friend_get_connection_status(
        &self,
        friend_number: FriendNumber,
    ) -> Result<types::ToxConnection, Tox_Err_Friend_Query> {
        ffi_call!(
            tox_friend_get_connection_status,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn friend_send_message(
        &self,
        friend_number: FriendNumber,
        message_type: types::MessageType,
        message: &[u8],
    ) -> Result<FriendMessageId, Tox_Err_Friend_Send_Message> {
        ffi_call!(
            tox_friend_send_message,
            ffi::Tox_Err_Friend_Send_Message::TOX_ERR_FRIEND_SEND_MESSAGE_OK,
            self.ptr,
            friend_number.0,
            message_type.into(),
            message.as_ptr(),
            message.len()
        )
        .map_err(|e| e.into())
        .map(FriendMessageId)
    }

    pub fn friend_send_lossy_packet(
        &self,
        friend_number: FriendNumber,
        data: &[u8],
    ) -> Result<(), Tox_Err_Friend_Custom_Packet> {
        ffi_call_unit!(
            tox_friend_send_lossy_packet,
            ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK,
            self.ptr,
            friend_number.0,
            data.as_ptr(),
            data.len()
        )
        .map_err(|e| e.into())
    }

    pub fn friend_send_lossless_packet(
        &self,
        friend_number: FriendNumber,
        data: &[u8],
    ) -> Result<(), Tox_Err_Friend_Custom_Packet> {
        ffi_call_unit!(
            tox_friend_send_lossless_packet,
            ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK,
            self.ptr,
            friend_number.0,
            data.as_ptr(),
            data.len()
        )
        .map_err(|e| e.into())
    }

    pub fn self_set_typing(
        &self,
        friend_number: FriendNumber,
        typing: bool,
    ) -> Result<(), Tox_Err_Set_Typing> {
        ffi_call_unit!(
            tox_self_set_typing,
            ffi::Tox_Err_Set_Typing::TOX_ERR_SET_TYPING_OK,
            self.ptr,
            friend_number.0,
            typing
        )
        .map_err(|e| e.into())
    }

    pub fn friend_get_typing(
        &self,
        friend_number: FriendNumber,
    ) -> Result<bool, Tox_Err_Friend_Query> {
        ffi_call!(
            tox_friend_get_typing,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn friend_exists(&self, friend_number: FriendNumber) -> bool {
        ffi_bool!(tox_friend_exists, self.ptr, friend_number.0)
    }

    pub fn friend_get_public_key(
        &self,
        friend_number: FriendNumber,
    ) -> Result<PublicKey, Tox_Err_Friend_Get_Public_Key> {
        ffi_get_array!(
            tox_friend_get_public_key,
            ffi::Tox_Err_Friend_Get_Public_Key::TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK,
            types::PUBLIC_KEY_SIZE,
            self.ptr,
            friend_number.0
        )
        .map(PublicKey)
        .map_err(|e| e.into())
    }

    pub fn friend_get_last_online(
        &self,
        friend_number: FriendNumber,
    ) -> Result<u64, Tox_Err_Friend_Get_Last_Online> {
        ffi_call!(
            tox_friend_get_last_online,
            ffi::Tox_Err_Friend_Get_Last_Online::TOX_ERR_FRIEND_GET_LAST_ONLINE_OK,
            self.ptr,
            friend_number.0
        )
        .map_err(|e| e.into())
    }
}
