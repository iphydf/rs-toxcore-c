use super::tox::Tox;
use crate::ffi;
use crate::types::{
    self, ChatId, FriendNumber, GROUP_CHAT_ID_SIZE, GroupMessageId, GroupNumber, GroupPeerNumber,
    MessageType, PublicKey, Tox_Err_Group_Disconnect, Tox_Err_Group_Invite_Accept,
    Tox_Err_Group_Invite_Friend, Tox_Err_Group_Is_Connected, Tox_Err_Group_Join,
    Tox_Err_Group_Kick_Peer, Tox_Err_Group_Leave, Tox_Err_Group_New, Tox_Err_Group_Peer_Query,
    Tox_Err_Group_Self_Name_Set, Tox_Err_Group_Self_Query, Tox_Err_Group_Self_Status_Set,
    Tox_Err_Group_Send_Custom_Packet, Tox_Err_Group_Send_Custom_Private_Packet,
    Tox_Err_Group_Send_Message, Tox_Err_Group_Send_Private_Message, Tox_Err_Group_Set_Ignore,
    Tox_Err_Group_Set_Password, Tox_Err_Group_Set_Peer_Limit, Tox_Err_Group_Set_Privacy_State,
    Tox_Err_Group_Set_Role, Tox_Err_Group_Set_Topic_Lock, Tox_Err_Group_Set_Voice_State,
    Tox_Err_Group_State_Query, Tox_Err_Group_Topic_Set, ToxConnection, ToxGroupPrivacyState,
    ToxGroupVoiceState, ToxUserStatus,
};

impl Tox {
    pub fn group_new(
        &self,
        privacy_state: ToxGroupPrivacyState,
        group_name: &[u8],
        name: &[u8],
    ) -> Result<GroupNumber, Tox_Err_Group_New> {
        ffi_call!(
            tox_group_new,
            ffi::Tox_Err_Group_New::TOX_ERR_GROUP_NEW_OK,
            self.ptr,
            privacy_state.into(),
            group_name.as_ptr(),
            group_name.len(),
            name.as_ptr(),
            name.len()
        )
        .map(GroupNumber)
        .map_err(|e| e.into())
    }

    pub fn group_send_message(
        &self,
        group_number: GroupNumber,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<GroupMessageId, Tox_Err_Group_Send_Message> {
        ffi_call!(
            tox_group_send_message,
            ffi::Tox_Err_Group_Send_Message::TOX_ERR_GROUP_SEND_MESSAGE_OK,
            self.ptr,
            group_number.0,
            message_type.into(),
            message.as_ptr(),
            message.len()
        )
        .map(GroupMessageId)
        .map_err(|e| e.into())
    }

    pub fn group_leave(
        &self,
        group_number: GroupNumber,
        part_message: &[u8],
    ) -> Result<(), Tox_Err_Group_Leave> {
        ffi_call_unit!(
            tox_group_leave,
            ffi::Tox_Err_Group_Leave::TOX_ERR_GROUP_LEAVE_OK,
            self.ptr,
            group_number.0,
            part_message.as_ptr(),
            part_message.len()
        )
        .map_err(|e| e.into())
    }

    pub fn group_join(
        &self,
        chat_id: &[u8; GROUP_CHAT_ID_SIZE],
        name: &[u8],
        password: &[u8],
    ) -> Result<GroupNumber, Tox_Err_Group_Join> {
        ffi_call!(
            tox_group_join,
            ffi::Tox_Err_Group_Join::TOX_ERR_GROUP_JOIN_OK,
            self.ptr,
            chat_id.as_ptr(),
            name.as_ptr(),
            name.len(),
            password.as_ptr(),
            password.len()
        )
        .map(GroupNumber)
        .map_err(|e| e.into())
    }

    pub fn group_get_name(
        &self,
        group_number: GroupNumber,
    ) -> Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(
            tox_group_get_name,
            tox_group_get_name_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_get_topic(
        &self,
        group_number: GroupNumber,
    ) -> Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(
            tox_group_get_topic,
            tox_group_get_topic_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_get_chat_id(
        &self,
        group_number: GroupNumber,
    ) -> Result<ChatId, Tox_Err_Group_State_Query> {
        ffi_get_array!(
            tox_group_get_chat_id,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            GROUP_CHAT_ID_SIZE,
            self.ptr,
            group_number.0
        )
        .map(ChatId)
        .map_err(|e| e.into())
    }

    pub fn group_invite_friend(
        &self,
        group_number: GroupNumber,
        friend_number: FriendNumber,
    ) -> Result<(), Tox_Err_Group_Invite_Friend> {
        ffi_call_unit!(
            tox_group_invite_friend,
            ffi::Tox_Err_Group_Invite_Friend::TOX_ERR_GROUP_INVITE_FRIEND_OK,
            self.ptr,
            group_number.0,
            friend_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_invite_accept(
        &self,
        friend_number: FriendNumber,
        invite_data: &[u8],
        name: &[u8],
        password: &[u8],
    ) -> Result<GroupNumber, Tox_Err_Group_Invite_Accept> {
        ffi_call!(
            tox_group_invite_accept,
            ffi::Tox_Err_Group_Invite_Accept::TOX_ERR_GROUP_INVITE_ACCEPT_OK,
            self.ptr,
            friend_number.0,
            invite_data.as_ptr(),
            invite_data.len(),
            name.as_ptr(),
            name.len(),
            password.as_ptr(),
            password.len()
        )
        .map(GroupNumber)
        .map_err(|e| e.into())
    }

    pub fn group_send_private_message(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<GroupMessageId, Tox_Err_Group_Send_Private_Message> {
        ffi_call!(
            tox_group_send_private_message,
            ffi::Tox_Err_Group_Send_Private_Message::TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            message_type.into(),
            message.as_ptr(),
            message.len()
        )
        .map(GroupMessageId)
        .map_err(|e| e.into())
    }

    pub fn group_send_custom_packet(
        &self,
        group_number: GroupNumber,
        lossless: bool,
        data: &[u8],
    ) -> Result<(), Tox_Err_Group_Send_Custom_Packet> {
        ffi_call_unit!(
            tox_group_send_custom_packet,
            ffi::Tox_Err_Group_Send_Custom_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK,
            self.ptr,
            group_number.0,
            lossless,
            data.as_ptr(),
            data.len()
        )
        .map_err(|e| e.into())
    }

    pub fn group_send_custom_private_packet(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        lossless: bool,
        data: &[u8],
    ) -> Result<(), Tox_Err_Group_Send_Custom_Private_Packet> {
        ffi_call_unit!(
            tox_group_send_custom_private_packet,
            ffi::Tox_Err_Group_Send_Custom_Private_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            lossless,
            data.as_ptr(),
            data.len()
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_password(
        &self,
        group_number: GroupNumber,
        password: &[u8],
    ) -> Result<(), Tox_Err_Group_Set_Password> {
        ffi_call_unit!(
            tox_group_set_password,
            ffi::Tox_Err_Group_Set_Password::TOX_ERR_GROUP_SET_PASSWORD_OK,
            self.ptr,
            group_number.0,
            password.as_ptr(),
            password.len()
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_topic_lock(
        &self,
        group_number: GroupNumber,
        topic_lock: crate::types::ToxGroupTopicLock,
    ) -> Result<(), Tox_Err_Group_Set_Topic_Lock> {
        ffi_call_unit!(
            tox_group_set_topic_lock,
            ffi::Tox_Err_Group_Set_Topic_Lock::TOX_ERR_GROUP_SET_TOPIC_LOCK_OK,
            self.ptr,
            group_number.0,
            topic_lock.into()
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_voice_state(
        &self,
        group_number: GroupNumber,
        voice_state: crate::types::ToxGroupVoiceState,
    ) -> Result<(), Tox_Err_Group_Set_Voice_State> {
        ffi_call_unit!(
            tox_group_set_voice_state,
            ffi::Tox_Err_Group_Set_Voice_State::TOX_ERR_GROUP_SET_VOICE_STATE_OK,
            self.ptr,
            group_number.0,
            voice_state.into()
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_privacy_state(
        &self,
        group_number: GroupNumber,
        privacy_state: ToxGroupPrivacyState,
    ) -> Result<(), Tox_Err_Group_Set_Privacy_State> {
        ffi_call_unit!(
            tox_group_set_privacy_state,
            ffi::Tox_Err_Group_Set_Privacy_State::TOX_ERR_GROUP_SET_PRIVACY_STATE_OK,
            self.ptr,
            group_number.0,
            privacy_state.into()
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_peer_limit(
        &self,
        group_number: GroupNumber,
        peer_limit: u16,
    ) -> Result<(), Tox_Err_Group_Set_Peer_Limit> {
        ffi_call_unit!(
            tox_group_set_peer_limit,
            ffi::Tox_Err_Group_Set_Peer_Limit::TOX_ERR_GROUP_SET_PEER_LIMIT_OK,
            self.ptr,
            group_number.0,
            peer_limit
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_ignore(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        ignore: bool,
    ) -> Result<(), Tox_Err_Group_Set_Ignore> {
        ffi_call_unit!(
            tox_group_set_ignore,
            ffi::Tox_Err_Group_Set_Ignore::TOX_ERR_GROUP_SET_IGNORE_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            ignore
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_role(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        role: crate::types::ToxGroupRole,
    ) -> Result<(), Tox_Err_Group_Set_Role> {
        ffi_call_unit!(
            tox_group_set_role,
            ffi::Tox_Err_Group_Set_Role::TOX_ERR_GROUP_SET_ROLE_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            role.into()
        )
        .map_err(|e| e.into())
    }

    pub fn group_kick_peer(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<(), Tox_Err_Group_Kick_Peer> {
        ffi_call_unit!(
            tox_group_kick_peer,
            ffi::Tox_Err_Group_Kick_Peer::TOX_ERR_GROUP_KICK_PEER_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_is_connected(
        &self,
        group_number: GroupNumber,
    ) -> Result<bool, Tox_Err_Group_Is_Connected> {
        ffi_call!(
            tox_group_is_connected,
            ffi::Tox_Err_Group_Is_Connected::TOX_ERR_GROUP_IS_CONNECTED_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_disconnect(
        &self,
        group_number: GroupNumber,
    ) -> Result<(), Tox_Err_Group_Disconnect> {
        ffi_call_unit!(
            tox_group_disconnect,
            ffi::Tox_Err_Group_Disconnect::TOX_ERR_GROUP_DISCONNECT_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_self_set_name(
        &self,
        group_number: GroupNumber,
        name: &[u8],
    ) -> Result<(), Tox_Err_Group_Self_Name_Set> {
        ffi_call_unit!(
            tox_group_self_set_name,
            ffi::Tox_Err_Group_Self_Name_Set::TOX_ERR_GROUP_SELF_NAME_SET_OK,
            self.ptr,
            group_number.0,
            name.as_ptr(),
            name.len()
        )
        .map_err(|e| e.into())
    }

    pub fn group_self_get_name(
        &self,
        group_number: GroupNumber,
    ) -> Result<Vec<u8>, Tox_Err_Group_Self_Query> {
        ffi_get_vec!(
            tox_group_self_get_name,
            tox_group_self_get_name_size,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_self_set_status(
        &self,
        group_number: GroupNumber,
        status: ToxUserStatus,
    ) -> Result<(), Tox_Err_Group_Self_Status_Set> {
        ffi_call_unit!(
            tox_group_self_set_status,
            ffi::Tox_Err_Group_Self_Status_Set::TOX_ERR_GROUP_SELF_STATUS_SET_OK,
            self.ptr,
            group_number.0,
            status.into()
        )
        .map_err(|e| e.into())
    }

    pub fn group_self_get_status(
        &self,
        group_number: GroupNumber,
    ) -> Result<ToxUserStatus, Tox_Err_Group_Self_Query> {
        ffi_call!(
            tox_group_self_get_status,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_self_get_role(
        &self,
        group_number: GroupNumber,
    ) -> Result<crate::types::ToxGroupRole, Tox_Err_Group_Self_Query> {
        ffi_call!(
            tox_group_self_get_role,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(|r| r.into())
        .map_err(|e| e.into())
    }

    pub fn group_self_get_peer_id(
        &self,
        group_number: GroupNumber,
    ) -> Result<GroupPeerNumber, Tox_Err_Group_Self_Query> {
        ffi_call!(
            tox_group_self_get_peer_id,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(GroupPeerNumber)
        .map_err(|e| e.into())
    }

    pub fn group_self_get_public_key(
        &self,
        group_number: GroupNumber,
    ) -> Result<PublicKey, Tox_Err_Group_Self_Query> {
        ffi_get_array!(
            tox_group_self_get_public_key,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            types::PUBLIC_KEY_SIZE,
            self.ptr,
            group_number.0
        )
        .map(PublicKey)
        .map_err(|e| e.into())
    }

    pub fn group_peer_get_name(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<Vec<u8>, Tox_Err_Group_Peer_Query> {
        ffi_get_vec!(
            tox_group_peer_get_name,
            tox_group_peer_get_name_size,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_peer_get_status(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<ToxUserStatus, Tox_Err_Group_Peer_Query> {
        ffi_call!(
            tox_group_peer_get_status,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_peer_get_role(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<crate::types::ToxGroupRole, Tox_Err_Group_Peer_Query> {
        ffi_call!(
            tox_group_peer_get_role,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map(|r| r.into())
        .map_err(|e| e.into())
    }

    pub fn group_peer_get_connection_status(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<ToxConnection, Tox_Err_Group_Peer_Query> {
        ffi_call!(
            tox_group_peer_get_connection_status,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_peer_get_public_key(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> Result<PublicKey, Tox_Err_Group_Peer_Query> {
        ffi_get_array!(
            tox_group_peer_get_public_key,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            types::PUBLIC_KEY_SIZE,
            self.ptr,
            group_number.0,
            peer_id.0
        )
        .map(PublicKey)
        .map_err(|e| e.into())
    }

    pub fn group_get_number_groups(&self) -> u32 {
        unsafe { ffi::tox_group_get_number_groups(self.ptr) }
    }

    pub fn group_get_privacy_state(
        &self,
        group_number: GroupNumber,
    ) -> Result<ToxGroupPrivacyState, Tox_Err_Group_State_Query> {
        ffi_call!(
            tox_group_get_privacy_state,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_get_voice_state(
        &self,
        group_number: GroupNumber,
    ) -> Result<ToxGroupVoiceState, Tox_Err_Group_State_Query> {
        ffi_call!(
            tox_group_get_voice_state,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_get_topic_lock(
        &self,
        group_number: GroupNumber,
    ) -> Result<crate::types::ToxGroupTopicLock, Tox_Err_Group_State_Query> {
        ffi_call!(
            tox_group_get_topic_lock,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(|s| s.into())
        .map_err(|e| e.into())
    }

    pub fn group_get_peer_limit(
        &self,
        group_number: GroupNumber,
    ) -> Result<u16, Tox_Err_Group_State_Query> {
        ffi_call!(
            tox_group_get_peer_limit,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_get_password(
        &self,
        group_number: GroupNumber,
    ) -> Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(
            tox_group_get_password,
            tox_group_get_password_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn group_set_topic(
        &self,
        group_number: GroupNumber,
        topic: &[u8],
    ) -> Result<(), Tox_Err_Group_Topic_Set> {
        ffi_call_unit!(
            tox_group_set_topic,
            ffi::Tox_Err_Group_Topic_Set::TOX_ERR_GROUP_TOPIC_SET_OK,
            self.ptr,
            group_number.0,
            topic.as_ptr(),
            topic.len()
        )
        .map_err(|e| e.into())
    }
}
