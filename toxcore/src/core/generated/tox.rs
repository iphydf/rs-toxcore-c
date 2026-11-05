use super::options::Options;
use crate::ffi;
use crate::types::*;

pub struct IterateOptions {
    pub(crate) ptr: *mut ffi::Tox_Iterate_Options,
}

pub struct System {
    pub(crate) ptr: *mut ffi::Tox_System,
}

pub struct Tox {
    pub(crate) ptr: *mut ffi::Tox,
}

impl Drop for Tox {
    fn drop(&mut self) {
        unsafe { ffi::tox_kill(self.ptr) }
    }
}

impl Tox {
    pub fn conference_new(&self) -> std::result::Result<ConferenceNumber, ConferenceNewError> {
        ffi_call!(
            tox_conference_new,
            ffi::Tox_Err_Conference_New::TOX_ERR_CONFERENCE_NEW_OK,
            self.ptr
        )
        .map(ConferenceNumber)
    }

    pub fn conference_join(
        &self,
        friend_number: FriendNumber,
        cookie: &[u8],
    ) -> std::result::Result<ConferenceNumber, ConferenceJoinError> {
        ffi_call!(
            tox_conference_join,
            ffi::Tox_Err_Conference_Join::TOX_ERR_CONFERENCE_JOIN_OK,
            self.ptr,
            friend_number.0,
            cookie.as_ptr(),
            cookie.len()
        )
        .map(ConferenceNumber)
    }

    pub fn conference_by_id(
        &self,
        id: &ConferenceId,
    ) -> std::result::Result<ConferenceNumber, ConferenceByIdError> {
        ffi_call!(
            tox_conference_by_id,
            ffi::Tox_Err_Conference_By_Id::TOX_ERR_CONFERENCE_BY_ID_OK,
            self.ptr,
            id.0.as_ptr()
        )
        .map(ConferenceNumber)
    }

    pub fn conference_delete(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<(), ConferenceDeleteError> {
        ffi_call_unit!(
            tox_conference_delete,
            ffi::Tox_Err_Conference_Delete::TOX_ERR_CONFERENCE_DELETE_OK,
            self.ptr,
            conference_number.0
        )
    }

    pub fn conference_peer_count(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<u32, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_peer_count,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0
        )
    }

    pub fn conference_offline_peer_count(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<u32, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_offline_peer_count,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0
        )
    }

    pub fn conference_set_max_offline(
        &self,
        conference_number: ConferenceNumber,
        max_offline: u32,
    ) -> std::result::Result<(), ConferenceSetMaxOfflineError> {
        ffi_call_unit!(
            tox_conference_set_max_offline,
            ffi::Tox_Err_Conference_Set_Max_Offline::TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK,
            self.ptr,
            conference_number.0,
            max_offline
        )
    }

    pub fn conference_send_message(
        &self,
        conference_number: ConferenceNumber,
        type_: MessageType,
        message: &[u8],
    ) -> std::result::Result<(), ConferenceSendMessageError> {
        ffi_call_unit!(
            tox_conference_send_message,
            ffi::Tox_Err_Conference_Send_Message::TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,
            self.ptr,
            conference_number.0,
            type_.into(),
            message.as_ptr(),
            message.len()
        )
    }

    pub fn conference_get_title_size(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<usize, ConferenceTitleError> {
        ffi_call!(
            tox_conference_get_title_size,
            ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK,
            self.ptr,
            conference_number.0
        )
    }

    pub fn conference_get_title(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<Vec<u8>, ConferenceTitleError> {
        ffi_get_vec!(
            tox_conference_get_title,
            tox_conference_get_title_size,
            ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK,
            self.ptr,
            conference_number.0
        )
    }

    pub fn conference_set_title(
        &self,
        conference_number: ConferenceNumber,
        title: &[u8],
    ) -> std::result::Result<(), ConferenceTitleError> {
        ffi_call_unit!(
            tox_conference_set_title,
            ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK,
            self.ptr,
            conference_number.0,
            title.as_ptr(),
            title.len()
        )
    }

    pub fn conference_get_type(
        &self,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<ConferenceType, ConferenceGetTypeError> {
        ffi_call!(
            tox_conference_get_type,
            ffi::Tox_Err_Conference_Get_Type::TOX_ERR_CONFERENCE_GET_TYPE_OK,
            self.ptr,
            conference_number.0
        )
        .map(Into::into)
    }

    pub fn conference_get_id(&self, conference_number: ConferenceNumber) -> Option<ConferenceId> {
        unsafe {
            let mut buf = [0; CONFERENCE_ID_SIZE];
            if ffi::tox_conference_get_id(self.ptr, conference_number.0, buf.as_mut_ptr()) {
                Some(ConferenceId(buf))
            } else {
                None
            }
        }
    }

    pub fn conference_id_size() -> u32 {
        unsafe { ffi::tox_conference_id_size() }
    }

    pub fn conference_type_to_string(value: ConferenceType) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_conference_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn conference_offline_peer_get_name_size(
        &self,
        conference_number: ConferenceNumber,
        conference_offline_peer_number: ConferenceOfflinePeerNumber,
    ) -> std::result::Result<usize, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_offline_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_offline_peer_number.0
        )
    }

    pub fn conference_offline_peer_get_name(
        &self,
        conference_number: ConferenceNumber,
        conference_offline_peer_number: ConferenceOfflinePeerNumber,
    ) -> std::result::Result<Vec<u8>, ConferencePeerQueryError> {
        ffi_get_vec!(
            tox_conference_offline_peer_get_name,
            tox_conference_offline_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_offline_peer_number.0
        )
    }

    pub fn conference_offline_peer_get_public_key(
        &self,
        conference_number: ConferenceNumber,
        conference_offline_peer_number: ConferenceOfflinePeerNumber,
    ) -> std::result::Result<PublicKey, ConferencePeerQueryError> {
        ffi_get_array!(
            tox_conference_offline_peer_get_public_key,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            conference_number.0,
            conference_offline_peer_number.0
        )
        .map(PublicKey)
    }

    pub fn conference_offline_peer_get_last_active(
        &self,
        conference_number: ConferenceNumber,
        conference_offline_peer_number: ConferenceOfflinePeerNumber,
    ) -> std::result::Result<u64, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_offline_peer_get_last_active,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_offline_peer_number.0
        )
    }

    pub fn conference_peer_get_name_size(
        &self,
        conference_number: ConferenceNumber,
        conference_peer_number: ConferencePeerNumber,
    ) -> std::result::Result<usize, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_peer_number.0
        )
    }

    pub fn conference_peer_get_name(
        &self,
        conference_number: ConferenceNumber,
        conference_peer_number: ConferencePeerNumber,
    ) -> std::result::Result<Vec<u8>, ConferencePeerQueryError> {
        ffi_get_vec!(
            tox_conference_peer_get_name,
            tox_conference_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_peer_number.0
        )
    }

    pub fn conference_peer_get_public_key(
        &self,
        conference_number: ConferenceNumber,
        conference_peer_number: ConferencePeerNumber,
    ) -> std::result::Result<PublicKey, ConferencePeerQueryError> {
        ffi_get_array!(
            tox_conference_peer_get_public_key,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            conference_number.0,
            conference_peer_number.0
        )
        .map(PublicKey)
    }

    pub fn conference_peer_number_is_ours(
        &self,
        conference_number: ConferenceNumber,
        conference_peer_number: ConferencePeerNumber,
    ) -> std::result::Result<bool, ConferencePeerQueryError> {
        ffi_call!(
            tox_conference_peer_number_is_ours,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            conference_peer_number.0
        )
    }

    pub fn file_by_id(
        &self,
        friend_number: FriendNumber,
        file_id: &FileId,
    ) -> std::result::Result<FileNumber, FileByIdError> {
        ffi_call!(
            tox_file_by_id,
            ffi::Tox_Err_File_By_Id::TOX_ERR_FILE_BY_ID_OK,
            self.ptr,
            friend_number.0,
            file_id.0.as_ptr()
        )
        .map(FileNumber)
    }

    pub fn file_send(
        &self,
        friend_number: FriendNumber,
        kind: FileKind,
        file_size: u64,
        file_id: Option<&FileId>,
        filename: &[u8],
    ) -> std::result::Result<FileNumber, FileSendError> {
        ffi_call!(
            tox_file_send,
            ffi::Tox_Err_File_Send::TOX_ERR_FILE_SEND_OK,
            self.ptr,
            friend_number.0,
            kind.into(),
            file_size,
            file_id.map_or(std::ptr::null(), |v| v.0.as_ptr()),
            filename.as_ptr(),
            filename.len()
        )
        .map(FileNumber)
    }

    pub fn file_id_length() -> u32 {
        unsafe { ffi::tox_file_id_length() }
    }

    pub fn file_control_to_string(value: FileControl) -> &'static str {
        unsafe {
            let ptr = ffi::tox_file_control_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn friend_add(
        &self,
        address: &Address,
        message: &[u8],
    ) -> std::result::Result<FriendNumber, FriendAddError> {
        ffi_call!(
            tox_friend_add,
            ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK,
            self.ptr,
            address.0.as_ptr(),
            message.as_ptr(),
            message.len()
        )
        .map(FriendNumber)
    }

    pub fn friend_add_norequest(
        &self,
        public_key: &PublicKey,
    ) -> std::result::Result<FriendNumber, FriendAddError> {
        ffi_call!(
            tox_friend_add_norequest,
            ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK,
            self.ptr,
            public_key.0.as_ptr()
        )
        .map(FriendNumber)
    }

    pub fn friend_by_public_key(
        &self,
        public_key: &PublicKey,
    ) -> std::result::Result<FriendNumber, FriendByPublicKeyError> {
        ffi_call!(
            tox_friend_by_public_key,
            ffi::Tox_Err_Friend_By_Public_Key::TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK,
            self.ptr,
            public_key.0.as_ptr()
        )
        .map(FriendNumber)
    }

    pub fn friend_delete(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<(), FriendDeleteError> {
        ffi_call_unit!(
            tox_friend_delete,
            ffi::Tox_Err_Friend_Delete::TOX_ERR_FRIEND_DELETE_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_exists(&self, friend_number: FriendNumber) -> bool {
        ffi_bool!(tox_friend_exists, self.ptr, friend_number.0)
    }

    pub fn friend_get_public_key(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<PublicKey, FriendGetPublicKeyError> {
        ffi_get_array!(
            tox_friend_get_public_key,
            ffi::Tox_Err_Friend_Get_Public_Key::TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            friend_number.0
        )
        .map(PublicKey)
    }

    pub fn friend_get_last_online(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<u64, FriendGetLastOnlineError> {
        ffi_call!(
            tox_friend_get_last_online,
            ffi::Tox_Err_Friend_Get_Last_Online::TOX_ERR_FRIEND_GET_LAST_ONLINE_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_get_name_size(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<usize, FriendQueryError> {
        ffi_call!(
            tox_friend_get_name_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_get_name(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<Vec<u8>, FriendQueryError> {
        ffi_get_vec!(
            tox_friend_get_name,
            tox_friend_get_name_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_get_status_message_size(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<usize, FriendQueryError> {
        ffi_call!(
            tox_friend_get_status_message_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_get_status_message(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<Vec<u8>, FriendQueryError> {
        ffi_get_vec!(
            tox_friend_get_status_message,
            tox_friend_get_status_message_size,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_get_status(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<UserStatus, FriendQueryError> {
        ffi_call!(
            tox_friend_get_status,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map(Into::into)
    }

    pub fn friend_get_connection_status(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<Connection, FriendQueryError> {
        ffi_call!(
            tox_friend_get_connection_status,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
        .map(Into::into)
    }

    pub fn friend_get_typing(
        &self,
        friend_number: FriendNumber,
    ) -> std::result::Result<bool, FriendQueryError> {
        ffi_call!(
            tox_friend_get_typing,
            ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK,
            self.ptr,
            friend_number.0
        )
    }

    pub fn friend_send_message(
        &self,
        friend_number: FriendNumber,
        type_: MessageType,
        message: &[u8],
    ) -> std::result::Result<FriendMessageId, FriendSendMessageError> {
        ffi_call!(
            tox_friend_send_message,
            ffi::Tox_Err_Friend_Send_Message::TOX_ERR_FRIEND_SEND_MESSAGE_OK,
            self.ptr,
            friend_number.0,
            type_.into(),
            message.as_ptr(),
            message.len()
        )
        .map(FriendMessageId)
    }

    pub fn friend_send_lossy_packet(
        &self,
        friend_number: FriendNumber,
        data: &[u8],
    ) -> std::result::Result<(), FriendCustomPacketError> {
        ffi_call_unit!(
            tox_friend_send_lossy_packet,
            ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK,
            self.ptr,
            friend_number.0,
            data.as_ptr(),
            data.len()
        )
    }

    pub fn friend_send_lossless_packet(
        &self,
        friend_number: FriendNumber,
        data: &[u8],
    ) -> std::result::Result<(), FriendCustomPacketError> {
        ffi_call_unit!(
            tox_friend_send_lossless_packet,
            ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK,
            self.ptr,
            friend_number.0,
            data.as_ptr(),
            data.len()
        )
    }

    pub fn group_new(
        &self,
        privacy_state: GroupPrivacyState,
        group_name: &[u8],
        name: &[u8],
    ) -> std::result::Result<GroupNumber, GroupNewError> {
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
    }

    pub fn group_join(
        &self,
        chat_id: &GroupChatId,
        name: &[u8],
        password: &[u8],
    ) -> std::result::Result<GroupNumber, GroupJoinError> {
        ffi_call!(
            tox_group_join,
            ffi::Tox_Err_Group_Join::TOX_ERR_GROUP_JOIN_OK,
            self.ptr,
            chat_id.0.as_ptr(),
            name.as_ptr(),
            name.len(),
            password.as_ptr(),
            password.len()
        )
        .map(GroupNumber)
    }

    pub fn group_by_id(
        &self,
        chat_id: &GroupChatId,
    ) -> std::result::Result<GroupNumber, GroupByIdError> {
        ffi_call!(
            tox_group_by_id,
            ffi::Tox_Err_Group_By_Id::TOX_ERR_GROUP_BY_ID_OK,
            self.ptr,
            chat_id.0.as_ptr()
        )
        .map(GroupNumber)
    }

    pub fn group_invite_accept(
        &self,
        friend_number: FriendNumber,
        invite_data: &[u8],
        name: &[u8],
        password: &[u8],
    ) -> std::result::Result<GroupNumber, GroupInviteAcceptError> {
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
    }

    pub fn group_is_connected(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<bool, GroupIsConnectedError> {
        ffi_call!(
            tox_group_is_connected,
            ffi::Tox_Err_Group_Is_Connected::TOX_ERR_GROUP_IS_CONNECTED_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_disconnect(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<(), GroupDisconnectError> {
        ffi_call_unit!(
            tox_group_disconnect,
            ffi::Tox_Err_Group_Disconnect::TOX_ERR_GROUP_DISCONNECT_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_leave(
        &self,
        group_number: GroupNumber,
        part_message: &[u8],
    ) -> std::result::Result<(), GroupLeaveError> {
        ffi_call_unit!(
            tox_group_leave,
            ffi::Tox_Err_Group_Leave::TOX_ERR_GROUP_LEAVE_OK,
            self.ptr,
            group_number.0,
            part_message.as_ptr(),
            part_message.len()
        )
    }

    pub fn group_self_set_name(
        &self,
        group_number: GroupNumber,
        name: &[u8],
    ) -> std::result::Result<(), GroupSelfNameSetError> {
        ffi_call_unit!(
            tox_group_self_set_name,
            ffi::Tox_Err_Group_Self_Name_Set::TOX_ERR_GROUP_SELF_NAME_SET_OK,
            self.ptr,
            group_number.0,
            name.as_ptr(),
            name.len()
        )
    }

    pub fn group_self_get_name_size(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<usize, GroupSelfQueryError> {
        ffi_call!(
            tox_group_self_get_name_size,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_self_get_name(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<Vec<u8>, GroupSelfQueryError> {
        ffi_get_vec!(
            tox_group_self_get_name,
            tox_group_self_get_name_size,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_self_set_status(
        &self,
        group_number: GroupNumber,
        status: UserStatus,
    ) -> std::result::Result<(), GroupSelfStatusSetError> {
        ffi_call_unit!(
            tox_group_self_set_status,
            ffi::Tox_Err_Group_Self_Status_Set::TOX_ERR_GROUP_SELF_STATUS_SET_OK,
            self.ptr,
            group_number.0,
            status.into()
        )
    }

    pub fn group_self_get_status(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<UserStatus, GroupSelfQueryError> {
        ffi_call!(
            tox_group_self_get_status,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(Into::into)
    }

    pub fn group_self_get_role(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupRole, GroupSelfQueryError> {
        ffi_call!(
            tox_group_self_get_role,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(Into::into)
    }

    pub fn group_self_get_peer_id(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupPeerNumber, GroupSelfQueryError> {
        ffi_call!(
            tox_group_self_get_peer_id,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(GroupPeerNumber)
    }

    pub fn group_self_get_public_key(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<PublicKey, GroupSelfQueryError> {
        ffi_get_array!(
            tox_group_self_get_public_key,
            ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            group_number.0
        )
        .map(PublicKey)
    }

    pub fn group_set_topic(
        &self,
        group_number: GroupNumber,
        topic: &[u8],
    ) -> std::result::Result<(), GroupTopicSetError> {
        ffi_call_unit!(
            tox_group_set_topic,
            ffi::Tox_Err_Group_Topic_Set::TOX_ERR_GROUP_TOPIC_SET_OK,
            self.ptr,
            group_number.0,
            topic.as_ptr(),
            topic.len()
        )
    }

    pub fn group_get_topic_size(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<usize, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_topic_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_topic(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<Vec<u8>, GroupStateQueryError> {
        ffi_get_vec!(
            tox_group_get_topic,
            tox_group_get_topic_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_name_size(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<usize, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_name_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_name(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<Vec<u8>, GroupStateQueryError> {
        ffi_get_vec!(
            tox_group_get_name,
            tox_group_get_name_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_chat_id(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupChatId, GroupStateQueryError> {
        ffi_get_array!(
            tox_group_get_chat_id,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            GROUP_CHAT_ID_SIZE,
            self.ptr,
            group_number.0
        )
        .map(GroupChatId)
    }

    pub fn group_get_privacy_state(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupPrivacyState, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_privacy_state,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(Into::into)
    }

    pub fn group_get_voice_state(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupVoiceState, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_voice_state,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(Into::into)
    }

    pub fn group_get_topic_lock(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<GroupTopicLock, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_topic_lock,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
        .map(Into::into)
    }

    pub fn group_get_peer_limit(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<u16, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_peer_limit,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_password_size(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<usize, GroupStateQueryError> {
        ffi_call!(
            tox_group_get_password_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_get_password(
        &self,
        group_number: GroupNumber,
    ) -> std::result::Result<Vec<u8>, GroupStateQueryError> {
        ffi_get_vec!(
            tox_group_get_password,
            tox_group_get_password_size,
            ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK,
            self.ptr,
            group_number.0
        )
    }

    pub fn group_send_message(
        &self,
        group_number: GroupNumber,
        message_type: MessageType,
        message: &[u8],
    ) -> std::result::Result<GroupMessageId, GroupSendMessageError> {
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
    }

    pub fn group_send_private_message(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        message_type: MessageType,
        message: &[u8],
    ) -> std::result::Result<GroupMessageId, GroupSendPrivateMessageError> {
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
    }

    pub fn group_send_custom_packet(
        &self,
        group_number: GroupNumber,
        lossless: bool,
        data: &[u8],
    ) -> std::result::Result<(), GroupSendCustomPacketError> {
        ffi_call_unit!(
            tox_group_send_custom_packet,
            ffi::Tox_Err_Group_Send_Custom_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK,
            self.ptr,
            group_number.0,
            lossless,
            data.as_ptr(),
            data.len()
        )
    }

    pub fn group_send_custom_private_packet(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        lossless: bool,
        data: &[u8],
    ) -> std::result::Result<(), GroupSendCustomPrivatePacketError> {
        ffi_call_unit!(tox_group_send_custom_private_packet, ffi::Tox_Err_Group_Send_Custom_Private_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK, self.ptr, group_number.0, peer_id.0, lossless, data.as_ptr(), data.len())
    }

    pub fn group_invite_friend(
        &self,
        group_number: GroupNumber,
        friend_number: FriendNumber,
    ) -> std::result::Result<(), GroupInviteFriendError> {
        ffi_call_unit!(
            tox_group_invite_friend,
            ffi::Tox_Err_Group_Invite_Friend::TOX_ERR_GROUP_INVITE_FRIEND_OK,
            self.ptr,
            group_number.0,
            friend_number.0
        )
    }

    pub fn group_set_password(
        &self,
        group_number: GroupNumber,
        password: &[u8],
    ) -> std::result::Result<(), GroupSetPasswordError> {
        ffi_call_unit!(
            tox_group_set_password,
            ffi::Tox_Err_Group_Set_Password::TOX_ERR_GROUP_SET_PASSWORD_OK,
            self.ptr,
            group_number.0,
            password.as_ptr(),
            password.len()
        )
    }

    pub fn group_set_topic_lock(
        &self,
        group_number: GroupNumber,
        topic_lock: GroupTopicLock,
    ) -> std::result::Result<(), GroupSetTopicLockError> {
        ffi_call_unit!(
            tox_group_set_topic_lock,
            ffi::Tox_Err_Group_Set_Topic_Lock::TOX_ERR_GROUP_SET_TOPIC_LOCK_OK,
            self.ptr,
            group_number.0,
            topic_lock.into()
        )
    }

    pub fn group_set_voice_state(
        &self,
        group_number: GroupNumber,
        voice_state: GroupVoiceState,
    ) -> std::result::Result<(), GroupSetVoiceStateError> {
        ffi_call_unit!(
            tox_group_set_voice_state,
            ffi::Tox_Err_Group_Set_Voice_State::TOX_ERR_GROUP_SET_VOICE_STATE_OK,
            self.ptr,
            group_number.0,
            voice_state.into()
        )
    }

    pub fn group_set_privacy_state(
        &self,
        group_number: GroupNumber,
        privacy_state: GroupPrivacyState,
    ) -> std::result::Result<(), GroupSetPrivacyStateError> {
        ffi_call_unit!(
            tox_group_set_privacy_state,
            ffi::Tox_Err_Group_Set_Privacy_State::TOX_ERR_GROUP_SET_PRIVACY_STATE_OK,
            self.ptr,
            group_number.0,
            privacy_state.into()
        )
    }

    pub fn group_set_peer_limit(
        &self,
        group_number: GroupNumber,
        peer_limit: u16,
    ) -> std::result::Result<(), GroupSetPeerLimitError> {
        ffi_call_unit!(
            tox_group_set_peer_limit,
            ffi::Tox_Err_Group_Set_Peer_Limit::TOX_ERR_GROUP_SET_PEER_LIMIT_OK,
            self.ptr,
            group_number.0,
            peer_limit
        )
    }

    pub fn group_set_ignore(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        ignore: bool,
    ) -> std::result::Result<(), GroupSetIgnoreError> {
        ffi_call_unit!(
            tox_group_set_ignore,
            ffi::Tox_Err_Group_Set_Ignore::TOX_ERR_GROUP_SET_IGNORE_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            ignore
        )
    }

    pub fn group_set_role(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
        role: GroupRole,
    ) -> std::result::Result<(), GroupSetRoleError> {
        ffi_call_unit!(
            tox_group_set_role,
            ffi::Tox_Err_Group_Set_Role::TOX_ERR_GROUP_SET_ROLE_OK,
            self.ptr,
            group_number.0,
            peer_id.0,
            role.into()
        )
    }

    pub fn group_kick_peer(
        &self,
        group_number: GroupNumber,
        peer_id: GroupPeerNumber,
    ) -> std::result::Result<(), GroupKickPeerError> {
        ffi_call_unit!(
            tox_group_kick_peer,
            ffi::Tox_Err_Group_Kick_Peer::TOX_ERR_GROUP_KICK_PEER_OK,
            self.ptr,
            group_number.0,
            peer_id.0
        )
    }

    pub fn group_max_topic_length() -> u32 {
        unsafe { ffi::tox_group_max_topic_length() }
    }

    pub fn group_max_part_length() -> u32 {
        unsafe { ffi::tox_group_max_part_length() }
    }

    pub fn group_max_message_length() -> u32 {
        unsafe { ffi::tox_group_max_message_length() }
    }

    pub fn group_max_custom_lossy_packet_length() -> u32 {
        unsafe { ffi::tox_group_max_custom_lossy_packet_length() }
    }

    pub fn group_max_custom_lossless_packet_length() -> u32 {
        unsafe { ffi::tox_group_max_custom_lossless_packet_length() }
    }

    pub fn group_max_group_name_length() -> u32 {
        unsafe { ffi::tox_group_max_group_name_length() }
    }

    pub fn group_max_password_size() -> u32 {
        unsafe { ffi::tox_group_max_password_size() }
    }

    pub fn group_chat_id_size() -> u32 {
        unsafe { ffi::tox_group_chat_id_size() }
    }

    pub fn group_privacy_state_to_string(value: GroupPrivacyState) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_privacy_state_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_topic_lock_to_string(value: GroupTopicLock) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_topic_lock_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_voice_state_to_string(value: GroupVoiceState) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_voice_state_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_role_to_string(value: GroupRole) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_role_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_exit_type_to_string(value: GroupExitType) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_exit_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_join_fail_to_string(value: GroupJoinFail) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_join_fail_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_mod_event_to_string(value: GroupModEvent) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_group_mod_event_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn group_peer_get_name_size(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<usize, GroupPeerQueryError> {
        ffi_call!(
            tox_group_peer_get_name_size,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
    }

    pub fn group_peer_get_name(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<Vec<u8>, GroupPeerQueryError> {
        ffi_get_vec!(
            tox_group_peer_get_name,
            tox_group_peer_get_name_size,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
    }

    pub fn group_peer_get_status(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<UserStatus, GroupPeerQueryError> {
        ffi_call!(
            tox_group_peer_get_status,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
        .map(Into::into)
    }

    pub fn group_peer_get_role(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<GroupRole, GroupPeerQueryError> {
        ffi_call!(
            tox_group_peer_get_role,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
        .map(Into::into)
    }

    pub fn group_peer_get_connection_status(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<Connection, GroupPeerQueryError> {
        ffi_call!(
            tox_group_peer_get_connection_status,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
        .map(Into::into)
    }

    pub fn group_peer_get_public_key(
        &self,
        group_number: GroupNumber,
        group_peer_number: GroupPeerNumber,
    ) -> std::result::Result<PublicKey, GroupPeerQueryError> {
        ffi_get_array!(
            tox_group_peer_get_public_key,
            ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            group_number.0,
            group_peer_number.0
        )
        .map(PublicKey)
    }

    pub fn group_peer_public_key_size() -> u32 {
        unsafe { ffi::tox_group_peer_public_key_size() }
    }

    pub fn new(options: &Options) -> std::result::Result<Self, NewError> {
        unsafe {
            ffi::tox_options_set_experimental_thread_safety(options.ptr, true);
        }
        ffi_call!(tox_new, ffi::Tox_Err_New::TOX_ERR_NEW_OK, options.ptr)
            .map(|val| Self { ptr: val })
    }

    pub fn get_savedata_size(&self) -> usize {
        unsafe { ffi::tox_get_savedata_size(self.ptr) }
    }

    pub fn get_savedata(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_get_savedata, tox_get_savedata_size, u8, self.ptr)
    }

    pub fn bootstrap(
        &self,
        host: &str,
        port: Port,
        public_key: &DhtId,
    ) -> std::result::Result<(), BootstrapError> {
        let host_cstr = c_str!(host);
        ffi_call_unit!(
            tox_bootstrap,
            ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK,
            self.ptr,
            host_cstr.as_ptr(),
            port.0,
            public_key.0.as_ptr()
        )
    }

    pub fn add_tcp_relay(
        &self,
        host: &str,
        port: Port,
        public_key: &DhtId,
    ) -> std::result::Result<(), BootstrapError> {
        let host_cstr = c_str!(host);
        ffi_call_unit!(
            tox_add_tcp_relay,
            ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK,
            self.ptr,
            host_cstr.as_ptr(),
            port.0,
            public_key.0.as_ptr()
        )
    }

    pub fn self_get_connection_status(&self) -> Connection {
        unsafe { ffi::tox_self_get_connection_status(self.ptr) }.into()
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe { ffi::tox_iteration_interval(self.ptr) }
    }

    pub fn iterate<T>(&self, user_data: &mut T) {
        unsafe { ffi::tox_iterate(self.ptr, user_data as *mut T as *mut std::ffi::c_void) }
    }

    pub fn self_get_address(&self) -> Address {
        unsafe {
            let mut buf = [0; ADDRESS_SIZE];
            ffi::tox_self_get_address(self.ptr, buf.as_mut_ptr());
            Address(buf)
        }
    }

    pub fn self_set_nospam(&self, nospam: u32) {
        unsafe { ffi::tox_self_set_nospam(self.ptr, nospam) }
    }

    pub fn self_get_nospam(&self) -> u32 {
        unsafe { ffi::tox_self_get_nospam(self.ptr) }
    }

    pub fn self_get_public_key(&self) -> PublicKey {
        unsafe {
            let mut buf = [0; PUBLIC_KEY_SIZE];
            ffi::tox_self_get_public_key(self.ptr, buf.as_mut_ptr());
            PublicKey(buf)
        }
    }

    pub fn self_get_secret_key(&self) -> SecretKey {
        unsafe {
            let mut buf = [0; SECRET_KEY_SIZE];
            ffi::tox_self_get_secret_key(self.ptr, buf.as_mut_ptr());
            SecretKey(buf)
        }
    }

    pub fn self_set_name(&self, name: &[u8]) -> std::result::Result<(), SetInfoError> {
        ffi_call_unit!(
            tox_self_set_name,
            ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK,
            self.ptr,
            name.as_ptr(),
            name.len()
        )
    }

    pub fn self_get_name_size(&self) -> usize {
        unsafe { ffi::tox_self_get_name_size(self.ptr) }
    }

    pub fn self_get_name(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_self_get_name, tox_self_get_name_size, u8, self.ptr)
    }

    pub fn self_set_status_message(
        &self,
        status_message: &[u8],
    ) -> std::result::Result<(), SetInfoError> {
        ffi_call_unit!(
            tox_self_set_status_message,
            ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK,
            self.ptr,
            status_message.as_ptr(),
            status_message.len()
        )
    }

    pub fn self_get_status_message_size(&self) -> usize {
        unsafe { ffi::tox_self_get_status_message_size(self.ptr) }
    }

    pub fn self_get_status_message(&self) -> Vec<u8> {
        ffi_get_vec_simple!(
            tox_self_get_status_message,
            tox_self_get_status_message_size,
            u8,
            self.ptr
        )
    }

    pub fn self_set_status(&self, status: UserStatus) {
        unsafe { ffi::tox_self_set_status(self.ptr, status.into()) }
    }

    pub fn self_get_status(&self) -> UserStatus {
        unsafe { ffi::tox_self_get_status(self.ptr) }.into()
    }

    pub fn self_get_friend_list_size(&self) -> usize {
        unsafe { ffi::tox_self_get_friend_list_size(self.ptr) }
    }

    pub fn self_get_friend_list(&self) -> Vec<FriendNumber> {
        ffi_get_vec_simple!(
            tox_self_get_friend_list,
            tox_self_get_friend_list_size,
            u32,
            self.ptr
        )
        .into_iter()
        .map(FriendNumber)
        .collect()
    }

    pub fn self_set_typing(
        &self,
        friend_number: FriendNumber,
        typing: bool,
    ) -> std::result::Result<(), SetTypingError> {
        ffi_call_unit!(
            tox_self_set_typing,
            ffi::Tox_Err_Set_Typing::TOX_ERR_SET_TYPING_OK,
            self.ptr,
            friend_number.0,
            typing
        )
    }

    pub fn self_get_dht_id(&self) -> DhtId {
        unsafe {
            let mut buf = [0; DHT_ID_SIZE];
            ffi::tox_self_get_dht_id(self.ptr, buf.as_mut_ptr());
            DhtId(buf)
        }
    }

    pub fn self_get_udp_port(&self) -> std::result::Result<Port, GetPortError> {
        ffi_call!(
            tox_self_get_udp_port,
            ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK,
            self.ptr
        )
        .map(Port)
    }

    pub fn self_get_tcp_port(&self) -> std::result::Result<Port, GetPortError> {
        ffi_call!(
            tox_self_get_tcp_port,
            ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK,
            self.ptr
        )
        .map(Port)
    }

    pub fn version_major() -> u32 {
        unsafe { ffi::tox_version_major() }
    }

    pub fn version_minor() -> u32 {
        unsafe { ffi::tox_version_minor() }
    }

    pub fn version_patch() -> u32 {
        unsafe { ffi::tox_version_patch() }
    }

    pub fn version_is_compatible(major: u32, minor: u32, patch: u32) -> bool {
        ffi_bool!(tox_version_is_compatible, major, minor, patch)
    }

    pub fn public_key_size() -> u32 {
        unsafe { ffi::tox_public_key_size() }
    }

    pub fn secret_key_size() -> u32 {
        unsafe { ffi::tox_secret_key_size() }
    }

    pub fn dht_id_size() -> u32 {
        unsafe { ffi::tox_dht_id_size() }
    }

    pub fn nospam_size() -> u32 {
        unsafe { ffi::tox_nospam_size() }
    }

    pub fn address_size() -> u32 {
        unsafe { ffi::tox_address_size() }
    }

    pub fn max_name_length() -> u32 {
        unsafe { ffi::tox_max_name_length() }
    }

    pub fn max_status_message_length() -> u32 {
        unsafe { ffi::tox_max_status_message_length() }
    }

    pub fn max_friend_request_length() -> u32 {
        unsafe { ffi::tox_max_friend_request_length() }
    }

    pub fn max_message_length() -> u32 {
        unsafe { ffi::tox_max_message_length() }
    }

    pub fn max_custom_packet_size() -> u32 {
        unsafe { ffi::tox_max_custom_packet_size() }
    }

    pub fn hash_length() -> u32 {
        unsafe { ffi::tox_hash_length() }
    }

    pub fn max_filename_length() -> u32 {
        unsafe { ffi::tox_max_filename_length() }
    }

    pub fn max_hostname_length() -> u32 {
        unsafe { ffi::tox_max_hostname_length() }
    }

    pub fn user_status_to_string(value: UserStatus) -> &'static str {
        unsafe {
            let ptr = ffi::tox_user_status_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn message_type_to_string(value: MessageType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_message_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_new_to_string(value: NewError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_new_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_bootstrap_to_string(value: BootstrapError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_bootstrap_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn connection_to_string(value: Connection) -> &'static str {
        unsafe {
            let ptr = ffi::tox_connection_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_set_info_to_string(value: SetInfoError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_set_info_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_add_to_string(value: FriendAddError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_friend_add_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_delete_to_string(value: FriendDeleteError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_friend_delete_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_by_public_key_to_string(value: FriendByPublicKeyError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_by_public_key_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_get_public_key_to_string(value: FriendGetPublicKeyError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_get_public_key_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_get_last_online_to_string(value: FriendGetLastOnlineError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_get_last_online_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_query_to_string(value: FriendQueryError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_friend_query_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_set_typing_to_string(value: SetTypingError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_set_typing_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_send_message_to_string(value: FriendSendMessageError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_send_message_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn hash(data: &[u8]) -> Hash {
        unsafe {
            let mut buf = [0; HASH_LENGTH];
            ffi::tox_hash(buf.as_mut_ptr(), data.as_ptr(), data.len());
            Hash(buf)
        }
    }

    pub fn err_file_control_to_string(value: FileControlError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_file_control_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_file_seek_to_string(value: FileSeekError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_seek_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_file_get_to_string(value: FileGetError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_get_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_file_by_id_to_string(value: FileByIdError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_file_by_id_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_file_send_to_string(value: FileSendError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_send_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_file_send_chunk_to_string(value: FileSendChunkError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_file_send_chunk_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_new_to_string(value: ConferenceNewError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_conference_new_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_delete_to_string(value: ConferenceDeleteError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_delete_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_peer_query_to_string(value: ConferencePeerQueryError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_peer_query_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_set_max_offline_to_string(
        value: ConferenceSetMaxOfflineError,
    ) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_set_max_offline_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_invite_to_string(value: ConferenceInviteError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_invite_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_join_to_string(value: ConferenceJoinError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_conference_join_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_send_message_to_string(
        value: ConferenceSendMessageError,
    ) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_send_message_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_title_to_string(value: ConferenceTitleError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_title_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_get_type_to_string(value: ConferenceGetTypeError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_get_type_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_by_id_to_string(value: ConferenceByIdError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_by_id_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_conference_by_uid_to_string(value: ConferenceByUidError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_by_uid_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_friend_custom_packet_to_string(value: FriendCustomPacketError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_custom_packet_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_get_port_to_string(value: GetPortError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_get_port_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_new_to_string(value: GroupNewError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_new_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_join_to_string(value: GroupJoinError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_join_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_is_connected_to_string(value: GroupIsConnectedError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_is_connected_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_disconnect_to_string(value: GroupDisconnectError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_disconnect_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_reconnect_to_string(value: GroupReconnectError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_reconnect_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_leave_to_string(value: GroupLeaveError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_leave_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_self_query_to_string(value: GroupSelfQueryError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_query_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_self_name_set_to_string(value: GroupSelfNameSetError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_name_set_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_self_status_set_to_string(value: GroupSelfStatusSetError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_status_set_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_peer_query_to_string(value: GroupPeerQueryError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_peer_query_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_state_query_to_string(value: GroupStateQueryError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_state_query_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_topic_set_to_string(value: GroupTopicSetError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_topic_set_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_by_id_to_string(value: GroupByIdError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_by_id_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_send_message_to_string(value: GroupSendMessageError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_message_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_send_private_message_to_string(
        value: GroupSendPrivateMessageError,
    ) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_private_message_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_send_custom_packet_to_string(
        value: GroupSendCustomPacketError,
    ) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_custom_packet_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_send_custom_private_packet_to_string(
        value: GroupSendCustomPrivatePacketError,
    ) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_custom_private_packet_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_invite_friend_to_string(value: GroupInviteFriendError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_invite_friend_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_invite_accept_to_string(value: GroupInviteAcceptError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_invite_accept_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_password_to_string(value: GroupSetPasswordError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_password_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_topic_lock_to_string(value: GroupSetTopicLockError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_topic_lock_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_voice_state_to_string(value: GroupSetVoiceStateError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_voice_state_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_privacy_state_to_string(value: GroupSetPrivacyStateError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_privacy_state_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_peer_limit_to_string(value: GroupSetPeerLimitError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_peer_limit_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_ignore_to_string(value: GroupSetIgnoreError) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_ignore_to_string(value.into())
                as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_set_role_to_string(value: GroupSetRoleError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_set_role_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_group_kick_peer_to_string(value: GroupKickPeerError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_group_kick_peer_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn log_level_to_string(value: LogLevel) -> &'static str {
        unsafe {
            let ptr = ffi::tox_log_level_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn proxy_type_to_string(value: ProxyType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_proxy_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn savedata_type_to_string(value: SavedataType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_savedata_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn err_options_new_to_string(value: OptionsNewError) -> &'static str {
        unsafe {
            let ptr =
                ffi::tox_err_options_new_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
        }
    }

    pub fn conference_invite(
        &self,
        friend_number: FriendNumber,
        conference_number: ConferenceNumber,
    ) -> std::result::Result<(), ConferenceInviteError> {
        ffi_call_unit!(
            tox_conference_invite,
            ffi::Tox_Err_Conference_Invite::TOX_ERR_CONFERENCE_INVITE_OK,
            self.ptr,
            friend_number.0,
            conference_number.0
        )
    }

    pub fn conference_get_chatlist_size(&self) -> usize {
        unsafe { ffi::tox_conference_get_chatlist_size(self.ptr) }
    }

    pub fn conference_get_chatlist(&self) -> Vec<ConferenceNumber> {
        ffi_get_vec_simple!(
            tox_conference_get_chatlist,
            tox_conference_get_chatlist_size,
            u32,
            self.ptr
        )
        .into_iter()
        .map(ConferenceNumber)
        .collect()
    }

    pub fn events_init(&self) {
        unsafe { ffi::tox_events_init(self.ptr) }
    }

    pub fn file_control(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        control: FileControl,
    ) -> std::result::Result<(), FileControlError> {
        ffi_call_unit!(
            tox_file_control,
            ffi::Tox_Err_File_Control::TOX_ERR_FILE_CONTROL_OK,
            self.ptr,
            friend_number.0,
            file_number.0,
            control.into()
        )
    }

    pub fn file_seek(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        position: u64,
    ) -> std::result::Result<(), FileSeekError> {
        ffi_call_unit!(
            tox_file_seek,
            ffi::Tox_Err_File_Seek::TOX_ERR_FILE_SEEK_OK,
            self.ptr,
            friend_number.0,
            file_number.0,
            position
        )
    }

    pub fn file_get_file_id(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
    ) -> std::result::Result<FileId, FileGetError> {
        ffi_get_array!(
            tox_file_get_file_id,
            ffi::Tox_Err_File_Get::TOX_ERR_FILE_GET_OK,
            FILE_ID_LENGTH,
            self.ptr,
            friend_number.0,
            file_number.0
        )
        .map(FileId)
    }

    pub fn file_send_chunk(
        &self,
        friend_number: FriendNumber,
        file_number: FileNumber,
        position: u64,
        data: &[u8],
    ) -> std::result::Result<(), FileSendChunkError> {
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
    }

    pub fn group_get_group_list_size(&self) -> u32 {
        unsafe { ffi::tox_group_get_group_list_size(self.ptr) }
    }

    pub fn group_get_group_list(&self) -> Vec<GroupNumber> {
        ffi_get_vec_simple!(
            tox_group_get_group_list,
            tox_group_get_group_list_size,
            u32,
            self.ptr
        )
        .into_iter()
        .map(GroupNumber)
        .collect()
    }

    pub fn groupchat_disable_av(&self, conference_number: ConferenceNumber) -> i32 {
        unsafe { ffi::toxav_groupchat_disable_av(self.ptr, conference_number.0) }
    }

    pub fn groupchat_av_enabled(&self, conference_number: ConferenceNumber) -> bool {
        ffi_bool!(toxav_groupchat_av_enabled, self.ptr, conference_number.0)
    }
}
