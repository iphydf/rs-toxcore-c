use super::tox::Tox;
use crate::ffi;
use crate::types::{
    self, ConferenceId, ConferenceNumber, ConferenceOfflinePeerNumber, ConferencePeerNumber,
    FriendNumber, PUBLIC_KEY_SIZE, PublicKey, Tox_Err_Conference_By_Id, Tox_Err_Conference_Delete,
    Tox_Err_Conference_Get_Type, Tox_Err_Conference_Invite, Tox_Err_Conference_Join,
    Tox_Err_Conference_New, Tox_Err_Conference_Peer_Query, Tox_Err_Conference_Send_Message,
    Tox_Err_Conference_Set_Max_Offline, Tox_Err_Conference_Title, ToxConferenceType,
};

impl Tox {
    pub fn conference_new(&self) -> Result<ConferenceNumber, Tox_Err_Conference_New> {
        ffi_call!(
            tox_conference_new,
            ffi::Tox_Err_Conference_New::TOX_ERR_CONFERENCE_NEW_OK,
            self.ptr
        )
        .map(ConferenceNumber)
        .map_err(|e| e.into())
    }

    pub fn conference_delete(
        &self,
        conference_number: ConferenceNumber,
    ) -> Result<(), Tox_Err_Conference_Delete> {
        ffi_call_unit!(
            tox_conference_delete,
            ffi::Tox_Err_Conference_Delete::TOX_ERR_CONFERENCE_DELETE_OK,
            self.ptr,
            conference_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_peer_count(
        &self,
        conference_number: ConferenceNumber,
    ) -> Result<u32, Tox_Err_Conference_Peer_Query> {
        ffi_call!(
            tox_conference_peer_count,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_peer_get_name(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferencePeerNumber,
    ) -> Result<Vec<u8>, Tox_Err_Conference_Peer_Query> {
        ffi_get_vec!(
            tox_conference_peer_get_name,
            tox_conference_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_peer_get_public_key(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferencePeerNumber,
    ) -> Result<PublicKey, Tox_Err_Conference_Peer_Query> {
        ffi_get_array!(
            tox_conference_peer_get_public_key,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map(PublicKey)
        .map_err(|e| e.into())
    }

    pub fn conference_peer_number_is_ours(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferencePeerNumber,
    ) -> Result<bool, Tox_Err_Conference_Peer_Query> {
        ffi_call!(
            tox_conference_peer_number_is_ours,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_set_max_offline(
        &self,
        conference_number: ConferenceNumber,
        max_offline: u32,
    ) -> Result<(), Tox_Err_Conference_Set_Max_Offline> {
        ffi_call_unit!(
            tox_conference_set_max_offline,
            ffi::Tox_Err_Conference_Set_Max_Offline::TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK,
            self.ptr,
            conference_number.0,
            max_offline
        )
        .map_err(|e| e.into())
    }

    pub fn conference_invite(
        &self,
        friend_number: FriendNumber,
        conference_number: ConferenceNumber,
    ) -> Result<(), Tox_Err_Conference_Invite> {
        ffi_call_unit!(
            tox_conference_invite,
            ffi::Tox_Err_Conference_Invite::TOX_ERR_CONFERENCE_INVITE_OK,
            self.ptr,
            friend_number.0,
            conference_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_join(
        &self,
        friend_number: FriendNumber,
        cookie: &[u8],
    ) -> Result<ConferenceNumber, Tox_Err_Conference_Join> {
        ffi_call!(
            tox_conference_join,
            ffi::Tox_Err_Conference_Join::TOX_ERR_CONFERENCE_JOIN_OK,
            self.ptr,
            friend_number.0,
            cookie.as_ptr(),
            cookie.len()
        )
        .map(ConferenceNumber)
        .map_err(|e| e.into())
    }

    pub fn conference_send_message(
        &self,
        conference_number: ConferenceNumber,
        message_type: ffi::Tox_Message_Type,
        message: &[u8],
    ) -> Result<(), Tox_Err_Conference_Send_Message> {
        ffi_call_unit!(
            tox_conference_send_message,
            ffi::Tox_Err_Conference_Send_Message::TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,
            self.ptr,
            conference_number.0,
            message_type,
            message.as_ptr(),
            message.len()
        )
        .map_err(|e| e.into())
    }

    pub fn conference_get_title(
        &self,
        conference_number: ConferenceNumber,
    ) -> Result<Vec<u8>, Tox_Err_Conference_Title> {
        ffi_get_vec!(
            tox_conference_get_title,
            tox_conference_get_title_size,
            ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK,
            self.ptr,
            conference_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_set_title(
        &self,
        conference_number: ConferenceNumber,
        title: &[u8],
    ) -> Result<(), Tox_Err_Conference_Title> {
        ffi_call_unit!(
            tox_conference_set_title,
            ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK,
            self.ptr,
            conference_number.0,
            title.as_ptr(),
            title.len()
        )
        .map_err(|e| e.into())
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

    pub fn conference_get_type(
        &self,
        conference_number: ConferenceNumber,
    ) -> Result<ToxConferenceType, Tox_Err_Conference_Get_Type> {
        ffi_call!(
            tox_conference_get_type,
            ffi::Tox_Err_Conference_Get_Type::TOX_ERR_CONFERENCE_GET_TYPE_OK,
            self.ptr,
            conference_number.0
        )
        .map(|t| t.into())
        .map_err(|e| e.into())
    }

    pub fn conference_get_id(&self, conference_number: ConferenceNumber) -> Option<ConferenceId> {
        let mut id = [0u8; types::CONFERENCE_ID_SIZE];
        if unsafe { ffi::tox_conference_get_id(self.ptr, conference_number.0, id.as_mut_ptr()) } {
            Some(ConferenceId(id))
        } else {
            None
        }
    }

    pub fn conference_by_id(
        &self,
        id: &ConferenceId,
    ) -> Result<ConferenceNumber, Tox_Err_Conference_By_Id> {
        ffi_call!(
            tox_conference_by_id,
            ffi::Tox_Err_Conference_By_Id::TOX_ERR_CONFERENCE_BY_ID_OK,
            self.ptr,
            id.0.as_ptr()
        )
        .map(ConferenceNumber)
        .map_err(|e| e.into())
    }

    pub fn conference_offline_peer_count(
        &self,
        conference_number: ConferenceNumber,
    ) -> Result<u32, Tox_Err_Conference_Peer_Query> {
        ffi_call!(
            tox_conference_offline_peer_count,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_offline_peer_get_name(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferenceOfflinePeerNumber,
    ) -> Result<Vec<u8>, Tox_Err_Conference_Peer_Query> {
        ffi_get_vec!(
            tox_conference_offline_peer_get_name,
            tox_conference_offline_peer_get_name_size,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map_err(|e| e.into())
    }

    pub fn conference_offline_peer_get_public_key(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferenceOfflinePeerNumber,
    ) -> Result<PublicKey, Tox_Err_Conference_Peer_Query> {
        ffi_get_array!(
            tox_conference_offline_peer_get_public_key,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            PUBLIC_KEY_SIZE,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map(PublicKey)
        .map_err(|e| e.into())
    }

    pub fn conference_offline_peer_get_last_active(
        &self,
        conference_number: ConferenceNumber,
        peer_number: ConferenceOfflinePeerNumber,
    ) -> Result<u64, Tox_Err_Conference_Peer_Query> {
        ffi_call!(
            tox_conference_offline_peer_get_last_active,
            ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK,
            self.ptr,
            conference_number.0,
            peer_number.0
        )
        .map_err(|e| e.into())
    }
}
