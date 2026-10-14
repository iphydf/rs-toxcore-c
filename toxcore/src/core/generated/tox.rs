#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
use super::iterate_options::IterateOptions;
use super::system::System;
use super::options::Options;
use super::av::ToxAV;
use crate::core::dispatch::ToxAVHandler;
impl Tox {
    pub fn conference_new(&self) -> std::result::Result<ConferenceNumber, Tox_Err_Conference_New> {
        ffi_call!(tox_conference_new, ffi::Tox_Err_Conference_New::TOX_ERR_CONFERENCE_NEW_OK, self.ptr).map(ConferenceNumber)
    }

    pub fn conference_join(&self, friend_number: FriendNumber, cookie: &[u8]) -> std::result::Result<ConferenceNumber, Tox_Err_Conference_Join> {
        ffi_call!(tox_conference_join, ffi::Tox_Err_Conference_Join::TOX_ERR_CONFERENCE_JOIN_OK, self.ptr, friend_number.0, cookie.as_ptr(), cookie.len()).map(ConferenceNumber)
    }

    pub fn conference_by_id(&self, id: &ConferenceId) -> std::result::Result<ConferenceNumber, Tox_Err_Conference_By_Id> {
        ffi_call!(tox_conference_by_id, ffi::Tox_Err_Conference_By_Id::TOX_ERR_CONFERENCE_BY_ID_OK, self.ptr, id.0.as_ptr()).map(ConferenceNumber)
    }

    pub fn conference_delete(&self, conference_number: ConferenceNumber) -> std::result::Result<(), Tox_Err_Conference_Delete> {
        ffi_call_unit!(tox_conference_delete, ffi::Tox_Err_Conference_Delete::TOX_ERR_CONFERENCE_DELETE_OK, self.ptr, conference_number.0)
    }

    pub fn conference_peer_count(&self, conference_number: ConferenceNumber) -> std::result::Result<u32, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_peer_count, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0)
    }

    pub fn conference_offline_peer_count(&self, conference_number: ConferenceNumber) -> std::result::Result<u32, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_offline_peer_count, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0)
    }

    pub fn conference_set_max_offline(&self, conference_number: ConferenceNumber, max_offline: u32) -> std::result::Result<(), Tox_Err_Conference_Set_Max_Offline> {
        ffi_call_unit!(tox_conference_set_max_offline, ffi::Tox_Err_Conference_Set_Max_Offline::TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK, self.ptr, conference_number.0, max_offline)
    }

    pub fn conference_send_message(&self, conference_number: ConferenceNumber, type_: MessageType, message: &[u8]) -> std::result::Result<(), Tox_Err_Conference_Send_Message> {
        ffi_call_unit!(tox_conference_send_message, ffi::Tox_Err_Conference_Send_Message::TOX_ERR_CONFERENCE_SEND_MESSAGE_OK, self.ptr, conference_number.0, type_.into(), message.as_ptr(), message.len())
    }

    pub fn conference_get_title_size(&self, conference_number: ConferenceNumber) -> std::result::Result<usize, Tox_Err_Conference_Title> {
        ffi_call!(tox_conference_get_title_size, ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK, self.ptr, conference_number.0)
    }

    pub fn conference_get_title(&self, conference_number: ConferenceNumber) -> std::result::Result<Vec<u8>, Tox_Err_Conference_Title> {
        ffi_get_vec!(tox_conference_get_title, tox_conference_get_title_size, ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK, self.ptr, conference_number.0)
    }

    pub fn conference_set_title(&self, conference_number: ConferenceNumber, title: &[u8]) -> std::result::Result<(), Tox_Err_Conference_Title> {
        ffi_call_unit!(tox_conference_set_title, ffi::Tox_Err_Conference_Title::TOX_ERR_CONFERENCE_TITLE_OK, self.ptr, conference_number.0, title.as_ptr(), title.len())
    }

    pub fn conference_get_type(&self, conference_number: ConferenceNumber) -> std::result::Result<ToxConferenceType, Tox_Err_Conference_Get_Type> {
        ffi_call!(tox_conference_get_type, ffi::Tox_Err_Conference_Get_Type::TOX_ERR_CONFERENCE_GET_TYPE_OK, self.ptr, conference_number.0).map(Into::into)
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

    pub fn conference_uid_size() -> u32 {
        unsafe {
            ffi::tox_conference_uid_size()
        }
    }

    pub fn conference_id_size() -> u32 {
        unsafe {
            ffi::tox_conference_id_size()
        }
    }

    pub fn conference_type_to_string(value: ToxConferenceType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_conference_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }
}
impl Tox {
    pub fn conference_offline_peer_get_name_size(&self, conference_number: ConferenceNumber, conference_offline_peer_number: ConferenceOfflinePeerNumber) -> std::result::Result<usize, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_offline_peer_get_name_size, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_offline_peer_number.0)
    }

    pub fn conference_offline_peer_get_name(&self, conference_number: ConferenceNumber, conference_offline_peer_number: ConferenceOfflinePeerNumber) -> std::result::Result<Vec<u8>, Tox_Err_Conference_Peer_Query> {
        ffi_get_vec!(tox_conference_offline_peer_get_name, tox_conference_offline_peer_get_name_size, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_offline_peer_number.0)
    }

    pub fn conference_offline_peer_get_public_key(&self, conference_number: ConferenceNumber, conference_offline_peer_number: ConferenceOfflinePeerNumber) -> std::result::Result<PublicKey, Tox_Err_Conference_Peer_Query> {
        ffi_get_array!(tox_conference_offline_peer_get_public_key, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, PUBLIC_KEY_SIZE, self.ptr, conference_number.0, conference_offline_peer_number.0).map(PublicKey)
    }

    pub fn conference_offline_peer_get_last_active(&self, conference_number: ConferenceNumber, conference_offline_peer_number: ConferenceOfflinePeerNumber) -> std::result::Result<u64, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_offline_peer_get_last_active, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_offline_peer_number.0)
    }
}
impl Tox {
    pub fn conference_peer_get_name_size(&self, conference_number: ConferenceNumber, conference_peer_number: ConferencePeerNumber) -> std::result::Result<usize, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_peer_get_name_size, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_peer_number.0)
    }

    pub fn conference_peer_get_name(&self, conference_number: ConferenceNumber, conference_peer_number: ConferencePeerNumber) -> std::result::Result<Vec<u8>, Tox_Err_Conference_Peer_Query> {
        ffi_get_vec!(tox_conference_peer_get_name, tox_conference_peer_get_name_size, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_peer_number.0)
    }

    pub fn conference_peer_get_public_key(&self, conference_number: ConferenceNumber, conference_peer_number: ConferencePeerNumber) -> std::result::Result<PublicKey, Tox_Err_Conference_Peer_Query> {
        ffi_get_array!(tox_conference_peer_get_public_key, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, PUBLIC_KEY_SIZE, self.ptr, conference_number.0, conference_peer_number.0).map(PublicKey)
    }

    pub fn conference_peer_number_is_ours(&self, conference_number: ConferenceNumber, conference_peer_number: ConferencePeerNumber) -> std::result::Result<bool, Tox_Err_Conference_Peer_Query> {
        ffi_call!(tox_conference_peer_number_is_ours, ffi::Tox_Err_Conference_Peer_Query::TOX_ERR_CONFERENCE_PEER_QUERY_OK, self.ptr, conference_number.0, conference_peer_number.0)
    }
}
pub struct EventConferenceConnected<'a>(pub &'a ffi::Tox_Event_Conference_Connected);
impl<'a> EventConferenceConnected<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_connected_get_conference_number(self.0)
        })
    }
}
pub struct EventConferenceInvite<'a>(pub &'a ffi::Tox_Event_Conference_Invite);
impl<'a> EventConferenceInvite<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_conference_invite_get_friend_number(self.0)
        })
    }

    pub fn conference_type(&self) -> ToxConferenceType {
        unsafe {
            ffi::tox_event_conference_invite_get_type(self.0)
        }.into()
    }

    pub fn cookie(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_conference_invite_get_cookie_length(self.0);
            let ptr = ffi::tox_event_conference_invite_get_cookie(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn cookie_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_conference_invite_get_cookie_length(self.0)
        }
    }
}
pub struct EventConferenceMessage<'a>(pub &'a ffi::Tox_Event_Conference_Message);
impl<'a> EventConferenceMessage<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_message_get_conference_number(self.0)
        })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe {
            ffi::tox_event_conference_message_get_peer_number(self.0)
        })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe {
            ffi::tox_event_conference_message_get_type(self.0)
        }.into()
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_conference_message_get_message_length(self.0);
            let ptr = ffi::tox_event_conference_message_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_conference_message_get_message_length(self.0)
        }
    }
}
pub struct EventConferencePeerListChanged<'a>(pub &'a ffi::Tox_Event_Conference_Peer_List_Changed);
impl<'a> EventConferencePeerListChanged<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_peer_list_changed_get_conference_number(self.0)
        })
    }
}
pub struct EventConferencePeerName<'a>(pub &'a ffi::Tox_Event_Conference_Peer_Name);
impl<'a> EventConferencePeerName<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_peer_name_get_conference_number(self.0)
        })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe {
            ffi::tox_event_conference_peer_name_get_peer_number(self.0)
        })
    }

    pub fn name(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_conference_peer_name_get_name_length(self.0);
            let ptr = ffi::tox_event_conference_peer_name_get_name(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn name_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_conference_peer_name_get_name_length(self.0)
        }
    }
}
pub struct EventConferenceTitle<'a>(pub &'a ffi::Tox_Event_Conference_Title);
impl<'a> EventConferenceTitle<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_title_get_conference_number(self.0)
        })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe {
            ffi::tox_event_conference_title_get_peer_number(self.0)
        })
    }

    pub fn title(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_conference_title_get_title_length(self.0);
            let ptr = ffi::tox_event_conference_title_get_title(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn title_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_conference_title_get_title_length(self.0)
        }
    }
}
pub struct EventDhtNodesResponse<'a>(pub &'a ffi::Tox_Event_Dht_Nodes_Response);
impl<'a> EventDhtNodesResponse<'a> {
    pub fn public_key(&self) -> PublicKey {
        unsafe {
            let ptr = ffi::tox_event_dht_nodes_response_get_public_key(self.0);
            let slice = std::slice::from_raw_parts(ptr, PUBLIC_KEY_SIZE);
            PublicKey(slice.try_into()
                .unwrap())
        }
    }

    pub fn ip(&self) -> &str {
        unsafe {
            let ptr = ffi::tox_event_dht_nodes_response_get_ip(self.0) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn ip_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_dht_nodes_response_get_ip_length(self.0)
        }
    }

    pub fn port(&self) -> u16 {
        unsafe {
            ffi::tox_event_dht_nodes_response_get_port(self.0)
        }
    }
}
pub struct EventFileChunkRequest<'a>(pub &'a ffi::Tox_Event_File_Chunk_Request);
impl<'a> EventFileChunkRequest<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_file_chunk_request_get_friend_number(self.0)
        })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe {
            ffi::tox_event_file_chunk_request_get_file_number(self.0)
        })
    }

    pub fn position(&self) -> u64 {
        unsafe {
            ffi::tox_event_file_chunk_request_get_position(self.0)
        }
    }

    pub fn length(&self) -> usize {
        (unsafe {
            ffi::tox_event_file_chunk_request_get_length(self.0)
        }) as usize
    }
}
pub struct EventFileRecv<'a>(pub &'a ffi::Tox_Event_File_Recv);
impl<'a> EventFileRecv<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_file_recv_get_friend_number(self.0)
        })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe {
            ffi::tox_event_file_recv_get_file_number(self.0)
        })
    }

    pub fn kind(&self) -> u32 {
        unsafe {
            ffi::tox_event_file_recv_get_kind(self.0)
        }
    }

    pub fn file_size(&self) -> u64 {
        unsafe {
            ffi::tox_event_file_recv_get_file_size(self.0)
        }
    }

    pub fn filename(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_file_recv_get_filename_length(self.0);
            let ptr = ffi::tox_event_file_recv_get_filename(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn filename_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_file_recv_get_filename_length(self.0)
        }
    }
}
pub struct EventFileRecvChunk<'a>(pub &'a ffi::Tox_Event_File_Recv_Chunk);
impl<'a> EventFileRecvChunk<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_file_recv_chunk_get_friend_number(self.0)
        })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe {
            ffi::tox_event_file_recv_chunk_get_file_number(self.0)
        })
    }

    pub fn position(&self) -> u64 {
        unsafe {
            ffi::tox_event_file_recv_chunk_get_position(self.0)
        }
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_file_recv_chunk_get_data_length(self.0);
            let ptr = ffi::tox_event_file_recv_chunk_get_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_file_recv_chunk_get_data_length(self.0)
        }
    }
}
pub struct EventFileRecvControl<'a>(pub &'a ffi::Tox_Event_File_Recv_Control);
impl<'a> EventFileRecvControl<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_file_recv_control_get_friend_number(self.0)
        })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe {
            ffi::tox_event_file_recv_control_get_file_number(self.0)
        })
    }

    pub fn control(&self) -> ToxFileControl {
        unsafe {
            ffi::tox_event_file_recv_control_get_control(self.0)
        }.into()
    }
}
pub struct EventFriendConnectionStatus<'a>(pub &'a ffi::Tox_Event_Friend_Connection_Status);
impl<'a> EventFriendConnectionStatus<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_connection_status_get_friend_number(self.0)
        })
    }

    pub fn connection_status(&self) -> ToxConnection {
        unsafe {
            ffi::tox_event_friend_connection_status_get_connection_status(self.0)
        }.into()
    }
}
pub struct EventFriendLosslessPacket<'a>(pub &'a ffi::Tox_Event_Friend_Lossless_Packet);
impl<'a> EventFriendLosslessPacket<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_lossless_packet_get_friend_number(self.0)
        })
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_lossless_packet_get_data_length(self.0);
            let ptr = ffi::tox_event_friend_lossless_packet_get_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_lossless_packet_get_data_length(self.0)
        }
    }
}
pub struct EventFriendLossyPacket<'a>(pub &'a ffi::Tox_Event_Friend_Lossy_Packet);
impl<'a> EventFriendLossyPacket<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_lossy_packet_get_friend_number(self.0)
        })
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_lossy_packet_get_data_length(self.0);
            let ptr = ffi::tox_event_friend_lossy_packet_get_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_lossy_packet_get_data_length(self.0)
        }
    }
}
pub struct EventFriendMessage<'a>(pub &'a ffi::Tox_Event_Friend_Message);
impl<'a> EventFriendMessage<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_message_get_friend_number(self.0)
        })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe {
            ffi::tox_event_friend_message_get_type(self.0)
        }.into()
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_message_get_message_length(self.0);
            let ptr = ffi::tox_event_friend_message_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_message_get_message_length(self.0)
        }
    }
}
pub struct EventFriendName<'a>(pub &'a ffi::Tox_Event_Friend_Name);
impl<'a> EventFriendName<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_name_get_friend_number(self.0)
        })
    }

    pub fn name(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_name_get_name_length(self.0);
            let ptr = ffi::tox_event_friend_name_get_name(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn name_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_name_get_name_length(self.0)
        }
    }
}
pub struct EventFriendReadReceipt<'a>(pub &'a ffi::Tox_Event_Friend_Read_Receipt);
impl<'a> EventFriendReadReceipt<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_read_receipt_get_friend_number(self.0)
        })
    }

    pub fn message_id(&self) -> FriendMessageId {
        FriendMessageId(unsafe {
            ffi::tox_event_friend_read_receipt_get_message_id(self.0)
        })
    }
}
pub struct EventFriendRequest<'a>(pub &'a ffi::Tox_Event_Friend_Request);
impl<'a> EventFriendRequest<'a> {
    pub fn public_key(&self) -> PublicKey {
        unsafe {
            let ptr = ffi::tox_event_friend_request_get_public_key(self.0);
            let slice = std::slice::from_raw_parts(ptr, PUBLIC_KEY_SIZE);
            PublicKey(slice.try_into()
                .unwrap())
        }
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_request_get_message_length(self.0);
            let ptr = ffi::tox_event_friend_request_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_request_get_message_length(self.0)
        }
    }
}
pub struct EventFriendStatus<'a>(pub &'a ffi::Tox_Event_Friend_Status);
impl<'a> EventFriendStatus<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_status_get_friend_number(self.0)
        })
    }

    pub fn status(&self) -> ToxUserStatus {
        unsafe {
            ffi::tox_event_friend_status_get_status(self.0)
        }.into()
    }
}
pub struct EventFriendStatusMessage<'a>(pub &'a ffi::Tox_Event_Friend_Status_Message);
impl<'a> EventFriendStatusMessage<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_status_message_get_friend_number(self.0)
        })
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_friend_status_message_get_message_length(self.0);
            let ptr = ffi::tox_event_friend_status_message_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_friend_status_message_get_message_length(self.0)
        }
    }
}
pub struct EventFriendTyping<'a>(pub &'a ffi::Tox_Event_Friend_Typing);
impl<'a> EventFriendTyping<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_friend_typing_get_friend_number(self.0)
        })
    }

    pub fn typing(&self) -> bool {
        ffi_bool!(tox_event_friend_typing_get_typing, self.0)
    }
}
pub struct EventGroupCustomPacket<'a>(pub &'a ffi::Tox_Event_Group_Custom_Packet);
impl<'a> EventGroupCustomPacket<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_custom_packet_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_custom_packet_get_peer_id(self.0)
        })
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_custom_packet_get_data_length(self.0);
            let ptr = ffi::tox_event_group_custom_packet_get_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_custom_packet_get_data_length(self.0)
        }
    }
}
pub struct EventGroupCustomPrivatePacket<'a>(pub &'a ffi::Tox_Event_Group_Custom_Private_Packet);
impl<'a> EventGroupCustomPrivatePacket<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_custom_private_packet_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_custom_private_packet_get_peer_id(self.0)
        })
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_custom_private_packet_get_data_length(self.0);
            let ptr = ffi::tox_event_group_custom_private_packet_get_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_custom_private_packet_get_data_length(self.0)
        }
    }
}
pub struct EventGroupInvite<'a>(pub &'a ffi::Tox_Event_Group_Invite);
impl<'a> EventGroupInvite<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe {
            ffi::tox_event_group_invite_get_friend_number(self.0)
        })
    }

    pub fn invite_data(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_invite_get_invite_data_length(self.0);
            let ptr = ffi::tox_event_group_invite_get_invite_data(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn invite_data_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_invite_get_invite_data_length(self.0)
        }
    }

    pub fn group_name(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_invite_get_group_name_length(self.0);
            let ptr = ffi::tox_event_group_invite_get_group_name(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn group_name_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_invite_get_group_name_length(self.0)
        }
    }
}
pub struct EventGroupJoinFail<'a>(pub &'a ffi::Tox_Event_Group_Join_Fail);
impl<'a> EventGroupJoinFail<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_join_fail_get_group_number(self.0)
        })
    }

    pub fn fail_type(&self) -> ToxGroupJoinFail {
        unsafe {
            ffi::tox_event_group_join_fail_get_fail_type(self.0)
        }.into()
    }
}
pub struct EventGroupMessage<'a>(pub &'a ffi::Tox_Event_Group_Message);
impl<'a> EventGroupMessage<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_message_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_message_get_peer_id(self.0)
        })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe {
            ffi::tox_event_group_message_get_message_type(self.0)
        }.into()
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_message_get_message_length(self.0);
            let ptr = ffi::tox_event_group_message_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_message_get_message_length(self.0)
        }
    }

    pub fn message_id(&self) -> GroupMessageId {
        GroupMessageId(unsafe {
            ffi::tox_event_group_message_get_message_id(self.0)
        })
    }
}
pub struct EventGroupModeration<'a>(pub &'a ffi::Tox_Event_Group_Moderation);
impl<'a> EventGroupModeration<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_moderation_get_group_number(self.0)
        })
    }

    pub fn source_peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_moderation_get_source_peer_id(self.0)
        })
    }

    pub fn target_peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_moderation_get_target_peer_id(self.0)
        })
    }

    pub fn mod_type(&self) -> ToxGroupModEvent {
        unsafe {
            ffi::tox_event_group_moderation_get_mod_type(self.0)
        }.into()
    }
}
pub struct EventGroupPassword<'a>(pub &'a ffi::Tox_Event_Group_Password);
impl<'a> EventGroupPassword<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_password_get_group_number(self.0)
        })
    }

    pub fn password(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_password_get_password_length(self.0);
            let ptr = ffi::tox_event_group_password_get_password(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn password_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_password_get_password_length(self.0)
        }
    }
}
pub struct EventGroupPeerExit<'a>(pub &'a ffi::Tox_Event_Group_Peer_Exit);
impl<'a> EventGroupPeerExit<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_peer_exit_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_peer_exit_get_peer_id(self.0)
        })
    }

    pub fn exit_type(&self) -> ToxGroupExitType {
        unsafe {
            ffi::tox_event_group_peer_exit_get_exit_type(self.0)
        }.into()
    }

    pub fn name(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_peer_exit_get_name_length(self.0);
            let ptr = ffi::tox_event_group_peer_exit_get_name(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn name_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_peer_exit_get_name_length(self.0)
        }
    }

    pub fn part_message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_peer_exit_get_part_message_length(self.0);
            let ptr = ffi::tox_event_group_peer_exit_get_part_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn part_message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_peer_exit_get_part_message_length(self.0)
        }
    }
}
pub struct EventGroupPeerJoin<'a>(pub &'a ffi::Tox_Event_Group_Peer_Join);
impl<'a> EventGroupPeerJoin<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_peer_join_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_peer_join_get_peer_id(self.0)
        })
    }
}
pub struct EventGroupPeerLimit<'a>(pub &'a ffi::Tox_Event_Group_Peer_Limit);
impl<'a> EventGroupPeerLimit<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_peer_limit_get_group_number(self.0)
        })
    }

    pub fn peer_limit(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_peer_limit_get_peer_limit(self.0)
        }
    }
}
pub struct EventGroupPeerName<'a>(pub &'a ffi::Tox_Event_Group_Peer_Name);
impl<'a> EventGroupPeerName<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_peer_name_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_peer_name_get_peer_id(self.0)
        })
    }

    pub fn name(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_peer_name_get_name_length(self.0);
            let ptr = ffi::tox_event_group_peer_name_get_name(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn name_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_peer_name_get_name_length(self.0)
        }
    }
}
pub struct EventGroupPeerStatus<'a>(pub &'a ffi::Tox_Event_Group_Peer_Status);
impl<'a> EventGroupPeerStatus<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_peer_status_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_peer_status_get_peer_id(self.0)
        })
    }

    pub fn status(&self) -> ToxUserStatus {
        unsafe {
            ffi::tox_event_group_peer_status_get_status(self.0)
        }.into()
    }
}
pub struct EventGroupPrivacyState<'a>(pub &'a ffi::Tox_Event_Group_Privacy_State);
impl<'a> EventGroupPrivacyState<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_privacy_state_get_group_number(self.0)
        })
    }

    pub fn privacy_state(&self) -> ToxGroupPrivacyState {
        unsafe {
            ffi::tox_event_group_privacy_state_get_privacy_state(self.0)
        }.into()
    }
}
pub struct EventGroupPrivateMessage<'a>(pub &'a ffi::Tox_Event_Group_Private_Message);
impl<'a> EventGroupPrivateMessage<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_private_message_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_private_message_get_peer_id(self.0)
        })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe {
            ffi::tox_event_group_private_message_get_message_type(self.0)
        }.into()
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_private_message_get_message_length(self.0);
            let ptr = ffi::tox_event_group_private_message_get_message(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn message_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_private_message_get_message_length(self.0)
        }
    }

    pub fn message_id(&self) -> GroupMessageId {
        GroupMessageId(unsafe {
            ffi::tox_event_group_private_message_get_message_id(self.0)
        })
    }
}
pub struct EventGroupSelfJoin<'a>(pub &'a ffi::Tox_Event_Group_Self_Join);
impl<'a> EventGroupSelfJoin<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_self_join_get_group_number(self.0)
        })
    }
}
pub struct EventGroupTopic<'a>(pub &'a ffi::Tox_Event_Group_Topic);
impl<'a> EventGroupTopic<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_topic_get_group_number(self.0)
        })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe {
            ffi::tox_event_group_topic_get_peer_id(self.0)
        })
    }

    pub fn topic(&self) -> &'a [u8] {
        unsafe {
            let size = ffi::tox_event_group_topic_get_topic_length(self.0);
            let ptr = ffi::tox_event_group_topic_get_topic(self.0);
            if size == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, size as usize)
            }
        }
    }

    pub fn topic_length(&self) -> u32 {
        unsafe {
            ffi::tox_event_group_topic_get_topic_length(self.0)
        }
    }
}
pub struct EventGroupTopicLock<'a>(pub &'a ffi::Tox_Event_Group_Topic_Lock);
impl<'a> EventGroupTopicLock<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_topic_lock_get_group_number(self.0)
        })
    }

    pub fn topic_lock(&self) -> ToxGroupTopicLock {
        unsafe {
            ffi::tox_event_group_topic_lock_get_topic_lock(self.0)
        }.into()
    }
}
pub struct EventGroupVoiceState<'a>(pub &'a ffi::Tox_Event_Group_Voice_State);
impl<'a> EventGroupVoiceState<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe {
            ffi::tox_event_group_voice_state_get_group_number(self.0)
        })
    }

    pub fn voice_state(&self) -> ToxGroupVoiceState {
        unsafe {
            ffi::tox_event_group_voice_state_get_voice_state(self.0)
        }.into()
    }
}
pub struct EventSelfConnectionStatus<'a>(pub &'a ffi::Tox_Event_Self_Connection_Status);
impl<'a> EventSelfConnectionStatus<'a> {
    pub fn connection_status(&self) -> ToxConnection {
        unsafe {
            ffi::tox_event_self_connection_status_get_connection_status(self.0)
        }.into()
    }
}
pub struct ToxEvents<'a> {
    pub(crate) ptr: *mut ffi::Tox_Events,
    _marker: std::marker::PhantomData<&'a ()>

}
impl<'a> Drop for ToxEvents<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::tox_events_free(self.ptr)
        }
    }
}
impl<'a> ToxEvents<'a> {
    pub fn iterate(tox: &Tox, options: &IterateOptions) -> std::result::Result<Self, Tox_Err_Events_Iterate> {
        ffi_call!(tox_events_iterate, ffi::Tox_Err_Events_Iterate::TOX_ERR_EVENTS_ITERATE_OK, tox.ptr, options.ptr).map(|val| Self { ptr: val, _marker: std::marker::PhantomData })
    }

    pub fn dispatch<T>(tox: &Tox, events: &ToxEvents<'a>, user_data: &mut T) {
        unsafe {
            ffi::tox_events_dispatch(tox.ptr, events.ptr, user_data as *mut T as *mut std::ffi::c_void)
        }
    }

    pub fn load(sys: &System, bytes: &[u8], bytes_size: u32) -> Option<Self> {
        unsafe {
            let raw = ffi::tox_events_load(sys.ptr, bytes.as_ptr(), bytes_size);
            if raw.is_null() {
                None
            } else {
                Some(Self { ptr: raw, _marker: std::marker::PhantomData })
            }
        }
    }

    pub fn get_size(&self) -> u32 {
        unsafe {
            ffi::tox_events_get_size(self.ptr)
        }
    }

    fn get(&self, index: u32) -> Option<Event<'a>> {
        unsafe {
            let raw = ffi::tox_events_get(self.ptr, index);
            if raw.is_null() {
                None
            } else {
                Some(Event::from_ptr(raw))
            }
        }
    }

    pub fn bytes_size(&self) -> u32 {
        unsafe {
            ffi::tox_events_bytes_size(self.ptr)
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_events_get_bytes, tox_events_bytes_size, u8, self.ptr)
    }

    pub fn equal(sys: &System, a: &ToxEvents<'a>, b: &ToxEvents<'a>) -> bool {
        ffi_bool!(tox_events_equal, sys.ptr, a.ptr, b.ptr)
    }
}
pub struct ToxEventsIter<'a> {
    parent: &'a ToxEvents<'a>,
    index: u32,
    count: u32,
    _marker: std::marker::PhantomData<&'a ()>

}
impl<'a> Iterator for ToxEventsIter<'a> {
    type Item = Event<'a>;

    fn next(&mut self) -> Option<Event<'a>> {
        if self.index >= self.count {
            return None;
        };
        let item = self.parent.get(self.index);
        self.index += 1;
        item
    }
}
impl<'a> IntoIterator for &'a ToxEvents<'a> {
    type Item = Event<'a>;

    type IntoIter = ToxEventsIter<'a>;

    fn into_iter(self) -> ToxEventsIter<'a> {
        ToxEventsIter { parent: self, index: 0, count: self.get_size(), _marker: std::marker::PhantomData }
    }
}
impl Tox {
    pub fn file_by_id(&self, friend_number: FriendNumber, file_id: Option<&FileId>) -> std::result::Result<FileNumber, Tox_Err_File_By_Id> {
        ffi_call!(tox_file_by_id, ffi::Tox_Err_File_By_Id::TOX_ERR_FILE_BY_ID_OK, self.ptr, friend_number.0, file_id.map_or(std::ptr::null(), |v| v.0.as_ptr())).map(FileNumber)
    }

    pub fn file_send(&self, friend_number: FriendNumber, kind: u32, file_size: u64, file_id: Option<&FileId>, filename: &[u8]) -> std::result::Result<FileNumber, Tox_Err_File_Send> {
        ffi_call!(tox_file_send, ffi::Tox_Err_File_Send::TOX_ERR_FILE_SEND_OK, self.ptr, friend_number.0, kind, file_size, file_id.map_or(std::ptr::null(), |v| v.0.as_ptr()), filename.as_ptr(), filename.len()).map(FileNumber)
    }

    pub fn file_id_length() -> u32 {
        unsafe {
            ffi::tox_file_id_length()
        }
    }

    pub fn file_control_to_string(value: ToxFileControl) -> &'static str {
        unsafe {
            let ptr = ffi::tox_file_control_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }
}
impl Tox {
    pub fn friend_add(&self, address: &Address, message: &[u8]) -> std::result::Result<FriendNumber, Tox_Err_Friend_Add> {
        ffi_call!(tox_friend_add, ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK, self.ptr, address.0.as_ptr(), message.as_ptr(), message.len()).map(FriendNumber)
    }

    pub fn friend_add_norequest(&self, public_key: &PublicKey) -> std::result::Result<FriendNumber, Tox_Err_Friend_Add> {
        ffi_call!(tox_friend_add_norequest, ffi::Tox_Err_Friend_Add::TOX_ERR_FRIEND_ADD_OK, self.ptr, public_key.0.as_ptr()).map(FriendNumber)
    }

    pub fn friend_by_public_key(&self, public_key: &PublicKey) -> std::result::Result<FriendNumber, Tox_Err_Friend_By_Public_Key> {
        ffi_call!(tox_friend_by_public_key, ffi::Tox_Err_Friend_By_Public_Key::TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK, self.ptr, public_key.0.as_ptr()).map(FriendNumber)
    }

    pub fn friend_delete(&self, friend_number: FriendNumber) -> std::result::Result<(), Tox_Err_Friend_Delete> {
        ffi_call_unit!(tox_friend_delete, ffi::Tox_Err_Friend_Delete::TOX_ERR_FRIEND_DELETE_OK, self.ptr, friend_number.0)
    }

    pub fn friend_exists(&self, friend_number: FriendNumber) -> bool {
        ffi_bool!(tox_friend_exists, self.ptr, friend_number.0)
    }

    pub fn friend_get_public_key(&self, friend_number: FriendNumber) -> std::result::Result<PublicKey, Tox_Err_Friend_Get_Public_Key> {
        ffi_get_array!(tox_friend_get_public_key, ffi::Tox_Err_Friend_Get_Public_Key::TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK, PUBLIC_KEY_SIZE, self.ptr, friend_number.0).map(PublicKey)
    }

    pub fn friend_get_last_online(&self, friend_number: FriendNumber) -> std::result::Result<u64, Tox_Err_Friend_Get_Last_Online> {
        ffi_call!(tox_friend_get_last_online, ffi::Tox_Err_Friend_Get_Last_Online::TOX_ERR_FRIEND_GET_LAST_ONLINE_OK, self.ptr, friend_number.0)
    }

    pub fn friend_get_name_size(&self, friend_number: FriendNumber) -> std::result::Result<usize, Tox_Err_Friend_Query> {
        ffi_call!(tox_friend_get_name_size, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0)
    }

    pub fn friend_get_name(&self, friend_number: FriendNumber) -> std::result::Result<Vec<u8>, Tox_Err_Friend_Query> {
        ffi_get_vec!(tox_friend_get_name, tox_friend_get_name_size, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0)
    }

    pub fn friend_get_status_message_size(&self, friend_number: FriendNumber) -> std::result::Result<usize, Tox_Err_Friend_Query> {
        ffi_call!(tox_friend_get_status_message_size, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0)
    }

    pub fn friend_get_status_message(&self, friend_number: FriendNumber) -> std::result::Result<Vec<u8>, Tox_Err_Friend_Query> {
        ffi_get_vec!(tox_friend_get_status_message, tox_friend_get_status_message_size, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0)
    }

    pub fn friend_get_status(&self, friend_number: FriendNumber) -> std::result::Result<ToxUserStatus, Tox_Err_Friend_Query> {
        ffi_call!(tox_friend_get_status, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0).map(Into::into)
    }

    pub fn friend_get_connection_status(&self, friend_number: FriendNumber) -> std::result::Result<ToxConnection, Tox_Err_Friend_Query> {
        ffi_call!(tox_friend_get_connection_status, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0).map(Into::into)
    }

    pub fn friend_get_typing(&self, friend_number: FriendNumber) -> std::result::Result<bool, Tox_Err_Friend_Query> {
        ffi_call!(tox_friend_get_typing, ffi::Tox_Err_Friend_Query::TOX_ERR_FRIEND_QUERY_OK, self.ptr, friend_number.0)
    }

    pub fn friend_send_message(&self, friend_number: FriendNumber, type_: MessageType, message: &[u8]) -> std::result::Result<FriendMessageId, Tox_Err_Friend_Send_Message> {
        ffi_call!(tox_friend_send_message, ffi::Tox_Err_Friend_Send_Message::TOX_ERR_FRIEND_SEND_MESSAGE_OK, self.ptr, friend_number.0, type_.into(), message.as_ptr(), message.len()).map(FriendMessageId)
    }

    pub fn friend_send_lossy_packet(&self, friend_number: FriendNumber, data: &[u8]) -> std::result::Result<(), Tox_Err_Friend_Custom_Packet> {
        ffi_call_unit!(tox_friend_send_lossy_packet, ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK, self.ptr, friend_number.0, data.as_ptr(), data.len())
    }

    pub fn friend_send_lossless_packet(&self, friend_number: FriendNumber, data: &[u8]) -> std::result::Result<(), Tox_Err_Friend_Custom_Packet> {
        ffi_call_unit!(tox_friend_send_lossless_packet, ffi::Tox_Err_Friend_Custom_Packet::TOX_ERR_FRIEND_CUSTOM_PACKET_OK, self.ptr, friend_number.0, data.as_ptr(), data.len())
    }
}
pub struct FriendMessageNumber(pub u32);
impl Tox {
    pub fn group_new(&self, privacy_state: ToxGroupPrivacyState, group_name: &[u8], name: &[u8]) -> std::result::Result<GroupNumber, Tox_Err_Group_New> {
        ffi_call!(tox_group_new, ffi::Tox_Err_Group_New::TOX_ERR_GROUP_NEW_OK, self.ptr, privacy_state.into(), group_name.as_ptr(), group_name.len(), name.as_ptr(), name.len()).map(GroupNumber)
    }

    pub fn group_join(&self, chat_id: &GroupChatId, name: &[u8], password: &[u8]) -> std::result::Result<GroupNumber, Tox_Err_Group_Join> {
        ffi_call!(tox_group_join, ffi::Tox_Err_Group_Join::TOX_ERR_GROUP_JOIN_OK, self.ptr, chat_id.0.as_ptr(), name.as_ptr(), name.len(), password.as_ptr(), password.len()).map(GroupNumber)
    }

    pub fn group_by_id(&self, chat_id: &GroupChatId) -> std::result::Result<GroupNumber, Tox_Err_Group_By_Id> {
        ffi_call!(tox_group_by_id, ffi::Tox_Err_Group_By_Id::TOX_ERR_GROUP_BY_ID_OK, self.ptr, chat_id.0.as_ptr()).map(GroupNumber)
    }

    pub fn group_invite_accept(&self, friend_number: FriendNumber, invite_data: &[u8], name: &[u8], password: &[u8]) -> std::result::Result<GroupNumber, Tox_Err_Group_Invite_Accept> {
        ffi_call!(tox_group_invite_accept, ffi::Tox_Err_Group_Invite_Accept::TOX_ERR_GROUP_INVITE_ACCEPT_OK, self.ptr, friend_number.0, invite_data.as_ptr(), invite_data.len(), name.as_ptr(), name.len(), password.as_ptr(), password.len()).map(GroupNumber)
    }

    pub fn group_is_connected(&self, group_number: GroupNumber) -> std::result::Result<bool, Tox_Err_Group_Is_Connected> {
        ffi_call!(tox_group_is_connected, ffi::Tox_Err_Group_Is_Connected::TOX_ERR_GROUP_IS_CONNECTED_OK, self.ptr, group_number.0)
    }

    pub fn group_disconnect(&self, group_number: GroupNumber) -> std::result::Result<(), Tox_Err_Group_Disconnect> {
        ffi_call_unit!(tox_group_disconnect, ffi::Tox_Err_Group_Disconnect::TOX_ERR_GROUP_DISCONNECT_OK, self.ptr, group_number.0)
    }

    pub fn group_leave(&self, group_number: GroupNumber, part_message: &[u8]) -> std::result::Result<(), Tox_Err_Group_Leave> {
        ffi_call_unit!(tox_group_leave, ffi::Tox_Err_Group_Leave::TOX_ERR_GROUP_LEAVE_OK, self.ptr, group_number.0, part_message.as_ptr(), part_message.len())
    }

    pub fn group_self_set_name(&self, group_number: GroupNumber, name: &[u8]) -> std::result::Result<(), Tox_Err_Group_Self_Name_Set> {
        ffi_call_unit!(tox_group_self_set_name, ffi::Tox_Err_Group_Self_Name_Set::TOX_ERR_GROUP_SELF_NAME_SET_OK, self.ptr, group_number.0, name.as_ptr(), name.len())
    }

    pub fn group_self_get_name_size(&self, group_number: GroupNumber) -> std::result::Result<usize, Tox_Err_Group_Self_Query> {
        ffi_call!(tox_group_self_get_name_size, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_self_get_name(&self, group_number: GroupNumber) -> std::result::Result<Vec<u8>, Tox_Err_Group_Self_Query> {
        ffi_get_vec!(tox_group_self_get_name, tox_group_self_get_name_size, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_self_set_status(&self, group_number: GroupNumber, status: ToxUserStatus) -> std::result::Result<(), Tox_Err_Group_Self_Status_Set> {
        ffi_call_unit!(tox_group_self_set_status, ffi::Tox_Err_Group_Self_Status_Set::TOX_ERR_GROUP_SELF_STATUS_SET_OK, self.ptr, group_number.0, status.into())
    }

    pub fn group_self_get_status(&self, group_number: GroupNumber) -> std::result::Result<ToxUserStatus, Tox_Err_Group_Self_Query> {
        ffi_call!(tox_group_self_get_status, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, self.ptr, group_number.0).map(Into::into)
    }

    pub fn group_self_get_role(&self, group_number: GroupNumber) -> std::result::Result<ToxGroupRole, Tox_Err_Group_Self_Query> {
        ffi_call!(tox_group_self_get_role, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, self.ptr, group_number.0).map(Into::into)
    }

    pub fn group_self_get_peer_id(&self, group_number: GroupNumber) -> std::result::Result<GroupPeerNumber, Tox_Err_Group_Self_Query> {
        ffi_call!(tox_group_self_get_peer_id, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, self.ptr, group_number.0).map(GroupPeerNumber)
    }

    pub fn group_self_get_public_key(&self, group_number: GroupNumber) -> std::result::Result<PublicKey, Tox_Err_Group_Self_Query> {
        ffi_get_array!(tox_group_self_get_public_key, ffi::Tox_Err_Group_Self_Query::TOX_ERR_GROUP_SELF_QUERY_OK, PUBLIC_KEY_SIZE, self.ptr, group_number.0).map(PublicKey)
    }

    pub fn group_set_topic(&self, group_number: GroupNumber, topic: &[u8]) -> std::result::Result<(), Tox_Err_Group_Topic_Set> {
        ffi_call_unit!(tox_group_set_topic, ffi::Tox_Err_Group_Topic_Set::TOX_ERR_GROUP_TOPIC_SET_OK, self.ptr, group_number.0, topic.as_ptr(), topic.len())
    }

    pub fn group_get_topic_size(&self, group_number: GroupNumber) -> std::result::Result<usize, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_topic_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_topic(&self, group_number: GroupNumber) -> std::result::Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(tox_group_get_topic, tox_group_get_topic_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_name_size(&self, group_number: GroupNumber) -> std::result::Result<usize, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_name_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_name(&self, group_number: GroupNumber) -> std::result::Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(tox_group_get_name, tox_group_get_name_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_chat_id(&self, group_number: GroupNumber) -> std::result::Result<GroupChatId, Tox_Err_Group_State_Query> {
        ffi_get_array!(tox_group_get_chat_id, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, GROUP_CHAT_ID_SIZE, self.ptr, group_number.0).map(GroupChatId)
    }

    pub fn group_get_privacy_state(&self, group_number: GroupNumber) -> std::result::Result<ToxGroupPrivacyState, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_privacy_state, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0).map(Into::into)
    }

    pub fn group_get_voice_state(&self, group_number: GroupNumber) -> std::result::Result<ToxGroupVoiceState, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_voice_state, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0).map(Into::into)
    }

    pub fn group_get_topic_lock(&self, group_number: GroupNumber) -> std::result::Result<ToxGroupTopicLock, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_topic_lock, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0).map(Into::into)
    }

    pub fn group_get_peer_limit(&self, group_number: GroupNumber) -> std::result::Result<u16, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_peer_limit, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_password_size(&self, group_number: GroupNumber) -> std::result::Result<usize, Tox_Err_Group_State_Query> {
        ffi_call!(tox_group_get_password_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_get_password(&self, group_number: GroupNumber) -> std::result::Result<Vec<u8>, Tox_Err_Group_State_Query> {
        ffi_get_vec!(tox_group_get_password, tox_group_get_password_size, ffi::Tox_Err_Group_State_Query::TOX_ERR_GROUP_STATE_QUERY_OK, self.ptr, group_number.0)
    }

    pub fn group_send_message(&self, group_number: GroupNumber, message_type: MessageType, message: &[u8]) -> std::result::Result<GroupMessageId, Tox_Err_Group_Send_Message> {
        ffi_call!(tox_group_send_message, ffi::Tox_Err_Group_Send_Message::TOX_ERR_GROUP_SEND_MESSAGE_OK, self.ptr, group_number.0, message_type.into(), message.as_ptr(), message.len()).map(GroupMessageId)
    }

    pub fn group_send_private_message(&self, group_number: GroupNumber, peer_id: GroupPeerNumber, message_type: MessageType, message: &[u8]) -> std::result::Result<GroupMessageId, Tox_Err_Group_Send_Private_Message> {
        ffi_call!(tox_group_send_private_message, ffi::Tox_Err_Group_Send_Private_Message::TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK, self.ptr, group_number.0, peer_id.0, message_type.into(), message.as_ptr(), message.len()).map(GroupMessageId)
    }

    pub fn group_send_custom_packet(&self, group_number: GroupNumber, lossless: bool, data: &[u8]) -> std::result::Result<(), Tox_Err_Group_Send_Custom_Packet> {
        ffi_call_unit!(tox_group_send_custom_packet, ffi::Tox_Err_Group_Send_Custom_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, self.ptr, group_number.0, lossless, data.as_ptr(), data.len())
    }

    pub fn group_send_custom_private_packet(&self, group_number: GroupNumber, peer_id: GroupPeerNumber, lossless: bool, data: &[u8]) -> std::result::Result<(), Tox_Err_Group_Send_Custom_Private_Packet> {
        ffi_call_unit!(tox_group_send_custom_private_packet, ffi::Tox_Err_Group_Send_Custom_Private_Packet::TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK, self.ptr, group_number.0, peer_id.0, lossless, data.as_ptr(), data.len())
    }

    pub fn group_invite_friend(&self, group_number: GroupNumber, friend_number: FriendNumber) -> std::result::Result<(), Tox_Err_Group_Invite_Friend> {
        ffi_call_unit!(tox_group_invite_friend, ffi::Tox_Err_Group_Invite_Friend::TOX_ERR_GROUP_INVITE_FRIEND_OK, self.ptr, group_number.0, friend_number.0)
    }

    pub fn group_set_password(&self, group_number: GroupNumber, password: &[u8]) -> std::result::Result<(), Tox_Err_Group_Set_Password> {
        ffi_call_unit!(tox_group_set_password, ffi::Tox_Err_Group_Set_Password::TOX_ERR_GROUP_SET_PASSWORD_OK, self.ptr, group_number.0, password.as_ptr(), password.len())
    }

    pub fn group_set_topic_lock(&self, group_number: GroupNumber, topic_lock: ToxGroupTopicLock) -> std::result::Result<(), Tox_Err_Group_Set_Topic_Lock> {
        ffi_call_unit!(tox_group_set_topic_lock, ffi::Tox_Err_Group_Set_Topic_Lock::TOX_ERR_GROUP_SET_TOPIC_LOCK_OK, self.ptr, group_number.0, topic_lock.into())
    }

    pub fn group_set_voice_state(&self, group_number: GroupNumber, voice_state: ToxGroupVoiceState) -> std::result::Result<(), Tox_Err_Group_Set_Voice_State> {
        ffi_call_unit!(tox_group_set_voice_state, ffi::Tox_Err_Group_Set_Voice_State::TOX_ERR_GROUP_SET_VOICE_STATE_OK, self.ptr, group_number.0, voice_state.into())
    }

    pub fn group_set_privacy_state(&self, group_number: GroupNumber, privacy_state: ToxGroupPrivacyState) -> std::result::Result<(), Tox_Err_Group_Set_Privacy_State> {
        ffi_call_unit!(tox_group_set_privacy_state, ffi::Tox_Err_Group_Set_Privacy_State::TOX_ERR_GROUP_SET_PRIVACY_STATE_OK, self.ptr, group_number.0, privacy_state.into())
    }

    pub fn group_set_peer_limit(&self, group_number: GroupNumber, peer_limit: u16) -> std::result::Result<(), Tox_Err_Group_Set_Peer_Limit> {
        ffi_call_unit!(tox_group_set_peer_limit, ffi::Tox_Err_Group_Set_Peer_Limit::TOX_ERR_GROUP_SET_PEER_LIMIT_OK, self.ptr, group_number.0, peer_limit)
    }

    pub fn group_set_ignore(&self, group_number: GroupNumber, peer_id: GroupPeerNumber, ignore: bool) -> std::result::Result<(), Tox_Err_Group_Set_Ignore> {
        ffi_call_unit!(tox_group_set_ignore, ffi::Tox_Err_Group_Set_Ignore::TOX_ERR_GROUP_SET_IGNORE_OK, self.ptr, group_number.0, peer_id.0, ignore)
    }

    pub fn group_set_role(&self, group_number: GroupNumber, peer_id: GroupPeerNumber, role: ToxGroupRole) -> std::result::Result<(), Tox_Err_Group_Set_Role> {
        ffi_call_unit!(tox_group_set_role, ffi::Tox_Err_Group_Set_Role::TOX_ERR_GROUP_SET_ROLE_OK, self.ptr, group_number.0, peer_id.0, role.into())
    }

    pub fn group_kick_peer(&self, group_number: GroupNumber, peer_id: GroupPeerNumber) -> std::result::Result<(), Tox_Err_Group_Kick_Peer> {
        ffi_call_unit!(tox_group_kick_peer, ffi::Tox_Err_Group_Kick_Peer::TOX_ERR_GROUP_KICK_PEER_OK, self.ptr, group_number.0, peer_id.0)
    }

    pub fn group_max_topic_length() -> u32 {
        unsafe {
            ffi::tox_group_max_topic_length()
        }
    }

    pub fn group_max_part_length() -> u32 {
        unsafe {
            ffi::tox_group_max_part_length()
        }
    }

    pub fn group_max_message_length() -> u32 {
        unsafe {
            ffi::tox_group_max_message_length()
        }
    }

    pub fn group_max_custom_lossy_packet_length() -> u32 {
        unsafe {
            ffi::tox_group_max_custom_lossy_packet_length()
        }
    }

    pub fn group_max_custom_lossless_packet_length() -> u32 {
        unsafe {
            ffi::tox_group_max_custom_lossless_packet_length()
        }
    }

    pub fn group_max_group_name_length() -> u32 {
        unsafe {
            ffi::tox_group_max_group_name_length()
        }
    }

    pub fn group_max_password_size() -> u32 {
        unsafe {
            ffi::tox_group_max_password_size()
        }
    }

    pub fn group_chat_id_size() -> u32 {
        unsafe {
            ffi::tox_group_chat_id_size()
        }
    }

    pub fn group_privacy_state_to_string(value: ToxGroupPrivacyState) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_privacy_state_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_topic_lock_to_string(value: ToxGroupTopicLock) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_topic_lock_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_voice_state_to_string(value: ToxGroupVoiceState) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_voice_state_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_role_to_string(value: ToxGroupRole) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_role_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_exit_type_to_string(value: ToxGroupExitType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_exit_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_join_fail_to_string(value: ToxGroupJoinFail) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_join_fail_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn group_mod_event_to_string(value: ToxGroupModEvent) -> &'static str {
        unsafe {
            let ptr = ffi::tox_group_mod_event_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }
}
pub struct GroupMessageNumber(pub u32);
impl Tox {
    pub fn group_peer_get_name_size(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<usize, Tox_Err_Group_Peer_Query> {
        ffi_call!(tox_group_peer_get_name_size, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, self.ptr, group_number.0, group_peer_number.0)
    }

    pub fn group_peer_get_name(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<Vec<u8>, Tox_Err_Group_Peer_Query> {
        ffi_get_vec!(tox_group_peer_get_name, tox_group_peer_get_name_size, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, self.ptr, group_number.0, group_peer_number.0)
    }

    pub fn group_peer_get_status(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<ToxUserStatus, Tox_Err_Group_Peer_Query> {
        ffi_call!(tox_group_peer_get_status, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, self.ptr, group_number.0, group_peer_number.0).map(Into::into)
    }

    pub fn group_peer_get_role(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<ToxGroupRole, Tox_Err_Group_Peer_Query> {
        ffi_call!(tox_group_peer_get_role, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, self.ptr, group_number.0, group_peer_number.0).map(Into::into)
    }

    pub fn group_peer_get_connection_status(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<ToxConnection, Tox_Err_Group_Peer_Query> {
        ffi_call!(tox_group_peer_get_connection_status, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, self.ptr, group_number.0, group_peer_number.0).map(Into::into)
    }

    pub fn group_peer_get_public_key(&self, group_number: GroupNumber, group_peer_number: GroupPeerNumber) -> std::result::Result<PublicKey, Tox_Err_Group_Peer_Query> {
        ffi_get_array!(tox_group_peer_get_public_key, ffi::Tox_Err_Group_Peer_Query::TOX_ERR_GROUP_PEER_QUERY_OK, PUBLIC_KEY_SIZE, self.ptr, group_number.0, group_peer_number.0).map(PublicKey)
    }

    pub fn group_peer_public_key_size() -> u32 {
        unsafe {
            ffi::tox_group_peer_public_key_size()
        }
    }
}
impl Tox {
    pub fn conference_invite(&self, friend_number: FriendNumber, conference_number: ConferenceNumber) -> std::result::Result<(), Tox_Err_Conference_Invite> {
        ffi_call_unit!(tox_conference_invite, ffi::Tox_Err_Conference_Invite::TOX_ERR_CONFERENCE_INVITE_OK, self.ptr, friend_number.0, conference_number.0)
    }

    pub fn conference_get_chatlist_size(&self) -> usize {
        unsafe {
            ffi::tox_conference_get_chatlist_size(self.ptr)
        }
    }

    pub fn conference_get_chatlist(&self) -> Vec<ConferenceNumber> {
        ffi_get_vec_simple!(tox_conference_get_chatlist, tox_conference_get_chatlist_size, u32, self.ptr).into_iter()
            .map(ConferenceNumber)
            .collect()
    }
}
impl Tox {
    pub fn events_init(&self) {
        unsafe {
            ffi::tox_events_init(self.ptr)
        }
    }
}
impl Tox {
    pub fn file_control(&self, friend_number: FriendNumber, file_number: FileNumber, control: ToxFileControl) -> std::result::Result<(), Tox_Err_File_Control> {
        ffi_call_unit!(tox_file_control, ffi::Tox_Err_File_Control::TOX_ERR_FILE_CONTROL_OK, self.ptr, friend_number.0, file_number.0, control.into())
    }

    pub fn file_seek(&self, friend_number: FriendNumber, file_number: FileNumber, position: u64) -> std::result::Result<(), Tox_Err_File_Seek> {
        ffi_call_unit!(tox_file_seek, ffi::Tox_Err_File_Seek::TOX_ERR_FILE_SEEK_OK, self.ptr, friend_number.0, file_number.0, position)
    }

    pub fn file_get_file_id(&self, friend_number: FriendNumber, file_number: FileNumber) -> std::result::Result<FileId, Tox_Err_File_Get> {
        ffi_get_array!(tox_file_get_file_id, ffi::Tox_Err_File_Get::TOX_ERR_FILE_GET_OK, FILE_ID_LENGTH, self.ptr, friend_number.0, file_number.0).map(FileId)
    }

    pub fn file_send_chunk(&self, friend_number: FriendNumber, file_number: FileNumber, position: u64, data: &[u8]) -> std::result::Result<(), Tox_Err_File_Send_Chunk> {
        ffi_call_unit!(tox_file_send_chunk, ffi::Tox_Err_File_Send_Chunk::TOX_ERR_FILE_SEND_CHUNK_OK, self.ptr, friend_number.0, file_number.0, position, data.as_ptr(), data.len())
    }
}
impl Tox {
    pub fn group_get_group_list_size(&self) -> u32 {
        unsafe {
            ffi::tox_group_get_group_list_size(self.ptr)
        }
    }

    pub fn group_get_group_list(&self) -> Vec<GroupNumber> {
        ffi_get_vec_simple!(tox_group_get_group_list, tox_group_get_group_list_size, u32, self.ptr).into_iter()
            .map(GroupNumber)
            .collect()
    }
}
pub struct Tox {
    pub(crate) ptr: *mut ffi::Tox

}
impl Drop for Tox {
    fn drop(&mut self) {
        unsafe {
            ffi::tox_kill(self.ptr)
        }
    }
}
impl Tox {
    pub fn new(options: &Options) -> std::result::Result<Self, Tox_Err_New> {
        ffi_call!(tox_new, ffi::Tox_Err_New::TOX_ERR_NEW_OK, options.ptr).map(|val| Self { ptr: val })
    }

    pub fn get_savedata_size(&self) -> usize {
        unsafe {
            ffi::tox_get_savedata_size(self.ptr)
        }
    }

    pub fn get_savedata(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_get_savedata, tox_get_savedata_size, u8, self.ptr)
    }

    pub fn bootstrap(&self, host: &str, port: u16, public_key: &DhtId) -> std::result::Result<(), Tox_Err_Bootstrap> {
        let host_cstr = std::ffi::CString::new(host).unwrap();
        ffi_call_unit!(tox_bootstrap, ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK, self.ptr, host_cstr.as_ptr(), port, public_key.0.as_ptr())
    }

    pub fn add_tcp_relay(&self, host: &str, port: u16, public_key: &DhtId) -> std::result::Result<(), Tox_Err_Bootstrap> {
        let host_cstr = std::ffi::CString::new(host).unwrap();
        ffi_call_unit!(tox_add_tcp_relay, ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK, self.ptr, host_cstr.as_ptr(), port, public_key.0.as_ptr())
    }

    pub fn self_get_connection_status(&self) -> ToxConnection {
        unsafe {
            ffi::tox_self_get_connection_status(self.ptr)
        }.into()
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe {
            ffi::tox_iteration_interval(self.ptr)
        }
    }

    pub fn iterate<T>(&self, user_data: &mut T) {
        unsafe {
            ffi::tox_iterate(self.ptr, user_data as *mut T as *mut std::ffi::c_void)
        }
    }

    pub fn self_get_address(&self) -> Address {
        unsafe {
            let mut buf = [0; ADDRESS_SIZE];
            ffi::tox_self_get_address(self.ptr, buf.as_mut_ptr());
            Address(buf)
        }
    }

    pub fn self_set_nospam(&self, nospam: u32) {
        unsafe {
            ffi::tox_self_set_nospam(self.ptr, nospam)
        }
    }

    pub fn self_get_nospam(&self) -> u32 {
        unsafe {
            ffi::tox_self_get_nospam(self.ptr)
        }
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

    pub fn self_set_name(&self, name: &[u8]) -> std::result::Result<(), Tox_Err_Set_Info> {
        ffi_call_unit!(tox_self_set_name, ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK, self.ptr, name.as_ptr(), name.len())
    }

    pub fn self_get_name_size(&self) -> usize {
        unsafe {
            ffi::tox_self_get_name_size(self.ptr)
        }
    }

    pub fn self_get_name(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_self_get_name, tox_self_get_name_size, u8, self.ptr)
    }

    pub fn self_set_status_message(&self, status_message: &[u8]) -> std::result::Result<(), Tox_Err_Set_Info> {
        ffi_call_unit!(tox_self_set_status_message, ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK, self.ptr, status_message.as_ptr(), status_message.len())
    }

    pub fn self_get_status_message_size(&self) -> usize {
        unsafe {
            ffi::tox_self_get_status_message_size(self.ptr)
        }
    }

    pub fn self_get_status_message(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_self_get_status_message, tox_self_get_status_message_size, u8, self.ptr)
    }

    pub fn self_set_status(&self, status: ToxUserStatus) {
        unsafe {
            ffi::tox_self_set_status(self.ptr, status.into())
        }
    }

    pub fn self_get_status(&self) -> ToxUserStatus {
        unsafe {
            ffi::tox_self_get_status(self.ptr)
        }.into()
    }

    pub fn self_get_friend_list_size(&self) -> usize {
        unsafe {
            ffi::tox_self_get_friend_list_size(self.ptr)
        }
    }

    pub fn self_get_friend_list(&self) -> Vec<FriendNumber> {
        ffi_get_vec_simple!(tox_self_get_friend_list, tox_self_get_friend_list_size, u32, self.ptr).into_iter()
            .map(FriendNumber)
            .collect()
    }

    pub fn self_set_typing(&self, friend_number: FriendNumber, typing: bool) -> std::result::Result<(), Tox_Err_Set_Typing> {
        ffi_call_unit!(tox_self_set_typing, ffi::Tox_Err_Set_Typing::TOX_ERR_SET_TYPING_OK, self.ptr, friend_number.0, typing)
    }

    pub fn self_get_dht_id(&self) -> DhtId {
        unsafe {
            let mut buf = [0; DHT_ID_SIZE];
            ffi::tox_self_get_dht_id(self.ptr, buf.as_mut_ptr());
            DhtId(buf)
        }
    }

    pub fn self_get_udp_port(&self) -> std::result::Result<u16, Tox_Err_Get_Port> {
        ffi_call!(tox_self_get_udp_port, ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK, self.ptr)
    }

    pub fn self_get_tcp_port(&self) -> std::result::Result<u16, Tox_Err_Get_Port> {
        ffi_call!(tox_self_get_tcp_port, ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK, self.ptr)
    }

    pub fn version_major() -> u32 {
        unsafe {
            ffi::tox_version_major()
        }
    }

    pub fn version_minor() -> u32 {
        unsafe {
            ffi::tox_version_minor()
        }
    }

    pub fn version_patch() -> u32 {
        unsafe {
            ffi::tox_version_patch()
        }
    }

    pub fn version_is_compatible(major: u32, minor: u32, patch: u32) -> bool {
        ffi_bool!(tox_version_is_compatible, major, minor, patch)
    }

    pub fn public_key_size() -> u32 {
        unsafe {
            ffi::tox_public_key_size()
        }
    }

    pub fn secret_key_size() -> u32 {
        unsafe {
            ffi::tox_secret_key_size()
        }
    }

    pub fn dht_id_size() -> u32 {
        unsafe {
            ffi::tox_dht_id_size()
        }
    }

    pub fn nospam_size() -> u32 {
        unsafe {
            ffi::tox_nospam_size()
        }
    }

    pub fn address_size() -> u32 {
        unsafe {
            ffi::tox_address_size()
        }
    }

    pub fn max_name_length() -> u32 {
        unsafe {
            ffi::tox_max_name_length()
        }
    }

    pub fn max_status_message_length() -> u32 {
        unsafe {
            ffi::tox_max_status_message_length()
        }
    }

    pub fn max_friend_request_length() -> u32 {
        unsafe {
            ffi::tox_max_friend_request_length()
        }
    }

    pub fn max_message_length() -> u32 {
        unsafe {
            ffi::tox_max_message_length()
        }
    }

    pub fn max_custom_packet_size() -> u32 {
        unsafe {
            ffi::tox_max_custom_packet_size()
        }
    }

    pub fn hash_length() -> u32 {
        unsafe {
            ffi::tox_hash_length()
        }
    }

    pub fn max_filename_length() -> u32 {
        unsafe {
            ffi::tox_max_filename_length()
        }
    }

    pub fn max_hostname_length() -> u32 {
        unsafe {
            ffi::tox_max_hostname_length()
        }
    }

    pub fn user_status_to_string(value: ToxUserStatus) -> &'static str {
        unsafe {
            let ptr = ffi::tox_user_status_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn message_type_to_string(value: MessageType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_message_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_new_to_string(value: ffi::Tox_Err_New) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_new_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_bootstrap_to_string(value: ffi::Tox_Err_Bootstrap) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_bootstrap_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn connection_to_string(value: ToxConnection) -> &'static str {
        unsafe {
            let ptr = ffi::tox_connection_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_set_info_to_string(value: ffi::Tox_Err_Set_Info) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_set_info_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_add_to_string(value: ffi::Tox_Err_Friend_Add) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_add_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_delete_to_string(value: ffi::Tox_Err_Friend_Delete) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_delete_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_by_public_key_to_string(value: ffi::Tox_Err_Friend_By_Public_Key) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_by_public_key_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_get_public_key_to_string(value: ffi::Tox_Err_Friend_Get_Public_Key) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_get_public_key_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_get_last_online_to_string(value: ffi::Tox_Err_Friend_Get_Last_Online) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_get_last_online_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_query_to_string(value: ffi::Tox_Err_Friend_Query) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_query_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_set_typing_to_string(value: ffi::Tox_Err_Set_Typing) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_set_typing_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_send_message_to_string(value: ffi::Tox_Err_Friend_Send_Message) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_send_message_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn hash(data: &[u8]) -> Hash {
        unsafe {
            let mut buf = [0; HASH_LENGTH];
            ffi::tox_hash(buf.as_mut_ptr(), data.as_ptr(), data.len());
            Hash(buf)
        }
    }

    pub fn err_file_control_to_string(value: ffi::Tox_Err_File_Control) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_control_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_file_seek_to_string(value: ffi::Tox_Err_File_Seek) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_seek_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_file_get_to_string(value: ffi::Tox_Err_File_Get) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_get_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_file_by_id_to_string(value: ffi::Tox_Err_File_By_Id) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_by_id_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_file_send_to_string(value: ffi::Tox_Err_File_Send) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_send_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_file_send_chunk_to_string(value: ffi::Tox_Err_File_Send_Chunk) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_file_send_chunk_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_new_to_string(value: ffi::Tox_Err_Conference_New) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_new_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_delete_to_string(value: ffi::Tox_Err_Conference_Delete) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_delete_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_peer_query_to_string(value: ffi::Tox_Err_Conference_Peer_Query) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_peer_query_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_set_max_offline_to_string(value: ffi::Tox_Err_Conference_Set_Max_Offline) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_set_max_offline_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_invite_to_string(value: ffi::Tox_Err_Conference_Invite) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_invite_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_join_to_string(value: ffi::Tox_Err_Conference_Join) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_join_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_send_message_to_string(value: ffi::Tox_Err_Conference_Send_Message) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_send_message_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_title_to_string(value: ffi::Tox_Err_Conference_Title) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_title_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_get_type_to_string(value: ffi::Tox_Err_Conference_Get_Type) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_get_type_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_by_id_to_string(value: ffi::Tox_Err_Conference_By_Id) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_by_id_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_conference_by_uid_to_string(value: ffi::Tox_Err_Conference_By_Uid) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_conference_by_uid_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_friend_custom_packet_to_string(value: ffi::Tox_Err_Friend_Custom_Packet) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_friend_custom_packet_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_get_port_to_string(value: ffi::Tox_Err_Get_Port) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_get_port_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_new_to_string(value: ffi::Tox_Err_Group_New) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_new_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_join_to_string(value: ffi::Tox_Err_Group_Join) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_join_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_is_connected_to_string(value: ffi::Tox_Err_Group_Is_Connected) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_is_connected_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_disconnect_to_string(value: ffi::Tox_Err_Group_Disconnect) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_disconnect_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_reconnect_to_string(value: ffi::Tox_Err_Group_Reconnect) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_reconnect_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_leave_to_string(value: ffi::Tox_Err_Group_Leave) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_leave_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_self_query_to_string(value: ffi::Tox_Err_Group_Self_Query) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_query_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_self_name_set_to_string(value: ffi::Tox_Err_Group_Self_Name_Set) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_name_set_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_self_status_set_to_string(value: ffi::Tox_Err_Group_Self_Status_Set) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_self_status_set_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_peer_query_to_string(value: ffi::Tox_Err_Group_Peer_Query) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_peer_query_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_state_query_to_string(value: ffi::Tox_Err_Group_State_Query) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_state_query_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_topic_set_to_string(value: ffi::Tox_Err_Group_Topic_Set) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_topic_set_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_by_id_to_string(value: ffi::Tox_Err_Group_By_Id) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_by_id_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_send_message_to_string(value: ffi::Tox_Err_Group_Send_Message) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_message_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_send_private_message_to_string(value: ffi::Tox_Err_Group_Send_Private_Message) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_private_message_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_send_custom_packet_to_string(value: ffi::Tox_Err_Group_Send_Custom_Packet) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_custom_packet_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_send_custom_private_packet_to_string(value: ffi::Tox_Err_Group_Send_Custom_Private_Packet) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_send_custom_private_packet_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_invite_friend_to_string(value: ffi::Tox_Err_Group_Invite_Friend) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_invite_friend_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_invite_accept_to_string(value: ffi::Tox_Err_Group_Invite_Accept) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_invite_accept_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_password_to_string(value: ffi::Tox_Err_Group_Set_Password) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_password_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_topic_lock_to_string(value: ffi::Tox_Err_Group_Set_Topic_Lock) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_topic_lock_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_voice_state_to_string(value: ffi::Tox_Err_Group_Set_Voice_State) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_voice_state_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_privacy_state_to_string(value: ffi::Tox_Err_Group_Set_Privacy_State) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_privacy_state_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_peer_limit_to_string(value: ffi::Tox_Err_Group_Set_Peer_Limit) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_peer_limit_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_ignore_to_string(value: ffi::Tox_Err_Group_Set_Ignore) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_ignore_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_set_role_to_string(value: ffi::Tox_Err_Group_Set_Role) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_set_role_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_group_kick_peer_to_string(value: ffi::Tox_Err_Group_Kick_Peer) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_group_kick_peer_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn log_level_to_string(value: ToxLogLevel) -> &'static str {
        unsafe {
            let ptr = ffi::tox_log_level_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn proxy_type_to_string(value: ToxProxyType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_proxy_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn savedata_type_to_string(value: ToxSavedataType) -> &'static str {
        unsafe {
            let ptr = ffi::tox_savedata_type_to_string(value.into()) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_options_new_to_string(value: ffi::Tox_Err_Options_New) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_options_new_to_string(value) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }
}
impl Tox {
    pub fn groupchat_disable_av(&self, conference_number: ConferenceNumber) -> i32 {
        unsafe {
            ffi::toxav_groupchat_disable_av(self.ptr, conference_number.0)
        }
    }

    pub fn groupchat_av_enabled(&self, conference_number: ConferenceNumber) -> bool {
        ffi_bool!(toxav_groupchat_av_enabled, self.ptr, conference_number.0)
    }
}
pub enum Event<'a> {
    SelfConnectionStatus(EventSelfConnectionStatus<'a>),
    FriendRequest(EventFriendRequest<'a>),
    FriendConnectionStatus(EventFriendConnectionStatus<'a>),
    FriendLossyPacket(EventFriendLossyPacket<'a>),
    FriendLosslessPacket(EventFriendLosslessPacket<'a>),
    FriendName(EventFriendName<'a>),
    FriendStatus(EventFriendStatus<'a>),
    FriendStatusMessage(EventFriendStatusMessage<'a>),
    FriendMessage(EventFriendMessage<'a>),
    FriendReadReceipt(EventFriendReadReceipt<'a>),
    FriendTyping(EventFriendTyping<'a>),
    FileChunkRequest(EventFileChunkRequest<'a>),
    FileRecv(EventFileRecv<'a>),
    FileRecvChunk(EventFileRecvChunk<'a>),
    FileRecvControl(EventFileRecvControl<'a>),
    ConferenceInvite(EventConferenceInvite<'a>),
    ConferenceConnected(EventConferenceConnected<'a>),
    ConferencePeerListChanged(EventConferencePeerListChanged<'a>),
    ConferencePeerName(EventConferencePeerName<'a>),
    ConferenceTitle(EventConferenceTitle<'a>),
    ConferenceMessage(EventConferenceMessage<'a>),
    GroupPeerName(EventGroupPeerName<'a>),
    GroupPeerStatus(EventGroupPeerStatus<'a>),
    GroupTopic(EventGroupTopic<'a>),
    GroupPrivacyState(EventGroupPrivacyState<'a>),
    GroupVoiceState(EventGroupVoiceState<'a>),
    GroupTopicLock(EventGroupTopicLock<'a>),
    GroupPeerLimit(EventGroupPeerLimit<'a>),
    GroupPassword(EventGroupPassword<'a>),
    GroupMessage(EventGroupMessage<'a>),
    GroupPrivateMessage(EventGroupPrivateMessage<'a>),
    GroupCustomPacket(EventGroupCustomPacket<'a>),
    GroupCustomPrivatePacket(EventGroupCustomPrivatePacket<'a>),
    GroupInvite(EventGroupInvite<'a>),
    GroupPeerJoin(EventGroupPeerJoin<'a>),
    GroupPeerExit(EventGroupPeerExit<'a>),
    GroupSelfJoin(EventGroupSelfJoin<'a>),
    GroupJoinFail(EventGroupJoinFail<'a>),
    GroupModeration(EventGroupModeration<'a>),
    DhtNodesResponse(EventDhtNodesResponse<'a>),
    Unknown

}
impl<'a> Event<'a> {
    /// # Safety
    /// 
    /// `ptr` must be a valid, non-null pointer to a live event
    /// object that stays alive for the lifetime `'a`.
    pub unsafe fn from_ptr(ptr: *const ffi::Tox_Event) -> Event<'a> {
        let type_ = unsafe {
            ffi::tox_event_get_type(ptr)
        };
        match type_ {
            ffi::Tox_Event_Type::TOX_EVENT_SELF_CONNECTION_STATUS => {
                Event::SelfConnectionStatus(EventSelfConnectionStatus(unsafe {
                    &*ffi::tox_event_get_self_connection_status(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_REQUEST => {
                Event::FriendRequest(EventFriendRequest(unsafe {
                    &*ffi::tox_event_get_friend_request(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_CONNECTION_STATUS => {
                Event::FriendConnectionStatus(EventFriendConnectionStatus(unsafe {
                    &*ffi::tox_event_get_friend_connection_status(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSY_PACKET => {
                Event::FriendLossyPacket(EventFriendLossyPacket(unsafe {
                    &*ffi::tox_event_get_friend_lossy_packet(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSLESS_PACKET => {
                Event::FriendLosslessPacket(EventFriendLosslessPacket(unsafe {
                    &*ffi::tox_event_get_friend_lossless_packet(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_NAME => {
                Event::FriendName(EventFriendName(unsafe {
                    &*ffi::tox_event_get_friend_name(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS => {
                Event::FriendStatus(EventFriendStatus(unsafe {
                    &*ffi::tox_event_get_friend_status(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS_MESSAGE => {
                Event::FriendStatusMessage(EventFriendStatusMessage(unsafe {
                    &*ffi::tox_event_get_friend_status_message(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_MESSAGE => {
                Event::FriendMessage(EventFriendMessage(unsafe {
                    &*ffi::tox_event_get_friend_message(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_READ_RECEIPT => {
                Event::FriendReadReceipt(EventFriendReadReceipt(unsafe {
                    &*ffi::tox_event_get_friend_read_receipt(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_TYPING => {
                Event::FriendTyping(EventFriendTyping(unsafe {
                    &*ffi::tox_event_get_friend_typing(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_CHUNK_REQUEST => {
                Event::FileChunkRequest(EventFileChunkRequest(unsafe {
                    &*ffi::tox_event_get_file_chunk_request(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV => {
                Event::FileRecv(EventFileRecv(unsafe {
                    &*ffi::tox_event_get_file_recv(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CHUNK => {
                Event::FileRecvChunk(EventFileRecvChunk(unsafe {
                    &*ffi::tox_event_get_file_recv_chunk(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CONTROL => {
                Event::FileRecvControl(EventFileRecvControl(unsafe {
                    &*ffi::tox_event_get_file_recv_control(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_INVITE => {
                Event::ConferenceInvite(EventConferenceInvite(unsafe {
                    &*ffi::tox_event_get_conference_invite(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_CONNECTED => {
                Event::ConferenceConnected(EventConferenceConnected(unsafe {
                    &*ffi::tox_event_get_conference_connected(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED => {
                Event::ConferencePeerListChanged(EventConferencePeerListChanged(unsafe {
                    &*ffi::tox_event_get_conference_peer_list_changed(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_NAME => {
                Event::ConferencePeerName(EventConferencePeerName(unsafe {
                    &*ffi::tox_event_get_conference_peer_name(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_TITLE => {
                Event::ConferenceTitle(EventConferenceTitle(unsafe {
                    &*ffi::tox_event_get_conference_title(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_MESSAGE => {
                Event::ConferenceMessage(EventConferenceMessage(unsafe {
                    &*ffi::tox_event_get_conference_message(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_NAME => {
                Event::GroupPeerName(EventGroupPeerName(unsafe {
                    &*ffi::tox_event_get_group_peer_name(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_STATUS => {
                Event::GroupPeerStatus(EventGroupPeerStatus(unsafe {
                    &*ffi::tox_event_get_group_peer_status(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC => {
                Event::GroupTopic(EventGroupTopic(unsafe {
                    &*ffi::tox_event_get_group_topic(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVACY_STATE => {
                Event::GroupPrivacyState(EventGroupPrivacyState(unsafe {
                    &*ffi::tox_event_get_group_privacy_state(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_VOICE_STATE => {
                Event::GroupVoiceState(EventGroupVoiceState(unsafe {
                    &*ffi::tox_event_get_group_voice_state(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC_LOCK => {
                Event::GroupTopicLock(EventGroupTopicLock(unsafe {
                    &*ffi::tox_event_get_group_topic_lock(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_LIMIT => {
                Event::GroupPeerLimit(EventGroupPeerLimit(unsafe {
                    &*ffi::tox_event_get_group_peer_limit(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PASSWORD => {
                Event::GroupPassword(EventGroupPassword(unsafe {
                    &*ffi::tox_event_get_group_password(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MESSAGE => {
                Event::GroupMessage(EventGroupMessage(unsafe {
                    &*ffi::tox_event_get_group_message(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVATE_MESSAGE => {
                Event::GroupPrivateMessage(EventGroupPrivateMessage(unsafe {
                    &*ffi::tox_event_get_group_private_message(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PACKET => {
                Event::GroupCustomPacket(EventGroupCustomPacket(unsafe {
                    &*ffi::tox_event_get_group_custom_packet(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET => {
                Event::GroupCustomPrivatePacket(EventGroupCustomPrivatePacket(unsafe {
                    &*ffi::tox_event_get_group_custom_private_packet(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_INVITE => {
                Event::GroupInvite(EventGroupInvite(unsafe {
                    &*ffi::tox_event_get_group_invite(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_JOIN => {
                Event::GroupPeerJoin(EventGroupPeerJoin(unsafe {
                    &*ffi::tox_event_get_group_peer_join(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_EXIT => {
                Event::GroupPeerExit(EventGroupPeerExit(unsafe {
                    &*ffi::tox_event_get_group_peer_exit(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_SELF_JOIN => {
                Event::GroupSelfJoin(EventGroupSelfJoin(unsafe {
                    &*ffi::tox_event_get_group_self_join(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_JOIN_FAIL => {
                Event::GroupJoinFail(EventGroupJoinFail(unsafe {
                    &*ffi::tox_event_get_group_join_fail(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MODERATION => {
                Event::GroupModeration(EventGroupModeration(unsafe {
                    &*ffi::tox_event_get_group_moderation(ptr)
                }))
            },
            ffi::Tox_Event_Type::TOX_EVENT_DHT_NODES_RESPONSE => {
                Event::DhtNodesResponse(EventDhtNodesResponse(unsafe {
                    &*ffi::tox_event_get_dht_nodes_response(ptr)
                }))
            },
            _ => {
                Event::Unknown
            },
        }
    }
}
