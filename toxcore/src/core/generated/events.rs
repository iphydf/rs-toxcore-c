#![allow(unused_imports)]
use super::tox::IterateOptions;
use super::tox::System;
use super::tox::Tox;
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
pub struct EventConferenceConnected<'a>(pub &'a ffi::Tox_Event_Conference_Connected);
pub struct EventConferenceInvite<'a>(pub &'a ffi::Tox_Event_Conference_Invite);
pub struct EventConferenceMessage<'a>(pub &'a ffi::Tox_Event_Conference_Message);
pub struct EventConferencePeerListChanged<'a>(pub &'a ffi::Tox_Event_Conference_Peer_List_Changed);
pub struct EventConferencePeerName<'a>(pub &'a ffi::Tox_Event_Conference_Peer_Name);
pub struct EventConferenceTitle<'a>(pub &'a ffi::Tox_Event_Conference_Title);
pub struct EventDhtNodesResponse<'a>(pub &'a ffi::Tox_Event_Dht_Nodes_Response);
pub struct EventFileChunkRequest<'a>(pub &'a ffi::Tox_Event_File_Chunk_Request);
pub struct EventFileRecv<'a>(pub &'a ffi::Tox_Event_File_Recv);
pub struct EventFileRecvChunk<'a>(pub &'a ffi::Tox_Event_File_Recv_Chunk);
pub struct EventFileRecvControl<'a>(pub &'a ffi::Tox_Event_File_Recv_Control);
pub struct EventFriendConnectionStatus<'a>(pub &'a ffi::Tox_Event_Friend_Connection_Status);
pub struct EventFriendLosslessPacket<'a>(pub &'a ffi::Tox_Event_Friend_Lossless_Packet);
pub struct EventFriendLossyPacket<'a>(pub &'a ffi::Tox_Event_Friend_Lossy_Packet);
pub struct EventFriendMessage<'a>(pub &'a ffi::Tox_Event_Friend_Message);
pub struct EventFriendName<'a>(pub &'a ffi::Tox_Event_Friend_Name);
pub struct EventFriendReadReceipt<'a>(pub &'a ffi::Tox_Event_Friend_Read_Receipt);
pub struct EventFriendRequest<'a>(pub &'a ffi::Tox_Event_Friend_Request);
pub struct EventFriendStatus<'a>(pub &'a ffi::Tox_Event_Friend_Status);
pub struct EventFriendStatusMessage<'a>(pub &'a ffi::Tox_Event_Friend_Status_Message);
pub struct EventFriendTyping<'a>(pub &'a ffi::Tox_Event_Friend_Typing);
pub struct EventGroupCustomPacket<'a>(pub &'a ffi::Tox_Event_Group_Custom_Packet);
pub struct EventGroupCustomPrivatePacket<'a>(pub &'a ffi::Tox_Event_Group_Custom_Private_Packet);
pub struct EventGroupInvite<'a>(pub &'a ffi::Tox_Event_Group_Invite);
pub struct EventGroupJoinFail<'a>(pub &'a ffi::Tox_Event_Group_Join_Fail);
pub struct EventGroupMessage<'a>(pub &'a ffi::Tox_Event_Group_Message);
pub struct EventGroupModeration<'a>(pub &'a ffi::Tox_Event_Group_Moderation);
pub struct EventGroupPassword<'a>(pub &'a ffi::Tox_Event_Group_Password);
pub struct EventGroupPeerExit<'a>(pub &'a ffi::Tox_Event_Group_Peer_Exit);
pub struct EventGroupPeerJoin<'a>(pub &'a ffi::Tox_Event_Group_Peer_Join);
pub struct EventGroupPeerLimit<'a>(pub &'a ffi::Tox_Event_Group_Peer_Limit);
pub struct EventGroupPeerName<'a>(pub &'a ffi::Tox_Event_Group_Peer_Name);
pub struct EventGroupPeerStatus<'a>(pub &'a ffi::Tox_Event_Group_Peer_Status);
pub struct EventGroupPrivacyState<'a>(pub &'a ffi::Tox_Event_Group_Privacy_State);
pub struct EventGroupPrivateMessage<'a>(pub &'a ffi::Tox_Event_Group_Private_Message);
pub struct EventGroupSelfJoin<'a>(pub &'a ffi::Tox_Event_Group_Self_Join);
pub struct EventGroupTopic<'a>(pub &'a ffi::Tox_Event_Group_Topic);
pub struct EventGroupTopicLock<'a>(pub &'a ffi::Tox_Event_Group_Topic_Lock);
pub struct EventGroupVoiceState<'a>(pub &'a ffi::Tox_Event_Group_Voice_State);
pub struct EventSelfConnectionStatus<'a>(pub &'a ffi::Tox_Event_Self_Connection_Status);
pub struct ToxEvents<'a> {
    pub(crate) ptr: *mut ffi::Tox_Events,
    _marker: std::marker::PhantomData<&'a Tox>,
}
impl<'a> Drop for ToxEvents<'a> {
    fn drop(&mut self) {
        unsafe { ffi::tox_events_free(self.ptr) }
    }
}
impl<'a> EventConferenceConnected<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_connected_get_conference_number(self.0)
        })
    }
}
impl<'a> EventConferenceInvite<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_conference_invite_get_friend_number(self.0) })
    }

    pub fn conference_type(&self) -> ToxConferenceType {
        unsafe { ffi::tox_event_conference_invite_get_type(self.0) }.into()
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
        unsafe { ffi::tox_event_conference_invite_get_cookie_length(self.0) }
    }
}
impl<'a> EventConferenceMessage<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe { ffi::tox_event_conference_message_get_conference_number(self.0) })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe { ffi::tox_event_conference_message_get_peer_number(self.0) })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe { ffi::tox_event_conference_message_get_type(self.0) }.into()
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
        unsafe { ffi::tox_event_conference_message_get_message_length(self.0) }
    }
}
impl<'a> EventConferencePeerListChanged<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_peer_list_changed_get_conference_number(self.0)
        })
    }
}
impl<'a> EventConferencePeerName<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe {
            ffi::tox_event_conference_peer_name_get_conference_number(self.0)
        })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe { ffi::tox_event_conference_peer_name_get_peer_number(self.0) })
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
        unsafe { ffi::tox_event_conference_peer_name_get_name_length(self.0) }
    }
}
impl<'a> EventConferenceTitle<'a> {
    pub fn conference_number(&self) -> ConferenceNumber {
        ConferenceNumber(unsafe { ffi::tox_event_conference_title_get_conference_number(self.0) })
    }

    pub fn peer_number(&self) -> ConferencePeerNumber {
        ConferencePeerNumber(unsafe { ffi::tox_event_conference_title_get_peer_number(self.0) })
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
        unsafe { ffi::tox_event_conference_title_get_title_length(self.0) }
    }
}
impl<'a> EventDhtNodesResponse<'a> {
    pub fn public_key(&self) -> PublicKey {
        unsafe {
            let ptr = ffi::tox_event_dht_nodes_response_get_public_key(self.0);
            let slice = std::slice::from_raw_parts(ptr, PUBLIC_KEY_SIZE);
            PublicKey(slice.try_into().unwrap())
        }
    }

    pub fn ip(&self) -> &str {
        unsafe {
            let ptr =
                ffi::tox_event_dht_nodes_response_get_ip(self.0) as *const std::os::raw::c_char;
            if ptr.is_null() {
                ""
            } else {
                std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
            }
        }
    }

    pub fn ip_length(&self) -> u32 {
        unsafe { ffi::tox_event_dht_nodes_response_get_ip_length(self.0) }
    }

    pub fn port(&self) -> u16 {
        unsafe { ffi::tox_event_dht_nodes_response_get_port(self.0) }
    }
}
impl<'a> EventFileChunkRequest<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_file_chunk_request_get_friend_number(self.0) })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe { ffi::tox_event_file_chunk_request_get_file_number(self.0) })
    }

    pub fn position(&self) -> u64 {
        unsafe { ffi::tox_event_file_chunk_request_get_position(self.0) }
    }

    pub fn length(&self) -> usize {
        (unsafe { ffi::tox_event_file_chunk_request_get_length(self.0) }) as usize
    }
}
impl<'a> EventFileRecv<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_file_recv_get_friend_number(self.0) })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe { ffi::tox_event_file_recv_get_file_number(self.0) })
    }

    pub fn kind(&self) -> u32 {
        unsafe { ffi::tox_event_file_recv_get_kind(self.0) }
    }

    pub fn file_size(&self) -> u64 {
        unsafe { ffi::tox_event_file_recv_get_file_size(self.0) }
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
        unsafe { ffi::tox_event_file_recv_get_filename_length(self.0) }
    }
}
impl<'a> EventFileRecvChunk<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_file_recv_chunk_get_friend_number(self.0) })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe { ffi::tox_event_file_recv_chunk_get_file_number(self.0) })
    }

    pub fn position(&self) -> u64 {
        unsafe { ffi::tox_event_file_recv_chunk_get_position(self.0) }
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
        unsafe { ffi::tox_event_file_recv_chunk_get_data_length(self.0) }
    }
}
impl<'a> EventFileRecvControl<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_file_recv_control_get_friend_number(self.0) })
    }

    pub fn file_number(&self) -> FileNumber {
        FileNumber(unsafe { ffi::tox_event_file_recv_control_get_file_number(self.0) })
    }

    pub fn control(&self) -> ToxFileControl {
        unsafe { ffi::tox_event_file_recv_control_get_control(self.0) }.into()
    }
}
impl<'a> EventFriendConnectionStatus<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_connection_status_get_friend_number(self.0) })
    }

    pub fn connection_status(&self) -> ToxConnection {
        unsafe { ffi::tox_event_friend_connection_status_get_connection_status(self.0) }.into()
    }
}
impl<'a> EventFriendLosslessPacket<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_lossless_packet_get_friend_number(self.0) })
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
        unsafe { ffi::tox_event_friend_lossless_packet_get_data_length(self.0) }
    }
}
impl<'a> EventFriendLossyPacket<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_lossy_packet_get_friend_number(self.0) })
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
        unsafe { ffi::tox_event_friend_lossy_packet_get_data_length(self.0) }
    }
}
impl<'a> EventFriendMessage<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_message_get_friend_number(self.0) })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe { ffi::tox_event_friend_message_get_type(self.0) }.into()
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
        unsafe { ffi::tox_event_friend_message_get_message_length(self.0) }
    }
}
impl<'a> EventFriendName<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_name_get_friend_number(self.0) })
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
        unsafe { ffi::tox_event_friend_name_get_name_length(self.0) }
    }
}
impl<'a> EventFriendReadReceipt<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_read_receipt_get_friend_number(self.0) })
    }

    pub fn message_id(&self) -> FriendMessageId {
        FriendMessageId(unsafe { ffi::tox_event_friend_read_receipt_get_message_id(self.0) })
    }
}
impl<'a> EventFriendRequest<'a> {
    pub fn public_key(&self) -> PublicKey {
        unsafe {
            let ptr = ffi::tox_event_friend_request_get_public_key(self.0);
            let slice = std::slice::from_raw_parts(ptr, PUBLIC_KEY_SIZE);
            PublicKey(slice.try_into().unwrap())
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
        unsafe { ffi::tox_event_friend_request_get_message_length(self.0) }
    }
}
impl<'a> EventFriendStatus<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_status_get_friend_number(self.0) })
    }

    pub fn status(&self) -> ToxUserStatus {
        unsafe { ffi::tox_event_friend_status_get_status(self.0) }.into()
    }
}
impl<'a> EventFriendStatusMessage<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_status_message_get_friend_number(self.0) })
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
        unsafe { ffi::tox_event_friend_status_message_get_message_length(self.0) }
    }
}
impl<'a> EventFriendTyping<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_friend_typing_get_friend_number(self.0) })
    }

    pub fn typing(&self) -> bool {
        ffi_bool!(tox_event_friend_typing_get_typing, self.0)
    }
}
impl<'a> EventGroupCustomPacket<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_custom_packet_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_custom_packet_get_peer_id(self.0) })
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
        unsafe { ffi::tox_event_group_custom_packet_get_data_length(self.0) }
    }
}
impl<'a> EventGroupCustomPrivatePacket<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_custom_private_packet_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_custom_private_packet_get_peer_id(self.0) })
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
        unsafe { ffi::tox_event_group_custom_private_packet_get_data_length(self.0) }
    }
}
impl<'a> EventGroupInvite<'a> {
    pub fn friend_number(&self) -> FriendNumber {
        FriendNumber(unsafe { ffi::tox_event_group_invite_get_friend_number(self.0) })
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
        unsafe { ffi::tox_event_group_invite_get_invite_data_length(self.0) }
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
        unsafe { ffi::tox_event_group_invite_get_group_name_length(self.0) }
    }
}
impl<'a> EventGroupJoinFail<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_join_fail_get_group_number(self.0) })
    }

    pub fn fail_type(&self) -> ToxGroupJoinFail {
        unsafe { ffi::tox_event_group_join_fail_get_fail_type(self.0) }.into()
    }
}
impl<'a> EventGroupMessage<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_message_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_message_get_peer_id(self.0) })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe { ffi::tox_event_group_message_get_message_type(self.0) }.into()
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
        unsafe { ffi::tox_event_group_message_get_message_length(self.0) }
    }

    pub fn message_id(&self) -> GroupMessageId {
        GroupMessageId(unsafe { ffi::tox_event_group_message_get_message_id(self.0) })
    }
}
impl<'a> EventGroupModeration<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_moderation_get_group_number(self.0) })
    }

    pub fn source_peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_moderation_get_source_peer_id(self.0) })
    }

    pub fn target_peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_moderation_get_target_peer_id(self.0) })
    }

    pub fn mod_type(&self) -> ToxGroupModEvent {
        unsafe { ffi::tox_event_group_moderation_get_mod_type(self.0) }.into()
    }
}
impl<'a> EventGroupPassword<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_password_get_group_number(self.0) })
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
        unsafe { ffi::tox_event_group_password_get_password_length(self.0) }
    }
}
impl<'a> EventGroupPeerExit<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_peer_exit_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_peer_exit_get_peer_id(self.0) })
    }

    pub fn exit_type(&self) -> ToxGroupExitType {
        unsafe { ffi::tox_event_group_peer_exit_get_exit_type(self.0) }.into()
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
        unsafe { ffi::tox_event_group_peer_exit_get_name_length(self.0) }
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
        unsafe { ffi::tox_event_group_peer_exit_get_part_message_length(self.0) }
    }
}
impl<'a> EventGroupPeerJoin<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_peer_join_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_peer_join_get_peer_id(self.0) })
    }
}
impl<'a> EventGroupPeerLimit<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_peer_limit_get_group_number(self.0) })
    }

    pub fn peer_limit(&self) -> u32 {
        unsafe { ffi::tox_event_group_peer_limit_get_peer_limit(self.0) }
    }
}
impl<'a> EventGroupPeerName<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_peer_name_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_peer_name_get_peer_id(self.0) })
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
        unsafe { ffi::tox_event_group_peer_name_get_name_length(self.0) }
    }
}
impl<'a> EventGroupPeerStatus<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_peer_status_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_peer_status_get_peer_id(self.0) })
    }

    pub fn status(&self) -> ToxUserStatus {
        unsafe { ffi::tox_event_group_peer_status_get_status(self.0) }.into()
    }
}
impl<'a> EventGroupPrivacyState<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_privacy_state_get_group_number(self.0) })
    }

    pub fn privacy_state(&self) -> ToxGroupPrivacyState {
        unsafe { ffi::tox_event_group_privacy_state_get_privacy_state(self.0) }.into()
    }
}
impl<'a> EventGroupPrivateMessage<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_private_message_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_private_message_get_peer_id(self.0) })
    }

    pub fn message_type(&self) -> MessageType {
        unsafe { ffi::tox_event_group_private_message_get_message_type(self.0) }.into()
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
        unsafe { ffi::tox_event_group_private_message_get_message_length(self.0) }
    }

    pub fn message_id(&self) -> GroupMessageId {
        GroupMessageId(unsafe { ffi::tox_event_group_private_message_get_message_id(self.0) })
    }
}
impl<'a> EventGroupSelfJoin<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_self_join_get_group_number(self.0) })
    }
}
impl<'a> EventGroupTopic<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_topic_get_group_number(self.0) })
    }

    pub fn peer_id(&self) -> GroupPeerNumber {
        GroupPeerNumber(unsafe { ffi::tox_event_group_topic_get_peer_id(self.0) })
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
        unsafe { ffi::tox_event_group_topic_get_topic_length(self.0) }
    }
}
impl<'a> EventGroupTopicLock<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_topic_lock_get_group_number(self.0) })
    }

    pub fn topic_lock(&self) -> ToxGroupTopicLock {
        unsafe { ffi::tox_event_group_topic_lock_get_topic_lock(self.0) }.into()
    }
}
impl<'a> EventGroupVoiceState<'a> {
    pub fn group_number(&self) -> GroupNumber {
        GroupNumber(unsafe { ffi::tox_event_group_voice_state_get_group_number(self.0) })
    }

    pub fn voice_state(&self) -> ToxGroupVoiceState {
        unsafe { ffi::tox_event_group_voice_state_get_voice_state(self.0) }.into()
    }
}
impl<'a> EventSelfConnectionStatus<'a> {
    pub fn connection_status(&self) -> ToxConnection {
        unsafe { ffi::tox_event_self_connection_status_get_connection_status(self.0) }.into()
    }
}
impl<'a> ToxEvents<'a> {
    pub fn iterate(
        tox: &Tox,
        options: &IterateOptions,
    ) -> std::result::Result<Self, Tox_Err_Events_Iterate> {
        ffi_call!(
            tox_events_iterate,
            ffi::Tox_Err_Events_Iterate::TOX_ERR_EVENTS_ITERATE_OK,
            tox.ptr,
            options.ptr
        )
        .map(|val| Self {
            ptr: val,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn dispatch<T>(tox: &Tox, events: &ToxEvents<'a>, user_data: &mut T) {
        unsafe {
            ffi::tox_events_dispatch(
                tox.ptr,
                events.ptr,
                user_data as *mut T as *mut std::ffi::c_void,
            )
        }
    }

    pub fn load(sys: &System, bytes: &[u8], bytes_size: u32) -> Option<Self> {
        unsafe {
            let raw = ffi::tox_events_load(sys.ptr, bytes.as_ptr(), bytes_size);
            if raw.is_null() {
                None
            } else {
                Some(Self {
                    ptr: raw,
                    _marker: std::marker::PhantomData,
                })
            }
        }
    }

    pub fn get_size(&self) -> u32 {
        unsafe { ffi::tox_events_get_size(self.ptr) }
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
        unsafe { ffi::tox_events_bytes_size(self.ptr) }
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
    _marker: std::marker::PhantomData<&'a ()>,
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
        ToxEventsIter {
            parent: self,
            index: 0,
            count: self.get_size(),
            _marker: std::marker::PhantomData,
        }
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
    Unknown,
}
impl<'a> Event<'a> {
    /// # Safety
    ///
    /// `ptr` must be a valid, non-null pointer to a live event
    /// object that stays alive for the lifetime `'a`.
    pub unsafe fn from_ptr(ptr: *const ffi::Tox_Event) -> Event<'a> {
        let type_ = unsafe { ffi::tox_event_get_type(ptr) };
        match type_ {
            ffi::Tox_Event_Type::TOX_EVENT_SELF_CONNECTION_STATUS => {
                Event::SelfConnectionStatus(EventSelfConnectionStatus(unsafe {
                    &*ffi::tox_event_get_self_connection_status(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_REQUEST => {
                Event::FriendRequest(EventFriendRequest(unsafe {
                    &*ffi::tox_event_get_friend_request(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_CONNECTION_STATUS => {
                Event::FriendConnectionStatus(EventFriendConnectionStatus(unsafe {
                    &*ffi::tox_event_get_friend_connection_status(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSY_PACKET => {
                Event::FriendLossyPacket(EventFriendLossyPacket(unsafe {
                    &*ffi::tox_event_get_friend_lossy_packet(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSLESS_PACKET => {
                Event::FriendLosslessPacket(EventFriendLosslessPacket(unsafe {
                    &*ffi::tox_event_get_friend_lossless_packet(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_NAME => {
                Event::FriendName(EventFriendName(unsafe {
                    &*ffi::tox_event_get_friend_name(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS => {
                Event::FriendStatus(EventFriendStatus(unsafe {
                    &*ffi::tox_event_get_friend_status(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS_MESSAGE => {
                Event::FriendStatusMessage(EventFriendStatusMessage(unsafe {
                    &*ffi::tox_event_get_friend_status_message(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_MESSAGE => {
                Event::FriendMessage(EventFriendMessage(unsafe {
                    &*ffi::tox_event_get_friend_message(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_READ_RECEIPT => {
                Event::FriendReadReceipt(EventFriendReadReceipt(unsafe {
                    &*ffi::tox_event_get_friend_read_receipt(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_TYPING => {
                Event::FriendTyping(EventFriendTyping(unsafe {
                    &*ffi::tox_event_get_friend_typing(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FILE_CHUNK_REQUEST => {
                Event::FileChunkRequest(EventFileChunkRequest(unsafe {
                    &*ffi::tox_event_get_file_chunk_request(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV => Event::FileRecv(EventFileRecv(unsafe {
                &*ffi::tox_event_get_file_recv(ptr)
            })),
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CHUNK => {
                Event::FileRecvChunk(EventFileRecvChunk(unsafe {
                    &*ffi::tox_event_get_file_recv_chunk(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CONTROL => {
                Event::FileRecvControl(EventFileRecvControl(unsafe {
                    &*ffi::tox_event_get_file_recv_control(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_INVITE => {
                Event::ConferenceInvite(EventConferenceInvite(unsafe {
                    &*ffi::tox_event_get_conference_invite(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_CONNECTED => {
                Event::ConferenceConnected(EventConferenceConnected(unsafe {
                    &*ffi::tox_event_get_conference_connected(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED => {
                Event::ConferencePeerListChanged(EventConferencePeerListChanged(unsafe {
                    &*ffi::tox_event_get_conference_peer_list_changed(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_NAME => {
                Event::ConferencePeerName(EventConferencePeerName(unsafe {
                    &*ffi::tox_event_get_conference_peer_name(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_TITLE => {
                Event::ConferenceTitle(EventConferenceTitle(unsafe {
                    &*ffi::tox_event_get_conference_title(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_MESSAGE => {
                Event::ConferenceMessage(EventConferenceMessage(unsafe {
                    &*ffi::tox_event_get_conference_message(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_NAME => {
                Event::GroupPeerName(EventGroupPeerName(unsafe {
                    &*ffi::tox_event_get_group_peer_name(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_STATUS => {
                Event::GroupPeerStatus(EventGroupPeerStatus(unsafe {
                    &*ffi::tox_event_get_group_peer_status(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC => {
                Event::GroupTopic(EventGroupTopic(unsafe {
                    &*ffi::tox_event_get_group_topic(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVACY_STATE => {
                Event::GroupPrivacyState(EventGroupPrivacyState(unsafe {
                    &*ffi::tox_event_get_group_privacy_state(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_VOICE_STATE => {
                Event::GroupVoiceState(EventGroupVoiceState(unsafe {
                    &*ffi::tox_event_get_group_voice_state(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC_LOCK => {
                Event::GroupTopicLock(EventGroupTopicLock(unsafe {
                    &*ffi::tox_event_get_group_topic_lock(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_LIMIT => {
                Event::GroupPeerLimit(EventGroupPeerLimit(unsafe {
                    &*ffi::tox_event_get_group_peer_limit(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PASSWORD => {
                Event::GroupPassword(EventGroupPassword(unsafe {
                    &*ffi::tox_event_get_group_password(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MESSAGE => {
                Event::GroupMessage(EventGroupMessage(unsafe {
                    &*ffi::tox_event_get_group_message(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVATE_MESSAGE => {
                Event::GroupPrivateMessage(EventGroupPrivateMessage(unsafe {
                    &*ffi::tox_event_get_group_private_message(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PACKET => {
                Event::GroupCustomPacket(EventGroupCustomPacket(unsafe {
                    &*ffi::tox_event_get_group_custom_packet(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET => {
                Event::GroupCustomPrivatePacket(EventGroupCustomPrivatePacket(unsafe {
                    &*ffi::tox_event_get_group_custom_private_packet(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_INVITE => {
                Event::GroupInvite(EventGroupInvite(unsafe {
                    &*ffi::tox_event_get_group_invite(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_JOIN => {
                Event::GroupPeerJoin(EventGroupPeerJoin(unsafe {
                    &*ffi::tox_event_get_group_peer_join(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_EXIT => {
                Event::GroupPeerExit(EventGroupPeerExit(unsafe {
                    &*ffi::tox_event_get_group_peer_exit(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_SELF_JOIN => {
                Event::GroupSelfJoin(EventGroupSelfJoin(unsafe {
                    &*ffi::tox_event_get_group_self_join(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_JOIN_FAIL => {
                Event::GroupJoinFail(EventGroupJoinFail(unsafe {
                    &*ffi::tox_event_get_group_join_fail(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MODERATION => {
                Event::GroupModeration(EventGroupModeration(unsafe {
                    &*ffi::tox_event_get_group_moderation(ptr)
                }))
            }
            ffi::Tox_Event_Type::TOX_EVENT_DHT_NODES_RESPONSE => {
                Event::DhtNodesResponse(EventDhtNodesResponse(unsafe {
                    &*ffi::tox_event_get_dht_nodes_response(ptr)
                }))
            }
            _ => Event::Unknown,
        }
    }
}
