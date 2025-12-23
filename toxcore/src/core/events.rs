use crate::ffi;
use crate::types::*;
use std::marker::PhantomData;
use std::ptr;
use std::slice;

/// A wrapper around `Tox_Events`.
pub struct ToxEvents<'a> {
    ptr: *mut ffi::Tox_Events,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Drop for ToxEvents<'a> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::tox_events_free(self.ptr) }
        }
    }
}

impl<'a> ToxEvents<'a> {
    pub fn new(ptr: *mut ffi::Tox_Events) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn iter(&self) -> EventsIter<'_, 'a> {
        EventsIter {
            events: self,
            index: 0,
            count: unsafe { ffi::tox_events_get_size(self.ptr) },
        }
    }
}

impl<'a> IntoIterator for &'a ToxEvents<'a> {
    type Item = Event<'a>;
    type IntoIter = EventsIter<'a, 'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct EventsIter<'iter, 'data> {
    events: &'iter ToxEvents<'data>,
    index: u32,
    count: u32,
}

impl<'iter, 'data> Iterator for EventsIter<'iter, 'data> {
    type Item = Event<'iter>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }

        let event_ptr = unsafe { ffi::tox_events_get(self.events.ptr, self.index) };
        self.index += 1;

        if event_ptr.is_null() {
            return None;
        }

        let type_ = unsafe { ffi::tox_event_get_type(event_ptr) };
        match type_ {
            ffi::Tox_Event_Type::TOX_EVENT_SELF_CONNECTION_STATUS => unsafe {
                let ptr = ffi::tox_event_get_self_connection_status(event_ptr);
                Some(Event::SelfConnectionStatus(EventSelfConnectionStatus(
                    &*ptr,
                )))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_REQUEST => unsafe {
                let ptr = ffi::tox_event_get_friend_request(event_ptr);
                Some(Event::FriendRequest(EventFriendRequest(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_CONNECTION_STATUS => unsafe {
                let ptr = ffi::tox_event_get_friend_connection_status(event_ptr);
                Some(Event::FriendConnectionStatus(EventFriendConnectionStatus(
                    &*ptr,
                )))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSY_PACKET => unsafe {
                let ptr = ffi::tox_event_get_friend_lossy_packet(event_ptr);
                Some(Event::FriendLossyPacket(EventFriendLossyPacket(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_LOSSLESS_PACKET => unsafe {
                let ptr = ffi::tox_event_get_friend_lossless_packet(event_ptr);
                Some(Event::FriendLosslessPacket(EventFriendLosslessPacket(
                    &*ptr,
                )))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_NAME => unsafe {
                let ptr = ffi::tox_event_get_friend_name(event_ptr);
                Some(Event::FriendName(EventFriendName(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS => unsafe {
                let ptr = ffi::tox_event_get_friend_status(event_ptr);
                Some(Event::FriendStatus(EventFriendStatus(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_STATUS_MESSAGE => unsafe {
                let ptr = ffi::tox_event_get_friend_status_message(event_ptr);
                Some(Event::FriendStatusMessage(EventFriendStatusMessage(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_MESSAGE => unsafe {
                let ptr = ffi::tox_event_get_friend_message(event_ptr);
                Some(Event::FriendMessage(EventFriendMessage(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_READ_RECEIPT => unsafe {
                let ptr = ffi::tox_event_get_friend_read_receipt(event_ptr);
                Some(Event::FriendReadReceipt(EventFriendReadReceipt(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FRIEND_TYPING => unsafe {
                let ptr = ffi::tox_event_get_friend_typing(event_ptr);
                Some(Event::FriendTyping(EventFriendTyping(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_CHUNK_REQUEST => unsafe {
                let ptr = ffi::tox_event_get_file_chunk_request(event_ptr);
                Some(Event::FileChunkRequest(EventFileChunkRequest(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV => unsafe {
                let ptr = ffi::tox_event_get_file_recv(event_ptr);
                Some(Event::FileRecv(EventFileRecv(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CHUNK => unsafe {
                let ptr = ffi::tox_event_get_file_recv_chunk(event_ptr);
                Some(Event::FileRecvChunk(EventFileRecvChunk(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_FILE_RECV_CONTROL => unsafe {
                let ptr = ffi::tox_event_get_file_recv_control(event_ptr);
                Some(Event::FileRecvControl(EventFileRecvControl(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_INVITE => unsafe {
                let ptr = ffi::tox_event_get_conference_invite(event_ptr);
                Some(Event::ConferenceInvite(EventConferenceInvite(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_CONNECTED => unsafe {
                let ptr = ffi::tox_event_get_conference_connected(event_ptr);
                Some(Event::ConferenceConnected(EventConferenceConnected(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED => unsafe {
                let ptr = ffi::tox_event_get_conference_peer_list_changed(event_ptr);
                Some(Event::ConferencePeerListChanged(
                    EventConferencePeerListChanged(&*ptr),
                ))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_PEER_NAME => unsafe {
                let ptr = ffi::tox_event_get_conference_peer_name(event_ptr);
                Some(Event::ConferencePeerName(EventConferencePeerName(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_TITLE => unsafe {
                let ptr = ffi::tox_event_get_conference_title(event_ptr);
                Some(Event::ConferenceTitle(EventConferenceTitle(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_CONFERENCE_MESSAGE => unsafe {
                let ptr = ffi::tox_event_get_conference_message(event_ptr);
                Some(Event::ConferenceMessage(EventConferenceMessage(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_NAME => unsafe {
                let ptr = ffi::tox_event_get_group_peer_name(event_ptr);
                Some(Event::GroupPeerName(EventGroupPeerName(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_STATUS => unsafe {
                let ptr = ffi::tox_event_get_group_peer_status(event_ptr);
                Some(Event::GroupPeerStatus(EventGroupPeerStatus(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC => unsafe {
                let ptr = ffi::tox_event_get_group_topic(event_ptr);
                Some(Event::GroupTopic(EventGroupTopic(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVACY_STATE => unsafe {
                let ptr = ffi::tox_event_get_group_privacy_state(event_ptr);
                Some(Event::GroupPrivacyState(EventGroupPrivacyState(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_VOICE_STATE => unsafe {
                let ptr = ffi::tox_event_get_group_voice_state(event_ptr);
                Some(Event::GroupVoiceState(EventGroupVoiceState(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_TOPIC_LOCK => unsafe {
                let ptr = ffi::tox_event_get_group_topic_lock(event_ptr);
                Some(Event::GroupTopicLock(EventGroupTopicLock(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_LIMIT => unsafe {
                let ptr = ffi::tox_event_get_group_peer_limit(event_ptr);
                Some(Event::GroupPeerLimit(EventGroupPeerLimit(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PASSWORD => unsafe {
                let ptr = ffi::tox_event_get_group_password(event_ptr);
                Some(Event::GroupPassword(EventGroupPassword(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MESSAGE => unsafe {
                let ptr = ffi::tox_event_get_group_message(event_ptr);
                Some(Event::GroupMessage(EventGroupMessage(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PRIVATE_MESSAGE => unsafe {
                let ptr = ffi::tox_event_get_group_private_message(event_ptr);
                Some(Event::GroupPrivateMessage(EventGroupPrivateMessage(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PACKET => unsafe {
                let ptr = ffi::tox_event_get_group_custom_packet(event_ptr);
                Some(Event::GroupCustomPacket(EventGroupCustomPacket(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET => unsafe {
                let ptr = ffi::tox_event_get_group_custom_private_packet(event_ptr);
                Some(Event::GroupCustomPrivatePacket(
                    EventGroupCustomPrivatePacket(&*ptr),
                ))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_INVITE => unsafe {
                let ptr = ffi::tox_event_get_group_invite(event_ptr);
                Some(Event::GroupInvite(EventGroupInvite(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_JOIN => unsafe {
                let ptr = ffi::tox_event_get_group_peer_join(event_ptr);
                Some(Event::GroupPeerJoin(EventGroupPeerJoin(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_PEER_EXIT => unsafe {
                let ptr = ffi::tox_event_get_group_peer_exit(event_ptr);
                Some(Event::GroupPeerExit(EventGroupPeerExit(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_SELF_JOIN => unsafe {
                let ptr = ffi::tox_event_get_group_self_join(event_ptr);
                Some(Event::GroupSelfJoin(EventGroupSelfJoin(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_JOIN_FAIL => unsafe {
                let ptr = ffi::tox_event_get_group_join_fail(event_ptr);
                Some(Event::GroupJoinFail(EventGroupJoinFail(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_GROUP_MODERATION => unsafe {
                let ptr = ffi::tox_event_get_group_moderation(event_ptr);
                Some(Event::GroupModeration(EventGroupModeration(&*ptr)))
            },
            ffi::Tox_Event_Type::TOX_EVENT_DHT_NODES_RESPONSE => unsafe {
                let ptr = ffi::tox_event_get_dht_nodes_response(event_ptr);
                Some(Event::DhtNodesResponse(EventDhtNodesResponse(&*ptr)))
            },
            _ => None,
        }
    }
}

#[derive(Debug)]
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
}

// Helpers for macros to limit unsafe blocks
unsafe fn get_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn get_public_key(ptr: *const u8) -> PublicKey {
    let mut pk = [0u8; PUBLIC_KEY_SIZE];
    unsafe { ptr::copy_nonoverlapping(ptr, pk.as_mut_ptr(), PUBLIC_KEY_SIZE) };
    PublicKey(pk)
}

macro_rules! event_attr_copy {
    ($name:ident, $type:ty, $ffi_func:ident) => {
        pub fn $name(&self) -> $type {
            unsafe { ffi::$ffi_func(self.0).into() }
        }
    };
    // Special case for wrapping in a newtype
    ($name:ident, $type:ty, $wrapper:path, $ffi_func:ident) => {
        pub fn $name(&self) -> $type {
            unsafe { $wrapper(ffi::$ffi_func(self.0)).into() }
        }
    };
}

macro_rules! event_attr_slice {
    ($name:ident, $ffi_get:ident, $ffi_len:ident) => {
        pub fn $name(&self) -> &[u8] {
            unsafe {
                let ptr = ffi::$ffi_get(self.0);
                let len = ffi::$ffi_len(self.0);
                get_slice(ptr, len as usize)
            }
        }
    };
}

macro_rules! event_attr_pk {
    ($name:ident, $ffi_get:ident) => {
        pub fn $name(&self) -> PublicKey {
            unsafe {
                let ptr = ffi::$ffi_get(self.0);
                get_public_key(ptr)
            }
        }
    };
}

#[derive(Debug)]
pub struct EventSelfConnectionStatus<'a>(&'a ffi::Tox_Event_Self_Connection_Status);
impl<'a> EventSelfConnectionStatus<'a> {
    event_attr_copy!(
        connection_status,
        ToxConnection,
        tox_event_self_connection_status_get_connection_status
    );
}

#[derive(Debug)]
pub struct EventFriendRequest<'a>(&'a ffi::Tox_Event_Friend_Request);
impl<'a> EventFriendRequest<'a> {
    event_attr_pk!(public_key, tox_event_friend_request_get_public_key);
    event_attr_slice!(
        message,
        tox_event_friend_request_get_message,
        tox_event_friend_request_get_message_length
    );
}

#[derive(Debug)]
pub struct EventFriendConnectionStatus<'a>(&'a ffi::Tox_Event_Friend_Connection_Status);
impl<'a> EventFriendConnectionStatus<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_connection_status_get_friend_number
    );
    event_attr_copy!(
        connection_status,
        ToxConnection,
        tox_event_friend_connection_status_get_connection_status
    );
}

#[derive(Debug)]
pub struct EventFriendLossyPacket<'a>(&'a ffi::Tox_Event_Friend_Lossy_Packet);
impl<'a> EventFriendLossyPacket<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_lossy_packet_get_friend_number
    );
    event_attr_slice!(
        data,
        tox_event_friend_lossy_packet_get_data,
        tox_event_friend_lossy_packet_get_data_length
    );
}

#[derive(Debug)]
pub struct EventFriendLosslessPacket<'a>(&'a ffi::Tox_Event_Friend_Lossless_Packet);
impl<'a> EventFriendLosslessPacket<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_lossless_packet_get_friend_number
    );
    event_attr_slice!(
        data,
        tox_event_friend_lossless_packet_get_data,
        tox_event_friend_lossless_packet_get_data_length
    );
}

#[derive(Debug)]
pub struct EventFriendName<'a>(&'a ffi::Tox_Event_Friend_Name);
impl<'a> EventFriendName<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_name_get_friend_number
    );
    event_attr_slice!(
        name,
        tox_event_friend_name_get_name,
        tox_event_friend_name_get_name_length
    );
}

#[derive(Debug)]
pub struct EventFriendStatus<'a>(&'a ffi::Tox_Event_Friend_Status);
impl<'a> EventFriendStatus<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_status_get_friend_number
    );
    event_attr_copy!(status, ToxUserStatus, tox_event_friend_status_get_status);
}

#[derive(Debug)]
pub struct EventFriendStatusMessage<'a>(&'a ffi::Tox_Event_Friend_Status_Message);
impl<'a> EventFriendStatusMessage<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_status_message_get_friend_number
    );
    event_attr_slice!(
        message,
        tox_event_friend_status_message_get_message,
        tox_event_friend_status_message_get_message_length
    );
}

#[derive(Debug)]
pub struct EventFriendMessage<'a>(&'a ffi::Tox_Event_Friend_Message);
impl<'a> EventFriendMessage<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_message_get_friend_number
    );
    event_attr_copy!(
        message_type,
        MessageType,
        MessageType::from,
        tox_event_friend_message_get_type
    );
    event_attr_slice!(
        message,
        tox_event_friend_message_get_message,
        tox_event_friend_message_get_message_length
    );
}

#[derive(Debug)]
pub struct EventFriendReadReceipt<'a>(&'a ffi::Tox_Event_Friend_Read_Receipt);
impl<'a> EventFriendReadReceipt<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_read_receipt_get_friend_number
    );
    event_attr_copy!(
        message_id,
        FriendMessageId,
        FriendMessageId,
        tox_event_friend_read_receipt_get_message_id
    );
}

#[derive(Debug)]
pub struct EventFriendTyping<'a>(&'a ffi::Tox_Event_Friend_Typing);
impl<'a> EventFriendTyping<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_friend_typing_get_friend_number
    );
    event_attr_copy!(is_typing, bool, tox_event_friend_typing_get_typing);
}

#[derive(Debug)]
pub struct EventFileChunkRequest<'a>(&'a ffi::Tox_Event_File_Chunk_Request);
impl<'a> EventFileChunkRequest<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_file_chunk_request_get_friend_number
    );
    event_attr_copy!(
        file_number,
        FileNumber,
        FileNumber,
        tox_event_file_chunk_request_get_file_number
    );
    event_attr_copy!(position, u64, tox_event_file_chunk_request_get_position);
    pub fn length(&self) -> usize {
        unsafe { ffi::tox_event_file_chunk_request_get_length(self.0) as usize }
    }
}

#[derive(Debug)]
pub struct EventFileRecv<'a>(&'a ffi::Tox_Event_File_Recv);
impl<'a> EventFileRecv<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_file_recv_get_friend_number
    );
    event_attr_copy!(
        file_number,
        FileNumber,
        FileNumber,
        tox_event_file_recv_get_file_number
    );
    event_attr_copy!(kind, u32, tox_event_file_recv_get_kind);
    event_attr_copy!(file_size, u64, tox_event_file_recv_get_file_size);
    event_attr_slice!(
        filename,
        tox_event_file_recv_get_filename,
        tox_event_file_recv_get_filename_length
    );
}

#[derive(Debug)]
pub struct EventFileRecvChunk<'a>(&'a ffi::Tox_Event_File_Recv_Chunk);
impl<'a> EventFileRecvChunk<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_file_recv_chunk_get_friend_number
    );
    event_attr_copy!(
        file_number,
        FileNumber,
        FileNumber,
        tox_event_file_recv_chunk_get_file_number
    );
    event_attr_copy!(position, u64, tox_event_file_recv_chunk_get_position);
    event_attr_slice!(
        data,
        tox_event_file_recv_chunk_get_data,
        tox_event_file_recv_chunk_get_data_length
    );
}

#[derive(Debug)]
pub struct EventFileRecvControl<'a>(&'a ffi::Tox_Event_File_Recv_Control);
impl<'a> EventFileRecvControl<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_file_recv_control_get_friend_number
    );
    event_attr_copy!(
        file_number,
        FileNumber,
        FileNumber,
        tox_event_file_recv_control_get_file_number
    );
    event_attr_copy!(
        control,
        ToxFileControl,
        tox_event_file_recv_control_get_control
    );
}

#[derive(Debug)]
pub struct EventConferenceInvite<'a>(&'a ffi::Tox_Event_Conference_Invite);
impl<'a> EventConferenceInvite<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_conference_invite_get_friend_number
    );
    event_attr_copy!(
        conference_type,
        ToxConferenceType,
        tox_event_conference_invite_get_type
    );
    event_attr_slice!(
        cookie,
        tox_event_conference_invite_get_cookie,
        tox_event_conference_invite_get_cookie_length
    );
}

#[derive(Debug)]
pub struct EventConferenceConnected<'a>(&'a ffi::Tox_Event_Conference_Connected);
impl<'a> EventConferenceConnected<'a> {
    event_attr_copy!(
        conference_number,
        ConferenceNumber,
        ConferenceNumber,
        tox_event_conference_connected_get_conference_number
    );
}

#[derive(Debug)]
pub struct EventConferencePeerListChanged<'a>(&'a ffi::Tox_Event_Conference_Peer_List_Changed);
impl<'a> EventConferencePeerListChanged<'a> {
    event_attr_copy!(
        conference_number,
        ConferenceNumber,
        ConferenceNumber,
        tox_event_conference_peer_list_changed_get_conference_number
    );
}

#[derive(Debug)]
pub struct EventConferencePeerName<'a>(&'a ffi::Tox_Event_Conference_Peer_Name);
impl<'a> EventConferencePeerName<'a> {
    event_attr_copy!(
        conference_number,
        ConferenceNumber,
        ConferenceNumber,
        tox_event_conference_peer_name_get_conference_number
    );
    event_attr_copy!(
        peer_number,
        ConferencePeerNumber,
        ConferencePeerNumber,
        tox_event_conference_peer_name_get_peer_number
    );
    event_attr_slice!(
        name,
        tox_event_conference_peer_name_get_name,
        tox_event_conference_peer_name_get_name_length
    );
}

#[derive(Debug)]
pub struct EventConferenceTitle<'a>(&'a ffi::Tox_Event_Conference_Title);
impl<'a> EventConferenceTitle<'a> {
    event_attr_copy!(
        conference_number,
        ConferenceNumber,
        ConferenceNumber,
        tox_event_conference_title_get_conference_number
    );
    event_attr_copy!(
        peer_number,
        ConferencePeerNumber,
        ConferencePeerNumber,
        tox_event_conference_title_get_peer_number
    );
    event_attr_slice!(
        title,
        tox_event_conference_title_get_title,
        tox_event_conference_title_get_title_length
    );
}

#[derive(Debug)]
pub struct EventConferenceMessage<'a>(&'a ffi::Tox_Event_Conference_Message);
impl<'a> EventConferenceMessage<'a> {
    event_attr_copy!(
        conference_number,
        ConferenceNumber,
        ConferenceNumber,
        tox_event_conference_message_get_conference_number
    );
    event_attr_copy!(
        peer_number,
        ConferencePeerNumber,
        ConferencePeerNumber,
        tox_event_conference_message_get_peer_number
    );
    event_attr_copy!(
        message_type,
        MessageType,
        MessageType::from,
        tox_event_conference_message_get_type
    );
    event_attr_slice!(
        message,
        tox_event_conference_message_get_message,
        tox_event_conference_message_get_message_length
    );
}

#[derive(Debug)]
pub struct EventGroupPeerName<'a>(&'a ffi::Tox_Event_Group_Peer_Name);
impl<'a> EventGroupPeerName<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_peer_name_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_peer_name_get_peer_id
    );
    event_attr_slice!(
        name,
        tox_event_group_peer_name_get_name,
        tox_event_group_peer_name_get_name_length
    );
}

#[derive(Debug)]
pub struct EventGroupPeerStatus<'a>(&'a ffi::Tox_Event_Group_Peer_Status);
impl<'a> EventGroupPeerStatus<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_peer_status_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_peer_status_get_peer_id
    );
    event_attr_copy!(
        status,
        ToxUserStatus,
        tox_event_group_peer_status_get_status
    );
}

#[derive(Debug)]
pub struct EventGroupTopic<'a>(&'a ffi::Tox_Event_Group_Topic);
impl<'a> EventGroupTopic<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_topic_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_topic_get_peer_id
    );
    event_attr_slice!(
        topic,
        tox_event_group_topic_get_topic,
        tox_event_group_topic_get_topic_length
    );
}

#[derive(Debug)]
pub struct EventGroupPrivacyState<'a>(&'a ffi::Tox_Event_Group_Privacy_State);
impl<'a> EventGroupPrivacyState<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_privacy_state_get_group_number
    );
    event_attr_copy!(
        privacy_state,
        ToxGroupPrivacyState,
        tox_event_group_privacy_state_get_privacy_state
    );
}

#[derive(Debug)]
pub struct EventGroupVoiceState<'a>(&'a ffi::Tox_Event_Group_Voice_State);
impl<'a> EventGroupVoiceState<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_voice_state_get_group_number
    );
    event_attr_copy!(
        voice_state,
        ToxGroupVoiceState,
        tox_event_group_voice_state_get_voice_state
    );
}

#[derive(Debug)]
pub struct EventGroupTopicLock<'a>(&'a ffi::Tox_Event_Group_Topic_Lock);
impl<'a> EventGroupTopicLock<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_topic_lock_get_group_number
    );
    event_attr_copy!(
        topic_lock,
        ToxGroupTopicLock,
        tox_event_group_topic_lock_get_topic_lock
    );
}

#[derive(Debug)]
pub struct EventGroupPeerLimit<'a>(&'a ffi::Tox_Event_Group_Peer_Limit);
impl<'a> EventGroupPeerLimit<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_peer_limit_get_group_number
    );
    event_attr_copy!(peer_limit, u32, tox_event_group_peer_limit_get_peer_limit);
}

#[derive(Debug)]
pub struct EventGroupPassword<'a>(&'a ffi::Tox_Event_Group_Password);
impl<'a> EventGroupPassword<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_password_get_group_number
    );
    event_attr_slice!(
        password,
        tox_event_group_password_get_password,
        tox_event_group_password_get_password_length
    );
}

#[derive(Debug)]
pub struct EventGroupMessage<'a>(&'a ffi::Tox_Event_Group_Message);
impl<'a> EventGroupMessage<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_message_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_message_get_peer_id
    );
    event_attr_copy!(
        message_type,
        MessageType,
        MessageType::from,
        tox_event_group_message_get_message_type
    );
    event_attr_slice!(
        message,
        tox_event_group_message_get_message,
        tox_event_group_message_get_message_length
    );
    event_attr_copy!(
        message_id,
        GroupMessageId,
        GroupMessageId,
        tox_event_group_message_get_message_id
    );
}

#[derive(Debug)]
pub struct EventGroupPrivateMessage<'a>(&'a ffi::Tox_Event_Group_Private_Message);
impl<'a> EventGroupPrivateMessage<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_private_message_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_private_message_get_peer_id
    );
    event_attr_copy!(
        message_type,
        MessageType,
        MessageType::from,
        tox_event_group_private_message_get_message_type
    );
    event_attr_slice!(
        message,
        tox_event_group_private_message_get_message,
        tox_event_group_private_message_get_message_length
    );
    event_attr_copy!(
        message_id,
        GroupMessageId,
        GroupMessageId,
        tox_event_group_private_message_get_message_id
    );
}

#[derive(Debug)]
pub struct EventGroupCustomPacket<'a>(&'a ffi::Tox_Event_Group_Custom_Packet);
impl<'a> EventGroupCustomPacket<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_custom_packet_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_custom_packet_get_peer_id
    );
    event_attr_slice!(
        data,
        tox_event_group_custom_packet_get_data,
        tox_event_group_custom_packet_get_data_length
    );
}

#[derive(Debug)]
pub struct EventGroupCustomPrivatePacket<'a>(&'a ffi::Tox_Event_Group_Custom_Private_Packet);
impl<'a> EventGroupCustomPrivatePacket<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_custom_private_packet_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_custom_private_packet_get_peer_id
    );
    event_attr_slice!(
        data,
        tox_event_group_custom_private_packet_get_data,
        tox_event_group_custom_private_packet_get_data_length
    );
}

#[derive(Debug)]
pub struct EventGroupInvite<'a>(&'a ffi::Tox_Event_Group_Invite);
impl<'a> EventGroupInvite<'a> {
    event_attr_copy!(
        friend_number,
        FriendNumber,
        FriendNumber,
        tox_event_group_invite_get_friend_number
    );
    event_attr_slice!(
        invite_data,
        tox_event_group_invite_get_invite_data,
        tox_event_group_invite_get_invite_data_length
    );
    event_attr_slice!(
        group_name,
        tox_event_group_invite_get_group_name,
        tox_event_group_invite_get_group_name_length
    );
}

#[derive(Debug)]
pub struct EventGroupPeerJoin<'a>(&'a ffi::Tox_Event_Group_Peer_Join);
impl<'a> EventGroupPeerJoin<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_peer_join_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_peer_join_get_peer_id
    );
}

#[derive(Debug)]
pub struct EventGroupPeerExit<'a>(&'a ffi::Tox_Event_Group_Peer_Exit);
impl<'a> EventGroupPeerExit<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_peer_exit_get_group_number
    );
    event_attr_copy!(
        peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_peer_exit_get_peer_id
    );
    event_attr_copy!(
        exit_type,
        ToxGroupExitType,
        tox_event_group_peer_exit_get_exit_type
    );
    event_attr_slice!(
        name,
        tox_event_group_peer_exit_get_name,
        tox_event_group_peer_exit_get_name_length
    );
    event_attr_slice!(
        part_message,
        tox_event_group_peer_exit_get_part_message,
        tox_event_group_peer_exit_get_part_message_length
    );
}

#[derive(Debug)]
pub struct EventGroupSelfJoin<'a>(&'a ffi::Tox_Event_Group_Self_Join);
impl<'a> EventGroupSelfJoin<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_self_join_get_group_number
    );
}

#[derive(Debug)]
pub struct EventGroupJoinFail<'a>(&'a ffi::Tox_Event_Group_Join_Fail);
impl<'a> EventGroupJoinFail<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_join_fail_get_group_number
    );
    event_attr_copy!(
        fail_type,
        ToxGroupJoinFail,
        tox_event_group_join_fail_get_fail_type
    );
}

#[derive(Debug)]
pub struct EventGroupModeration<'a>(&'a ffi::Tox_Event_Group_Moderation);
impl<'a> EventGroupModeration<'a> {
    event_attr_copy!(
        group_number,
        GroupNumber,
        GroupNumber,
        tox_event_group_moderation_get_group_number
    );
    event_attr_copy!(
        source_peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_moderation_get_source_peer_id
    );
    event_attr_copy!(
        target_peer_id,
        GroupPeerNumber,
        GroupPeerNumber,
        tox_event_group_moderation_get_target_peer_id
    );
    event_attr_copy!(
        mod_type,
        ToxGroupModEvent,
        tox_event_group_moderation_get_mod_type
    );
}

#[derive(Debug)]
pub struct EventDhtNodesResponse<'a>(&'a ffi::Tox_Event_Dht_Nodes_Response);
impl<'a> EventDhtNodesResponse<'a> {
    event_attr_pk!(public_key, tox_event_dht_nodes_response_get_public_key);
    event_attr_slice!(
        ip,
        tox_event_dht_nodes_response_get_ip,
        tox_event_dht_nodes_response_get_ip_length
    );
    event_attr_copy!(port, u16, tox_event_dht_nodes_response_get_port);
}
