use super::tox::Tox;
use crate::ffi;
use crate::types::*;
use std::os::raw::c_void;
use std::slice;

pub trait ToxHandler {
    fn on_friend_message(&mut self, _friend: FriendNumber, _type: MessageType, _message: &[u8]) {}
    fn on_friend_name(&mut self, _friend: FriendNumber, _name: &[u8]) {}
    fn on_friend_status_message(&mut self, _friend: FriendNumber, _message: &[u8]) {}
    fn on_friend_status(&mut self, _friend: FriendNumber, _status: ToxUserStatus) {}
    fn on_self_connection_status(&mut self, _status: ToxConnection) {}
    fn on_friend_connection_status(&mut self, _friend: FriendNumber, _status: ToxConnection) {}
    fn on_friend_typing(&mut self, _friend: FriendNumber, _typing: bool) {}
    fn on_friend_read_receipt(&mut self, _friend: FriendNumber, _message_id: FriendMessageId) {}
    fn on_friend_request(&mut self, _public_key: PublicKey, _message: &[u8]) {}
    fn on_file_recv(
        &mut self,
        _friend: FriendNumber,
        _file: FileNumber,
        _kind: u32,
        _file_size: u64,
        _filename: &[u8],
    ) {
    }
    fn on_file_chunk_request(
        &mut self,
        _friend: FriendNumber,
        _file: FileNumber,
        _position: u64,
        _length: usize,
    ) {
    }
    fn on_file_recv_chunk(
        &mut self,
        _friend: FriendNumber,
        _file: FileNumber,
        _position: u64,
        _data: &[u8],
    ) {
    }
    fn on_file_recv_control(
        &mut self,
        _friend: FriendNumber,
        _file: FileNumber,
        _control: ToxFileControl,
    ) {
    }
    fn on_conference_invite(
        &mut self,
        _friend: FriendNumber,
        _type: ToxConferenceType,
        _cookie: &[u8],
    ) {
    }
    fn on_conference_connected(&mut self, _conference: ConferenceNumber) {}
    fn on_conference_message(
        &mut self,
        _conference: ConferenceNumber,
        _peer: ConferencePeerNumber,
        _type: MessageType,
        _message: &[u8],
    ) {
    }
    fn on_conference_title(
        &mut self,
        _conference: ConferenceNumber,
        _peer: ConferencePeerNumber,
        _title: &[u8],
    ) {
    }
    fn on_conference_peer_name(
        &mut self,
        _conference: ConferenceNumber,
        _peer: ConferencePeerNumber,
        _name: &[u8],
    ) {
    }
    fn on_conference_peer_list_changed(&mut self, _conference: ConferenceNumber) {}
    fn on_friend_lossy_packet(&mut self, _friend: FriendNumber, _data: &[u8]) {}
    fn on_friend_lossless_packet(&mut self, _friend: FriendNumber, _data: &[u8]) {}
    fn on_group_invite(&mut self, _friend: FriendNumber, _invite_data: &[u8], _group_name: &[u8]) {}
    fn on_group_message(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _type: MessageType,
        _message: &[u8],
        _message_id: GroupMessageId,
    ) {
    }
    fn on_group_private_message(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _type: MessageType,
        _message: &[u8],
        _message_id: GroupMessageId,
    ) {
    }
    fn on_group_custom_packet(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _data: &[u8],
    ) {
    }
    fn on_group_custom_private_packet(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _data: &[u8],
    ) {
    }
    fn on_group_peer_join(&mut self, _group: GroupNumber, _peer: GroupPeerNumber) {}
    fn on_group_peer_exit(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _exit_type: ToxGroupExitType,
        _name: &[u8],
        _part_message: &[u8],
    ) {
    }
    fn on_group_self_join(&mut self, _group: GroupNumber) {}
    fn on_group_join_fail(&mut self, _group: GroupNumber, _fail_type: ToxGroupJoinFail) {}
    fn on_group_topic(&mut self, _group: GroupNumber, _peer: GroupPeerNumber, _topic: &[u8]) {}
    fn on_group_privacy_state(
        &mut self,
        _group: GroupNumber,
        _privacy_state: ToxGroupPrivacyState,
    ) {
    }
    fn on_group_voice_state(&mut self, _group: GroupNumber, _voice_state: ToxGroupVoiceState) {}
    fn on_group_topic_lock(&mut self, _group: GroupNumber, _topic_lock: ToxGroupTopicLock) {}
    fn on_group_peer_limit(&mut self, _group: GroupNumber, _peer_limit: u32) {}
    fn on_group_password(&mut self, _group: GroupNumber, _password: &[u8]) {}
    fn on_group_peer_name(&mut self, _group: GroupNumber, _peer: GroupPeerNumber, _name: &[u8]) {}
    fn on_group_peer_status(
        &mut self,
        _group: GroupNumber,
        _peer: GroupPeerNumber,
        _status: ToxUserStatus,
    ) {
    }
    fn on_group_moderation(
        &mut self,
        _group: GroupNumber,
        _source_peer: GroupPeerNumber,
        _target_peer: GroupPeerNumber,
        _mod_type: ToxGroupModEvent,
    ) {
    }
}

unsafe fn safe_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

pub fn tox_iterate<H: ToxHandler>(tox: &Tox, handler: &mut H) {
    let tox_ptr = tox.ptr;
    unsafe {
        ffi::tox_callback_friend_message(tox_ptr, Some(dispatch_friend_message::<H>));
        ffi::tox_callback_friend_name(tox_ptr, Some(dispatch_friend_name::<H>));
        ffi::tox_callback_friend_status_message(tox_ptr, Some(dispatch_friend_status_message::<H>));
        ffi::tox_callback_friend_status(tox_ptr, Some(dispatch_friend_status::<H>));
        ffi::tox_callback_self_connection_status(
            tox_ptr,
            Some(dispatch_self_connection_status::<H>),
        );
        ffi::tox_callback_friend_connection_status(
            tox_ptr,
            Some(dispatch_friend_connection_status::<H>),
        );
        ffi::tox_callback_friend_typing(tox_ptr, Some(dispatch_friend_typing::<H>));
        ffi::tox_callback_friend_read_receipt(tox_ptr, Some(dispatch_friend_read_receipt::<H>));
        ffi::tox_callback_friend_request(tox_ptr, Some(dispatch_friend_request::<H>));

        ffi::tox_callback_file_recv(tox_ptr, Some(dispatch_file_recv::<H>));
        ffi::tox_callback_file_chunk_request(tox_ptr, Some(dispatch_file_chunk_request::<H>));
        ffi::tox_callback_file_recv_chunk(tox_ptr, Some(dispatch_file_recv_chunk::<H>));
        ffi::tox_callback_file_recv_control(tox_ptr, Some(dispatch_file_recv_control::<H>));

        ffi::tox_callback_conference_invite(tox_ptr, Some(dispatch_conference_invite::<H>));
        ffi::tox_callback_conference_connected(tox_ptr, Some(dispatch_conference_connected::<H>));
        ffi::tox_callback_conference_message(tox_ptr, Some(dispatch_conference_message::<H>));
        ffi::tox_callback_conference_title(tox_ptr, Some(dispatch_conference_title::<H>));
        ffi::tox_callback_conference_peer_name(tox_ptr, Some(dispatch_conference_peer_name::<H>));
        ffi::tox_callback_conference_peer_list_changed(
            tox_ptr,
            Some(dispatch_conference_peer_list_changed::<H>),
        );

        ffi::tox_callback_friend_lossy_packet(tox_ptr, Some(dispatch_friend_lossy_packet::<H>));
        ffi::tox_callback_friend_lossless_packet(
            tox_ptr,
            Some(dispatch_friend_lossless_packet::<H>),
        );

        ffi::tox_callback_group_invite(tox_ptr, Some(dispatch_group_invite::<H>));
        ffi::tox_callback_group_message(tox_ptr, Some(dispatch_group_message::<H>));
        ffi::tox_callback_group_private_message(tox_ptr, Some(dispatch_group_private_message::<H>));
        ffi::tox_callback_group_custom_packet(tox_ptr, Some(dispatch_group_custom_packet::<H>));
        ffi::tox_callback_group_custom_private_packet(
            tox_ptr,
            Some(dispatch_group_custom_private_packet::<H>),
        );
        ffi::tox_callback_group_peer_join(tox_ptr, Some(dispatch_group_peer_join::<H>));
        ffi::tox_callback_group_peer_exit(tox_ptr, Some(dispatch_group_peer_exit::<H>));
        ffi::tox_callback_group_self_join(tox_ptr, Some(dispatch_group_self_join::<H>));
        ffi::tox_callback_group_join_fail(tox_ptr, Some(dispatch_group_join_fail::<H>));
        ffi::tox_callback_group_topic(tox_ptr, Some(dispatch_group_topic::<H>));
        ffi::tox_callback_group_privacy_state(tox_ptr, Some(dispatch_group_privacy_state::<H>));
        ffi::tox_callback_group_voice_state(tox_ptr, Some(dispatch_group_voice_state::<H>));
        ffi::tox_callback_group_topic_lock(tox_ptr, Some(dispatch_group_topic_lock::<H>));
        ffi::tox_callback_group_peer_limit(tox_ptr, Some(dispatch_group_peer_limit::<H>));
        ffi::tox_callback_group_password(tox_ptr, Some(dispatch_group_password::<H>));
        ffi::tox_callback_group_peer_name(tox_ptr, Some(dispatch_group_peer_name::<H>));
        ffi::tox_callback_group_peer_status(tox_ptr, Some(dispatch_group_peer_status::<H>));
        ffi::tox_callback_group_moderation(tox_ptr, Some(dispatch_group_moderation::<H>));

        ffi::tox_iterate(tox_ptr, handler as *mut H as *mut c_void);
    }
}

macro_rules! define_dispatch {
    ($func_name:ident, ($($arg_name:ident: $arg_type:ty),*), $body:expr) => {
        unsafe extern "C" fn $func_name<H: ToxHandler>(
            _tox: *mut ffi::Tox,
            $($arg_name: $arg_type),*,
            user_data: *mut c_void,
        ) {
            if !user_data.is_null() {
                let handler = unsafe { &mut *(user_data as *mut H) };
                // We use AssertUnwindSafe because &mut H is not technically UnwindSafe (panic could leave it in inconsistent state).
                // However, since we must prevent unwinding across the FFI boundary (which causes UB/Abort), catching the panic is necessary.
                // If the user's handler panics, their state might be broken, but that is preferable to crashing the whole process via UB.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    $body(handler)
                }));
            }
        }
    }
}

define_dispatch!(
    dispatch_friend_message,
    (friend_number: u32, message_type: ffi::Tox_Message_Type, message: *const u8, length: usize),
    |handler: &mut H| {
        let msg = unsafe { safe_slice(message, length) };
        handler.on_friend_message(crate::types::FriendNumber(friend_number), message_type.into(), msg);
    }
);

define_dispatch!(
    dispatch_friend_name,
    (friend_number: u32, name: *const u8, length: usize),
    |handler: &mut H| {
        let name = unsafe { safe_slice(name, length) };
        handler.on_friend_name(crate::types::FriendNumber(friend_number), name);
    }
);

define_dispatch!(
    dispatch_friend_status_message,
    (friend_number: u32, message: *const u8, length: usize),
    |handler: &mut H| {
        let msg = unsafe { safe_slice(message, length) };
        handler.on_friend_status_message(crate::types::FriendNumber(friend_number), msg);
    }
);

define_dispatch!(
    dispatch_friend_status,
    (friend_number: u32, status: ffi::Tox_User_Status),
    |handler: &mut H| {
        handler.on_friend_status(crate::types::FriendNumber(friend_number), status.into());
    }
);

define_dispatch!(
    dispatch_self_connection_status,
    (connection_status: ffi::Tox_Connection),
    |handler: &mut H| {
        handler.on_self_connection_status(connection_status.into());
    }
);

define_dispatch!(
    dispatch_friend_connection_status,
    (friend_number: u32, connection_status: ffi::Tox_Connection),
    |handler: &mut H| {
        handler.on_friend_connection_status(
            crate::types::FriendNumber(friend_number),
            connection_status.into(),
        );
    }
);

define_dispatch!(
    dispatch_friend_typing,
    (friend_number: u32, typing: bool),
    |handler: &mut H| {
        handler.on_friend_typing(crate::types::FriendNumber(friend_number), typing);
    }
);

define_dispatch!(
    dispatch_friend_read_receipt,
    (friend_number: u32, message_id: u32),
    |handler: &mut H| {
        handler.on_friend_read_receipt(
            crate::types::FriendNumber(friend_number),
            crate::types::FriendMessageId(message_id),
        );
    }
);

define_dispatch!(
    dispatch_friend_request,
    (public_key: *const u8, message: *const u8, length: usize),
    |handler: &mut H| {
        let pk = unsafe { slice::from_raw_parts(public_key, PUBLIC_KEY_SIZE) };
        let mut pk_arr = [0u8; PUBLIC_KEY_SIZE];
        pk_arr.copy_from_slice(pk);
        let msg = unsafe { slice::from_raw_parts(message, length) };
        handler.on_friend_request(crate::types::PublicKey(pk_arr), msg);
    }
);

define_dispatch!(
    dispatch_file_recv,
    (friend_number: u32, file_number: u32, kind: u32, file_size: u64, filename: *const u8, filename_length: usize),
    |handler: &mut H| {
        let name = unsafe { safe_slice(filename, filename_length) };
        handler.on_file_recv(
            crate::types::FriendNumber(friend_number),
            crate::types::FileNumber(file_number),
            kind,
            file_size,
            name,
        );
    }
);

define_dispatch!(
    dispatch_file_chunk_request,
    (friend_number: u32, file_number: u32, position: u64, length: usize),
    |handler: &mut H| {
        handler.on_file_chunk_request(
            crate::types::FriendNumber(friend_number),
            crate::types::FileNumber(file_number),
            position,
            length,
        );
    }
);

define_dispatch!(
    dispatch_file_recv_chunk,
    (friend_number: u32, file_number: u32, position: u64, data: *const u8, length: usize),
    |handler: &mut H| {
        let chunk = unsafe { safe_slice(data, length) };
        handler.on_file_recv_chunk(
            crate::types::FriendNumber(friend_number),
            crate::types::FileNumber(file_number),
            position,
            chunk,
        );
    }
);

define_dispatch!(
    dispatch_file_recv_control,
    (friend_number: u32, file_number: u32, control: ffi::Tox_File_Control),
    |handler: &mut H| {
        handler.on_file_recv_control(
            crate::types::FriendNumber(friend_number),
            crate::types::FileNumber(file_number),
            control.into(),
        );
    }
);

define_dispatch!(
    dispatch_conference_invite,
    (friend_number: u32, _type: ffi::Tox_Conference_Type, cookie: *const u8, length: usize),
    |handler: &mut H| {
        let c = unsafe { slice::from_raw_parts(cookie, length) };
        handler.on_conference_invite(crate::types::FriendNumber(friend_number), _type.into(), c);
    }
);

define_dispatch!(
    dispatch_conference_connected,
    (conference_number: u32),
    |handler: &mut H| {
        handler.on_conference_connected(crate::types::ConferenceNumber(conference_number));
    }
);

define_dispatch!(
    dispatch_conference_message,
    (conference_number: u32, peer_number: u32, message_type: ffi::Tox_Message_Type, message: *const u8, length: usize),
    |handler: &mut H| {
        let msg = unsafe { slice::from_raw_parts(message, length) };
        handler.on_conference_message(
            crate::types::ConferenceNumber(conference_number),
            crate::types::ConferencePeerNumber(peer_number),
            message_type.into(),
            msg,
        );
    }
);

define_dispatch!(
    dispatch_conference_title,
    (conference_number: u32, peer_number: u32, title: *const u8, length: usize),
    |handler: &mut H| {
        let t = unsafe { slice::from_raw_parts(title, length) };
        handler.on_conference_title(
            crate::types::ConferenceNumber(conference_number),
            crate::types::ConferencePeerNumber(peer_number),
            t,
        );
    }
);

define_dispatch!(
    dispatch_conference_peer_name,
    (conference_number: u32, peer_number: u32, name: *const u8, length: usize),
    |handler: &mut H| {
        let n = unsafe { slice::from_raw_parts(name, length) };
        handler.on_conference_peer_name(
            crate::types::ConferenceNumber(conference_number),
            crate::types::ConferencePeerNumber(peer_number),
            n,
        );
    }
);

define_dispatch!(
    dispatch_conference_peer_list_changed,
    (conference_number: u32),
    |handler: &mut H| {
        handler.on_conference_peer_list_changed(crate::types::ConferenceNumber(conference_number));
    }
);

define_dispatch!(
    dispatch_friend_lossy_packet,
    (friend_number: u32, data: *const u8, length: usize),
    |handler: &mut H| {
        let d = unsafe { slice::from_raw_parts(data, length) };
        handler.on_friend_lossy_packet(crate::types::FriendNumber(friend_number), d);
    }
);

define_dispatch!(
    dispatch_friend_lossless_packet,
    (friend_number: u32, data: *const u8, length: usize),
    |handler: &mut H| {
        let d = unsafe { slice::from_raw_parts(data, length) };
        handler.on_friend_lossless_packet(crate::types::FriendNumber(friend_number), d);
    }
);

define_dispatch!(
    dispatch_group_invite,
    (friend_number: u32, invite_data: *const u8, invite_data_length: usize, group_name: *const u8, group_name_length: usize),
    |handler: &mut H| {
        let idata = unsafe { slice::from_raw_parts(invite_data, invite_data_length) };
        let gname = unsafe { slice::from_raw_parts(group_name, group_name_length) };
        handler.on_group_invite(crate::types::FriendNumber(friend_number), idata, gname);
    }
);

define_dispatch!(
    dispatch_group_message,
    (group_number: u32, peer_id: u32, message_type: ffi::Tox_Message_Type, message: *const u8, message_length: usize, message_id: u32),
    |handler: &mut H| {
        let msg = unsafe { slice::from_raw_parts(message, message_length) };
        handler.on_group_message(
            crate::types::GroupNumber(group_number),
            crate::types::GroupPeerNumber(peer_id),
            message_type.into(),
            msg,
            crate::types::GroupMessageId(message_id),
        );
    }
);

define_dispatch!(
    dispatch_group_private_message,
    (group_number: u32, peer_id: u32, message_type: ffi::Tox_Message_Type, message: *const u8, message_length: usize, message_id: u32),
    |handler: &mut H| {
        let msg = unsafe { slice::from_raw_parts(message, message_length) };
        handler.on_group_private_message(
            crate::types::GroupNumber(group_number),
            crate::types::GroupPeerNumber(peer_id),
            message_type.into(),
            msg,
            crate::types::GroupMessageId(message_id),
        );
    }
);

define_dispatch!(
    dispatch_group_custom_packet,
    (group_number: u32, peer_id: u32, data: *const u8, data_length: usize),
    |handler: &mut H| {
        let d = unsafe { slice::from_raw_parts(data, data_length) };
        handler.on_group_custom_packet(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id), d);
    }
);

define_dispatch!(
    dispatch_group_custom_private_packet,
    (group_number: u32, peer_id: u32, data: *const u8, data_length: usize),
    |handler: &mut H| {
        let d = unsafe { slice::from_raw_parts(data, data_length) };
        handler.on_group_custom_private_packet(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id), d);
    }
);

define_dispatch!(
    dispatch_group_peer_join,
    (group_number: u32, peer_id: u32),
    |handler: &mut H| {
        handler.on_group_peer_join(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id));
    }
);

define_dispatch!(
    dispatch_group_peer_exit,
    (group_number: u32, peer_id: u32, exit_type: ffi::Tox_Group_Exit_Type, name: *const u8, name_length: usize, part_message: *const u8, part_message_length: usize),
    |handler: &mut H| {
        let n = unsafe { slice::from_raw_parts(name, name_length) };
        let pm = unsafe { slice::from_raw_parts(part_message, part_message_length) };
        handler.on_group_peer_exit(
            crate::types::GroupNumber(group_number),
            crate::types::GroupPeerNumber(peer_id),
            exit_type.into(),
            n,
            pm,
        );
    }
);

define_dispatch!(
    dispatch_group_self_join,
    (group_number: u32),
    |handler: &mut H| {
        handler.on_group_self_join(crate::types::GroupNumber(group_number));
    }
);

define_dispatch!(
    dispatch_group_join_fail,
    (group_number: u32, fail_type: ffi::Tox_Group_Join_Fail),
    |handler: &mut H| {
        handler.on_group_join_fail(crate::types::GroupNumber(group_number), fail_type.into());
    }
);

define_dispatch!(
    dispatch_group_topic,
    (group_number: u32, peer_id: u32, topic: *const u8, topic_length: usize),
    |handler: &mut H| {
        let t = unsafe { slice::from_raw_parts(topic, topic_length) };
        handler.on_group_topic(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id), t);
    }
);

define_dispatch!(
    dispatch_group_privacy_state,
    (group_number: u32, privacy_state: ffi::Tox_Group_Privacy_State),
    |handler: &mut H| {
        handler.on_group_privacy_state(crate::types::GroupNumber(group_number), privacy_state.into());
    }
);

define_dispatch!(
    dispatch_group_voice_state,
    (group_number: u32, voice_state: ffi::Tox_Group_Voice_State),
    |handler: &mut H| {
        handler.on_group_voice_state(crate::types::GroupNumber(group_number), voice_state.into());
    }
);

define_dispatch!(
    dispatch_group_topic_lock,
    (group_number: u32, topic_lock: ffi::Tox_Group_Topic_Lock),
    |handler: &mut H| {
        handler.on_group_topic_lock(crate::types::GroupNumber(group_number), topic_lock.into());
    }
);

define_dispatch!(
    dispatch_group_peer_limit,
    (group_number: u32, peer_limit: u32),
    |handler: &mut H| {
        handler.on_group_peer_limit(crate::types::GroupNumber(group_number), peer_limit);
    }
);

define_dispatch!(
    dispatch_group_password,
    (group_number: u32, password: *const u8, password_length: usize),
    |handler: &mut H| {
        let p = unsafe { slice::from_raw_parts(password, password_length) };
        handler.on_group_password(crate::types::GroupNumber(group_number), p);
    }
);

define_dispatch!(
    dispatch_group_peer_name,
    (group_number: u32, peer_id: u32, name: *const u8, name_length: usize),
    |handler: &mut H| {
        let n = unsafe { slice::from_raw_parts(name, name_length) };
        handler.on_group_peer_name(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id), n);
    }
);

define_dispatch!(
    dispatch_group_peer_status,
    (group_number: u32, peer_id: u32, status: ffi::Tox_User_Status),
    |handler: &mut H| {
        handler.on_group_peer_status(crate::types::GroupNumber(group_number), crate::types::GroupPeerNumber(peer_id), status.into());
    }
);

define_dispatch!(
    dispatch_group_moderation,
    (group_number: u32, source_peer_id: u32, target_peer_id: u32, mod_type: ffi::Tox_Group_Mod_Event),
    |handler: &mut H| {
        handler.on_group_moderation(
            crate::types::GroupNumber(group_number),
            crate::types::GroupPeerNumber(source_peer_id),
            crate::types::GroupPeerNumber(target_peer_id),
            mod_type.into(),
        );
    }
);
