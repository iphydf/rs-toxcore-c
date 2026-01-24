use crate::ffi;
use serde::{Deserialize, Serialize};
use std::{error, ffi as std_ffi, fmt};

pub const ADDRESS_SIZE: usize = ffi::TOX_ADDRESS_SIZE as usize;

pub const PUBLIC_KEY_SIZE: usize = ffi::TOX_PUBLIC_KEY_SIZE as usize;
pub const SECRET_KEY_SIZE: usize = ffi::TOX_SECRET_KEY_SIZE as usize;

pub const MAX_NAME_LENGTH: usize = ffi::TOX_MAX_NAME_LENGTH as usize;
pub const MAX_STATUS_MESSAGE_LENGTH: usize = ffi::TOX_MAX_STATUS_MESSAGE_LENGTH as usize;
pub const MAX_FRIEND_REQUEST_LENGTH: usize = ffi::TOX_MAX_FRIEND_REQUEST_LENGTH as usize;
pub const MAX_MESSAGE_LENGTH: usize = ffi::TOX_MAX_MESSAGE_LENGTH as usize;

pub const HASH_LENGTH: usize = ffi::TOX_HASH_LENGTH as usize;
pub const FILE_ID_LENGTH: usize = ffi::TOX_FILE_ID_LENGTH as usize;
pub const MAX_FILENAME_LENGTH: usize = ffi::TOX_MAX_FILENAME_LENGTH as usize;
pub const MAX_CUSTOM_PACKET_SIZE: usize = ffi::TOX_MAX_CUSTOM_PACKET_SIZE as usize;
pub const CONFERENCE_ID_SIZE: usize = ffi::TOX_CONFERENCE_ID_SIZE as usize;

pub const GROUP_MAX_TOPIC_LENGTH: usize = ffi::TOX_GROUP_MAX_TOPIC_LENGTH as usize;
pub const GROUP_MAX_MESSAGE_LENGTH: usize = ffi::TOX_GROUP_MAX_MESSAGE_LENGTH as usize;
pub const GROUP_MAX_GROUP_NAME_LENGTH: usize = ffi::TOX_GROUP_MAX_GROUP_NAME_LENGTH as usize;
pub const GROUP_CHAT_ID_SIZE: usize = ffi::TOX_GROUP_CHAT_ID_SIZE as usize;

pub const PASS_SALT_LENGTH: usize = ffi::TOX_PASS_SALT_LENGTH as usize;
pub const PASS_ENCRYPTION_EXTRA_LENGTH: usize = ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize;

macro_rules! impl_byte_array_type {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $size]);

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&hex::encode(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let bytes = hex::decode(&s)
                    .ok_or_else(|| serde::de::Error::custom("Invalid hex string"))?;
                if bytes.len() != $size {
                    return Err(serde::de::Error::custom(format!(
                        "Invalid length for {}: expected {}, got {}",
                        stringify!($name),
                        $size,
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(&bytes);
                Ok($name(arr))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

macro_rules! impl_safe_newtype {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub u32);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! impl_tox_enum {
    ($name:ident, $ffi:path, { $($variant:ident),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum $name {
            $($variant),*
        }

        impl From<$ffi> for $name {
            fn from(e: $ffi) -> Self {
                match e {
                    $(<$ffi>::$variant => $name::$variant),*
                }
            }
        }

        impl From<$name> for $ffi {
            fn from(e: $name) -> Self {
                match e {
                    $($name::$variant => <$ffi>::$variant),*
                }
            }
        }
    };
}

// --- Safe Newtypes ---

impl_safe_newtype!(FriendNumber);
impl_safe_newtype!(GroupNumber);
impl_safe_newtype!(FileNumber);
impl_safe_newtype!(ConferenceNumber);
impl_safe_newtype!(ConferencePeerNumber);
impl_safe_newtype!(ConferenceOfflinePeerNumber);
impl_safe_newtype!(MessageId);
impl_safe_newtype!(FriendMessageId);
impl_safe_newtype!(GroupMessageId);
impl_safe_newtype!(GroupPeerNumber);

impl_byte_array_type!(Address, ADDRESS_SIZE);
impl_byte_array_type!(PublicKey, PUBLIC_KEY_SIZE);
impl_byte_array_type!(FileId, FILE_ID_LENGTH);
impl_byte_array_type!(ConferenceId, CONFERENCE_ID_SIZE);
impl_byte_array_type!(ChatId, GROUP_CHAT_ID_SIZE);

impl Address {
    pub fn from_public_key(pk: PublicKey, nospam: u32) -> Self {
        let mut arr = [0u8; ADDRESS_SIZE];
        arr[0..PUBLIC_KEY_SIZE].copy_from_slice(&pk.0);
        arr[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + 4].copy_from_slice(&nospam.to_be_bytes());

        let mut checksum = [0u8; 2];
        for i in (0..PUBLIC_KEY_SIZE + 4).step_by(2) {
            checksum[0] ^= arr[i];
            checksum[1] ^= arr[i + 1];
        }

        arr[ADDRESS_SIZE - 2] = checksum[0];
        arr[ADDRESS_SIZE - 1] = checksum[1];
        Address(arr)
    }

    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        pk.copy_from_slice(&self.0[0..PUBLIC_KEY_SIZE]);
        PublicKey(pk)
    }

    pub fn nospam(&self) -> u32 {
        u32::from_be_bytes(
            self.0[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + 4]
                .try_into()
                .unwrap(),
        )
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(
            self.0[PUBLIC_KEY_SIZE + 4..ADDRESS_SIZE]
                .try_into()
                .unwrap(),
        )
    }
}

impl_tox_enum!(ToxConferenceType, ffi::Tox_Conference_Type, {
    TOX_CONFERENCE_TYPE_TEXT,
    TOX_CONFERENCE_TYPE_AV,
});

impl_tox_enum!(ToxConnection, ffi::Tox_Connection, {
    TOX_CONNECTION_NONE,
    TOX_CONNECTION_TCP,
    TOX_CONNECTION_UDP,
});

impl_tox_enum!(ToxFileControl, ffi::Tox_File_Control, {
    TOX_FILE_CONTROL_RESUME,
    TOX_FILE_CONTROL_PAUSE,
    TOX_FILE_CONTROL_CANCEL,
});

impl_tox_enum!(ToxFileKind, ffi::Tox_File_Kind, {
    TOX_FILE_KIND_DATA,
    TOX_FILE_KIND_AVATAR,
});

impl_tox_enum!(ToxGroupExitType, ffi::Tox_Group_Exit_Type, {
    TOX_GROUP_EXIT_TYPE_QUIT,
    TOX_GROUP_EXIT_TYPE_KICK,
    TOX_GROUP_EXIT_TYPE_TIMEOUT,
    TOX_GROUP_EXIT_TYPE_DISCONNECTED,
    TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED,
    TOX_GROUP_EXIT_TYPE_SYNC_ERROR,
});

impl_tox_enum!(ToxGroupJoinFail, ffi::Tox_Group_Join_Fail, {
    TOX_GROUP_JOIN_FAIL_PEER_LIMIT,
    TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD,
    TOX_GROUP_JOIN_FAIL_UNKNOWN,
});

impl_tox_enum!(ToxGroupModEvent, ffi::Tox_Group_Mod_Event, {
    TOX_GROUP_MOD_EVENT_KICK,
    TOX_GROUP_MOD_EVENT_OBSERVER,
    TOX_GROUP_MOD_EVENT_USER,
    TOX_GROUP_MOD_EVENT_MODERATOR,
});

impl_tox_enum!(ToxGroupPrivacyState, ffi::Tox_Group_Privacy_State, {
    TOX_GROUP_PRIVACY_STATE_PUBLIC,
    TOX_GROUP_PRIVACY_STATE_PRIVATE,
});

impl_tox_enum!(ToxGroupRole, ffi::Tox_Group_Role, {
    TOX_GROUP_ROLE_FOUNDER,
    TOX_GROUP_ROLE_MODERATOR,
    TOX_GROUP_ROLE_USER,
    TOX_GROUP_ROLE_OBSERVER,
});

impl_tox_enum!(ToxGroupTopicLock, ffi::Tox_Group_Topic_Lock, {
    TOX_GROUP_TOPIC_LOCK_ENABLED,
    TOX_GROUP_TOPIC_LOCK_DISABLED,
});

impl_tox_enum!(ToxGroupVoiceState, ffi::Tox_Group_Voice_State, {
    TOX_GROUP_VOICE_STATE_ALL,
    TOX_GROUP_VOICE_STATE_MODERATOR,
    TOX_GROUP_VOICE_STATE_FOUNDER,
});

impl_tox_enum!(ToxLogLevel, ffi::Tox_Log_Level, {
    TOX_LOG_LEVEL_TRACE,
    TOX_LOG_LEVEL_DEBUG,
    TOX_LOG_LEVEL_INFO,
    TOX_LOG_LEVEL_WARNING,
    TOX_LOG_LEVEL_ERROR,
});

impl_tox_enum!(ToxProxyType, ffi::Tox_Proxy_Type, {
    TOX_PROXY_TYPE_NONE,
    TOX_PROXY_TYPE_HTTP,
    TOX_PROXY_TYPE_SOCKS5,
});

impl_tox_enum!(ToxSavedataType, ffi::Tox_Savedata_Type, {
    TOX_SAVEDATA_TYPE_NONE,
    TOX_SAVEDATA_TYPE_TOX_SAVE,
    TOX_SAVEDATA_TYPE_SECRET_KEY,
});

impl_tox_enum!(ToxUserStatus, ffi::Tox_User_Status, {
    TOX_USER_STATUS_NONE,
    TOX_USER_STATUS_AWAY,
    TOX_USER_STATUS_BUSY,
});

impl_tox_enum!(ToxavCallControl, ffi::Toxav_Call_Control, {
    TOXAV_CALL_CONTROL_RESUME,
    TOXAV_CALL_CONTROL_PAUSE,
    TOXAV_CALL_CONTROL_CANCEL,
    TOXAV_CALL_CONTROL_HIDE_VIDEO,
    TOXAV_CALL_CONTROL_SHOW_VIDEO,
    TOXAV_CALL_CONTROL_MUTE_AUDIO,
    TOXAV_CALL_CONTROL_UNMUTE_AUDIO,
});

impl_tox_enum!(ToxavFriendCallState, ffi::Toxav_Friend_Call_State, {
    TOXAV_FRIEND_CALL_STATE_NONE,
    TOXAV_FRIEND_CALL_STATE_ERROR,
    TOXAV_FRIEND_CALL_STATE_FINISHED,
    TOXAV_FRIEND_CALL_STATE_SENDING_A,
    TOXAV_FRIEND_CALL_STATE_SENDING_V,
    TOXAV_FRIEND_CALL_STATE_ACCEPTING_A,
    TOXAV_FRIEND_CALL_STATE_ACCEPTING_V,
});

impl_tox_enum!(Tox_Err_New, ffi::Tox_Err_New, {
    TOX_ERR_NEW_OK,
    TOX_ERR_NEW_NULL,
    TOX_ERR_NEW_MALLOC,
    TOX_ERR_NEW_PORT_ALLOC,
    TOX_ERR_NEW_PROXY_BAD_TYPE,
    TOX_ERR_NEW_PROXY_BAD_HOST,
    TOX_ERR_NEW_PROXY_BAD_PORT,
    TOX_ERR_NEW_PROXY_NOT_FOUND,
    TOX_ERR_NEW_LOAD_ENCRYPTED,
    TOX_ERR_NEW_LOAD_BAD_FORMAT,
});

impl_tox_enum!(Tox_Err_Options_New, ffi::Tox_Err_Options_New, {
    TOX_ERR_OPTIONS_NEW_OK,
    TOX_ERR_OPTIONS_NEW_MALLOC,
});

impl_tox_enum!(Tox_Err_Bootstrap, ffi::Tox_Err_Bootstrap, {
    TOX_ERR_BOOTSTRAP_OK,
    TOX_ERR_BOOTSTRAP_NULL,
    TOX_ERR_BOOTSTRAP_BAD_HOST,
    TOX_ERR_BOOTSTRAP_BAD_PORT,
});

impl_tox_enum!(Tox_Err_Set_Info, ffi::Tox_Err_Set_Info, {
    TOX_ERR_SET_INFO_OK,
    TOX_ERR_SET_INFO_NULL,
    TOX_ERR_SET_INFO_TOO_LONG,
});

impl_tox_enum!(Tox_Err_Friend_Add, ffi::Tox_Err_Friend_Add, {
    TOX_ERR_FRIEND_ADD_OK,
    TOX_ERR_FRIEND_ADD_NULL,
    TOX_ERR_FRIEND_ADD_TOO_LONG,
    TOX_ERR_FRIEND_ADD_NO_MESSAGE,
    TOX_ERR_FRIEND_ADD_OWN_KEY,
    TOX_ERR_FRIEND_ADD_ALREADY_SENT,
    TOX_ERR_FRIEND_ADD_BAD_CHECKSUM,
    TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM,
    TOX_ERR_FRIEND_ADD_MALLOC,
});

impl_tox_enum!(Tox_Err_Friend_Delete, ffi::Tox_Err_Friend_Delete, {
    TOX_ERR_FRIEND_DELETE_OK,
    TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Friend_By_Public_Key, ffi::Tox_Err_Friend_By_Public_Key, {
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK,
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL,
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND,
});

impl_tox_enum!(Toxav_Err_New, ffi::Toxav_Err_New, {
    TOXAV_ERR_NEW_OK,
    TOXAV_ERR_NEW_NULL,
    TOXAV_ERR_NEW_MALLOC,
    TOXAV_ERR_NEW_MULTIPLE,
});

impl_tox_enum!(Toxav_Err_Call, ffi::Toxav_Err_Call, {
    TOXAV_ERR_CALL_OK,
    TOXAV_ERR_CALL_MALLOC,
    TOXAV_ERR_CALL_SYNC,
    TOXAV_ERR_CALL_FRIEND_NOT_FOUND,
    TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED,
    TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL,
    TOXAV_ERR_CALL_INVALID_BIT_RATE,
});

impl_tox_enum!(Toxav_Err_Answer, ffi::Toxav_Err_Answer, {
    TOXAV_ERR_ANSWER_OK,
    TOXAV_ERR_ANSWER_SYNC,
    TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND,
    TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING,
    TOXAV_ERR_ANSWER_INVALID_BIT_RATE,
    TOXAV_ERR_ANSWER_CODEC_INITIALIZATION,
});

impl_tox_enum!(Toxav_Err_Call_Control, ffi::Toxav_Err_Call_Control, {
    TOXAV_ERR_CALL_CONTROL_OK,
    TOXAV_ERR_CALL_CONTROL_SYNC,
    TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND,
    TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL,
    TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION,
});

impl_tox_enum!(Toxav_Err_Bit_Rate_Set, ffi::Toxav_Err_Bit_Rate_Set, {
    TOXAV_ERR_BIT_RATE_SET_OK,
    TOXAV_ERR_BIT_RATE_SET_SYNC,
    TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND,
    TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL,
    TOXAV_ERR_BIT_RATE_SET_INVALID_BIT_RATE,
});

impl_tox_enum!(Toxav_Err_Send_Frame, ffi::Toxav_Err_Send_Frame, {
    TOXAV_ERR_SEND_FRAME_OK,
    TOXAV_ERR_SEND_FRAME_NULL,
    TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND,
    TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL,
    TOXAV_ERR_SEND_FRAME_SYNC,
    TOXAV_ERR_SEND_FRAME_INVALID,
    TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED,
    TOXAV_ERR_SEND_FRAME_RTP_FAILED,
});

impl_tox_enum!(Tox_Err_Conference_New, ffi::Tox_Err_Conference_New, {
    TOX_ERR_CONFERENCE_NEW_OK,
    TOX_ERR_CONFERENCE_NEW_INIT,
});

impl_tox_enum!(Tox_Err_Conference_Delete, ffi::Tox_Err_Conference_Delete, {
    TOX_ERR_CONFERENCE_DELETE_OK,
    TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Conference_Peer_Query, ffi::Tox_Err_Conference_Peer_Query, {
    TOX_ERR_CONFERENCE_PEER_QUERY_OK,
    TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND,
    TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND,
    TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION,
});

impl_tox_enum!(Tox_Err_Conference_Set_Max_Offline, ffi::Tox_Err_Conference_Set_Max_Offline, {
    TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK,
    TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_CONFERENCE_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Conference_Invite, ffi::Tox_Err_Conference_Invite, {
    TOX_ERR_CONFERENCE_INVITE_OK,
    TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND,
    TOX_ERR_CONFERENCE_INVITE_NO_CONNECTION,
    TOX_ERR_CONFERENCE_INVITE_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Conference_Join, ffi::Tox_Err_Conference_Join, {
    TOX_ERR_CONFERENCE_JOIN_OK,
    TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH,
    TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND,
    TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE,
    TOX_ERR_CONFERENCE_JOIN_DUPLICATE,
    TOX_ERR_CONFERENCE_JOIN_INIT_FAIL,
    TOX_ERR_CONFERENCE_JOIN_FAIL_SEND,
    TOX_ERR_CONFERENCE_JOIN_NULL,
});

impl_tox_enum!(Tox_Err_Conference_Send_Message, ffi::Tox_Err_Conference_Send_Message, {
    TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,
    TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND,
    TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG,
    TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION,
    TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Conference_Title, ffi::Tox_Err_Conference_Title, {
    TOX_ERR_CONFERENCE_TITLE_OK,
    TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND,
    TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH,
    TOX_ERR_CONFERENCE_TITLE_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Conference_Get_Type, ffi::Tox_Err_Conference_Get_Type, {
    TOX_ERR_CONFERENCE_GET_TYPE_OK,
    TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Conference_By_Id, ffi::Tox_Err_Conference_By_Id, {
    TOX_ERR_CONFERENCE_BY_ID_OK,
    TOX_ERR_CONFERENCE_BY_ID_NULL,
    TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Conference_By_Uid, ffi::Tox_Err_Conference_By_Uid, {
    TOX_ERR_CONFERENCE_BY_UID_OK,
    TOX_ERR_CONFERENCE_BY_UID_NULL,
    TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Friend_Get_Public_Key, ffi::Tox_Err_Friend_Get_Public_Key, {
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK,
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Friend_Get_Last_Online, ffi::Tox_Err_Friend_Get_Last_Online, {
    TOX_ERR_FRIEND_GET_LAST_ONLINE_OK,
    TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Set_Typing, ffi::Tox_Err_Set_Typing, {
    TOX_ERR_SET_TYPING_OK,
    TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Friend_Query, ffi::Tox_Err_Friend_Query, {
    TOX_ERR_FRIEND_QUERY_OK,
    TOX_ERR_FRIEND_QUERY_NULL,
    TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Friend_Send_Message, ffi::Tox_Err_Friend_Send_Message, {
    TOX_ERR_FRIEND_SEND_MESSAGE_OK,
    TOX_ERR_FRIEND_SEND_MESSAGE_NULL,
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND,
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED,
    TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ,
    TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG,
    TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY,
});

impl_tox_enum!(Tox_Err_File_Control, ffi::Tox_Err_File_Control, {
    TOX_ERR_FILE_CONTROL_OK,
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND,
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED,
    TOX_ERR_FILE_CONTROL_NOT_FOUND,
    TOX_ERR_FILE_CONTROL_NOT_PAUSED,
    TOX_ERR_FILE_CONTROL_DENIED,
    TOX_ERR_FILE_CONTROL_ALREADY_PAUSED,
    TOX_ERR_FILE_CONTROL_SENDQ,
});

impl_tox_enum!(Tox_Err_File_Seek, ffi::Tox_Err_File_Seek, {
    TOX_ERR_FILE_SEEK_OK,
    TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND,
    TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED,
    TOX_ERR_FILE_SEEK_NOT_FOUND,
    TOX_ERR_FILE_SEEK_DENIED,
    TOX_ERR_FILE_SEEK_INVALID_POSITION,
    TOX_ERR_FILE_SEEK_SENDQ,
});

impl_tox_enum!(Tox_Err_File_Get, ffi::Tox_Err_File_Get, {
    TOX_ERR_FILE_GET_OK,
    TOX_ERR_FILE_GET_NULL,
    TOX_ERR_FILE_GET_FRIEND_NOT_FOUND,
    TOX_ERR_FILE_GET_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_File_By_Id, ffi::Tox_Err_File_By_Id, {
    TOX_ERR_FILE_BY_ID_OK,
    TOX_ERR_FILE_BY_ID_NULL,
    TOX_ERR_FILE_BY_ID_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_File_Send, ffi::Tox_Err_File_Send, {
    TOX_ERR_FILE_SEND_OK,
    TOX_ERR_FILE_SEND_NULL,
    TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND,
    TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED,
    TOX_ERR_FILE_SEND_NAME_TOO_LONG,
    TOX_ERR_FILE_SEND_TOO_MANY,
});

impl_tox_enum!(Tox_Err_File_Send_Chunk, ffi::Tox_Err_File_Send_Chunk, {
    TOX_ERR_FILE_SEND_CHUNK_OK,
    TOX_ERR_FILE_SEND_CHUNK_NULL,
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND,
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED,
    TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND,
    TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING,
    TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH,
    TOX_ERR_FILE_SEND_CHUNK_SENDQ,
    TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION,
});

impl_tox_enum!(Tox_Err_Friend_Custom_Packet, ffi::Tox_Err_Friend_Custom_Packet, {
    TOX_ERR_FRIEND_CUSTOM_PACKET_OK,
    TOX_ERR_FRIEND_CUSTOM_PACKET_NULL,
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND,
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED,
    TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID,
    TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY,
    TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG,
    TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ,
});

impl_tox_enum!(Tox_Err_Group_New, ffi::Tox_Err_Group_New, {
    TOX_ERR_GROUP_NEW_OK,
    TOX_ERR_GROUP_NEW_TOO_LONG,
    TOX_ERR_GROUP_NEW_EMPTY,
    TOX_ERR_GROUP_NEW_INIT,
    TOX_ERR_GROUP_NEW_STATE,
    TOX_ERR_GROUP_NEW_ANNOUNCE,
});

impl_tox_enum!(Tox_Err_Group_Join, ffi::Tox_Err_Group_Join, {
    TOX_ERR_GROUP_JOIN_OK,
    TOX_ERR_GROUP_JOIN_BAD_CHAT_ID,
    TOX_ERR_GROUP_JOIN_INIT,
    TOX_ERR_GROUP_JOIN_EMPTY,
    TOX_ERR_GROUP_JOIN_TOO_LONG,
    TOX_ERR_GROUP_JOIN_PASSWORD,
    TOX_ERR_GROUP_JOIN_CORE,
});

impl_tox_enum!(Tox_Err_Group_Leave, ffi::Tox_Err_Group_Leave, {
    TOX_ERR_GROUP_LEAVE_OK,
    TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_LEAVE_TOO_LONG,
    TOX_ERR_GROUP_LEAVE_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Group_State_Query, ffi::Tox_Err_Group_State_Query, {
    TOX_ERR_GROUP_STATE_QUERY_OK,
    TOX_ERR_GROUP_STATE_QUERY_GROUP_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Group_Invite_Friend, ffi::Tox_Err_Group_Invite_Friend, {
    TOX_ERR_GROUP_INVITE_FRIEND_OK,
    TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND,
    TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL,
    TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND,
    TOX_ERR_GROUP_INVITE_FRIEND_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Invite_Accept, ffi::Tox_Err_Group_Invite_Accept, {
    TOX_ERR_GROUP_INVITE_ACCEPT_OK,
    TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE,
    TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED,
    TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG,
    TOX_ERR_GROUP_INVITE_ACCEPT_EMPTY,
    TOX_ERR_GROUP_INVITE_ACCEPT_PASSWORD,
    TOX_ERR_GROUP_INVITE_ACCEPT_FRIEND_NOT_FOUND,
    TOX_ERR_GROUP_INVITE_ACCEPT_FAIL_SEND,
    TOX_ERR_GROUP_INVITE_ACCEPT_NULL,
});

impl_tox_enum!(Tox_Err_Group_Set_Password, ffi::Tox_Err_Group_Set_Password, {
    TOX_ERR_GROUP_SET_PASSWORD_OK,
    TOX_ERR_GROUP_SET_PASSWORD_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_PASSWORD_PERMISSIONS,
    TOX_ERR_GROUP_SET_PASSWORD_TOO_LONG,
    TOX_ERR_GROUP_SET_PASSWORD_FAIL_SEND,
    TOX_ERR_GROUP_SET_PASSWORD_MALLOC,
    TOX_ERR_GROUP_SET_PASSWORD_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Set_Topic_Lock, ffi::Tox_Err_Group_Set_Topic_Lock, {
    TOX_ERR_GROUP_SET_TOPIC_LOCK_OK,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_INVALID,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_PERMISSIONS,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_FAIL_SET,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_FAIL_SEND,
    TOX_ERR_GROUP_SET_TOPIC_LOCK_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Set_Voice_State, ffi::Tox_Err_Group_Set_Voice_State, {
    TOX_ERR_GROUP_SET_VOICE_STATE_OK,
    TOX_ERR_GROUP_SET_VOICE_STATE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_VOICE_STATE_FAIL_SET,
    TOX_ERR_GROUP_SET_VOICE_STATE_PERMISSIONS,
    TOX_ERR_GROUP_SET_VOICE_STATE_FAIL_SEND,
    TOX_ERR_GROUP_SET_VOICE_STATE_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Set_Privacy_State, ffi::Tox_Err_Group_Set_Privacy_State, {
    TOX_ERR_GROUP_SET_PRIVACY_STATE_OK,
    TOX_ERR_GROUP_SET_PRIVACY_STATE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_PRIVACY_STATE_FAIL_SET,
    TOX_ERR_GROUP_SET_PRIVACY_STATE_PERMISSIONS,
    TOX_ERR_GROUP_SET_PRIVACY_STATE_FAIL_SEND,
    TOX_ERR_GROUP_SET_PRIVACY_STATE_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Set_Peer_Limit, ffi::Tox_Err_Group_Set_Peer_Limit, {
    TOX_ERR_GROUP_SET_PEER_LIMIT_OK,
    TOX_ERR_GROUP_SET_PEER_LIMIT_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_PEER_LIMIT_FAIL_SET,
    TOX_ERR_GROUP_SET_PEER_LIMIT_PERMISSIONS,
    TOX_ERR_GROUP_SET_PEER_LIMIT_FAIL_SEND,
    TOX_ERR_GROUP_SET_PEER_LIMIT_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Set_Ignore, ffi::Tox_Err_Group_Set_Ignore, {
    TOX_ERR_GROUP_SET_IGNORE_OK,
    TOX_ERR_GROUP_SET_IGNORE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_IGNORE_PEER_NOT_FOUND,
    TOX_ERR_GROUP_SET_IGNORE_SELF,
});

impl_tox_enum!(Tox_Err_Group_Set_Role, ffi::Tox_Err_Group_Set_Role, {
    TOX_ERR_GROUP_SET_ROLE_OK,
    TOX_ERR_GROUP_SET_ROLE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SET_ROLE_PEER_NOT_FOUND,
    TOX_ERR_GROUP_SET_ROLE_ASSIGNMENT,
    TOX_ERR_GROUP_SET_ROLE_PERMISSIONS,
    TOX_ERR_GROUP_SET_ROLE_FAIL_ACTION,
    TOX_ERR_GROUP_SET_ROLE_SELF,
});

impl_tox_enum!(Tox_Err_Group_Kick_Peer, ffi::Tox_Err_Group_Kick_Peer, {
    TOX_ERR_GROUP_KICK_PEER_OK,
    TOX_ERR_GROUP_KICK_PEER_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_KICK_PEER_PEER_NOT_FOUND,
    TOX_ERR_GROUP_KICK_PEER_FAIL_SEND,
    TOX_ERR_GROUP_KICK_PEER_PERMISSIONS,
    TOX_ERR_GROUP_KICK_PEER_FAIL_ACTION,
    TOX_ERR_GROUP_KICK_PEER_SELF,
});

impl_tox_enum!(Tox_Err_Group_Is_Connected, ffi::Tox_Err_Group_Is_Connected, {
    TOX_ERR_GROUP_IS_CONNECTED_OK,
    TOX_ERR_GROUP_IS_CONNECTED_GROUP_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Group_Disconnect, ffi::Tox_Err_Group_Disconnect, {
    TOX_ERR_GROUP_DISCONNECT_OK,
    TOX_ERR_GROUP_DISCONNECT_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_DISCONNECT_ALREADY_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Self_Name_Set, ffi::Tox_Err_Group_Self_Name_Set, {
    TOX_ERR_GROUP_SELF_NAME_SET_OK,
    TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG,
    TOX_ERR_GROUP_SELF_NAME_SET_INVALID,
    TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Group_Self_Query, ffi::Tox_Err_Group_Self_Query, {
    TOX_ERR_GROUP_SELF_QUERY_OK,
    TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Group_Self_Status_Set, ffi::Tox_Err_Group_Self_Status_Set, {
    TOX_ERR_GROUP_SELF_STATUS_SET_OK,
    TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Group_Peer_Query, ffi::Tox_Err_Group_Peer_Query, {
    TOX_ERR_GROUP_PEER_QUERY_OK,
    TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Group_Topic_Set, ffi::Tox_Err_Group_Topic_Set, {
    TOX_ERR_GROUP_TOPIC_SET_OK,
    TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_TOPIC_SET_TOO_LONG,
    TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS,
    TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE,
    TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND,
    TOX_ERR_GROUP_TOPIC_SET_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Send_Message, ffi::Tox_Err_Group_Send_Message, {
    TOX_ERR_GROUP_SEND_MESSAGE_OK,
    TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG,
    TOX_ERR_GROUP_SEND_MESSAGE_EMPTY,
    TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE,
    TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS,
    TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND,
    TOX_ERR_GROUP_SEND_MESSAGE_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Send_Private_Message, ffi::Tox_Err_Group_Send_Private_Message, {
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_BAD_TYPE,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND,
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_Send_Custom_Packet, ffi::Tox_Err_Group_Send_Custom_Packet, {
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK,
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG,
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY,
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_DISCONNECTED,
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_FAIL_SEND,
});

impl_tox_enum!(Tox_Err_Group_Send_Custom_Private_Packet, ffi::Tox_Err_Group_Send_Custom_Private_Packet, {
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_GROUP_NOT_FOUND,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_TOO_LONG,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_EMPTY,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PEER_NOT_FOUND,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_FAIL_SEND,
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_DISCONNECTED,
});

impl_tox_enum!(Tox_Err_Group_By_Id, ffi::Tox_Err_Group_By_Id, {
    TOX_ERR_GROUP_BY_ID_OK,
    TOX_ERR_GROUP_BY_ID_NULL,
    TOX_ERR_GROUP_BY_ID_NOT_FOUND,
});

impl_tox_enum!(Tox_Err_Key_Derivation, ffi::Tox_Err_Key_Derivation, {
    TOX_ERR_KEY_DERIVATION_OK,
    TOX_ERR_KEY_DERIVATION_NULL,
    TOX_ERR_KEY_DERIVATION_FAILED,
});

impl_tox_enum!(Tox_Err_Encryption, ffi::Tox_Err_Encryption, {
    TOX_ERR_ENCRYPTION_OK,
    TOX_ERR_ENCRYPTION_NULL,
    TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED,
    TOX_ERR_ENCRYPTION_FAILED,
});

impl_tox_enum!(Tox_Err_Decryption, ffi::Tox_Err_Decryption, {
    TOX_ERR_DECRYPTION_OK,
    TOX_ERR_DECRYPTION_NULL,
    TOX_ERR_DECRYPTION_INVALID_LENGTH,
    TOX_ERR_DECRYPTION_BAD_FORMAT,
    TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED,
    TOX_ERR_DECRYPTION_FAILED,
});

impl_tox_enum!(Tox_Err_Get_Salt, ffi::Tox_Err_Get_Salt, {
    TOX_ERR_GET_SALT_OK,
    TOX_ERR_GET_SALT_NULL,
    TOX_ERR_GET_SALT_BAD_FORMAT,
});

impl_tox_enum!(Tox_Err_Get_Port, ffi::Tox_Err_Get_Port, {
    TOX_ERR_GET_PORT_OK,
    TOX_ERR_GET_PORT_NOT_BOUND,
});

impl_tox_enum!(Tox_Err_Events_Iterate, ffi::Tox_Err_Events_Iterate, {
    TOX_ERR_EVENTS_ITERATE_OK,
    TOX_ERR_EVENTS_ITERATE_MALLOC,
});

impl_tox_enum!(MessageType, ffi::Tox_Message_Type, {
    TOX_MESSAGE_TYPE_NORMAL,
    TOX_MESSAGE_TYPE_ACTION,
});

// --- Safe Results ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToxError {
    New(Tox_Err_New),
    OptionsNew(Tox_Err_Options_New),
    Bootstrap(Tox_Err_Bootstrap),
    SetInfo(Tox_Err_Set_Info),
    FriendAdd(Tox_Err_Friend_Add),
    FriendDelete(Tox_Err_Friend_Delete),
    FriendByPublicKey(Tox_Err_Friend_By_Public_Key),
    FriendSendMessage(Tox_Err_Friend_Send_Message),
    FriendQuery(Tox_Err_Friend_Query),
    FriendGetPublicKey(Tox_Err_Friend_Get_Public_Key),
    FriendGetLastOnline(Tox_Err_Friend_Get_Last_Online),
    SetTyping(Tox_Err_Set_Typing),
    FriendCustomPacket(Tox_Err_Friend_Custom_Packet),
    FileSend(Tox_Err_File_Send),
    FileControl(Tox_Err_File_Control),
    FileSeek(Tox_Err_File_Seek),
    FileGet(Tox_Err_File_Get),
    FileById(Tox_Err_File_By_Id),
    FileSendChunk(Tox_Err_File_Send_Chunk),
    ConferenceNew(Tox_Err_Conference_New),
    ConferenceDelete(Tox_Err_Conference_Delete),
    ConferencePeerQuery(Tox_Err_Conference_Peer_Query),
    ConferenceSetMaxOffline(Tox_Err_Conference_Set_Max_Offline),
    ConferenceInvite(Tox_Err_Conference_Invite),
    ConferenceJoin(Tox_Err_Conference_Join),
    ConferenceSendMessage(Tox_Err_Conference_Send_Message),
    ConferenceTitle(Tox_Err_Conference_Title),
    ConferenceGetType(Tox_Err_Conference_Get_Type),
    ConferenceById(Tox_Err_Conference_By_Id),
    GroupNew(Tox_Err_Group_New),
    GroupJoin(Tox_Err_Group_Join),
    GroupLeave(Tox_Err_Group_Leave),
    GroupSendMessage(Tox_Err_Group_Send_Message),
    GroupStateQuery(Tox_Err_Group_State_Query),
    GroupInviteFriend(Tox_Err_Group_Invite_Friend),
    GroupInviteAccept(Tox_Err_Group_Invite_Accept),
    GroupSendPrivateMessage(Tox_Err_Group_Send_Private_Message),
    GroupSendCustomPacket(Tox_Err_Group_Send_Custom_Packet),
    GroupSendCustomPrivatePacket(Tox_Err_Group_Send_Custom_Private_Packet),
    GroupSetPassword(Tox_Err_Group_Set_Password),
    GroupSetTopicLock(Tox_Err_Group_Set_Topic_Lock),
    GroupSetVoiceState(Tox_Err_Group_Set_Voice_State),
    GroupSetPrivacyState(Tox_Err_Group_Set_Privacy_State),
    GroupSetPeerLimit(Tox_Err_Group_Set_Peer_Limit),
    GroupSetIgnore(Tox_Err_Group_Set_Ignore),
    GroupSetRole(Tox_Err_Group_Set_Role),
    GroupKickPeer(Tox_Err_Group_Kick_Peer),
    GroupIsConnected(Tox_Err_Group_Is_Connected),
    GroupDisconnect(Tox_Err_Group_Disconnect),
    GroupSelfNameSet(Tox_Err_Group_Self_Name_Set),
    GroupSelfQuery(Tox_Err_Group_Self_Query),
    GroupSelfStatusSet(Tox_Err_Group_Self_Status_Set),
    GroupPeerQuery(Tox_Err_Group_Peer_Query),
    GroupTopicSet(Tox_Err_Group_Topic_Set),
    GroupById(Tox_Err_Group_By_Id),
    GetPort(Tox_Err_Get_Port),
    EventsIterate(Tox_Err_Events_Iterate),
    AvNew(Toxav_Err_New),
    AvCall(Toxav_Err_Call),
    AvAnswer(Toxav_Err_Answer),
    AvCallControl(Toxav_Err_Call_Control),
    AvBitRateSet(Toxav_Err_Bit_Rate_Set),
    AvSendFrame(Toxav_Err_Send_Frame),
    AvGroupError,
    KeyDerivation(Tox_Err_Key_Derivation),
    Encryption(Tox_Err_Encryption),
    Decryption(Tox_Err_Decryption),
    GetSalt(Tox_Err_Get_Salt),
    InvalidString(std_ffi::NulError),
}

impl error::Error for ToxError {}
impl fmt::Display for ToxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type Result<T> = std::result::Result<T, ToxError>;

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }
}
