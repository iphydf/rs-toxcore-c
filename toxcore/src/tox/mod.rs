use crate::core;
use crate::toxav::ToxAVConferenceHandler;
pub use crate::types::*;

mod conference;
mod conference_scope;
pub mod encryptsave;
pub mod events;
mod file;
mod friend;
mod group;

pub use conference::Conference;
pub use conference_scope::ConferenceAvScope;
use events::ToxEvents;
pub use file::File;
pub use friend::Friend;
pub use group::Group;

// Re-export traits
pub use crate::core::ToxHandler;
pub use crate::core::ToxLogger;

pub struct Options {
    inner: core::Options,
}

impl Options {
    pub fn new() -> Result<Self> {
        let inner = core::Options::new().map_err(ToxError::OptionsNew)?;
        // Default experimental options that were in the original code
        let mut opts = Options { inner };
        opts.set_experimental_owned_data(true);
        Ok(opts)
    }

    pub fn set_ipv6_enabled(&mut self, enabled: bool) {
        self.inner.ipv6_enabled(enabled);
    }

    pub fn set_start_port(&mut self, port: u16) {
        self.inner.start_port(port);
    }

    pub fn set_end_port(&mut self, port: u16) {
        self.inner.end_port(port);
    }

    pub fn set_udp_enabled(&mut self, enabled: bool) {
        self.inner.udp_enabled(enabled);
    }

    pub fn set_local_discovery_enabled(&mut self, enabled: bool) {
        self.inner.local_discovery_enabled(enabled);
    }

    pub fn set_dht_announcements_enabled(&mut self, enabled: bool) {
        self.inner.dht_announcements_enabled(enabled);
    }

    pub fn set_proxy_type(&mut self, proxy_type: ToxProxyType) {
        self.inner.proxy_type(proxy_type.into());
    }

    pub fn set_proxy_host(&mut self, host: &str) -> Result<()> {
        self.inner.proxy_host(host);
        Ok(())
    }

    pub fn set_proxy_port(&mut self, port: u16) {
        self.inner.proxy_port(port);
    }

    pub fn set_tcp_port(&mut self, port: u16) {
        self.inner.tcp_port(port);
    }

    pub fn set_hole_punching_enabled(&mut self, enabled: bool) {
        self.inner.hole_punching_enabled(enabled);
    }

    pub fn set_savedata_type(&mut self, savedata_type: ToxSavedataType) {
        self.inner.savedata_type(savedata_type.into());
    }

    pub fn set_savedata_data(&mut self, data: &[u8]) -> Result<()> {
        self.inner.savedata_data(data);
        Ok(())
    }

    pub fn set_experimental_thread_safety(&mut self, enabled: bool) {
        self.inner.experimental_thread_safety(enabled);
    }

    pub fn set_experimental_groups_persistence(&mut self, enabled: bool) {
        self.inner.experimental_groups_persistence(enabled);
    }

    pub fn set_experimental_disable_dns(&mut self, enabled: bool) {
        self.inner.experimental_disable_dns(enabled);
    }

    pub fn set_experimental_owned_data(&mut self, enabled: bool) {
        self.inner.experimental_owned_data(enabled);
    }

    pub fn set_logger<L: ToxLogger + 'static>(&mut self, logger: L) {
        self.inner.set_logger(logger);
    }
}

pub(crate) struct Inner {
    pub(crate) core: core::Tox,
    #[allow(dead_code)] // Kept for ownership
    _options: Option<Options>,
}

pub struct Tox {
    pub(crate) inner: Inner,
}

impl Tox {
    pub fn new(options: Options) -> Result<Self> {
        let core = core::Tox::new(&options.inner).map_err(ToxError::New)?;
        Ok(Tox {
            inner: Inner {
                core,
                _options: Some(options),
            },
        })
    }

    pub fn iterate<H: ToxHandler>(&self, handler: &mut H) {
        core::tox_iterate(&self.inner.core, handler);
    }

    pub fn events(&self) -> Result<ToxEvents<'_>> {
        self.inner.core.events_init();
        self.inner
            .core
            .events_iterate(true)
            .map_err(ToxError::EventsIterate)
    }

    pub fn bootstrap(&self, host: &str, port: u16, public_key: &PublicKey) -> Result<()> {
        self.inner
            .core
            .bootstrap(host, port, public_key)
            .map_err(ToxError::Bootstrap)
    }

    pub fn address(&self) -> Address {
        self.inner.core.self_get_address()
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.core.self_get_public_key()
    }

    pub fn dht_id(&self) -> PublicKey {
        self.inner.core.self_get_dht_id()
    }

    pub fn udp_port(&self) -> Result<u16> {
        self.inner
            .core
            .self_get_udp_port()
            .map_err(ToxError::GetPort)
    }

    pub fn tcp_port(&self) -> Result<u16> {
        self.inner
            .core
            .self_get_tcp_port()
            .map_err(ToxError::GetPort)
    }

    pub fn savedata(&self) -> Vec<u8> {
        self.inner.core.get_savedata()
    }

    pub fn secret_key(&self) -> [u8; SECRET_KEY_SIZE] {
        self.inner.core.self_get_secret_key()
    }

    pub fn set_nospam(&self, nospam: u32) {
        self.inner.core.self_set_nospam(nospam);
    }

    pub fn nospam(&self) -> u32 {
        self.inner.core.self_get_nospam()
    }

    pub fn add_tcp_relay(&self, host: &str, port: u16, public_key: &PublicKey) -> Result<()> {
        self.inner
            .core
            .add_tcp_relay(host, port, public_key)
            .map_err(ToxError::Bootstrap)
    }

    pub fn hash(data: &[u8]) -> [u8; HASH_LENGTH] {
        core::Tox::hash(data)
    }

    pub fn set_name(&self, name: &[u8]) -> Result<()> {
        self.inner
            .core
            .self_set_name(name)
            .map_err(ToxError::SetInfo)
    }

    pub fn name(&self) -> Vec<u8> {
        self.inner.core.self_get_name()
    }

    pub fn set_status_message(&self, message: &[u8]) -> Result<()> {
        self.inner
            .core
            .self_set_status_message(message)
            .map_err(ToxError::SetInfo)
    }

    pub fn status_message(&self) -> Vec<u8> {
        self.inner.core.self_get_status_message()
    }

    pub fn set_status(&self, status: ToxUserStatus) {
        self.inner.core.self_set_status(status);
    }

    pub fn status(&self) -> ToxUserStatus {
        self.inner.core.self_get_status()
    }

    pub fn friend(&self, number: FriendNumber) -> Friend<'_> {
        Friend { tox: self, number }
    }

    pub fn friend_add(&self, address: &Address, message: &[u8]) -> Result<Friend<'_>> {
        let number = self
            .inner
            .core
            .friend_add(address, message)
            .map_err(ToxError::FriendAdd)?;
        Ok(self.friend(number))
    }

    pub fn friend_add_norequest(&self, public_key: &PublicKey) -> Result<Friend<'_>> {
        let number = self
            .inner
            .core
            .friend_add_norequest(public_key)
            .map_err(ToxError::FriendAdd)?;
        Ok(self.friend(number))
    }

    pub fn lookup_friend(&self, public_key: &PublicKey) -> Result<Friend<'_>> {
        let number = self
            .inner
            .core
            .friend_by_public_key(public_key)
            .map_err(ToxError::FriendByPublicKey)?;
        Ok(self.friend(number))
    }

    pub fn friend_list_len(&self) -> usize {
        self.inner.core.self_get_friend_list_size()
    }

    pub fn friend_list(&self) -> Vec<Friend<'_>> {
        self.inner
            .core
            .self_get_friend_list()
            .into_iter()
            .map(|n| self.friend(n))
            .collect()
    }

    pub fn group(&self, number: GroupNumber) -> Group<'_> {
        Group { tox: self, number }
    }

    pub fn group_new(
        &self,
        privacy_state: ToxGroupPrivacyState,
        group_name: &[u8],
        name: &[u8],
    ) -> Result<Group<'_>> {
        let number = self
            .inner
            .core
            .group_new(privacy_state, group_name, name)
            .map_err(ToxError::GroupNew)?;
        Ok(self.group(number))
    }

    pub fn group_join(
        &self,
        chat_id: &[u8; GROUP_CHAT_ID_SIZE],
        name: &[u8],
        password: Option<&[u8]>,
    ) -> Result<Group<'_>> {
        let number = self
            .inner
            .core
            .group_join(chat_id, name, password.unwrap_or(&[]))
            .map_err(ToxError::GroupJoin)?;
        Ok(self.group(number))
    }

    pub fn group_invite_accept(
        &self,
        friend: &Friend,
        invite_data: &[u8],
        name: &[u8],
        password: Option<&[u8]>,
    ) -> Result<Group<'_>> {
        let number = self
            .inner
            .core
            .group_invite_accept(
                friend.get_number(),
                invite_data,
                name,
                password.unwrap_or(&[]),
            )
            .map_err(ToxError::GroupInviteAccept)?;
        Ok(self.group(number))
    }

    pub fn group_count(&self) -> u32 {
        self.inner.core.group_get_number_groups()
    }

    pub fn file(&self, friend: &Friend, number: FileNumber) -> File<'_> {
        File {
            tox: self,
            friend: friend.get_number(),
            number,
        }
    }

    pub fn file_send(
        &self,
        friend: &Friend,
        kind: u32,
        file_size: u64,
        file_id: Option<&FileId>,
        filename: &[u8],
    ) -> Result<File<'_>> {
        let number = self
            .inner
            .core
            .file_send(friend.get_number(), kind, file_size, file_id, filename)
            .map_err(ToxError::FileSend)?;
        Ok(self.file(friend, number))
    }

    pub fn conference(&self, number: ConferenceNumber) -> Conference<'_> {
        Conference { tox: self, number }
    }

    pub fn conference_new(&self) -> Result<Conference<'_>> {
        let number = self
            .inner
            .core
            .conference_new()
            .map_err(ToxError::ConferenceNew)?;
        Ok(self.conference(number))
    }

    pub fn conference_join(&self, friend: &Friend, cookie: &[u8]) -> Result<Conference<'_>> {
        let number = self
            .inner
            .core
            .conference_join(friend.get_number(), cookie)
            .map_err(ToxError::ConferenceJoin)?;
        Ok(self.conference(number))
    }

    pub fn conference_by_id(&self, id: &ConferenceId) -> Result<Conference<'_>> {
        let number = self
            .inner
            .core
            .conference_by_id(id)
            .map_err(ToxError::ConferenceById)?;
        Ok(self.conference(number))
    }

    pub fn conference_chatlist(&self) -> Vec<Conference<'_>> {
        self.inner
            .core
            .conference_get_chatlist()
            .into_iter()
            .map(|n| self.conference(n))
            .collect()
    }

    pub fn add_av_groupchat<'a, H: ToxAVConferenceHandler>(
        &'a self,
        handler: &H,
    ) -> Result<(Conference<'a>, ConferenceAvScope<'a, H>)> {
        let res = self.inner.core.add_av_groupchat(handler);
        if res >= 0 {
            let conf_num = ConferenceNumber(res as u32);
            Ok((
                self.conference(conf_num),
                ConferenceAvScope {
                    inner: &self.inner,
                    conference: conf_num,
                    _marker: std::marker::PhantomData,
                },
            ))
        } else {
            Err(ToxError::AvGroupError)
        }
    }

    pub fn join_av_groupchat<'a, H: ToxAVConferenceHandler>(
        &'a self,
        friend: &Friend,
        data: &[u8],
        handler: &H,
    ) -> Result<(Conference<'a>, ConferenceAvScope<'a, H>)> {
        let res = self
            .inner
            .core
            .join_av_groupchat(friend.get_number(), data, handler);
        if res >= 0 {
            let conf_num = ConferenceNumber(res as u32);
            Ok((
                self.conference(conf_num),
                ConferenceAvScope {
                    inner: &self.inner,
                    conference: conf_num,
                    _marker: std::marker::PhantomData,
                },
            ))
        } else {
            Err(ToxError::AvGroupError)
        }
    }

    pub fn iteration_interval(&self) -> u32 {
        self.inner.core.iteration_interval()
    }
}

impl Drop for Tox {
    fn drop(&mut self) {
        // inner drops itself
    }
}

pub fn version() -> (u32, u32, u32) {
    (
        core::Tox::version_major(),
        core::Tox::version_minor(),
        core::Tox::version_patch(),
    )
}

pub fn is_compatible(major: u32, minor: u32, patch: u32) -> bool {
    core::Tox::version_is_compatible(major, minor, patch)
}
