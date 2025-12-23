use crate::tox::Inner;
use crate::toxav::ToxAVConferenceHandler;
use crate::types::*;

pub struct ConferenceAvScope<'a, H: ToxAVConferenceHandler> {
    pub(crate) inner: &'a Inner,
    pub(crate) conference: ConferenceNumber,
    pub(crate) _marker: std::marker::PhantomData<&'a mut H>,
}

impl<'a, H: ToxAVConferenceHandler> Drop for ConferenceAvScope<'a, H> {
    fn drop(&mut self) {
        self.inner.core.groupchat_disable_av(self.conference);
    }
}
