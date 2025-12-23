use crate::types::*;

#[derive(Clone, Copy)]
pub struct File<'a> {
    pub(crate) tox: &'a super::Tox,
    pub(crate) friend: FriendNumber,
    pub(crate) number: FileNumber,
}

impl<'a> std::fmt::Debug for File<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("friend", &self.friend)
            .field("number", &self.number)
            .finish()
    }
}

impl<'a> File<'a> {
    pub fn number(&self) -> FileNumber {
        self.number
    }

    pub fn friend_number(&self) -> FriendNumber {
        self.friend
    }

    pub fn send_chunk(&self, position: u64, data: &[u8]) -> Result<()> {
        self.tox
            .inner
            .core
            .file_send_chunk(self.friend, self.number, position, data)
            .map_err(ToxError::FileSendChunk)
    }

    pub fn control(&self, control: ToxFileControl) -> Result<()> {
        self.tox
            .inner
            .core
            .file_control(self.friend, self.number, control)
            .map_err(ToxError::FileControl)
    }

    pub fn seek(&self, position: u64) -> Result<()> {
        self.tox
            .inner
            .core
            .file_seek(self.friend, self.number, position)
            .map_err(ToxError::FileSeek)
    }

    pub fn file_id(&self) -> Result<FileId> {
        self.tox
            .inner
            .core
            .file_get_file_id(self.friend, self.number)
            .map_err(ToxError::FileGet)
    }
}
