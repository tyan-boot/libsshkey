use std::convert::TryInto;
use std::iter::FromIterator;
use std::ops::{Deref, DerefMut};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;

#[derive(Clone)]
pub struct SSHBuffer {
    buf: BytesMut,
}

impl Deref for SSHBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for SSHBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl SSHBuffer {
    pub fn new(buf: Vec<u8>) -> Result<SSHBuffer, Error> {
        let buf = BytesMut::from_iter(buf);
        Ok(SSHBuffer { buf })
    }

    pub fn from_bytes_mut(buf: BytesMut) -> Result<SSHBuffer, Error> {
        Ok(SSHBuffer { buf })
    }

    pub fn empty() -> Result<SSHBuffer, Error> {
        let buf = BytesMut::new();

        Ok(SSHBuffer { buf })
    }

    pub fn get_string(&mut self) -> Result<Bytes, Error> {
        if !(self.buf.len() > 4) {
            return Err(Error::BufferError(anyhow!("no enough space")));
        }

        let len = self.buf.get_u32();
        if !(self.buf.len() >= len as usize) {
            return Err(Error::BufferError(anyhow!("string length overflow")));
        }

        Ok(self.buf.split_to(len as usize).freeze())
    }

    pub fn put_string(&mut self, buf: impl AsRef<[u8]>) -> Result<(), Error> {
        let buf = buf.as_ref();
        let len = buf.len();

        self.buf.put_u32(len as u32);
        self.buf.put(buf);

        Ok(())
    }

    pub fn peek_string(&mut self) -> Result<String, Error> {
        let len = self
            .buf
            .get(..4)
            .and_then(|it| TryInto::<[u8; 4]>::try_into(it).ok())
            .map(u32::from_be_bytes)
            .ok_or(Error::BufferError(anyhow!("no enough space")))? as usize;

        if len > self.buf.len() - 4 {
            return Err(Error::BufferError(anyhow!("length overflow")));
        }

        let slice = self
            .buf
            .get(4..4 + len)
            .ok_or(Error::BufferError(anyhow!("length overflow")))?;
        let s = String::from_utf8(slice.to_vec())?;
        Ok(s)
    }

    pub fn put_raw(&mut self, buf: impl AsRef<[u8]>) -> Result<(), Error> {
        self.buf.put(buf.as_ref());

        Ok(())
    }

    pub fn consume(&mut self, len: isize) -> Result<(), Error> {
        if len as usize > self.buf.len() {
            return Err(Error::BufferError(anyhow!("length overflow")));
        }

        let _d = self.buf.split_to(len as usize);
        let _s = &*self.buf;
        Ok(())
    }

    pub fn new_from_s(&mut self) -> Result<SSHBuffer, Error> {
        if !(self.buf.len() > 4) {
            return Err(Error::BufferError(anyhow!("no enough space")));
        }

        let len = self.buf.get_u32();
        if !(self.buf.len() >= len as usize) {
            return Err(Error::BufferError(anyhow!("string length overflow")));
        }

        let new = self.buf.split_to(len as usize);
        SSHBuffer::from_bytes_mut(new)
    }

    pub fn into_bytes(self) -> Result<Bytes, Error> {
        Ok(self.buf.freeze())
    }
}
