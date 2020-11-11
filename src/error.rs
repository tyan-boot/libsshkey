use std::str::Utf8Error;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("openssl error: {}", _0)]
    OpensslError(#[from] openssl::error::ErrorStack),

    #[error("ssh buffer error: {}", _0)]
    BufferError(anyhow::Error),

    #[error("utf8 error: {}", _0)]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("utf8 error: {}", _0)]
    Utf8Error(#[from] Utf8Error),

    #[error("base64 error: {}", _0)]
    Base64Error(#[from] base64::DecodeError),

    #[error("unsupported key format: {}", _0)]
    UnsupportedKeyFormat(anyhow::Error),

    #[error("invalid key format: {}", _0)]
    InvalidKeyFormat(anyhow::Error),

    #[error("Incorrect key type: {}", _0)]
    KeyTypeIncorrect(anyhow::Error),

    #[error("{}", _0)]
    Generic(#[from] anyhow::Error),

    #[error("bcrypt kdf error: {}", _0)]
    BcryptError(#[from] bcrypt_pbkdf::Error),
}
