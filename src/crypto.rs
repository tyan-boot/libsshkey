use once_cell::sync::Lazy;
use openssl::symm::Cipher;
use std::collections::HashMap;

const CFLAG_CBC: u32 = 1 << 0;
const CFLAG_CHACHAPOLY: u32 = 1 << 1;
#[allow(dead_code)]
const CFLAG_AESCTR: u32 = 1 << 2;
#[allow(dead_code)]
const CFLAG_NONE: u32 = 1 << 3;
#[allow(dead_code)]
const CFLAG_INTERNAL: u32 = CFLAG_NONE;

pub struct SSHCipher {
    pub block_size: u32,
    pub key_len: usize,
    pub iv_len: usize,
    pub auth_len: u32,
    pub flags: u32,
    pub cipher: Option<Cipher>,
}

pub static SSH_CIPHERS: Lazy<HashMap<&'static str, SSHCipher>> = Lazy::new(|| {
    let mut ciphers = HashMap::new();
    ciphers.insert(
        "3des-cbc",
        SSHCipher {
            block_size: 8,
            key_len: 24,
            iv_len: 8,
            auth_len: 0,
            flags: CFLAG_CBC,
            cipher: Some(Cipher::des_ede3()),
        },
    );

    ciphers.insert(
        "aes128-cbc",
        SSHCipher {
            block_size: 16,
            key_len: 16,
            iv_len: 16,
            auth_len: 0,
            flags: CFLAG_CBC,
            cipher: Some(Cipher::aes_128_cbc()),
        },
    );

    ciphers.insert(
        "aes192-cbc",
        SSHCipher {
            block_size: 16,
            key_len: 24,
            iv_len: 16,
            auth_len: 0,
            flags: CFLAG_CBC,
            cipher: Some(Cipher::aes_192_cbc()),
        },
    );

    ciphers.insert(
        "aes256-cbc",
        SSHCipher {
            block_size: 16,
            key_len: 32,
            iv_len: 16,
            auth_len: 0,
            flags: CFLAG_CBC,
            cipher: Some(Cipher::aes_256_cbc()),
        },
    );

    ciphers.insert(
        "rijndael-cbc@lysator.liu.se",
        SSHCipher {
            block_size: 16,
            key_len: 32,
            iv_len: 16,
            auth_len: 0,
            flags: CFLAG_CBC,
            cipher: Some(Cipher::aes_256_cbc()),
        },
    );

    ciphers.insert(
        "aes128-ctr",
        SSHCipher {
            block_size: 16,
            key_len: 16,
            iv_len: 16,
            auth_len: 0,
            flags: 0,
            cipher: Some(Cipher::aes_128_ctr()),
        },
    );

    ciphers.insert(
        "aes192-ctr",
        SSHCipher {
            block_size: 16,
            key_len: 24,
            iv_len: 16,
            auth_len: 0,
            flags: 0,
            cipher: Some(Cipher::aes_192_ctr()),
        },
    );

    ciphers.insert(
        "aes256-ctr",
        SSHCipher {
            block_size: 16,
            key_len: 32,
            iv_len: 16,
            auth_len: 0,
            flags: 0,
            cipher: Some(Cipher::aes_256_ctr()),
        },
    );

    ciphers.insert(
        "aes128-gcm@openssh.com",
        SSHCipher {
            block_size: 16,
            key_len: 16,
            iv_len: 12,
            auth_len: 16,
            flags: 0,
            cipher: Some(Cipher::aes_128_gcm()),
        },
    );

    ciphers.insert(
        "aes256-gcm@openssh.com",
        SSHCipher {
            block_size: 16,
            key_len: 32,
            iv_len: 12,
            auth_len: 16,
            flags: 0,
            cipher: Some(Cipher::aes_256_gcm()),
        },
    );

    ciphers.insert(
        "chacha20-poly1305@openssh.com",
        SSHCipher {
            block_size: 8,
            key_len: 64,
            iv_len: 0,
            auth_len: 16,
            flags: CFLAG_CHACHAPOLY,
            cipher: Some(Cipher::chacha20_poly1305()),
        },
    );

    ciphers.insert(
        "none",
        SSHCipher {
            block_size: 8,
            key_len: 0,
            iv_len: 0,
            auth_len: 0,
            flags: 0,
            cipher: None,
        },
    );

    ciphers
});
