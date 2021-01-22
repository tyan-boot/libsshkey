use std::str;

use bytes::{Buf, BufMut};
use rand::{Rng, RngCore};

use crate::buffer::SSHBuffer;
use crate::crypto::SSH_CIPHERS;
use crate::error::Error;
use crate::key::{OPENSSH_AUTH_MAGIC, OPENSSH_BEGIN, OPENSSH_END};

macro_rules! impl_sign {
    ($pkey_from:ident) => {
        pub fn sign(
            &self,
            type_: ::openssl::hash::MessageDigest,
            input: impl AsRef<[u8]>,
        ) -> Result<Vec<u8>, crate::error::Error> {
            let pk = match &self.inner {
                Inner::Private(pk) => ::openssl::pkey::PKey::$pkey_from(pk.clone())?,
                Inner::Public(_) => {
                    return Err(Error::KeyTypeIncorrect(anyhow!("sign require private key")));
                }
            };

            let mut signer = ::openssl::sign::Signer::new(type_, &pk)?;
            signer.update(input.as_ref())?;
            Ok(signer.sign_to_vec()?)
        }
    };
}

macro_rules! impl_verify {
    ($pkey_from:ident) => {
        pub fn verify(
            &self,
            type_: ::openssl::hash::MessageDigest,
            input: impl AsRef<[u8]>,
            signature: impl AsRef<[u8]>,
        ) -> Result<bool, crate::error::Error> {
            match &self.inner {
                Inner::Private(pk) => {
                    let pk = ::openssl::pkey::PKey::$pkey_from(pk.clone())?;
                    let mut verifier = ::openssl::sign::Verifier::new(type_, &pk)?;
                    verifier.update(input.as_ref())?;
                    Ok(verifier.verify(signature.as_ref())?)
                }
                Inner::Public(pk) => {
                    let pk = ::openssl::pkey::PKey::$pkey_from(pk.clone())?;
                    let mut verifier = ::openssl::sign::Verifier::new(type_, &pk)?;
                    verifier.update(input.as_ref())?;
                    Ok(verifier.verify(signature.as_ref())?)
                }
            }
        }
    };
}

macro_rules! impl_sign_verify {
    ($pkey_from:ident) => {
        impl_sign!($pkey_from);
        impl_verify!($pkey_from);
    };
}

macro_rules! impl_fingerprint {
    () => {
        pub fn fingerprint(
            &self,
            hash_type: $crate::key::HashType,
        ) -> Result<String, $crate::error::Error> {
            use hex::ToHex;
            let blob = self.encode_public()?;
            let fingerprint = match hash_type {
                HashType::MD5 => {
                    let hash = ::openssl::hash::hash(::openssl::hash::MessageDigest::md5(), &blob)?;
                    let hash = hash.encode_hex::<String>();
                    let mut hash_hexa = String::with_capacity(hash.len() + hash.len() / 2);

                    for idx in (0..hash.len()).step_by(2) {
                        hash_hexa.push(hash.as_bytes()[idx] as char);
                        hash_hexa.push(hash.as_bytes()[idx + 1] as char);
                        hash_hexa.push(':');
                    }

                    hash_hexa.pop();
                    hash_hexa
                }
                HashType::SHA1 => {
                    let hash =
                        ::openssl::hash::hash(::openssl::hash::MessageDigest::sha1(), &blob)?;
                    base64::encode_config(hash, base64::STANDARD_NO_PAD)
                }
                HashType::SHA256 => {
                    let hash = hash::hash(MessageDigest::sha256(), &blob)?;
                    base64::encode_config(hash, base64::STANDARD_NO_PAD)
                }
            };

            Ok(fingerprint)
        }
    };
}

pub fn decrypt_openssh_private_pem(
    pem: impl AsRef<[u8]>,
    phase: Option<impl AsRef<[u8]>>,
) -> Result<(SSHBuffer, SSHBuffer), Error> {
    let pem = pem.as_ref();

    let pem_str = str::from_utf8(pem)?;
    let pem_str = pem_str.trim();

    if !pem_str.starts_with(OPENSSH_BEGIN) {
        return Err(Error::UnsupportedKeyFormat(anyhow!("unknown key type")));
    }

    let pem_str = &pem_str[OPENSSH_BEGIN.len()..];
    if !pem_str.ends_with(OPENSSH_END) {
        return Err(Error::UnsupportedKeyFormat(anyhow!("missing end")));
    }

    // join lines
    let pem_str = &pem_str[..pem_str.len() - OPENSSH_END.len()];
    let pem_str = pem_str.lines().collect::<Vec<&str>>().concat();

    let decoded = base64::decode(pem_str)?;
    // check openssh auth magic
    if decoded.len() < OPENSSH_AUTH_MAGIC.len()
        || !decoded.starts_with(OPENSSH_AUTH_MAGIC.as_bytes())
    {
        return Err(Error::UnsupportedKeyFormat(anyhow!("unknown auth magic")));
    }

    let mut buf = SSHBuffer::new(decoded)?;
    buf.consume(OPENSSH_AUTH_MAGIC.len() as isize + 1)?; // c string end with \0

    let cipher_name = buf.get_string()?;
    let kdf_name = buf.get_string()?;
    let cipher_name = str::from_utf8(&cipher_name)?;
    let kdf_name = str::from_utf8(&kdf_name)?;

    // extract kdf info
    let mut kdf = buf.new_from_s()?;

    // openssh format only support 1 key currently
    let n_keys = buf.get_u32();
    if n_keys != 1 {
        return Err(Error::UnsupportedKeyFormat(anyhow!("only support one key")));
    }

    // extract public key
    let pub_key = buf.new_from_s()?;
    // private key len
    let encrypt_len = buf.get_u32();

    let cipher = SSH_CIPHERS
        .get(cipher_name)
        .ok_or(Error::UnsupportedKeyFormat(anyhow!("unsupported cipher")))?;

    if kdf_name != "none" && kdf_name != "bcrypt" {
        return Err(Error::UnsupportedKeyFormat(anyhow!("unsupported cipher")));
    }

    if kdf_name == "none" && cipher_name != "none" {
        return Err(Error::UnsupportedKeyFormat(anyhow!("invalid cipher")));
    }

    if kdf_name != "none" && phase.is_none() {
        return Err(Error::Generic(anyhow!("passphrase required")));
    }

    if encrypt_len < cipher.block_size || encrypt_len % cipher.block_size != 0 {
        return Err(Error::InvalidKeyFormat(anyhow!(
            "invalid format: block size"
        )));
    }

    // key and iv in one buffer
    let mut key = vec![0; (cipher.key_len + cipher.iv_len) as usize];

    if kdf_name == "bcrypt" {
        let salt = kdf.get_string()?;
        let rounds = kdf.get_u32();

        let phrase = phase.unwrap();
        let phrase = phrase.as_ref();
        let phrase = str::from_utf8(phrase).map_err(Error::Utf8Error)?;
        // derive key and iv
        let _ = bcrypt_pbkdf::bcrypt_pbkdf(phrase, &salt, rounds, &mut key)?;
    }

    if buf.len() < cipher.auth_len as usize
        || buf.len() - (cipher.auth_len as usize) < encrypt_len as usize
    {
        return Err(Error::InvalidKeyFormat(anyhow!(
            "invalid key format: auth data"
        )));
    }

    let mut decrypted = match cipher.cipher {
        Some(ssl_cipher) => {
            let iv = if cipher.iv_len != 0 {
                Some(&key[cipher.key_len..cipher.key_len + cipher.iv_len])
            } else {
                None
            };

            let decrypted = openssl::symm::decrypt(ssl_cipher, &key[0..cipher.key_len], iv, &buf)?;

            SSHBuffer::new(decrypted)?
        }
        None => buf.clone(), // todo: do we need clone?
    };

    // ensure no more data
    buf.consume((encrypt_len + cipher.auth_len) as isize)?;
    if buf.len() != 0 {
        return Err(Error::UnsupportedKeyFormat(anyhow!("invalid key format")));
    }

    // check if phrase correct
    let check1 = decrypted.get_u32();
    let check2 = decrypted.get_u32();

    if check1 != check2 {
        return Err(Error::InvalidKeyFormat(anyhow!("invalid phrase")));
    }

    Ok((pub_key, decrypted))
}

pub fn encrypt_openssh_private_pem(
    public: SSHBuffer,
    private: SSHBuffer,
    phase: Option<impl AsRef<[u8]>>,
) -> Result<String, Error> {
    let mut buf = SSHBuffer::empty()?;
    buf.put_raw(OPENSSH_AUTH_MAGIC)?;
    buf.put_raw([0])?;

    let cipher_name;
    let kdf_name;
    let cipher;
    let mut key;

    match phase {
        Some(phase) => {
            cipher_name = "aes256-ctr";
            kdf_name = "bcrypt";
            cipher = SSH_CIPHERS.get(cipher_name).expect("unreachable");

            let phase = phase.as_ref();

            buf.put_string(cipher_name)?;
            buf.put_string(kdf_name)?;

            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);

            key = vec![0; cipher.key_len + cipher.iv_len];

            bcrypt_pbkdf::bcrypt_pbkdf(str::from_utf8(&phase)?, &salt, 16, &mut key)?;

            let mut kdf = SSHBuffer::empty()?;
            kdf.put_string(salt)?;
            kdf.put_u32(16); // rounds

            buf.put_string(&*kdf)?;
        }
        None => {
            cipher_name = "none";
            kdf_name = "none";
            cipher = SSH_CIPHERS.get(cipher_name).expect("unreachable");
            key = Vec::with_capacity(0);
            let kdf = SSHBuffer::empty()?;
            buf.put_string(cipher_name)?;
            buf.put_string(kdf_name)?;

            buf.put_string(&*kdf)?;
        }
    }

    buf.put_u32(1); // n keys, always 1
    buf.put_string(&*public)?;

    let mut private_pad = SSHBuffer::empty()?;
    // rand nonce
    let check = rand::thread_rng().gen();
    private_pad.put_u32(check);
    private_pad.put_u32(check);
    private_pad.put_raw(&*private)?;

    // pad buffer
    let mut idx = 1;
    while private_pad.len() % cipher.block_size as usize != 0 {
        private_pad.put_u8(idx & 0xff);
        idx += 1;
    }

    let encrypted = match cipher.cipher {
        Some(ssl_cipher) => {
            let iv = if cipher.iv_len != 0 {
                Some(&key[cipher.key_len..cipher.key_len + cipher.iv_len])
            } else {
                None
            };

            let encrypted =
                openssl::symm::encrypt(ssl_cipher, &key[0..cipher.key_len], iv, &private_pad)?;

            SSHBuffer::new(encrypted)?
        }
        None => private_pad,
    };

    buf.put_u32(encrypted.len() as u32);
    buf.put_raw(&*encrypted)?;

    let blob = buf.into_bytes()?;
    let blob = base64::encode(blob);

    let final_pem = format!(
        "{begin}\n{key}\n{end}",
        begin = OPENSSH_BEGIN,
        key = blob,
        end = OPENSSH_END
    );
    Ok(final_pem)
}
