use openssl::hash::MessageDigest;

pub use dss::Dss;
pub use ecdsa::{EcGroup, Ecdsa};
pub use rsa::Rsa;

use crate::error::Error;
use crate::key::utils::decrypt_openssh_private_pem;
use crate::SSHBuffer;

#[macro_use]
mod utils;

mod dss;
mod ecdsa;
mod rsa;

const OPENSSH_BEGIN: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
// no \n
const OPENSSH_END: &'static str = "-----END OPENSSH PRIVATE KEY-----";
const OPENSSH_AUTH_MAGIC: &'static str = "openssh-key-v1";

const RSA_BEGIN: &'static str = "-----BEGIN RSA PRIVATE KEY-----\n";
const EC_BEGIN: &'static str = "-----BEGIN EC PRIVATE KEY-----\n";

#[derive(Debug)]
pub enum Key {
    Dss,
    Rsa(Rsa),
    Ed25519,
    EcdsaP256(Ecdsa),
    EcdsaP384(Ecdsa),
    EcdsaP521(Ecdsa),
}

impl Key {
    pub fn fingerprint(&self, hash_type: HashType) -> Result<String, Error> {
        match &self {
            Key::Rsa(key) => key.fingerprint(hash_type),
            Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => {
                key.fingerprint(hash_type)
            }
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format"
            ))),
        }
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        match &self {
            Key::Rsa(key) => key.sign(MessageDigest::sha256(), data),
            Key::EcdsaP256(key) => {
                let (r, s) = key.sign(MessageDigest::sha256(), data)?;
                let mut buf = SSHBuffer::empty()?;
                buf.put_string(r)?;
                buf.put_string(s)?;

                Ok(buf.to_vec())
            }
            Key::EcdsaP384(key) => {
                let (r, s) = key.sign(MessageDigest::sha384(), data)?;
                let mut buf = SSHBuffer::empty()?;
                buf.put_string(r)?;
                buf.put_string(s)?;

                Ok(buf.to_vec())
            }
            Key::EcdsaP521(key) => {
                let (r, s) = key.sign(MessageDigest::sha512(), data)?;
                let mut buf = SSHBuffer::empty()?;
                buf.put_string(r)?;
                buf.put_string(s)?;

                Ok(buf.to_vec())
            }
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format"
            ))),
        }
    }

    pub fn export_public_ssh(&self) -> Result<String, Error> {
        match &self {
            Key::Rsa(key) => key.export_public_ssh(),
            Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => {
                key.export_public_ssh()
            }
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format"
            ))),
        }
    }

    pub fn export_private_pem(&self) -> Result<String, Error> {
        match &self {
            Key::Rsa(key) => key.export_private_pem(PEMFormat::Openssh, None::<&str>),
            Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => {
                key.export_private_pem(PEMFormat::Openssh, None::<&str>)
            }
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format"
            ))),
        }
    }

    pub fn export_public_blob(&self) -> Result<SSHBuffer, Error> {
        match &self {
            Key::Rsa(key) => key.export_public_blob(),
            Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => {
                key.export_public_blob()
            }
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format"
            ))),
        }
    }

    pub fn comment(&self) -> Option<&str> {
        match &self {
            Key::Rsa(key) => key.comment(),
            Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => key.comment(),
            _ => None,
        }
    }
}

pub enum HashType {
    MD5,
    SHA1,
    SHA256,
}

/// Private key pem format
pub enum PEMFormat {
    /// openssl pem
    Openssl,
    /// openssh new format
    Openssh,
}

fn wrap_ec(key: Ecdsa) -> Key {
    match key.group() {
        EcGroup::P256 => Key::EcdsaP256(key),
        EcGroup::P384 => Key::EcdsaP384(key),
        EcGroup::P521 => Key::EcdsaP521(key),
    }
}

pub fn parse_public_blob(blob: impl AsRef<[u8]>) -> Result<Key, Error> {
    let blob = blob.as_ref();
    let buf = SSHBuffer::new(blob.to_vec())?;
    let key_type = buf.peek_string()?;

    if key_type.starts_with("ssh-rsa") {
        let rsa = Rsa::import_public_blob(buf)?;
        Ok(Key::Rsa(rsa))
    } else if key_type.starts_with("ecdsa-sha2-") {
        let ecdsa = Ecdsa::import_public_blob(buf)?;

        Ok(wrap_ec(ecdsa))
    } else {
        Err(Error::UnsupportedKeyFormat(anyhow!(
            "unsupported key: {}",
            key_type
        )))
    }
}

pub fn parse_private_pem(
    pem: impl AsRef<[u8]>,
    phase: Option<impl AsRef<[u8]>>,
) -> Result<Key, Error> {
    let pem = pem.as_ref();

    if pem.starts_with(OPENSSH_BEGIN.as_bytes()) {
        let (_, decrypt) = decrypt_openssh_private_pem(pem, phase)?;
        let tname = decrypt.peek_string()?;

        if tname == "ssh-rsa" {
            let key = Rsa::import_private_blob(decrypt)?;
            return Ok(Key::Rsa(key));
        } else if tname.starts_with("ecdsa-sha2-") {
            let key = Ecdsa::import_private_blob(decrypt)?;
            return Ok(wrap_ec(key));
        } else {
            return Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported key format {}",
                tname
            )));
        }
    } else if pem.starts_with(RSA_BEGIN.as_bytes()) {
        let key = Rsa::import_private_pem(pem, phase)?;

        return Ok(Key::Rsa(key));
    } else if pem.starts_with(EC_BEGIN.as_bytes()) {
        let key = Ecdsa::import_private_pem(pem, phase)?;

        return Ok(wrap_ec(key));
    }

    Err(Error::InvalidKeyFormat(anyhow!("unknown key format")))
}
