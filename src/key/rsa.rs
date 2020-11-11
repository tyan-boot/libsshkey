use bn::BigNum;
use bytes::BufMut;
use hex::ToHex;
use openssl::bn;
use openssl::bn::BigNumContext;
use openssl::hash;
use openssl::hash::MessageDigest;
use openssl::pkey::{Private, Public};
use openssl::rsa;

use crate::buffer::SSHBuffer;
use crate::error::Error;
use crate::key::{HashType, KeyExt, PEMFormat};
use crate::utils::to_asn1_vec;

use super::utils::encrypt_openssh_private_pem;

#[derive(Debug)]
enum Inner {
    Private(rsa::Rsa<Private>),
    Public(rsa::Rsa<Public>),
}

#[derive(Debug)]
pub struct Rsa {
    inner: Inner,
    comment: Option<String>,
}

impl Rsa {
    pub fn generate(bits: u32, comment: Option<String>) -> Result<Rsa, Error> {
        let pk = rsa::Rsa::generate(bits)?;

        Ok(Rsa {
            inner: Inner::Private(pk),
            comment,
        })
    }

    pub fn import_public_pem(pem: impl AsRef<[u8]>) -> Result<Self, Error> {
        let pem = pem.as_ref();

        if !pem.starts_with("ssh-rsa".as_bytes()) {
            return Err(Error::InvalidKeyFormat(anyhow!("expect ssh-rsa")));
        }

        let mut parts = pem.split(|it| *it == ' ' as u8).filter(|it| !it.is_empty()).rev().collect::<Vec<_>>();
        let _prefix = parts.pop().ok_or(Error::InvalidKeyFormat(anyhow!("expect ssh-rsa")))?;
        let pem = parts.pop().ok_or(Error::InvalidKeyFormat(anyhow!("expect pem encoded key")))?;
        let comment = parts.pop().and_then(|it| String::from_utf8(it.to_vec()).ok());

        let pem = Vec::from(base64::decode(pem)?);

        let buf = SSHBuffer::new(pem)?;

        let mut pk = Rsa::import_public_blob(buf)?;
        pk.comment = comment;

        Ok(pk)
    }

    pub fn import_public_blob(mut blob: SSHBuffer) -> Result<Rsa, Error> {
        let ty = blob.get_string()?;
        let ty = String::from_utf8(ty.to_vec())?;
        debug_assert_eq!(&*ty, "ssh-rsa");

        let e = blob.get_string()?;
        let n = blob.get_string()?;

        let e = BigNum::from_slice(e.as_ref())?;
        let n = BigNum::from_slice(n.as_ref())?;

        let pk = rsa::Rsa::from_public_components(n, e)?;

        Ok(Rsa {
            inner: Inner::Public(pk),
            comment: None,
        })
    }

    pub fn import_private_pem(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Rsa, Error> {
        let pem = pem.as_ref();
        let pem_str = std::str::from_utf8(pem)?;

        if pem_str.contains("BEGIN OPENSSH PRIVATE KEY") {
            Self::import_private_pem_openssh(pem, phase)
        } else {
            Self::import_private_pem_openssl(pem, phase)
        }
    }

    pub fn import_private_blob(mut blob: SSHBuffer) -> Result<Rsa, Error> {
        let tname = blob.get_string()?;
        if tname != "ssh-rsa" {
            return Err(Error::KeyTypeIncorrect(anyhow!(
                "expect ssh-rsa, found {}",
                std::str::from_utf8(&tname)?
            )));
        }

        let n = blob.get_string()?;
        let e = blob.get_string()?;

        let d = blob.get_string()?;
        let iqmp = blob.get_string()?;
        let p = blob.get_string()?;
        let q = blob.get_string()?;
        let comment = blob.get_string()?;
        let comment = if comment.is_empty() {
            None
        } else {
            Some(String::from_utf8(comment.to_vec())?)
        };

        let mut dmp1 = BigNum::new()?;
        let mut dmq1 = BigNum::new()?;
        let mut aux = BigNum::new()?;

        let (n, e, d, p, q, iqmp) = (
            BigNum::from_slice(&n)?,
            BigNum::from_slice(&e)?,
            BigNum::from_slice(&d)?,
            BigNum::from_slice(&p)?,
            BigNum::from_slice(&q)?,
            BigNum::from_slice(&iqmp)?,
        );

        {
            let mut ctx = BigNumContext::new()?;
            let one = BigNum::from_u32(1)?;
            let _iqmp = iqmp.to_owned()?;
            let d_consttime = d.to_owned()?;

            aux.checked_sub(&q, &one)?;
            dmq1.checked_rem(&d_consttime, &aux, &mut ctx)?;

            aux.checked_sub(&p, &one)?;
            dmp1.checked_rem(&d_consttime, &aux, &mut ctx)?;
        }

        let pk = rsa::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;

        let check = pk.check_key()?;

        if check {
            Ok(Rsa {
                inner: Inner::Private(pk),
                comment,
            })
        } else {
            Err(Error::Generic(anyhow!("check rsa failed")))
        }
    }

    pub fn export_public_ssh(&self) -> Result<String, Error> {
        let blob = self.encode_public()?;
        let encoded = base64::encode(&*blob);

        match &self.comment {
            Some(comment) => Ok(format!("ssh-rsa {} {}", encoded, comment)),
            None => Ok(format!("ssh-rsa {}", encoded)),
        }
    }

    pub fn export_public_blob(&self) -> Result<SSHBuffer, Error> {
        self.encode_public()
    }

    pub fn export_private_pem(
        &self,
        format: PEMFormat,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<String, Error> {
        match format {
            PEMFormat::Openssh => self.private_to_openssh(phase),
            PEMFormat::Openssl => self.private_to_openssl(phase),
        }
    }

    fn import_private_pem_openssl(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Rsa, Error> {
        let pem = pem.as_ref();
        match phase {
            Some(phase) => {
                let phase = phase.as_ref();
                let pk = rsa::Rsa::private_key_from_pem_passphrase(pem, phase)?;
                Ok(Rsa {
                    inner: Inner::Private(pk),
                    comment: None,
                })
            }
            None => {
                let pk = rsa::Rsa::private_key_from_pem(pem)?;

                Ok(Rsa {
                    inner: Inner::Private(pk),
                    comment: None,
                })
            }
        }
    }

    fn import_private_pem_openssh(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Rsa, Error> {
        let (_, decrypted) = super::utils::decrypt_openssh_private_pem(pem, phase)?;

        Rsa::import_private_blob(decrypted)
    }

    fn private_to_openssl(&self, phase: Option<impl AsRef<[u8]>>) -> Result<String, Error> {
        match &self.inner {
            Inner::Private(pk) => {
                let pem = match phase {
                    Some(phase) => pk.private_key_to_pem_passphrase(
                        openssl::symm::Cipher::aes_256_cfb1(),
                        phase.as_ref(),
                    )?,
                    None => pk.private_key_to_pem()?,
                };

                let pem = String::from_utf8(pem)?;
                Ok(pem)
            }
            _ => {
                return Err(Error::KeyTypeIncorrect(anyhow!(
                    "expect private key, found public key"
                )));
            }
        }
    }

    fn private_to_openssh(&self, phase: Option<impl AsRef<[u8]>>) -> Result<String, Error> {
        match &self.inner {
            Inner::Private(pk) => {
                let mut buf = SSHBuffer::empty()?;
                buf.put_string("ssh-rsa")?;

                buf.put_string(to_asn1_vec(pk.n().to_vec())?)?;
                buf.put_string(to_asn1_vec(pk.e().to_vec())?)?;
                buf.put_string(to_asn1_vec(pk.d().to_vec())?)?;
                buf.put_string(to_asn1_vec(pk.iqmp().expect("unreachable").to_vec())?)?;
                buf.put_string(to_asn1_vec(pk.p().expect("unreachable").to_vec())?)?;
                buf.put_string(to_asn1_vec(pk.q().expect("unreachable").to_vec())?)?;

                match &self.comment {
                    Some(comment) => buf.put_string(comment)?,
                    None => buf.put_u32(0),
                }

                let pem = encrypt_openssh_private_pem(self.encode_public()?, buf, phase)?;
                Ok(pem)
            }
            _ => {
                return Err(Error::KeyTypeIncorrect(anyhow!(
                    "expect private key, found public key"
                )));
            }
        }
    }

    fn encode_public(&self) -> Result<SSHBuffer, Error> {
        let mut buf = SSHBuffer::empty()?;
        buf.put_string("ssh-rsa")?;
        match self.inner {
            Inner::Private(ref rsa) => {
                buf.put_string(to_asn1_vec(rsa.e().to_vec())?)?;
                buf.put_string(to_asn1_vec(rsa.n().to_vec())?)?;
            }
            Inner::Public(ref rsa) => {
                buf.put_string(to_asn1_vec(rsa.e().to_vec())?)?;
                buf.put_string(to_asn1_vec(rsa.n().to_vec())?)?;
            }
        }

        Ok(buf)
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|it| it.as_ref())
    }

    impl_sign_verify!(from_rsa);

    impl_fingerprint!();
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use openssl::hash::MessageDigest;
    use rand::RngCore;

    use crate::key::{HashType, PEMFormat};

    use super::Rsa;

    const PHASE: Option<&str> = Some("12345678");
    const PHASE_NONE: Option<&str> = None;

    const KEY_2048: &'static str = include_str!("../../tests/rsa/rsa_2048");
    const KEY_2048_PUB: &'static str = include_str!("../../tests/rsa/rsa_2048.pub");
    const KEY_2048_FIG: &'static str = "ZiiPTpaXb59pK3KYx7hbRuxEKPwnSPSRWCZUtdw1hQQ";

    const KEY_4096: &'static str = include_str!("../../tests/rsa/rsa_4096");
    const KEY_4096_PUB: &'static str = include_str!("../../tests/rsa/rsa_4096.pub");
    const KEY_4096_FIG: &'static str = "UVlud9hZkLO0Md2GBk2jyguUVsNW7tQOMaIEkpff8Ik";

    #[test]
    fn import_openssh() -> Result<()> {
        let _rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let _rsa = Rsa::import_private_pem(KEY_4096, PHASE_NONE)?;

        Ok(())
    }

    #[test]
    fn export_openssh() -> Result<()> {
        let rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let _pem = rsa.export_private_pem(PEMFormat::Openssh, PHASE_NONE)?;

        let rsa = Rsa::import_private_pem(KEY_4096, PHASE_NONE)?;
        let _pem = rsa.export_private_pem(PEMFormat::Openssh, PHASE_NONE)?;

        Ok(())
    }

    #[test]
    fn export_public() -> Result<()> {
        let rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let public = rsa.export_public_ssh()?;

        assert_eq!(public, KEY_2048_PUB.trim());

        let rsa = Rsa::import_private_pem(KEY_4096, PHASE_NONE)?;
        let public = rsa.export_public_ssh()?;

        assert_eq!(public, KEY_4096_PUB.trim());

        Ok(())
    }

    #[test]
    fn fingerprint() -> Result<()> {
        let rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let fingerprint = rsa.fingerprint(HashType::SHA256)?;

        assert_eq!(fingerprint, KEY_2048_FIG.trim());

        let rsa = Rsa::import_private_pem(KEY_4096, PHASE_NONE)?;
        let fingerprint = rsa.fingerprint(HashType::SHA256)?;

        assert_eq!(fingerprint, KEY_4096_FIG.trim());

        Ok(())
    }

    #[test]
    fn signature() -> Result<()> {
        let buf = [0u8; 4096];

        let rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let sig = rsa.sign(MessageDigest::sha256(), &buf)?;
        let check = rsa.verify(MessageDigest::sha256(), &buf, sig)?;
        assert!(check);

        let rsa = Rsa::import_private_pem(KEY_2048, PHASE_NONE)?;
        let sig = rsa.sign(MessageDigest::sha256(), &buf)?;
        let check = rsa.verify(MessageDigest::sha256(), &buf, sig)?;
        assert!(check);

        Ok(())
    }

    #[test]
    fn generate() -> Result<()> {
        let _rsa = Rsa::generate(2048, None)?;
        let _rsa = Rsa::generate(4096, None)?;

        Ok(())
    }
}