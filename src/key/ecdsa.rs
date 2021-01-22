use bytes::BufMut;

use openssl::bn::{BigNum, BigNumContext};
use openssl::derive;
use openssl::ec;
use openssl::ec::PointConversionForm;
use openssl::nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::{bn, hash};

use crate::buffer::SSHBuffer;
use crate::error::Error;
use crate::key::utils::encrypt_openssh_private_pem;
use crate::key::{HashType, PEMFormat};
use crate::utils::to_asn1_vec;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum EcGroup {
    P256,
    P384,
    P521,
}

impl EcGroup {
    fn to_nid(&self) -> nid::Nid {
        match self {
            EcGroup::P256 => nid::Nid::X9_62_PRIME256V1,
            EcGroup::P384 => nid::Nid::SECP384R1,
            EcGroup::P521 => nid::Nid::SECP521R1,
        }
    }

    fn to_ec_group(&self) -> Result<ec::EcGroup, Error> {
        ec::EcGroup::from_curve_name(self.to_nid()).map_err(Error::OpensslError)
    }

    fn from_nid_string(s: impl AsRef<str>) -> Result<EcGroup, Error> {
        match s.as_ref() {
            "nistp256" => Ok(EcGroup::P256),
            "nistp384" => Ok(EcGroup::P384),
            "nistp521" => Ok(EcGroup::P521),
            _ => Err(Error::UnsupportedKeyFormat(anyhow!(
                "unsupported nid: {}",
                s.as_ref()
            ))),
        }
    }

    fn from_nid(nid: nid::Nid) -> Result<EcGroup, Error> {
        match nid {
            nid::Nid::X9_62_PRIME256V1 => Ok(EcGroup::P256),
            nid::Nid::SECP384R1 => Ok(EcGroup::P384),
            nid::Nid::SECP521R1 => Ok(EcGroup::P521),
            _ => Err(Error::UnsupportedKeyFormat(anyhow!("unsupported nid"))),
        }
    }

    fn to_type_name(&self) -> &str {
        match self {
            EcGroup::P256 => "ecdsa-sha2-nistp256",
            EcGroup::P384 => "ecdsa-sha2-nistp384",
            EcGroup::P521 => "ecdsa-sha2-nistp521",
        }
    }

    fn to_curve_name(&self) -> &str {
        match self {
            EcGroup::P256 => "nistp256",
            EcGroup::P384 => "nistp384",
            EcGroup::P521 => "nistp521",
        }
    }
}

#[derive(Debug)]
enum Inner {
    Private(ec::EcKey<Private>),
    Public(ec::EcKey<Public>),
}

#[derive(Debug)]
pub struct Ecdsa {
    inner: Inner,
    group: EcGroup,
    comment: Option<String>,
}

impl Ecdsa {
    pub fn generate(group: EcGroup, comment: Option<String>) -> Result<Ecdsa, Error> {
        let ec_group = group.to_ec_group()?;
        let pk = ec::EcKey::generate(&ec_group)?;

        Ok(Ecdsa {
            inner: Inner::Private(pk),
            group,
            comment,
        })
    }

    pub fn import_public_pem(pem: impl AsRef<[u8]>) -> Result<Self, Error> {
        let pem = pem.as_ref();
        let pem = Vec::from(base64::decode(pem)?);

        let buf = SSHBuffer::new(pem)?;
        Ecdsa::import_public_blob(buf)
    }

    pub fn import_public_blob(mut blob: SSHBuffer) -> Result<Ecdsa, Error> {
        let ty = blob.get_string()?;
        let ty = String::from_utf8(ty.to_vec())?;
        debug_assert!(ty.starts_with("ecdsa-sha2-nistp"));

        let nid = blob.get_string()?;
        let point = blob.get_string()?;

        let nid = std::str::from_utf8(&nid)?;

        let group = EcGroup::from_nid_string(nid)?;
        let ec_group = group.to_ec_group()?;

        let mut cx = bn::BigNumContext::new()?;
        let point = ec::EcPoint::from_bytes(&ec_group, &point, &mut cx)?;

        let pk = ec::EcKey::from_public_key(&ec_group, &point)?;

        Ok(Ecdsa {
            inner: Inner::Public(pk),
            group,
            comment: None,
        })
    }

    pub fn import_private_pem(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Ecdsa, Error> {
        let pem = pem.as_ref();
        let pem_str = std::str::from_utf8(&pem)?;

        if pem_str.contains("BEGIN OPENSSH PRIVATE KEY") {
            Self::from_private_pem_openssh(pem_str, phase)
        } else {
            Self::from_private_pem_openssl(pem, phase)
        }
    }

    pub fn import_private_blob(mut blob: SSHBuffer) -> Result<Ecdsa, Error> {
        let tname = blob.get_string()?;
        let tname = std::str::from_utf8(&tname)?;

        let group = {
            let nid = tname.trim_start_matches("ecdsa-sha2-");
            EcGroup::from_nid_string(nid)?
        };

        let curve = blob.get_string()?;
        let curve = std::str::from_utf8(&curve)?;

        if group != EcGroup::from_nid_string(curve)? {
            return Err(Error::InvalidKeyFormat(anyhow!("curve mismatch")));
        }

        let ec_group = group.to_ec_group()?;

        let point = blob.get_string()?;
        let mut ctx = bn::BigNumContext::new()?;
        let point = ec::EcPoint::from_bytes(&ec_group, &point, &mut ctx)?;

        let e = blob.get_string()?;
        let e = BigNum::from_slice(&e)?;

        let comment = blob.get_string()?;
        let comment = if comment.is_empty() {
            None
        } else {
            Some(String::from_utf8(comment.to_vec())?)
        };

        let pk = ec::EcKey::from_private_components(&ec_group, &e, &point)?;
        pk.check_key()?;

        Ok(Ecdsa {
            inner: Inner::Private(pk),
            group,
            comment,
        })
    }

    pub fn export_public_ssh(&self) -> Result<String, Error> {
        let blob = self.encode_public()?;
        let blob = base64::encode(&*blob);

        match &self.comment {
            Some(comment) => Ok(format!("{} {} {}", self.key_type(), blob, comment)),
            None => Ok(format!("{} {}", self.key_type(), blob)),
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
            PEMFormat::Openssl => self.private_to_openssl(phase),
            PEMFormat::Openssh => self.private_to_openssh(phase),
        }
    }

    fn from_private_pem_openssl(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Ecdsa, Error> {
        let pem = pem.as_ref();
        match phase {
            Some(phase) => {
                let phase = phase.as_ref();
                let pk = ec::EcKey::private_key_from_pem_passphrase(pem, phase)?;
                let nid = pk
                    .group()
                    .curve_name()
                    .ok_or(Error::InvalidKeyFormat(anyhow!("no nid info")))?;
                let group = EcGroup::from_nid(nid)?;

                Ok(Ecdsa {
                    inner: Inner::Private(pk),
                    group,
                    comment: None,
                })
            }
            None => {
                let pk = ec::EcKey::private_key_from_pem(pem)?;
                let nid = pk
                    .group()
                    .curve_name()
                    .ok_or(Error::InvalidKeyFormat(anyhow!("no nid info")))?;
                let group = EcGroup::from_nid(nid)?;

                Ok(Ecdsa {
                    inner: Inner::Private(pk),
                    group,
                    comment: None,
                })
            }
        }
    }

    fn from_private_pem_openssh(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Ecdsa, Error> {
        let (_, decrypted) = super::utils::decrypt_openssh_private_pem(pem, phase)?;

        Ecdsa::import_private_blob(decrypted)
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
            _ => Err(Error::KeyTypeIncorrect(anyhow!(
                "expect private key, found public key"
            ))),
        }
    }

    fn private_to_openssh(&self, phase: Option<impl AsRef<[u8]>>) -> Result<String, Error> {
        match &self.inner {
            Inner::Private(pk) => {
                let mut buf = SSHBuffer::empty()?;

                buf.put_string(self.group.to_type_name())?;
                buf.put_string(self.group.to_curve_name())?;

                let point = pk.public_key();
                let mut ctx = BigNumContext::new()?;
                let point = point.to_bytes(
                    &*self.group.to_ec_group()?,
                    PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )?;

                buf.put_string(to_asn1_vec(point)?)?;

                let e = pk.private_key();
                buf.put_string(to_asn1_vec(e.to_vec())?)?;
                match &self.comment {
                    Some(comment) => buf.put_string(comment)?,
                    None => buf.put_u32(0),
                }

                let pem = encrypt_openssh_private_pem(self.encode_public()?, buf, phase)?;
                Ok(pem)
            }
            _ => Err(Error::KeyTypeIncorrect(anyhow!(
                "expect private key, found public key"
            ))),
        }
    }

    pub fn derive(&self, rhs: &Self) -> Result<Vec<u8>, Error> {
        let pk = match &self.inner {
            Inner::Private(pk) => PKey::from_ec_key(pk.clone())?,
            Inner::Public(_) => {
                return Err(Error::KeyTypeIncorrect(anyhow!(
                    "derive require private key"
                )));
            }
        };

        let mut deriver = derive::Deriver::new(&pk)?;

        match &rhs.inner {
            Inner::Private(pk) => {
                let rhs = PKey::from_ec_key(pk.clone())?;
                deriver.set_peer(&rhs)?;
                Ok(deriver.derive_to_vec()?)
            }
            Inner::Public(pk) => {
                let rhs = PKey::from_ec_key(pk.clone())?;
                deriver.set_peer(&rhs)?;
                Ok(deriver.derive_to_vec()?)
            }
        }
    }

    pub fn key_type(&self) -> &'static str {
        match self.group {
            EcGroup::P256 => "ecdsa-sha2-nistp256",
            EcGroup::P384 => "ecdsa-sha2-nistp384",
            EcGroup::P521 => "ecdsa-sha2-nistp521",
        }
    }

    pub fn nid(&self) -> &'static str {
        match self.group {
            EcGroup::P256 => "nistp256",
            EcGroup::P384 => "nistp384",
            EcGroup::P521 => "nistp521",
        }
    }

    fn encode_public(&self) -> Result<SSHBuffer, Error> {
        let mut buf = SSHBuffer::empty()?;
        let ty = self.key_type();
        buf.put_string(ty)?;

        let nid = self.nid();
        buf.put_string(nid)?;
        let mut ctx = BigNumContext::new()?;

        let point = match &self.inner {
            Inner::Private(pk) => {
                pk.public_key()
                    .to_bytes(pk.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?
            }
            Inner::Public(pk) => {
                pk.public_key()
                    .to_bytes(pk.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?
            }
        };

        buf.put_string(point)?;

        Ok(buf)
    }

    pub fn group(&self) -> EcGroup {
        self.group
    }

    pub fn sign(
        &self,
        type_: MessageDigest,
        input: impl AsRef<[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let buf = input.as_ref();
        let hash = openssl::hash::hash(type_, buf)?;

        match &self.inner {
            Inner::Private(pk) => {
                let sig = EcdsaSig::sign(&hash, pk.as_ref())?;
                Ok((sig.r().to_vec(), sig.s().to_vec()))
            }
            Inner::Public(_) => {
                return Err(Error::KeyTypeIncorrect(anyhow!("sign require private key")));
            }
        }
    }

    pub fn verify(
        &self,
        type_: MessageDigest,
        input: impl AsRef<[u8]>,
        r: Vec<u8>,
        s: Vec<u8>,
    ) -> Result<bool, Error> {
        let hash = openssl::hash::hash(type_, input.as_ref())?;

        let r = BigNum::from_slice(&r)?;
        let s = BigNum::from_slice(&s)?;

        let sig = EcdsaSig::from_private_components(r, s)?;
        let check = match &self.inner {
            Inner::Private(pk) => sig.verify(&hash, pk.as_ref())?,
            Inner::Public(pk) => sig.verify(&hash, pk.as_ref())?,
        };

        Ok(check)
    }

    impl_fingerprint!();
}

#[cfg(test)]
mod test {
    use super::{EcGroup, Ecdsa, HashType, PEMFormat};
    use anyhow::Result;
    use openssl::hash::MessageDigest;

    const KEY_256: &'static str = include_str!("../../tests/ecdsa/ecdsa_256");
    const KEY_256_ENC: &'static str = include_str!("../../tests/ecdsa/ecdsa_256_enc");
    const KEY_256_PUB: &'static str = include_str!("../../tests/ecdsa/ecdsa_256.pub");
    const KEY_256_FIG: &'static str = "d2/OomSuIb8W4rrPTQE3yui35o6nlXJIzivYVbveHu4";

    const KEY_384: &'static str = include_str!("../../tests/ecdsa/ecdsa_384");
    const KEY_384_ENC: &'static str = include_str!("../../tests/ecdsa/ecdsa_384_enc");
    const KEY_384_PUB: &'static str = include_str!("../../tests/ecdsa/ecdsa_384.pub");
    const KEY_384_FIG: &'static str = "YXyd4CCYGiawAepDxIFeY9GjH0LqHdHIL7nBnf6NOfE";

    const KEY_521: &'static str = include_str!("../../tests/ecdsa/ecdsa_521");
    const KEY_521_ENC: &'static str = include_str!("../../tests/ecdsa/ecdsa_521_enc");
    const KEY_521_PUB: &'static str = include_str!("../../tests/ecdsa/ecdsa_521.pub");
    const KEY_521_FIG: &'static str = "HEnKR0vhaIBhIyz5AF2shR/v3Rs9Z9kvHjhZxw8mRNA";

    const PHASE: Option<&str> = Some("12345678");
    const PHASE_NONE: Option<&str> = None;

    #[test]
    fn import_openssh() -> Result<()> {
        let _ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let _ecdsa = Ecdsa::import_private_pem(KEY_384, PHASE_NONE)?;
        let _ecdsa = Ecdsa::import_private_pem(KEY_521, PHASE_NONE)?;

        Ok(())
    }

    #[test]
    fn import_openssh_enc() -> Result<()> {
        let _ecdsa = Ecdsa::import_private_pem(KEY_256_ENC, PHASE)?;
        let _ecdsa = Ecdsa::import_private_pem(KEY_384_ENC, PHASE)?;
        let _ecdsa = Ecdsa::import_private_pem(KEY_521_ENC, PHASE)?;

        Ok(())
    }

    #[test]
    fn export_openssh() -> Result<()> {
        let ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let _pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE_NONE)?;

        let ecdsa = Ecdsa::import_private_pem(KEY_384, PHASE_NONE)?;
        let _pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE_NONE)?;

        let ecdsa = Ecdsa::import_private_pem(KEY_521, PHASE_NONE)?;
        let _pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE_NONE)?;

        Ok(())
    }

    #[test]
    fn export_openssh_enc() -> Result<()> {
        let ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE)?;
        let _ecdsa = Ecdsa::import_private_pem(pem, PHASE)?;

        let ecdsa = Ecdsa::import_private_pem(KEY_384, PHASE_NONE)?;
        let pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE)?;
        let _ecdsa = Ecdsa::import_private_pem(pem, PHASE)?;

        let ecdsa = Ecdsa::import_private_pem(KEY_521, PHASE_NONE)?;
        let pem = ecdsa.export_private_pem(PEMFormat::Openssh, PHASE)?;
        let _ecdsa = Ecdsa::import_private_pem(pem, PHASE)?;

        Ok(())
    }

    #[test]
    fn export_public() -> Result<()> {
        let ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let public = ecdsa.export_public_ssh()?;
        assert_eq!(public, KEY_256_PUB.trim());

        let ecdsa = Ecdsa::import_private_pem(KEY_384, PHASE_NONE)?;
        let public = ecdsa.export_public_ssh()?;
        assert_eq!(public, KEY_384_PUB.trim());

        let ecdsa = Ecdsa::import_private_pem(KEY_521, PHASE_NONE)?;
        let public = ecdsa.export_public_ssh()?;
        assert_eq!(public, KEY_521_PUB.trim());

        Ok(())
    }

    #[test]
    fn fingerprint() -> Result<()> {
        let ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let fingerprint = ecdsa.fingerprint(HashType::SHA256)?;

        assert_eq!(fingerprint, KEY_256_FIG);

        let ecdsa = Ecdsa::import_private_pem(KEY_384, PHASE_NONE)?;
        let fingerprint = ecdsa.fingerprint(HashType::SHA256)?;

        assert_eq!(fingerprint, KEY_384_FIG);

        let ecdsa = Ecdsa::import_private_pem(KEY_521, PHASE_NONE)?;
        let fingerprint = ecdsa.fingerprint(HashType::SHA256)?;

        assert_eq!(fingerprint, KEY_521_FIG);
        Ok(())
    }

    #[test]
    fn signature() -> Result<()> {
        let ecdsa = Ecdsa::import_private_pem(KEY_256, PHASE_NONE)?;
        let buf = [0u8; 4096];

        let (r, s) = ecdsa.sign(MessageDigest::sha256(), &buf)?;

        let check = ecdsa.verify(MessageDigest::sha256(), &buf, r, s)?;
        assert!(check);

        Ok(())
    }

    #[test]
    fn generate() -> Result<()> {
        let _ecdsa = Ecdsa::generate(EcGroup::P256, None)?;
        let _ecdsa = Ecdsa::generate(EcGroup::P384, None)?;
        let _ecdsa = Ecdsa::generate(EcGroup::P521, None)?;

        Ok(())
    }
}
