use crate::buffer::SSHBuffer;
use crate::error::Error;
use openssl::bn;
use openssl::dsa;
use openssl::pkey::{Private, Public};

enum Inner {
    Private(dsa::Dsa<Private>),
    Public(dsa::Dsa<Public>),
}

pub struct Dss {
    #[allow(dead_code)]
    inner: Inner,
}

impl Dss {
    pub fn generate(bits: u32) -> Result<Dss, Error> {
        let pk = dsa::Dsa::generate(bits)?;

        Ok(Dss {
            inner: Inner::Private(pk),
        })
    }

    pub fn from_pub_pem(pem: impl AsRef<[u8]>) -> Result<Dss, Error> {
        let pem = pem.as_ref();
        let pem = Vec::from(base64::decode(pem)?);

        let mut buf = SSHBuffer::new(pem)?;
        let ty = buf.get_string()?;
        let ty = std::str::from_utf8(&ty)?;
        debug_assert_eq!(ty, "ssh-dss");

        let p = buf.get_string()?;
        let q = buf.get_string()?;
        let g = buf.get_string()?;
        let n = buf.get_string()?;

        let (p, q, g, n) = (
            bn::BigNum::from_slice(&p)?,
            bn::BigNum::from_slice(&q)?,
            bn::BigNum::from_slice(&g)?,
            bn::BigNum::from_slice(&n)?,
        );

        let pk = dsa::Dsa::from_public_components(p, q, g, n)?;

        Ok(Dss {
            inner: Inner::Public(pk),
        })
    }

    fn from_private_pem_openssl(
        _pem: impl AsRef<[u8]>,
        _phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Dss, Error> {
        Err(Error::UnsupportedKeyFormat(anyhow!(
            "unimplemented: dss is not support currently"
        )))
    }

    fn from_private_pem_openssh(
        _pem: impl AsRef<[u8]>,
        _phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Dss, Error> {
        Err(Error::UnsupportedKeyFormat(anyhow!(
            "unimplemented: dss is not support currently"
        )))
    }

    pub fn from_private_pem(
        pem: impl AsRef<[u8]>,
        phase: Option<impl AsRef<[u8]>>,
    ) -> Result<Dss, Error> {
        let pem = pem.as_ref();
        let pem_str = std::str::from_utf8(&pem)?;

        if pem_str.contains("BEGIN OPENSSH PRIVATE KEY") {
            Self::from_private_pem_openssh(pem_str, phase)
        } else {
            Self::from_private_pem_openssl(pem, phase)
        }
    }
}
