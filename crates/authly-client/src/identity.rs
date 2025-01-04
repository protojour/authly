use crate::Error;

pub struct Identity {
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
}

impl Identity {
    /// Load identity from PEM file containing a certificate and private key
    pub fn from_multi_pem(pem: impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut identity_pems = pem::parse_many(pem)
            .map_err(|_| Error::Identity("invalid pem format"))?
            .into_iter();
        let cert = identity_pems
            .next()
            .ok_or_else(|| Error::Identity("pem: missing certificate"))?;
        let key = identity_pems
            .next()
            .ok_or_else(|| Error::Identity("pem: missing private key"))?;

        Ok(Self {
            cert_pem: pem::encode(&cert).into_bytes(),
            key_pem: pem::encode(&key).into_bytes(),
        })
    }
}
