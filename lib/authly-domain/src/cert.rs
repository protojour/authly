use std::ops::Deref;

use authly_common::id::ServiceId;
use pem::{EncodeConfig, Pem};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SigningKey,
};
use rustls::pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

pub struct Cert<'a, K> {
    pub params: CertificateParams,
    pub der: CertificateDer<'static>,
    pub key: Key<'a, K>,
}

pub enum Key<'a, K> {
    Borrowed(&'a K),
    Owned(K),
}

impl<K> Deref for Key<'_, K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(k) => k,
            Self::Owned(k) => k,
        }
    }
}

impl<K: PublicKeyData> PublicKeyData for Key<'_, K> {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.deref().algorithm()
    }

    fn der_bytes(&self) -> &[u8] {
        self.deref().der_bytes()
    }

    fn subject_public_key_info(&self) -> Vec<u8> {
        self.deref().subject_public_key_info()
    }
}

impl<K: SigningKey> SigningKey for Key<'_, K> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.deref().sign(msg)
    }
}

impl Cert<'_, KeyPair> {
    pub fn sign<'a, K: PublicKeyData>(&self, request: SigningRequest<'a, K>) -> Cert<'a, K> {
        let cert = request
            .params
            .signed_by(request.key.deref(), &self.params, &self.key)
            .unwrap();

        Cert {
            params: CertificateParams::from_ca_cert_der(cert.der()).unwrap(),
            der: cert.der().clone(),
            key: request.key,
        }
    }
}

impl<K> Cert<'_, K> {
    pub fn certificate_pem(&self) -> String {
        pem::encode_config(
            &Pem::new("CERTIFICATE", self.der.to_vec()),
            EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }
}

impl Cert<'_, KeyPair> {
    pub fn certificate_and_key_pem(&self) -> String {
        format!("{}{}", self.certificate_pem(), self.key.serialize_pem())
    }
}

pub struct SigningRequest<'a, K> {
    pub params: CertificateParams,
    pub key: Key<'a, K>,
}

impl<'a> SigningRequest<'a, KeyPair> {
    pub fn self_signed(self) -> Cert<'a, KeyPair> {
        let cert = self.params.self_signed(&self.key).unwrap();

        Cert {
            params: CertificateParams::from_ca_cert_der(cert.der()).unwrap(),
            der: cert.der().clone(),
            key: self.key,
        }
    }
}

pub trait CertificateParamsExt {
    fn with_owned_key<K>(self, key: K) -> SigningRequest<'static, K>;
    fn with_borrowed_key<K>(self, key: &K) -> SigningRequest<'_, K>;
    fn with_new_key_pair(self) -> SigningRequest<'static, KeyPair>;
}

impl CertificateParamsExt for CertificateParams {
    fn with_owned_key<K>(self, key: K) -> SigningRequest<'static, K> {
        SigningRequest {
            params: self,
            key: Key::Owned(key),
        }
    }

    fn with_borrowed_key<K>(self, key: &K) -> SigningRequest<'_, K> {
        SigningRequest {
            params: self,
            key: Key::Borrowed(key),
        }
    }

    fn with_new_key_pair(self) -> SigningRequest<'static, KeyPair> {
        SigningRequest {
            params: self,
            key: Key::Owned(key_pair()),
        }
    }
}

/// Create a new Authly CA with a very long expiry date
pub fn authly_ca() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Authly ID");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Protojour AS");
    params.distinguished_name.push(
        DnType::CountryName,
        DnValue::PrintableString("NO".try_into().unwrap()),
    );
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = past(Duration::days(1));

    params
}

pub fn server_cert(
    common_name: &str,
    alt_names: impl Into<Vec<String>>,
    not_after: Duration,
) -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(alt_names)?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = past(Duration::days(1));
    params.not_after = future(not_after);

    Ok(params)
}

const EID_UNIQUE_IDENTIFIER: &[u64] = &[2, 5, 4, 45];

pub fn server_cert_csr(
    common_name: &str,
    alt_names: impl Into<Vec<String>>,
    not_after: Duration,
) -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(alt_names)?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.distinguished_name.push(
        DnType::CustomDnType(EID_UNIQUE_IDENTIFIER.to_vec()),
        common_name,
    );
    params.use_authority_key_identifier_extension = false;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = past(Duration::days(1));
    params.not_after = future(not_after);

    Ok(params)
}

pub fn client_cert(common_name: &str, svc_id: ServiceId, not_after: Duration) -> CertificateParams {
    let mut params = CertificateParams::new(vec![]).expect("we know the name is valid");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.distinguished_name.push(
        DnType::CustomDnType(EID_UNIQUE_IDENTIFIER.to_vec()),
        svc_id.to_string(),
    );
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.not_before = past(Duration::days(1));
    params.not_after = future(not_after);

    params
}

pub fn client_cert_csr(
    common_name: &str,
    svc_id: ServiceId,
    not_after: Duration,
) -> CertificateParams {
    let mut params = CertificateParams::new(vec![]).expect("we know the name is valid");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.distinguished_name.push(
        DnType::CustomDnType(EID_UNIQUE_IDENTIFIER.to_vec()),
        svc_id.to_string(),
    );
    params.use_authority_key_identifier_extension = false;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.not_before = past(Duration::days(1));
    params.not_after = future(not_after);

    params
}

impl<K> From<&Cert<'_, K>> for reqwest::Certificate {
    fn from(value: &Cert<K>) -> Self {
        reqwest::tls::Certificate::from_der(&value.der).unwrap()
    }
}

impl From<&Cert<'_, KeyPair>> for reqwest::Identity {
    fn from(value: &Cert<KeyPair>) -> Self {
        reqwest::Identity::from_pem(value.certificate_and_key_pem().as_bytes()).unwrap()
    }
}

pub fn key_pair() -> KeyPair {
    KeyPair::generate().unwrap()
}

fn past(duration: Duration) -> OffsetDateTime {
    OffsetDateTime::now_utc().checked_sub(duration).unwrap()
}

fn future(duration: Duration) -> OffsetDateTime {
    OffsetDateTime::now_utc().checked_add(duration).unwrap()
}
