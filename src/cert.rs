use pem::{EncodeConfig, Pem};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SubjectPublicKeyInfo,
};
use rustls::pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

pub struct Cert<K> {
    pub params: CertificateParams,
    pub der: CertificateDer<'static>,
    pub key: K,
}

impl Cert<KeyPair> {
    pub fn sign<K: PublicKeyData>(&self, request: SigningRequest<K>) -> Cert<K> {
        let cert = request
            .params
            .signed_by(&request.key, &self.params, &self.key)
            .unwrap();

        Cert {
            params: cert.params().clone(),
            der: cert.der().clone(),
            key: request.key,
        }
    }
}

impl<K> Cert<K> {
    pub fn certificate_pem(&self) -> String {
        pem::encode_config(
            &Pem::new("CERTIFICATE", self.der.to_vec()),
            EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }
}

impl Cert<KeyPair> {
    pub fn certificate_and_key_pem(&self) -> String {
        format!("{}{}", self.certificate_pem(), self.key.serialize_pem())
    }
}

pub struct SigningRequest<K> {
    pub params: CertificateParams,
    pub key: K,
}

impl SigningRequest<KeyPair> {
    pub fn self_signed(self) -> Cert<KeyPair> {
        let cert = self.params.self_signed(&self.key).unwrap();

        Cert {
            params: cert.params().clone(),
            der: cert.der().clone(),
            key: self.key,
        }
    }
}

pub trait MakeSigningRequest: Sized {
    /// Create a new Authly CA with a very long expiry date
    fn authly_ca(self) -> SigningRequest<Self> {
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

        SigningRequest { params, key: self }
    }

    fn server_cert(self, common_name: &str, not_after: Duration) -> SigningRequest<Self> {
        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .expect("we know the name is valid");
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

        SigningRequest { params, key: self }
    }

    fn server_cert_csr(self, common_name: &str, not_after: Duration) -> SigningRequest<Self> {
        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .expect("we know the name is valid");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = false;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.not_before = past(Duration::days(1));
        params.not_after = future(not_after);

        SigningRequest { params, key: self }
    }

    fn client_cert(self, common_name: &str, not_after: Duration) -> SigningRequest<Self> {
        let mut params = CertificateParams::new(vec![]).expect("we know the name is valid");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params.not_before = past(Duration::days(1));
        params.not_after = future(not_after);

        SigningRequest { params, key: self }
    }
}

impl MakeSigningRequest for KeyPair {}
impl MakeSigningRequest for SubjectPublicKeyInfo {}

impl<K> From<&Cert<K>> for reqwest::Certificate {
    fn from(value: &Cert<K>) -> Self {
        reqwest::tls::Certificate::from_der(&value.der).unwrap()
    }
}

impl From<&Cert<KeyPair>> for reqwest::Identity {
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
