use std::{error::Error, sync::Arc};

use axum::{response::IntoResponse, Extension};
use hyper::body::Incoming;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PrintableString, PublicKeyData, SubjectPublicKeyInfo,
};
use rustls::{pki_types::PrivateKeyDer, server::WebPkiClientVerifier, RootCertStore};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use tower_server::TlsConfigFactory;

#[tokio::test]
async fn test_tls_localhost_cert_ok() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let text_response = reqwest::ClientBuilder::new()
        .add_root_certificate((&ca).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(text_response, "it works: no client auth");

    cancel.cancel();
}

#[tokio::test]
async fn test_tls_missing_client_ca_results_in_unknown_issuer() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap_err();

    let error_source = error.source();

    assert_eq!(
        "Some(hyper_util::client::legacy::Error(Connect, Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(UnknownIssuer) } }))",
        format!("{error_source:?}"),
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_tls_incorrect_trusted_ca_results_in_bad_signature() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&CertifiedKey::new_ca()).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap_err();

    let error_source = error.source();

    assert_eq!(
        "Some(hyper_util::client::legacy::Error(Connect, Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(BadSignature) } }))",
        format!("{error_source:?}"),
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_tls_invalid_host_cert() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("gooofy"));

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&ca).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap_err();

    let error_source = error.source();

    assert_eq!(
        "Some(hyper_util::client::legacy::Error(Connect, Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(NotValidForName) } }))",
        format!("{error_source:?}"),
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_mtls_verified() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));
    let client_cert = ca.sign(SigningRequest::client_cert("testclientname"));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let text_response = reqwest::ClientBuilder::new()
        .add_root_certificate((&ca).into())
        .identity((&client_cert).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(
        text_response,
        "it works: peer_subject_common_name=testclientname"
    );

    cancel.cancel();
}

// TODO: It should be possible to use optional client auth?
#[tokio::test]
async fn test_mtls_missing_client_identity() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&ca).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap_err();

    let error_source = error.source();

    assert_eq!(
        "Some(hyper_util::client::legacy::Error(SendRequest, hyper::Error(Io, Custom { kind: InvalidData, error: \"received fatal alert: CertificateRequired\" })))",
        format!("{error_source:?}"),
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_mtls_invalid_issuer() {
    let ca = CertifiedKey::new_ca();
    let server_cert = ca.sign(SigningRequest::server_cert("localhost"));

    let bad_ca = CertifiedKey::new_ca();
    let bad_client_cert = bad_ca.sign(SigningRequest::client_cert("someclient"));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&ca).into())
        .identity((&bad_client_cert).into())
        .build()
        .unwrap()
        .get(format!("https://localhost:{server_port}/test"))
        .send()
        .await
        .unwrap_err();

    let error_source = error.source();

    assert_eq!(
        "Some(hyper_util::client::legacy::Error(SendRequest, hyper::Error(Io, Custom { kind: InvalidData, error: \"received fatal alert: DecryptError\" })))",
        format!("{error_source:?}"),
    );
}

async fn spawn_server(rustls_config_factory: TlsConfigFactory) -> (u16, CancellationToken) {
    let cancel = CancellationToken::new();
    let server = tower_server::Server::bind(
        tower_server::ServerConfig::new("0.0.0.0:0".parse().unwrap())
            .with_tls_config(rustls_config_factory)
            .with_scheme(tower_server::Scheme::Https)
            .with_tls_connection_middleware(tls_middleware::TlsMiddleware)
            .with_cancellation_token(cancel.clone()),
    )
    .await
    .unwrap();

    let server_port = server.local_addr().unwrap().port();
    let app = axum::Router::new().route("/test", axum::routing::get(test_handler));

    tokio::spawn(server.serve(app));

    (server_port, cancel)
}

mod tls_middleware {
    use hyper::body::Incoming;
    use rustls::server::ParsedCertificate;
    use tracing::info;
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[derive(Clone)]
    pub struct TlsMiddleware;

    #[derive(Default)]
    pub struct TlsConnectionData {
        peer_subject_common_name: Option<String>,
    }

    #[derive(Clone)]
    pub struct PeerSubjectCommonName(pub String);

    impl tower_server::tls::TlsConnectionMiddleware for TlsMiddleware {
        type Data = Option<TlsConnectionData>;

        fn data(&self, connection: &rustls::ServerConnection) -> Self::Data {
            let peer_der = connection.peer_certificates()?.first()?;
            let (_, peer_cert) = X509Certificate::from_der(&peer_der).ok()?;

            let mut data = TlsConnectionData::default();

            for rdn in peer_cert.subject.iter() {
                for attr in rdn.iter() {
                    if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                        if let Ok(value) = attr.attr_value().as_str() {
                            data.peer_subject_common_name = Some(value.to_string());
                        }
                    }
                }
            }

            Some(data)
        }

        fn call(&self, req: &mut axum::http::Request<Incoming>, data: &Self::Data) {
            let Some(data) = data else {
                return;
            };
            if let Some(peer_subject_common_name) = &data.peer_subject_common_name {
                req.extensions_mut()
                    .insert(PeerSubjectCommonName(peer_subject_common_name.clone()));
            }
        }
    }
}

async fn test_handler(
    peer_subject_common_name: Option<Extension<tls_middleware::PeerSubjectCommonName>>,
) -> axum::response::Response {
    if let Some(Extension(peer_subject_common_name)) = peer_subject_common_name {
        format!(
            "it works: peer_subject_common_name={}",
            peer_subject_common_name.0
        )
        .into_response()
    } else {
        "it works: no client auth".into_response()
    }
}

fn rustls_server_config_no_client_auth(
    server_cert: &CertifiedKey,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der = PrivateKeyDer::try_from(server_cert.key_pair.serialize_der()).unwrap();

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert.cert.der().clone()], private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn rustls_server_config_mtls(
    server_cert: &CertifiedKey,
    root_ca: &Certificate,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der = PrivateKeyDer::try_from(server_cert.key_pair.serialize_der()).unwrap();

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(root_ca.der().clone())?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_cert_store.into()).build()?)
        .with_single_cert(vec![server_cert.cert.der().clone()], private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn key_pair() -> KeyPair {
    KeyPair::generate().unwrap()
}

struct CertifiedKey {
    cert: Certificate,
    key_pair: KeyPair,
}

impl CertifiedKey {
    fn new_ca() -> Self {
        let mut params = CertificateParams::default();
        let (yesterday, tomorrow) = validity_period();
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

        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate().unwrap();
        Self {
            cert: params.self_signed(&key_pair).unwrap(),
            key_pair,
        }
    }

    fn sign(&self, request: SigningRequest) -> Self {
        let public_key =
            SubjectPublicKeyInfo::from_der(&request.key_pair.public_key_der()).unwrap();
        Self {
            cert: request
                .params
                .signed_by(&public_key, &self.cert, &self.key_pair)
                .unwrap(),
            key_pair: request.key_pair,
        }
    }
}

struct SigningRequest {
    params: CertificateParams,
    key_pair: KeyPair,
}

impl SigningRequest {
    fn server_cert(common_name: &str) -> Self {
        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .expect("we know the name is valid");
        let (yesterday, tomorrow) = validity_period();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.not_before = yesterday;
        params.not_after = tomorrow;

        Self {
            params,
            key_pair: KeyPair::generate().unwrap(),
        }
    }

    fn client_cert(common_name: &str) -> Self {
        let mut params = CertificateParams::new(vec![]).expect("we know the name is valid");
        let (yesterday, tomorrow) = validity_period();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params.not_before = yesterday;
        params.not_after = tomorrow;

        Self {
            params,
            key_pair: KeyPair::generate().unwrap(),
        }
    }
}

impl Into<reqwest::Certificate> for &CertifiedKey {
    fn into(self) -> reqwest::Certificate {
        reqwest::tls::Certificate::from_der(self.cert.der()).unwrap()
    }
}

impl Into<reqwest::Identity> for &CertifiedKey {
    fn into(self) -> reqwest::Identity {
        reqwest::Identity::from_pem(
            format!("{}{}", self.cert.pem(), self.key_pair.serialize_pem()).as_bytes(),
        )
        .unwrap()
    }
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}
