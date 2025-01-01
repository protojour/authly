use std::{error::Error, sync::Arc};

use axum::response::IntoResponse;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PrintableString, PublicKeyData,
};
use rustls::{pki_types::PrivateKeyDer, server::WebPkiClientVerifier, RootCertStore};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use tower_server::TlsConfigFactory;

#[tokio::test]
async fn test_tls_localhost_cert_ok() {
    let ca = KeyedCertificate::new_ca();
    let server_cert = ca.issue_server_cert("localhost");

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

    assert_eq!(text_response, "it works");

    cancel.cancel();
}

#[tokio::test]
async fn test_tls_missing_client_ca_results_in_unknown_issuer() {
    let ca = KeyedCertificate::new_ca();
    let cert = ca.issue_server_cert("localhost");

    let rustls_config_factory = rustls_server_config_no_client_auth(&cert).unwrap();
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
    let ca = KeyedCertificate::new_ca();
    let server_cert = ca.issue_server_cert("localhost");

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&KeyedCertificate::new_ca()).into())
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
    let ca = KeyedCertificate::new_ca();
    let cert = ca.issue_server_cert("goofy");

    let rustls_config_factory = rustls_server_config_no_client_auth(&cert).unwrap();
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
    let ca = KeyedCertificate::new_ca();
    let server_cert = ca.issue_server_cert("localhost");
    let client_cert = ca.issue_client_cert();

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

    assert_eq!(text_response, "it works");

    cancel.cancel();
}

#[tokio::test]
async fn test_mtls_invalid_issuer() {
    let ca = KeyedCertificate::new_ca();
    let server_cert = ca.issue_server_cert("localhost");

    let bad_ca = KeyedCertificate::new_ca();
    let bad_client_cert = bad_ca.issue_client_cert();

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
            .with_cancellation_token(cancel.clone()),
    )
    .await
    .unwrap();

    let server_port = server.local_addr().unwrap().port();
    let app = axum::Router::new().route("/test", axum::routing::get(test_handler));

    tokio::spawn(server.serve(app));

    (server_port, cancel)
}

async fn test_handler() -> axum::response::Response {
    "it works".into_response()
}

fn rustls_server_config_no_client_auth(
    server_cert: &KeyedCertificate,
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
    server_cert: &KeyedCertificate,
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

struct KeyedCertificate {
    cert: Certificate,
    key_pair: KeyPair,
}

impl KeyedCertificate {
    fn new_ca() -> Self {
        let mut params = CertificateParams::new(Vec::default())
            .expect("empty subject alt name can't produce error");
        let (yesterday, tomorrow) = validity_period();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            DnType::CountryName,
            DnValue::PrintableString("BR".try_into().unwrap()),
        );
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Crab widgits SE");
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

    fn issue_server_cert(&self, common_name: &str) -> Self {
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

        let key_pair = KeyPair::generate().unwrap();
        Self {
            cert: params
                .signed_by(&key_pair, &self.cert, &self.key_pair)
                .unwrap(),
            key_pair,
        }
    }

    fn issue_client_cert(&self) -> Self {
        let mut params = CertificateParams::new(vec![]).expect("we know the name is valid");
        let (yesterday, tomorrow) = validity_period();
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params.not_before = yesterday;
        params.not_after = tomorrow;

        let key_pair = KeyPair::generate().unwrap();
        Self {
            cert: params
                .signed_by(&key_pair, &self.cert, &self.key_pair)
                .unwrap(),
            key_pair,
        }
    }
}

impl Into<reqwest::Certificate> for &KeyedCertificate {
    fn into(self) -> reqwest::Certificate {
        reqwest::tls::Certificate::from_der(self.cert.der()).unwrap()
    }
}

impl Into<reqwest::Identity> for &KeyedCertificate {
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
