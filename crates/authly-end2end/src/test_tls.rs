use std::{error::Error, sync::Arc};

use authly::{
    cert::{Cert, MakeSigningRequest},
    mtls::PeerServiceEID,
};
use axum::{response::IntoResponse, Extension};
use hyper::body::Incoming;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PrintableString, PublicKeyData, SubjectPublicKeyInfo,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use tower_server::TlsConfigFactory;

#[tokio::test]
async fn test_tls_localhost_cert_ok() {
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));

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
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));

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
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));

    let rustls_config_factory = rustls_server_config_no_client_auth(&server_cert).unwrap();
    let (server_port, cancel) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&Cert::new_authly_ca()).into())
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
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("gooofy", Duration::hours(1)));

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
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));
    let client_cert =
        ca.sign(new_key_pair().client_cert("cf2e74c3f26240908e1b4e8817bfde7c", Duration::hours(1)));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.der).unwrap();
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
        "it works: peer_service_eid=cf2e74c3f26240908e1b4e8817bfde7c"
    );

    cancel.cancel();
}

// TODO: It should be possible to use optional client auth?
#[tokio::test]
async fn test_mtls_missing_client_identity() {
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.der).unwrap();
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
    let ca = Cert::new_authly_ca();
    let server_cert = ca.sign(new_key_pair().server_cert("localhost", Duration::hours(1)));

    let bad_ca = Cert::new_authly_ca();
    let bad_client_cert = bad_ca.sign(new_key_pair().client_cert("1337", Duration::hours(1)));

    let rustls_config_factory = rustls_server_config_mtls(&server_cert, &ca.der).unwrap();
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
    let server = tower_server::Builder::new("0.0.0.0:0".parse().unwrap())
        .with_scheme(tower_server::Scheme::Https)
        .with_tls_config(rustls_config_factory)
        .with_tls_connection_middleware(authly::mtls::MTLSMiddleware)
        .with_cancellation_token(cancel.clone())
        .bind()
        .await
        .unwrap();

    let server_port = server.local_addr().unwrap().port();
    let app = axum::Router::new().route("/test", axum::routing::get(test_handler));

    tokio::spawn(server.serve(app));

    (server_port, cancel)
}

async fn test_handler(
    peer_service_eid: Option<Extension<PeerServiceEID>>,
) -> axum::response::Response {
    if let Some(Extension(PeerServiceEID(eid))) = peer_service_eid {
        format!("it works: peer_service_eid={}", eid).into_response()
    } else {
        "it works: no client auth".into_response()
    }
}

fn rustls_server_config_no_client_auth(
    server_cert: &Cert<KeyPair>,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der()).unwrap();

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert.der.clone()], private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn rustls_server_config_mtls(
    server_cert: &Cert<KeyPair>,
    root_ca: &CertificateDer,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der()).unwrap();

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(root_ca.clone())?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_cert_store.into()).build()?)
        .with_single_cert(vec![server_cert.der.clone()], private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn new_key_pair() -> KeyPair {
    KeyPair::generate().unwrap()
}
