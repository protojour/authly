use std::{error::Error, sync::Arc};

use authly_common::{id::ServiceId, mtls_server::PeerServiceEntity};
use authly_domain::cert::{
    authly_ca, client_cert, server_cert, server_cert_csr, Cert, CertificateParamsExt,
};
use axum::{response::IntoResponse, Extension};
use rcgen::CertificateSigningRequestParams;
use rustls::{pki_types::CertificateSigningRequestDer, ServerConfig};
use time::Duration;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::util::{rustls_server_config_mtls, rustls_server_config_no_client_auth};

fn localhost() -> Vec<String> {
    vec!["localhost".to_string()]
}

#[tokio::test]
async fn test_tls_localhost_cert_ok() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_no_client_auth(&[&server_cert]).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
}

#[tokio::test]
async fn test_tls_localhost_intermediate_cert_ok() {
    let root_ca = authly_ca().with_new_key_pair().self_signed();
    let intermediate_ca = root_ca.sign(authly_ca().with_new_key_pair());
    let server_cert = intermediate_ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory =
        rustls_server_config_no_client_auth(&[&server_cert, &intermediate_ca]).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

    let text_response = reqwest::ClientBuilder::new()
        .add_root_certificate((&root_ca).into())
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
}

#[tokio::test]
async fn test_tls_missing_client_ca_results_in_unknown_issuer() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_no_client_auth(&[&server_cert]).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
}

#[tokio::test]
async fn test_tls_incorrect_trusted_ca_results_in_bad_signature() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_no_client_auth(&[&server_cert]).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

    let error = reqwest::ClientBuilder::new()
        .add_root_certificate((&authly_ca().with_new_key_pair().self_signed()).into())
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
}

#[tokio::test]
async fn test_tls_invalid_host_cert() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", vec!["gooofy".to_string()], Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_no_client_auth(&[&server_cert]).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
        r#"Some(hyper_util::client::legacy::Error(Connect, Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(NotValidForNameContext { expected: DnsName("localhost"), presented: ["DnsName(\"gooofy\")"] }) } }))"#,
        format!("{error_source:?}"),
    );
}

#[tokio::test]
async fn test_mtls_verified() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );
    let client_cert = ca.sign(
        client_cert("svc", ServiceId::from_uint(777_666), Duration::hours(1)).with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_mtls(&[&server_cert], &ca.der).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
        "it works: peer_service_eid=s.000000000000000000000000000bddc2"
    );
}

#[tokio::test]
async fn test_mtls_server_cert_through_csr() {
    let ca = authly_ca().with_new_key_pair().self_signed();

    let server_cert = {
        let req = server_cert_csr("svc", localhost(), Duration::days(1))
            .unwrap()
            .with_new_key_pair();

        let csr_der = req
            .params
            .serialize_request(&req.key)
            .unwrap()
            .der()
            .to_vec();

        let csr_params =
            CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der))
                .unwrap();
        let signed_cert = csr_params.signed_by(&ca.params, &ca.key).unwrap();

        Cert {
            params: signed_cert.params().clone(),
            der: signed_cert.der().clone(),
            key: req.key,
        }
    };

    // let server_cert = ca.sign(gen_key_pair().server_cert_csr("localhost", Duration::hours(1)));
    let client_cert = ca.sign(
        client_cert("svc", ServiceId::from_uint(666_777), Duration::hours(1)).with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_mtls(&[&server_cert], &ca.der).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
        "it works: peer_service_eid=s.000000000000000000000000000a2c99"
    );
}

// TODO: It should be possible to use optional client auth?
#[tokio::test]
async fn test_mtls_missing_client_identity() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_mtls(&[&server_cert], &ca.der).unwrap();
    let (server_port, _drop) = spawn_server(rustls_config_factory).await;

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
}

#[tokio::test]
async fn test_mtls_invalid_issuer() {
    let ca = authly_ca().with_new_key_pair().self_signed();
    let server_cert = ca.sign(
        server_cert("svc", localhost(), Duration::hours(1))
            .unwrap()
            .with_new_key_pair(),
    );

    let bad_ca = authly_ca().with_new_key_pair().self_signed();
    let bad_client_cert = bad_ca.sign(
        client_cert("bad", ServiceId::from_uint(666), Duration::hours(1)).with_new_key_pair(),
    );

    let rustls_config_factory = rustls_server_config_mtls(&[&server_cert], &ca.der).unwrap();
    let (server_port, _cancel) = spawn_server(rustls_config_factory).await;

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

async fn spawn_server(rustls_config: Arc<ServerConfig>) -> (u16, DropGuard) {
    let cancel = CancellationToken::new();
    let server = tower_server::Builder::new("0.0.0.0:0".parse().unwrap())
        .with_scheme(tower_server::Scheme::Https)
        .with_tls_config(rustls_config)
        .with_tls_connection_middleware(authly_common::mtls_server::MTLSMiddleware)
        .with_graceful_shutdown(cancel.clone())
        .bind()
        .await
        .unwrap();

    let server_port = server.local_addr().unwrap().port();
    let app = axum::Router::new().route("/test", axum::routing::get(test_handler));

    tokio::spawn(server.serve(app));

    (server_port, cancel.drop_guard())
}

async fn test_handler(
    peer_service_eid: Option<Extension<PeerServiceEntity>>,
) -> axum::response::Response {
    if let Some(Extension(PeerServiceEntity(eid))) = peer_service_eid {
        format!("it works: peer_service_eid={}", eid).into_response()
    } else {
        "it works: no client auth".into_response()
    }
}
