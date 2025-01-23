use std::sync::Arc;

use authly::{
    cert::{Cert, MakeSigningRequest},
    proto::connect_server::ConnectServer,
    tunnel::authly_connect_client_tunnel,
};
use authly_common::{
    mtls_server::PeerServiceEntity,
    proto::connect::{
        authly_connect_client::AuthlyConnectClient, authly_connect_server::AuthlyConnectServer,
    },
};
use axum::{response::IntoResponse, Extension};
use rcgen::KeyPair;
use rustls::{pki_types::ServerName, RootCertStore, ServerConfig};
use test_log::test;
use time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::rustls_server_config_mtls;

#[test(tokio::test)]
async fn test_connect() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = Cert::new_authly_ca();
    let tunneled_server_cert = ca.sign(
        KeyPair::generate()
            .unwrap()
            .server_cert("authly-connect", Duration::hours(1)),
    );
    let client_cert = ca.sign(
        KeyPair::generate()
            .unwrap()
            .client_cert("cf2e74c3f26240908e1b4e8817bfde7c", Duration::hours(1)),
    );
    let cancel = CancellationToken::new();

    let port = spawn_connect_server(
        rustls_server_config_mtls(&tunneled_server_cert, &ca.der).unwrap(),
        hello_service(),
        cancel.clone(),
    )
    .await;

    // wraps mutual https over an insecure HTTP channel:
    let connect_client = AuthlyConnectClient::connect(format!("http://localhost:{port}"))
        .await
        .unwrap();
    info!("setting up connect tunnel");
    let tunnel = authly_connect_client_tunnel(connect_client, cancel.clone())
        .await
        .unwrap();

    let tls_client_config = {
        let mut root_store = RootCertStore::empty();
        root_store.add(ca.der).unwrap();
        rustls::client::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(
                vec![client_cert.der],
                client_cert.key.serialize_der().try_into().unwrap(),
            )
            .unwrap()
    };

    let connector = TlsConnector::from(Arc::new(tls_client_config));
    let domain = ServerName::try_from("authly-connect").unwrap();
    let mut tunneled_tls = connector.connect(domain, tunnel).await.unwrap();

    tunneled_tls
        .write_all(
            concat!(
                "GET /hello HTTP/1.1\r\n",
                "Host: authly-tunnel\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut plaintext = Vec::new();
    tunneled_tls.read_to_end(&mut plaintext).await.unwrap();

    let plaintext = std::str::from_utf8(&plaintext).unwrap();

    assert!(plaintext.ends_with("HELLO cf2e74c3f26240908e1b4e8817bfde7c!"));

    cancel.cancel();
}

async fn spawn_connect_server(
    tls_config: ServerConfig,
    service: axum::Router,
    cancel: CancellationToken,
) -> u16 {
    let server = tower_server::Builder::new("0.0.0.0:0".parse().unwrap())
        .with_graceful_shutdown(cancel.clone())
        .bind()
        .await
        .unwrap();
    let port = server.local_addr().unwrap().port();

    let mut grpc_routes = tonic::service::RoutesBuilder::default();
    grpc_routes.add_service(AuthlyConnectServer::new(ConnectServer {
        tls_server_config: Arc::new(tls_config),
        service,
        cancel,
    }));

    tokio::spawn(server.serve(grpc_routes.routes().into_axum_router()));

    port
}

fn hello_service() -> axum::Router {
    async fn hello(
        Extension(PeerServiceEntity(eid)): Extension<PeerServiceEntity>,
    ) -> axum::response::Response {
        format!("HELLO {eid}!").into_response()
    }

    axum::Router::new().route("/hello", axum::routing::get(hello))
}
