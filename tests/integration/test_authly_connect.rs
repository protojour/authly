use std::sync::Arc;

use authly::{
    cert::{Cert, MakeSigningRequest},
    connect::{
        grpc_client::new_authly_connect_grpc_client_service, tunnel::authly_connect_client_tunnel,
    },
    proto::connect_server::ConnectServer,
};
use authly_common::{
    mtls_server::PeerServiceEntity,
    proto::{
        authority::{
            authly_authority_client::AuthlyAuthorityClient,
            authly_authority_server::AuthlyAuthorityServer,
        },
        connect::{
            authly_connect_client::AuthlyConnectClient, authly_connect_server::AuthlyConnectServer,
        },
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
                "POST /hello HTTP/1.1\r\n",
                "Host: authly-tunnel\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    tunneled_tls.read_to_end(&mut response).await.unwrap();

    let response = std::str::from_utf8(&response).unwrap();

    info!("response: {response}");

    assert!(response.ends_with("HELLO cf2e74c3f26240908e1b4e8817bfde7c!"));

    cancel.cancel();
}

#[test(tokio::test)]
async fn test_connect_authority() {
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
        mock_authority_service(),
        cancel.clone(),
    )
    .await;

    let mut authority_client = AuthlyAuthorityClient::new(
        new_authly_connect_grpc_client_service(
            format!("http://localhost:{port}").into(),
            Arc::new({
                let mut root_store = RootCertStore::empty();
                root_store.add(ca.der).unwrap();
                rustls::client::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(
                        vec![client_cert.der],
                        client_cert.key.serialize_der().try_into().unwrap(),
                    )
                    .unwrap()
            }),
            cancel.clone(),
        )
        .await
        .unwrap(),
    );

    let response = authority_client
        .get_mandate_contract(tonic::Request::new(Default::default()))
        .await
        .unwrap();

    println!("response: {response:?}");

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

fn mock_authority_service() -> axum::Router {
    let mut grpc_routes = tonic::service::RoutesBuilder::default();
    grpc_routes.add_service(AuthlyAuthorityServer::new(mock::MockAuthlyAuthority));
    grpc_routes.routes().into_axum_router()
}

mod mock {
    use authly_common::id::Eid;
    use authly_common::proto::authority as proto;
    use authly_common::proto::authority::authly_authority_server::AuthlyAuthority;
    use hexhex::hex_literal;

    pub struct MockAuthlyAuthority;

    #[tonic::async_trait]
    impl AuthlyAuthority for MockAuthlyAuthority {
        async fn get_mandate_contract(
            &self,
            _request: tonic::Request<proto::Empty>,
        ) -> tonic::Result<tonic::Response<proto::MandateContract>> {
            Ok(tonic::Response::new(proto::MandateContract {
                authority_entity_id: Eid::from_array(hex_literal!(
                    "e5462a0d22b54d9f9ca37bd96e9b9d8b"
                ))
                .to_bytes()
                .to_vec(),
                authority_certificate: vec![],
                mandate_grants: vec![],
            }))
        }
    }
}
