use std::sync::Arc;

use authly_common::{
    id::ServiceId, mtls_server::PeerServiceEntity,
    proto::connect::authly_connect_client::AuthlyConnectClient,
};
use authly_connect::{
    client::new_authly_connect_grpc_client_service, tunnel::authly_connect_client_tunnel,
    TunnelSecurity,
};
use authly_test_grpc::{
    test_grpc_client::TestGrpcClient, test_grpc_server::TestGrpcServer, TestMsg,
};
use axum::{response::IntoResponse, Extension};
use futures_util::{stream::BoxStream, StreamExt};
use rustls::{pki_types::ServerName, RootCertStore};
use test_log::test;
use time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    cert::{authly_ca, client_cert, server_cert, CertificateParamsExt},
    tests::{rustls_server_config_mtls, spawn_test_connect_server},
};

#[test(tokio::test)]
async fn test_connect_grpc() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = authly_ca().with_new_key_pair().self_signed();
    let tunneled_server_cert = ca.sign(
        server_cert(
            "svc",
            vec!["authly-connect".to_string()],
            Duration::hours(1),
        )
        .unwrap()
        .with_new_key_pair(),
    );
    let client_cert = ca.sign(
        client_cert("client", ServiceId::from_uint(666_777), Duration::hours(1))
            .with_new_key_pair(),
    );

    let (local_url, _drop) = spawn_test_connect_server(
        rustls_server_config_mtls(&[&tunneled_server_cert], &ca.der).unwrap(),
        TunnelSecurity::MutuallySecure,
        tonic::service::Routes::default()
            .add_service(TestGrpcServer::new(TestGrpcServerImpl))
            .into_axum_router(),
    )
    .await;

    let cancel = CancellationToken::new();
    let mut authority_client = TestGrpcClient::new(
        new_authly_connect_grpc_client_service(
            local_url.into(),
            TunnelSecurity::MutuallySecure,
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
    let _drop = cancel.drop_guard();

    let response = authority_client
        .echo(tonic::Request::new(TestMsg {
            foo: "bar".to_string(),
        }))
        .await
        .unwrap();

    println!("echo response: {response:?}");

    let messages: Vec<tonic::Result<TestMsg>> = authority_client
        .duplex(async_stream::stream! {
            for i in 0..3 {
                yield TestMsg { foo: format!("message {i}") };
                sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
        .into_inner()
        .collect()
        .await;

    println!("duplex messages: {messages:?}");

    assert_eq!(4, messages.len());
}

struct TestGrpcServerImpl;

#[tonic::async_trait]
impl authly_test_grpc::test_grpc_server::TestGrpc for TestGrpcServerImpl {
    type DuplexStream = BoxStream<'static, tonic::Result<TestMsg>>;

    async fn echo(&self, req: tonic::Request<TestMsg>) -> tonic::Result<tonic::Response<TestMsg>> {
        Ok(tonic::Response::new(req.into_inner()))
    }

    async fn duplex(
        &self,
        req: tonic::Request<tonic::Streaming<TestMsg>>,
    ) -> tonic::Result<tonic::Response<Self::DuplexStream>> {
        let msg_counter = tokio::spawn(
            req.into_inner()
                .map(|msg| {
                    info!(?msg, "server received");
                })
                .count(),
        );

        Ok(tonic::Response::new(
            async_stream::stream! {
                for i in 0..3 {
                    let msg = TestMsg {
                        foo: format!("item {i}")
                    };
                    info!(?msg, "server yield");
                    yield Ok(msg);

                    sleep(std::time::Duration::from_millis(50)).await;
                }

                let n_incoming_messages = msg_counter.await.unwrap();
                yield Ok(TestMsg { foo: format!("{n_incoming_messages} received") });
            }
            .boxed(),
        ))
    }
}

#[test(tokio::test)]
async fn test_connect_http() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = authly_ca().with_new_key_pair().self_signed();
    let tunneled_server_cert = ca.sign(
        server_cert(
            "svc",
            vec!["authly-connect".to_string()],
            Duration::hours(1),
        )
        .unwrap()
        .with_new_key_pair(),
    );
    let client_cert = ca.sign(
        client_cert("client", ServiceId::from_uint(666_777), Duration::hours(1))
            .with_new_key_pair(),
    );
    let (local_url, _drop) = spawn_test_connect_server(
        rustls_server_config_mtls(&[&tunneled_server_cert], &ca.der).unwrap(),
        TunnelSecurity::MutuallySecure,
        axum::Router::new().route(
            "/hello",
            axum::routing::get(async |ext: Extension<PeerServiceEntity>| {
                let Extension(PeerServiceEntity(eid)) = ext;
                format!("HELLO {eid}!").into_response()
            }),
        ),
    )
    .await;

    // wraps mutual https over an insecure HTTP channel:
    info!("setting up connect tunnel");
    let cancel = CancellationToken::new();
    let tunnel = authly_connect_client_tunnel(
        AuthlyConnectClient::connect(local_url).await.unwrap(),
        TunnelSecurity::MutuallySecure,
        cancel.clone(),
    )
    .await
    .unwrap();
    let _drop = cancel.drop_guard();

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

    let mut response = Vec::new();
    tunneled_tls.read_to_end(&mut response).await.unwrap();

    let response = std::str::from_utf8(&response).unwrap();

    info!("response: {response}");

    assert!(response.ends_with("HELLO s.000000000000000000000000000a2c99!"));
}
