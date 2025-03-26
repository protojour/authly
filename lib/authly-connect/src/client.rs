//! Authly Connect gRPC service
//!
//! Known bugs that must be fixed:
//! - On network failures, need to reconnect the outer channel

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use authly_common::proto::connect::authly_connect_client::AuthlyConnectClient;
use axum::body::Bytes;
use futures_util::future::BoxFuture;
use http::{
    uri::{Authority, Scheme},
    Uri,
};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::{pki_types::ServerName, ClientConfig};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tonic::body::Body;
use tower::Service;
use tracing::{info, trace};

use crate::{TunnelSecurity, SERVER_NAME};

use super::tunnel::{authly_connect_client_tunnel, StdError};

/// Create a gRPC service (client-side) that tunnels through AuthlyConnect
pub async fn new_authly_connect_grpc_client_service(
    connect_uri: Bytes,
    security: TunnelSecurity,
    tls_client_config: Arc<ClientConfig>,
    cancel: CancellationToken,
) -> anyhow::Result<TunneledGrpcClientService> {
    let endpoint = tonic::transport::Endpoint::from_shared(connect_uri.clone()).unwrap();
    let channel = endpoint.connect().await?;

    let close_signal = cancel.child_token();

    let raw_tunnel = authly_connect_client_tunnel(
        AuthlyConnectClient::new(channel.clone()),
        security,
        close_signal.clone(),
    )
    .await?;

    let tls_tunnel = {
        let connector = TlsConnector::from(tls_client_config.clone());
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();
        connector.connect(server_name, raw_tunnel).await?
    };

    let http2_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .clone();

    let (send_request, connection) = http2_builder
        .handshake::<_, Body>(TokioIo::new(tls_tunnel))
        .await?;

    tokio::spawn({
        let close_signal = close_signal.clone();
        async move {
            tokio::select! {
                result = connection => {
                    if let Err(err) = result {
                        info!(?err, "Tunneled GRPC client connection error");
                    }
                }
                _ = close_signal.cancelled() => {
                    info!("Connect connection explicitly closed");
                }
            }
        }
    });

    Ok(TunneledGrpcClientService {
        send_request_buffer: tower::buffer::Buffer::new(
            SendTunneledRequestService { send_request },
            1024,
        ),
        close_signal,
    })
}

pub struct TunneledGrpcClientService {
    // FIXME: This can't just have a SendRequest buffer, if the underlying tunnel fails
    // there's no way to recover.
    send_request_buffer: tower::buffer::Buffer<
        http::Request<Body>,
        <SendTunneledRequestService as Service<http::Request<Body>>>::Future,
    >,

    close_signal: CancellationToken,
}

impl Service<http::Request<Body>> for TunneledGrpcClientService {
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = tower::buffer::future::ResponseFuture<
        <SendTunneledRequestService as Service<http::Request<Body>>>::Future,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.send_request_buffer, cx)
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        self.send_request_buffer.call(req)
    }
}

impl Drop for TunneledGrpcClientService {
    fn drop(&mut self) {
        // When the service is dropped, end the connection manager task
        self.close_signal.cancel();
    }
}

pub struct SendTunneledRequestService {
    send_request: SendRequest<Body>,
}

impl Service<http::Request<Body>> for SendTunneledRequestService {
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        trace!("SendTunneledRequestService::poll_ready");
        self.send_request.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: http::Request<Body>) -> Self::Future {
        trace!(?req, "SendTunneledRequestService::call");

        // manipulate the request URI to inject scheme and authority
        {
            let mut uri_parts = std::mem::take(req.uri_mut()).into_parts();
            uri_parts.scheme = Some(Scheme::HTTPS);
            uri_parts.authority = Some(Authority::from_static(SERVER_NAME));

            *req.uri_mut() = Uri::from_parts(uri_parts).expect("should not fail");
        }

        let fut = self.send_request.send_request(req);

        Box::pin(async move {
            fut.await
                .map_err(Into::into)
                .map(|res| res.map(tonic::body::Body::new))
        })
    }
}
