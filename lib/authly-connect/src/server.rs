use std::{collections::HashMap, sync::Arc};

use authly_common::proto::connect::{self as proto};
use futures_util::{future::poll_fn, pin_mut, stream::BoxStream};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncRead;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_server::tls::TlsConnectionMiddleware;
use tracing::info;

use crate::{tunnel, TunnelSecurity};

#[derive(Clone)]
pub struct ConnectService {
    /// How TLS wrapped in the connect tunnel works:
    pub tls_server_config: Arc<rustls::server::ServerConfig>,
    /// The inner service that's wrapped inside TLS inside the tunnel:
    pub service: axum::Router,
}

/// This is a generic service that serves any axum::Router
/// through the tunnel defined by AuthlyConnect.
#[derive(Clone)]
pub struct AuthlyConnectServerImpl {
    pub services: HashMap<TunnelSecurity, ConnectService>,
    pub cancel: CancellationToken,
}

#[tonic::async_trait]
impl authly_common::proto::connect::authly_connect_server::AuthlyConnect
    for AuthlyConnectServerImpl
{
    type SecureStream = BoxStream<'static, tonic::Result<proto::Frame>>;
    type MutuallySecureStream = BoxStream<'static, tonic::Result<proto::Frame>>;

    async fn secure(
        &self,
        request: tonic::Request<tonic::Streaming<proto::Frame>>,
    ) -> tonic::Result<tonic::Response<Self::SecureStream>> {
        let service = self.service(TunnelSecurity::Secure)?;
        let incoming = request.into_inner();
        let (tunnel, outgoing) = tunnel::grpc_serverside_tunnel(incoming);

        tokio::spawn(Self::serve_https_tunneled(
            tunnel,
            service,
            self.cancel.clone(),
        ));

        Ok(tonic::Response::new(outgoing))
    }

    async fn mutually_secure(
        &self,
        request: tonic::Request<tonic::Streaming<proto::Frame>>,
    ) -> tonic::Result<tonic::Response<Self::MutuallySecureStream>> {
        let service = self.service(TunnelSecurity::MutuallySecure)?;
        let incoming = request.into_inner();
        let (tunnel, outgoing) = tunnel::grpc_serverside_tunnel(incoming);

        tokio::spawn(Self::serve_https_tunneled(
            tunnel,
            service,
            self.cancel.clone(),
        ));

        Ok(tonic::Response::new(outgoing))
    }
}

impl AuthlyConnectServerImpl {
    fn service(&self, security: TunnelSecurity) -> tonic::Result<ConnectService> {
        self.services
            .get(&security)
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("no service"))
    }

    async fn serve_https_tunneled(
        tunnel: tunnel::Tunnel<impl AsyncRead + Unpin + Send + 'static>,
        service: ConnectService,
        cancel: CancellationToken,
    ) {
        let connection_builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());

        let tls_stream = match TlsAcceptor::from(service.tls_server_config)
            .accept(tunnel)
            .await
        {
            Ok(tls_stream) => tls_stream,
            Err(err) => {
                info!(?err, "TLS tunnel accept error");
                return;
            }
        };

        let middleware = authly_common::mtls_server::MTLSMiddleware;
        let tls_middleware_data = middleware.data(tls_stream.get_ref().1);

        let connection = connection_builder.serve_connection_with_upgrades(
            TokioIo::new(tls_stream),
            hyper::service::service_fn(move |mut req| {
                middleware.call(&mut req, &tls_middleware_data);
                let mut service = service.service.clone();

                async move {
                    poll_fn(|cx| {
                        <axum::Router as tower::Service<http::Request<Incoming>>>::poll_ready(
                            &mut service,
                            cx,
                        )
                    })
                    .await?;
                    service.call(req).await
                }
            }),
        );

        pin_mut!(connection);

        loop {
            tokio::select! {
                biased;
                _ = connection.as_mut() => {
                    break;
                }
                _ = cancel.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                }
            }
        }
    }
}
