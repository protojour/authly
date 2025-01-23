use std::sync::Arc;

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

use crate::connect::tunnel;

#[derive(Clone)]
pub struct ConnectServer {
    /// How TLS wrapped in the connect tunnel works:
    pub tls_server_config: Arc<rustls::server::ServerConfig>,
    /// The inner service that's wrapped inside TLS inside the tunnel:
    pub service: axum::Router,
    pub cancel: CancellationToken,
}

#[tonic::async_trait]
impl authly_common::proto::connect::authly_connect_server::AuthlyConnect for ConnectServer {
    type TunnelStream = BoxStream<'static, tonic::Result<proto::Frame>>;

    async fn tunnel(
        &self,
        request: tonic::Request<tonic::Streaming<proto::Frame>>,
    ) -> tonic::Result<tonic::Response<Self::TunnelStream>> {
        let incoming = request.into_inner();
        let (tunnel, outgoing) = tunnel::grpc_serverside_tunnel(incoming);

        tokio::spawn(self.clone().serve_https_tunneled(tunnel));

        Ok(tonic::Response::new(outgoing))
    }
}

impl ConnectServer {
    async fn serve_https_tunneled(
        self,
        tunnel: tunnel::Tunnel<impl AsyncRead + Unpin + Send + 'static>,
    ) {
        let connection_builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());

        let tls_stream = match TlsAcceptor::from(self.tls_server_config)
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
                let mut service = self.service.clone();

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
                _ = self.cancel.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                }
            }
        }
    }
}
