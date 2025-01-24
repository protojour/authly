use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use authly_common::proto::connect::authly_connect_client::AuthlyConnectClient;
use axum::body::Bytes;
use futures_util::{future::BoxFuture, ready, FutureExt};
use http::{
    uri::{Authority, Scheme},
    Uri,
};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_project_lite::pin_project;
use rustls::{pki_types::ServerName, ClientConfig};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::sync::CancellationToken;
use tonic::{body::BoxBody, transport::Channel};
use tower::{Service, ServiceExt};
use tower_04::buffer::Buffer;
use tracing::{info, trace};

use crate::SERVER_NAME;

use super::tunnel::{authly_connect_client_tunnel, ClientSideTunnel, StdError};

const TUNNEL_BUFSIZE: usize = 128;

/// Create a gRPC service (client-side) that tunnels through AuthlyConnect
pub async fn new_authly_connect_grpc_client_service(
    connect_uri: Bytes,
    tls_client_config: Arc<ClientConfig>,
    cancel: CancellationToken,
) -> anyhow::Result<grpc_service::TunneledGrpcClientService> {
    let endpoint = tonic::transport::Endpoint::from_shared(connect_uri.clone()).unwrap();
    let channel = endpoint.connect().await?;

    Ok(grpc_service::TunneledGrpcClientService {
        make_send_request: MakeTunneledSendRequestService {
            tunnel_buffer: Buffer::new(
                TunneledTlsStreamService {
                    connect_uri,
                    channel,
                    tls_client_config,
                    cancel: cancel.clone(),
                },
                TUNNEL_BUFSIZE,
            ),
            cancel,
        },
    })
}

mod grpc_service {
    use super::*;

    pub struct TunneledGrpcClientService {
        pub(super) make_send_request: MakeTunneledSendRequestService,
    }

    impl Service<http::Request<BoxBody>> for TunneledGrpcClientService {
        type Response = http::Response<BoxBody>;
        type Error = StdError;
        type Future = ResponseFuture;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            trace!("TunneledGrpcClientService::poll_ready");
            Service::poll_ready(&mut self.make_send_request, cx)
        }

        fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
            trace!("TunneledGrpcClientService::call");
            let future = self.make_send_request.call(());

            ResponseFuture {
                state: State::MakeSendRequest { future },
                req: Some(req),
            }
        }
    }

    pin_project! {
        pub struct ResponseFuture {
            #[pin]
            state: State,

            req: Option<http::Request<BoxBody>>,
        }
    }

    pin_project! {
        #[project = StateProj]
        enum State {
            MakeSendRequest {
                #[pin]
                future: <MakeTunneledSendRequestService as Service<()>>::Future,
            },
            SendRequestPollReady {
                svc: SendTunneledRequestService,
            },
            SendRequest {
                #[pin]
                future: <SendTunneledRequestService as Service<http::Request<BoxBody>>>::Future,
            }
        }
    }

    impl Future for ResponseFuture {
        type Output = Result<http::Response<BoxBody>, StdError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut zelf = self.project();

            loop {
                match zelf.state.as_mut().project() {
                    StateProj::MakeSendRequest { future } => {
                        trace!("grpc::ResponseFuture::MakeSendRequest");
                        let send_request = ready!(future.poll(cx))?;

                        zelf.state
                            .set(State::SendRequestPollReady { svc: send_request });
                    }
                    StateProj::SendRequestPollReady { svc } => {
                        trace!("grpc::ResponseFuture::SendRequestPollReady");
                        ready!(svc.poll_ready(cx))?;
                        let future = svc.call(zelf.req.take().expect("request already sent"));
                        zelf.state.set(State::SendRequest { future });
                    }
                    StateProj::SendRequest { future } => {
                        trace!("grpc::ResponseFuture::SendRequest");
                        let response = ready!(future.poll(cx))?;
                        return Poll::Ready(Ok(response));
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct MakeTunneledSendRequestService {
    tunnel_buffer: tower_04::buffer::Buffer<TunneledTlsStreamService, ()>,
    cancel: CancellationToken,
}

impl Service<()> for MakeTunneledSendRequestService {
    type Response = SendTunneledRequestService;
    type Error = StdError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        let mut tunnel_buffer = self.tunnel_buffer.clone();
        let cancel = self.cancel.clone();

        async move {
            // TODO: Should reuse tunnels?
            tunnel_buffer.ready().await?;
            let available_tunnel = tunnel_buffer.call(()).await?;

            let builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                // .initial_stream_window_size(endpoint.init_stream_window_size)
                // .initial_connection_window_size(endpoint.init_connection_window_size)
                // .keep_alive_interval(endpoint.http2_keep_alive_interval)
                // .timer(TokioTimer::new())
                .clone();

            let (send_request, connection) = builder
                .handshake::<_, BoxBody>(TokioIo::new(available_tunnel))
                .await?;

            tokio::spawn(async move {
                tokio::select! {
                    result = connection => {
                        if let Err(err) = result {
                            info!(?err, "Tunneled GRPC client connection error");
                        }
                    }
                    _ = cancel.cancelled() => {}
                }
            });

            Ok(SendTunneledRequestService { send_request })
        }
        .boxed()
    }
}

struct SendTunneledRequestService {
    send_request: SendRequest<BoxBody>,
}

impl Service<http::Request<BoxBody>> for SendTunneledRequestService {
    type Response = http::Response<BoxBody>;
    type Error = StdError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        trace!("SendTunneledRequestService::poll_ready");
        self.send_request.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: http::Request<BoxBody>) -> Self::Future {
        trace!("SendTunneledRequestService::call: {req:?}");

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
                .map(|res| res.map(tonic::body::boxed))
        })
    }
}

/// Service that produces a new client side tunnel
#[derive(Clone)]
struct TunneledTlsStreamService {
    connect_uri: Bytes,
    channel: Channel,
    tls_client_config: Arc<ClientConfig>,
    cancel: CancellationToken,
}

impl Service<()> for TunneledTlsStreamService {
    type Response = TlsStream<ClientSideTunnel>;
    type Error = StdError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        trace!("TunneledTlsStreamService::poll_ready");
        Service::poll_ready(&mut self.channel, cx).map_err(|err| err.into())
    }

    fn call(&mut self, _: ()) -> Self::Future {
        info!(
            "opening new tunnel to {:?}",
            std::str::from_utf8(&self.connect_uri)
        );

        let channel = self.channel.clone();
        let tls_client_config = self.tls_client_config.clone();
        let cancel = self.cancel.clone();

        async move {
            let raw_tunnel =
                authly_connect_client_tunnel(AuthlyConnectClient::new(channel), cancel.clone())
                    .await?;

            let connector = TlsConnector::from(tls_client_config);
            let server_name = ServerName::try_from(SERVER_NAME).unwrap();
            Ok(connector.connect(server_name, raw_tunnel).await?)
        }
        .boxed()
    }
}
