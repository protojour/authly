use std::io::ErrorKind;

use authly_common::proto::connect::{self as proto, authly_connect_client::AuthlyConnectClient};
use axum::body::Bytes;
use futures_util::{stream::BoxStream, StreamExt};
use hyper::body::Body;
use tokio::io::{AsyncRead, ReadHalf, SimplexStream, WriteHalf};
use tokio_util::{
    io::{ReaderStream, StreamReader},
    sync::CancellationToken,
};
use tracing::info;

use crate::TunnelSecurity;

/// The maximum amount of bytes to write into the tunnel before gRPC must produce an output frame
const BUFSIZE: usize = 16 * 1024;

pub type Tunnel<R> = tokio::io::Join<R, WriteHalf<SimplexStream>>;

pub type ClientSideTunnel = Tunnel<ReadHalf<SimplexStream>>;

pub fn grpc_serverside_tunnel(
    incoming: tonic::Streaming<proto::Frame>,
) -> (
    Tunnel<impl AsyncRead>,
    BoxStream<'static, tonic::Result<proto::Frame>>,
) {
    let incoming_stream_reader = {
        let mapped = incoming.map(|result| {
            result.map(|frame| frame.payload).map_err(|status| {
                info!(?status, "input stream error");
                std::io::Error::new(ErrorKind::BrokenPipe, "broken pipe")
            })
        });
        StreamReader::new(mapped)
    };

    let (outgoing_read_half, outgoing_write_half) = tokio::io::simplex(BUFSIZE);

    (
        tokio::io::join(incoming_stream_reader, outgoing_write_half),
        ReaderStream::new(outgoing_read_half)
            .map(|result| match result {
                Ok(payload) => Ok(proto::Frame { payload }),
                Err(err) => {
                    info!(?err, "tunnel outgoing error");
                    Err(tonic::Status::cancelled("closed"))
                }
            })
            .boxed(),
    )
}

pub type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub async fn authly_connect_client_tunnel<T>(
    mut connect_client: AuthlyConnectClient<T>,
    security: TunnelSecurity,
    close_signal: CancellationToken,
) -> tonic::Result<ClientSideTunnel>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
{
    let (outgoing_read_half, outgoing_write_half) = tokio::io::simplex(BUFSIZE);
    let (incoming_read_half, mut incoming_write_half) = tokio::io::simplex(BUFSIZE);

    let response = {
        let tonic_request = tonic::Request::new(ReaderStream::new(outgoing_read_half).scan(
            (),
            |_, result| async {
                match result {
                    Ok(payload) => Some(proto::Frame { payload }),
                    Err(err) => {
                        info!(?err, "tunnel outgoing error");
                        None
                    }
                }
            },
        ));

        match security {
            TunnelSecurity::Secure => connect_client.secure(tonic_request).await?,
            TunnelSecurity::MutuallySecure => connect_client.mutually_secure(tonic_request).await?,
        }
    };

    let mut incoming_reader = StreamReader::new(response.into_inner().map(|result| {
        result.map(|frame| frame.payload).map_err(|status| {
            info!(?status, "input stream error");
            std::io::Error::new(ErrorKind::BrokenPipe, "broken pipe")
        })
    }));

    // copy incoming bytes into the tunnel
    tokio::spawn(async move {
        tokio::select! {
            result = tokio::io::copy(&mut incoming_reader, &mut incoming_write_half) => {
                if let Err(err) = result {
                    info!(?err, "client tunnel incoming error");
                }
            }
            _ = close_signal.cancelled() => {}
        }
    });

    Ok(tokio::io::join(incoming_read_half, outgoing_write_half))
}
