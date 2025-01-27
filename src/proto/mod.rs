use std::collections::HashMap;

use authly_common::proto::connect::authly_connect_server::AuthlyConnectServer;
use authly_connect::{
    server::{AuthlyConnectServerImpl, ConnectService},
    TunnelSecurity,
};
use mandate_submission::AuthlyMandateSubmissionServerImpl;
use tracing::warn;

use crate::{db::DbError, tls, AuthlyCtx};

pub mod mandate_submission;
pub mod service_server;

impl From<DbError> for tonic::Status {
    fn from(err: DbError) -> Self {
        warn!(?err, "gRPC db error");
        tonic::Status::internal("db error")
    }
}

// gRPC entry point
pub(crate) fn main_service_grpc_router(ctx: AuthlyCtx) -> anyhow::Result<axum::Router> {
    Ok(tonic::service::Routes::default()
        .add_service(service_server::AuthlyServiceServerImpl::from(ctx.clone()).into_service())
        .add_service(AuthlyConnectServer::new(AuthlyConnectServerImpl {
            services: HashMap::from([(
                TunnelSecurity::Secure,
                ConnectService {
                    service: tonic::service::Routes::default()
                        .add_service(
                            AuthlyMandateSubmissionServerImpl { ctx: ctx.clone() }.into_service(),
                        )
                        .into_axum_router(),
                    tls_server_config: tls::generate_tls_server_config(
                        "authly-connect",
                        &ctx.instance,
                        std::time::Duration::from_secs(365 * 100),
                    )?,
                },
            )]),
            cancel: ctx.shutdown.clone(),
        }))
        .into_axum_router())
}
