use std::collections::HashMap;

use authly_common::proto::connect::authly_connect_server::AuthlyConnectServer;
use authly_connect::{
    server::{AuthlyConnectServerImpl, ConnectService},
    TunnelSecurity,
};
use authly_db::DbError;
use mandate_submission::AuthlyMandateSubmissionServerImpl;
use tracing::warn;

use crate::{tls, AuthlyCtx};

pub mod mandate_submission;
pub mod service_server;

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

fn grpc_db_err(err: DbError) -> tonic::Status {
    warn!(?err, "gRPC DbError");
    tonic::Status::internal("internal error")
}
