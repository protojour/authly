use std::collections::HashMap;

use authly_common::proto::connect::authly_connect_server::AuthlyConnectServer;
use authly_connect::{
    server::{AuthlyConnectServerImpl, ConnectService},
    TunnelSecurity,
};
use authly_domain::ctx::GetInstance;
use authly_service::proto::{
    mandate_submission::AuthlyMandateSubmissionServerImpl, service_server::AuthlyServiceServerImpl,
};

use crate::{tls, AuthlyCtx};

// gRPC entry point
pub(crate) fn main_service_grpc_router(ctx: AuthlyCtx) -> anyhow::Result<axum::Router> {
    Ok(tonic::service::Routes::default()
        .add_service(AuthlyServiceServerImpl::new_service(ctx.clone()))
        .add_service(AuthlyConnectServer::new(AuthlyConnectServerImpl {
            services: HashMap::from([(
                TunnelSecurity::Secure,
                ConnectService {
                    service: tonic::service::Routes::default()
                        .add_service(AuthlyMandateSubmissionServerImpl::new_service(ctx.clone()))
                        .into_axum_router(),
                    tls_server_config: tls::generate_tls_server_config(
                        "authly-connect",
                        &ctx.get_instance(),
                        std::time::Duration::from_secs(365 * 100),
                    )?,
                },
            )]),
            cancel: ctx.shutdown.clone(),
        }))
        .into_axum_router())
}
