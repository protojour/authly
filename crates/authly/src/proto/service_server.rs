use authly_proto::service::{
    self as proto,
    authly_service_server::{AuthlyService, AuthlyServiceServer},
};

use crate::AuthlyCtx;

pub struct AuthlyServiceServerImpl {
    ctx: AuthlyCtx,
}

impl From<AuthlyCtx> for AuthlyServiceServerImpl {
    fn from(value: AuthlyCtx) -> Self {
        Self { ctx: value }
    }
}

impl AuthlyServiceServerImpl {
    pub fn into_service(self) -> AuthlyServiceServer<Self> {
        AuthlyServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl AuthlyService for AuthlyServiceServerImpl {
    async fn auth(
        &self,
        _request: tonic::Request<proto::Empty>,
    ) -> tonic::Result<tonic::Response<proto::Empty>> {
        Err(tonic::Status::unimplemented("TODO"))
    }
}
