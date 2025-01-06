use authly_proto::service::{
    self as proto,
    authly_service_server::{AuthlyService, AuthlyServiceServer},
};

use crate::{
    db::service_db::find_service_label_by_eid, tls_middleware::PeerSubjectCommonName, AuthlyCtx,
    EID,
};

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
    async fn metadata(
        &self,
        request: tonic::Request<proto::Empty>,
    ) -> tonic::Result<tonic::Response<proto::ServiceMetadata>> {
        let eid = auth(&request)?;
        let label = find_service_label_by_eid(eid, &self.ctx)
            .await
            .map_err(|err| {
                tracing::error!(?err, "error");
                tonic::Status::internal("db error")
            })?;

        Ok(tonic::Response::new(proto::ServiceMetadata {
            eid: eid.0.to_string(),
            label,
        }))
    }
}

fn auth<T>(request: &tonic::Request<T>) -> tonic::Result<EID> {
    let common_name = request
        .extensions()
        .get::<PeerSubjectCommonName>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid identity"))?;

    let eid = EID(common_name
        .0
        .parse()
        .map_err(|_| tonic::Status::unauthenticated("invalid EID"))?);

    Ok(eid)
}
