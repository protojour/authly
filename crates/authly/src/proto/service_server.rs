use authly_domain::BuiltinID;
use authly_proto::service::{
    self as proto,
    authly_service_server::{AuthlyService, AuthlyServiceServer},
};
use http::header::COOKIE;
use tonic::{metadata::MetadataMap, Request, Response};

use crate::{
    db::{entity_db, service_db::find_service_label_by_eid},
    mtls::PeerSubjectCommonName,
    session::{self, authenticate_session_cookie, Session},
    AuthlyCtx, EID,
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
    async fn get_metadata(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::ServiceMetadata>> {
        let svc_eid = svc_auth(request.extensions(), None, &self.ctx).await?;
        let label = find_service_label_by_eid(svc_eid, &self.ctx)
            .await?
            .ok_or_else(|| tonic::Status::internal("no service label"))?;

        Ok(Response::new(proto::ServiceMetadata {
            eid: svc_eid.0.to_string(),
            label,
        }))
    }

    async fn get_access_token(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::AccessToken>> {
        let _svc_eid = svc_auth(
            request.extensions(),
            Some(BuiltinID::AttrAuthlyRoleGetAccessToken),
            &self.ctx,
        )
        .await?;

        let session = session_auth(request.metadata(), &self.ctx)
            .await
            .map_err(|msg| tonic::Status::unauthenticated(msg))?;

        Ok(Response::new(proto::AccessToken {
            token: "TODO".to_string(),
            user_eid: session.eid.0.to_string(),
        }))
    }
}

/// Authenticate and authorize the client
async fn svc_auth(
    extensions: &tonic::Extensions,
    required_role: Option<BuiltinID>,
    ctx: &AuthlyCtx,
) -> tonic::Result<EID> {
    let common_name = extensions
        .get::<PeerSubjectCommonName>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    let svc_eid = EID(common_name
        .0
        .parse()
        .map_err(|_| tonic::Status::unauthenticated("invalid service entity id"))?);

    if let Some(required_role) = required_role {
        let attributes = entity_db::list_entity_attrs(svc_eid, ctx).await?;

        if !attributes.contains(&required_role.to_eid()) {
            return Err(tonic::Status::permission_denied(
                "the service does not have the required authly role",
            ));
        }
    }

    Ok(svc_eid)
}

async fn session_auth(metadata: &MetadataMap, ctx: &AuthlyCtx) -> Result<Session, &'static str> {
    let cookie_headers = metadata
        .get_all(COOKIE.as_str())
        .iter()
        .filter_map(|data| data.to_str().ok());

    authenticate_session_cookie(session::parse_cookie_jar(cookie_headers), ctx).await
}
