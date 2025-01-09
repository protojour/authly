use authly_domain::BuiltinID;
use authly_proto::service::{
    self as proto,
    authly_service_server::{AuthlyService, AuthlyServiceServer},
};
use http::header::COOKIE;
use tonic::{metadata::MetadataMap, Request, Response};

use crate::{
    access_control, access_token,
    db::service_db::find_service_label_by_eid,
    mtls::PeerServiceEID,
    session::{self, authenticate_session_cookie, Session},
    AuthlyCtx, Eid,
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
        let svc_eid = svc_auth(request.extensions(), &[], &self.ctx).await?;
        let label = find_service_label_by_eid(&self.ctx, svc_eid)
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
            &[BuiltinID::AttrAuthlyRoleGetAccessToken],
            &self.ctx,
        )
        .await?;

        let session = session_auth(request.metadata(), &self.ctx)
            .await
            .map_err(tonic::Status::unauthenticated)?;

        let token = access_token::create_access_token(&session, &self.ctx)
            .map_err(|_| tonic::Status::internal("access token error"))?;

        Ok(Response::new(proto::AccessToken {
            token,
            user_eid: session.eid.0.to_string(),
        }))
    }
}

/// Authenticate and authorize the client
async fn svc_auth(
    extensions: &tonic::Extensions,
    required_roles: &[BuiltinID],
    ctx: &AuthlyCtx,
) -> tonic::Result<Eid> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEID>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    access_control::svc_access_control(peer_svc_eid.0, required_roles, ctx)
        .await
        .map_err(|_| {
            tonic::Status::unauthenticated("the service does not have the required role")
        })?;

    Ok(peer_svc_eid.0)
}

async fn session_auth(metadata: &MetadataMap, ctx: &AuthlyCtx) -> Result<Session, &'static str> {
    let cookie_headers = metadata
        .get_all(COOKIE.as_str())
        .iter()
        .filter_map(|data| data.to_str().ok());

    authenticate_session_cookie(session::parse_cookie_jar(cookie_headers), ctx).await
}
