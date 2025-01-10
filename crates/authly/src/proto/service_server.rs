use authly_common::{access_token::AuthlyAccessTokenClaims, BuiltinID, Eid};
use authly_proto::service::{
    self as proto,
    authly_service_server::{AuthlyService, AuthlyServiceServer},
};
use fnv::FnvHashSet;
use http::header::{AUTHORIZATION, COOKIE};
use tonic::{
    metadata::{Ascii, MetadataMap},
    Request, Response,
};

use crate::{
    access_control::{self, AuthorizedPeerService},
    access_token,
    db::{entity_db, service_db::find_service_label_by_eid},
    mtls::PeerServiceEID,
    session::{authenticate_session_cookie, find_session_cookie, Session},
    AuthlyCtx,
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
        let peer_svc = svc_mtls_auth(request.extensions(), &[], &self.ctx).await?;
        let label = find_service_label_by_eid(&self.ctx, peer_svc.eid)
            .await?
            .ok_or_else(|| tonic::Status::internal("no service label"))?;

        Ok(Response::new(proto::ServiceMetadata {
            eid: peer_svc.eid.value().to_string(),
            label,
        }))
    }

    // TODO: This could use some local caching of both service auth and user auth?
    // Calling the RPC from authly-test takes over 2ms.
    async fn get_access_token(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::AccessToken>> {
        // let start = Instant::now();

        let (peer_svc_result, access_token_result) = tokio::join!(
            svc_mtls_auth(
                request.extensions(),
                &[BuiltinID::AttrAuthlyRoleGetAccessToken],
                &self.ctx,
            ),
            async {
                let session = session_auth(request.metadata(), &self.ctx)
                    .await
                    .map_err(tonic::Status::unauthenticated)?;

                let user_attrs = entity_db::list_entity_attrs(&self.ctx, session.eid).await?;

                let token = access_token::create_access_token(
                    &session,
                    user_attrs,
                    &self.ctx.dynamic_config,
                )
                .map_err(|_| tonic::Status::internal("access token error"))?;

                Result::<_, tonic::Status>::Ok(proto::AccessToken {
                    token,
                    user_eid: session.eid.value().to_string(),
                })
            },
        );

        // info!("get_access_token async took {:?}", start.elapsed());

        let _peer_svc = peer_svc_result?;
        let access_token = access_token_result?;

        Ok(Response::new(access_token))
    }

    async fn access_control(
        &self,
        request: Request<proto::AccessControlRequest>,
    ) -> tonic::Result<Response<proto::AccessControlResponse>> {
        let _peer_svc = svc_mtls_auth(
            request.extensions(),
            &[BuiltinID::AttrAuthlyRoleGetAccessToken],
            &self.ctx,
        )
        .await?;
        let _opt_user_claims = get_access_token_opt(request.metadata(), &self.ctx)?;

        let _resource_attributes: FnvHashSet<Eid> = request
            .into_inner()
            .resource_attributes
            .into_iter()
            .map(|bytes| {
                Eid::from_bytes(&bytes)
                    .ok_or_else(|| tonic::Status::invalid_argument("invalid attribute"))
            })
            .collect::<Result<_, tonic::Status>>()?;

        Ok(Response::new(proto::AccessControlResponse { outcome: 0 }))
    }
}

/// Authenticate and authorize the client
async fn svc_mtls_auth(
    extensions: &tonic::Extensions,
    required_roles: &[BuiltinID],
    ctx: &AuthlyCtx,
) -> tonic::Result<AuthorizedPeerService> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEID>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    let authorized = access_control::authorize_peer_service(peer_svc_eid.0, required_roles, ctx)
        .await
        .map_err(|_| {
            tonic::Status::unauthenticated("the service does not have the required role")
        })?;

    Ok(authorized)
}

async fn session_auth(metadata: &MetadataMap, ctx: &AuthlyCtx) -> Result<Session, &'static str> {
    let session_cookie = find_session_cookie(
        metadata
            .get_all(COOKIE.as_str())
            .iter()
            .filter_map(|data| data.to_str().ok()),
    )?;

    authenticate_session_cookie(session_cookie, ctx).await
}

fn get_access_token_opt(
    metadata: &MetadataMap,
    ctx: &AuthlyCtx,
) -> tonic::Result<Option<AuthlyAccessTokenClaims>> {
    let Some(authorization) = metadata.get(AUTHORIZATION.as_str()) else {
        return Ok(None);
    };
    let claims = verify_bearer(authorization, ctx)?;
    Ok(Some(claims))
}

#[expect(unused)]
fn get_access_token(
    metadata: &MetadataMap,
    ctx: &AuthlyCtx,
) -> tonic::Result<AuthlyAccessTokenClaims> {
    verify_bearer(
        metadata
            .get(AUTHORIZATION.as_str())
            .ok_or_else(|| tonic::Status::unauthenticated("access token is missing"))?,
        ctx,
    )
}

fn verify_bearer(
    value: &tonic::metadata::MetadataValue<Ascii>,
    ctx: &AuthlyCtx,
) -> tonic::Result<AuthlyAccessTokenClaims> {
    let token = value
        .to_str()
        .ok()
        .and_then(|bearer| bearer.strip_prefix("Bearer "))
        .ok_or_else(|| tonic::Status::unauthenticated("invalid access token encoding"))?;

    access_token::verify_access_token(token, &ctx.dynamic_config)
        .map_err(|_| tonic::Status::unauthenticated("access token not verified"))
}
