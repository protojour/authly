use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::{BuiltinID, ObjId},
    policy::{code::Outcome, engine::AccessControlParams},
    proto::service::{
        self as proto,
        authly_service_server::{AuthlyService, AuthlyServiceServer},
    },
};
use http::header::{AUTHORIZATION, COOKIE};
use tonic::{
    metadata::{Ascii, MetadataMap},
    Request, Response,
};
use tracing::warn;

use crate::{
    access_control::{self, AuthorizedPeerService},
    access_token,
    db::{
        entity_db,
        service_db::{self, find_service_label_by_eid},
    },
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
                    entity_id: session.eid.value().to_string(),
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
        let peer_svc = svc_mtls_auth(
            request.extensions(),
            &[BuiltinID::AttrAuthlyRoleGetAccessToken],
            &self.ctx,
        )
        .await?;
        let opt_user_claims = get_access_token_opt(request.metadata(), &self.ctx)?;

        let mut params = AccessControlParams::default();

        // svc attributes
        for attr in peer_svc.attributes {
            params.subject_attrs.insert(attr.value());
        }

        // FIXME: should support multiple entity IDs in environment?
        if let Some(user_claims) = opt_user_claims {
            // user attributes
            for attr in user_claims.authly.entity_attributes {
                params.subject_attrs.insert(attr.value());
            }

            params.subject_eids.insert(
                BuiltinID::PropEntity.to_obj_id().value(),
                user_claims.authly.entity_id.value(),
            );
        } else {
            params.subject_eids.insert(
                BuiltinID::PropEntity.to_obj_id().value(),
                peer_svc.eid.value(),
            );
        }

        // resource attributes
        for resource_attr in request.into_inner().resource_attributes {
            let obj_id = ObjId::from_bytes(&resource_attr)
                .ok_or_else(|| tonic::Status::invalid_argument("invalid attribute"))?;

            params.resource_attrs.insert(obj_id.value());
        }

        // TODO: Should definitely cache service policy engine in memory
        let policy_engine = service_db::load_policy_engine(&self.ctx, peer_svc.eid).await?;

        let outcome = match policy_engine.eval(&params) {
            Ok(outcome) => {
                if matches!(outcome, Outcome::Allow) {
                    1
                } else {
                    0
                }
            }
            Err(err) => {
                warn!(?err, "policy engine error");
                0
            }
        };

        Ok(Response::new(proto::AccessControlResponse { outcome }))
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
