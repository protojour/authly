use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::{Eid, Id128},
    mtls_server::PeerServiceEntity,
    policy::{code::Outcome, engine::AccessControlParams},
    proto::service::{
        self as proto,
        authly_service_server::{AuthlyService, AuthlyServiceServer},
    },
};
use http::header::{AUTHORIZATION, COOKIE};
use rcgen::CertificateSigningRequestParams;
use rustls::pki_types::CertificateSigningRequestDer;
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
        service_db::{self, find_service_label_by_eid, ServicePropertyKind},
    },
    id::BuiltinID,
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
            entity_id: peer_svc.eid.to_bytes().to_vec(),
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

                let token =
                    access_token::create_access_token(&session, user_attrs, &self.ctx.instance)
                        .map_err(|_| tonic::Status::internal("access token error"))?;

                Result::<_, tonic::Status>::Ok(proto::AccessToken {
                    token,
                    entity_id: session.eid.to_bytes().to_vec(),
                })
            },
        );

        // info!("get_access_token async took {:?}", start.elapsed());

        let _peer_svc = peer_svc_result?;
        let access_token = access_token_result?;

        Ok(Response::new(access_token))
    }

    async fn get_resource_property_mappings(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::PropertyMappingsResponse>> {
        let peer_svc_eid = svc_mtls_auth_trivial(request.extensions())?;

        let resource_property_mapping = service_db::get_service_property_mapping(
            &self.ctx,
            peer_svc_eid,
            ServicePropertyKind::Resource,
        )
        .await?;

        let response = proto::PropertyMappingsResponse {
            properties: resource_property_mapping
                .into_iter()
                .map(|(prop_label, attributes)| proto::PropertyMapping {
                    label: prop_label,
                    attributes: attributes
                        .into_iter()
                        .map(|(attr_label, obj_id)| proto::AttributeMapping {
                            label: attr_label,
                            obj_id: obj_id.to_bytes().to_vec(),
                        })
                        .collect(),
                })
                .collect(),
        };

        Ok(Response::new(response))
    }

    async fn access_control(
        &self,
        request: Request<proto::AccessControlRequest>,
    ) -> tonic::Result<Response<proto::AccessControlResponse>> {
        let peer_svc_eid = svc_mtls_auth_trivial(request.extensions())?;
        let opt_user_claims = get_access_token_opt(request.metadata(), &self.ctx)?;

        let mut params = AccessControlParams::default();

        let request = request.into_inner();

        // resource attributes
        for resource_attr in request.resource_attributes {
            params.resource_attrs.insert(id_from_proto(&resource_attr)?);
        }

        // user attributes from access token
        if let Some(user_claims) = opt_user_claims {
            for attr in user_claims.authly.entity_attributes {
                params.subject_attrs.insert(attr.to_any());
            }

            params.subject_eids.insert(
                BuiltinID::PropEntity.to_obj_id().to_any(),
                user_claims.authly.entity_id.to_any(),
            );
        }

        // additional subject attributes
        for subject_attr in request.peer_entity_attributes {
            params.subject_attrs.insert(id_from_proto(&subject_attr)?);
        }

        // resolve attributes of all of the peers of the peer service
        // TODO: improve concurrency?
        for subject_entity_id in request.peer_entity_ids {
            let subject_entity_id: Eid = id_from_proto(&subject_entity_id)?;

            let subject_entity_property_mapping = service_db::get_service_property_mapping(
                &self.ctx,
                subject_entity_id,
                ServicePropertyKind::Entity,
            )
            .await?;

            for (_, attributes) in subject_entity_property_mapping {
                for (_, attribute) in attributes {
                    params.subject_attrs.insert(attribute.to_any());
                }
            }
        }

        // TODO: Should definitely cache service policy engine in memory
        let policy_engine = service_db::load_policy_engine(&self.ctx, peer_svc_eid).await?;

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

    async fn sign_certificate(
        &self,
        request: Request<proto::CertificateSigningRequest>,
    ) -> tonic::Result<Response<proto::Certificate>> {
        let _peer_svc_eid = svc_mtls_auth_trivial(request.extensions())?;

        let csr_params = CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(request.into_inner().der),
        )
        .map_err(|_err| tonic::Status::invalid_argument("invalid Certificate Signing Request"))?;

        // TODO: If a server certificate: Somehow verify that the peer service does not lie about its hostname/common name?
        // Authly would have to know its hostname in that case, if it's not the same as the service label.

        let certificate = csr_params
            .signed_by(
                &self.ctx.instance.local_ca().params,
                self.ctx.instance.private_key(),
            )
            .map_err(|err| {
                warn!(?err, "unable to sign service certificate");
                tonic::Status::invalid_argument("Certificate signing problem")
            })?;

        Ok(Response::new(proto::Certificate {
            der: certificate.der().to_vec(),
        }))
    }
}

/// Just extract the peer entity id without checking any required roles
fn svc_mtls_auth_trivial(extensions: &tonic::Extensions) -> tonic::Result<Eid> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEntity>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    Ok(peer_svc_eid.0)
}

/// Authenticate and authorize the client
async fn svc_mtls_auth(
    extensions: &tonic::Extensions,
    required_roles: &[BuiltinID],
    ctx: &AuthlyCtx,
) -> tonic::Result<AuthorizedPeerService> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEntity>()
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

    access_token::verify_access_token(token, &ctx.instance)
        .map_err(|_| tonic::Status::unauthenticated("access token not verified"))
}

fn id_from_proto<K>(bytes: &[u8]) -> tonic::Result<Id128<K>> {
    Id128::from_bytes(bytes).ok_or_else(|| tonic::Status::invalid_argument("invalid ID"))
}
