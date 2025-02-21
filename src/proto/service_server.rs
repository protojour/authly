use std::net::SocketAddr;

use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::{Id128DynamicArrayConv, ServiceId},
    mtls_server::PeerServiceEntity,
    policy::{
        code::PolicyValue,
        engine::{AccessControlParams, NoOpPolicyTracer},
    },
    proto::service::{
        self as proto,
        authly_service_server::{AuthlyService, AuthlyServiceServer},
    },
};
use futures_util::{stream::BoxStream, StreamExt};
use http::header::{AUTHORIZATION, COOKIE};
use rcgen::{CertificateSigningRequestParams, DnType, SanType};
use rustls::pki_types::CertificateSigningRequestDer;
use tonic::{
    metadata::{Ascii, MetadataMap},
    Request, Response,
};
use tracing::{info, warn};

use crate::{
    access_control::{self, AuthorizedPeerService},
    access_token,
    bus::{message::ServiceMessage, service_events::ServiceMessageConnection},
    ctx::{GetBuiltins, GetDb, GetInstance, HostsConfig, ServiceBus},
    db::{
        entity_db, policy_db,
        service_db::{self, find_service_label_by_eid, PropertyKind, SvcNamespaceWithMetadata},
    },
    id::{BuiltinAttr, BuiltinProp},
    proto::grpc_db_err,
    service,
    session::{authenticate_session_cookie, find_session_cookie, Session},
    util::remote_addr::RemoteAddr,
};

pub struct AuthlyServiceServerImpl<Ctx> {
    ctx: Ctx,
}

impl<Ctx> AuthlyServiceServerImpl<Ctx> {
    pub(crate) fn new_service(ctx: Ctx) -> AuthlyServiceServer<Self> {
        AuthlyServiceServer::new(Self { ctx })
    }
}

#[tonic::async_trait]
impl<Ctx> AuthlyService for AuthlyServiceServerImpl<Ctx>
where
    Ctx: GetDb + GetBuiltins + GetInstance + ServiceBus + HostsConfig + Send + Sync + 'static,
{
    type MessagesStream = BoxStream<'static, tonic::Result<proto::ServiceMessage>>;

    async fn get_configuration(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::ServiceConfiguration>> {
        let peer_svc = svc_mtls_auth(&self.ctx, request.extensions(), &[]).await?;

        let hosts = service::get_service_hosts(&self.ctx, peer_svc.eid)
            .await
            .map_err(grpc_db_err)?;

        let property_mapping_namespaces = {
            let resource_property_mapping = service_db::get_service_property_mapping(
                self.ctx.get_db(),
                peer_svc.eid,
                PropertyKind::Resource,
            )
            .await
            .map_err(grpc_db_err)?;

            resource_property_mapping
                .into_iter()
                .map(|(label, properties)| proto::PropertyMappingNamespace {
                    label,
                    properties: properties
                        .into_iter()
                        .map(|(label, attributes)| proto::PropertyMapping {
                            label,
                            attributes: attributes
                                .into_iter()
                                .map(|(label, attr_id)| proto::AttributeMapping {
                                    label,
                                    obj_id: attr_id.to_array_dynamic().to_vec(),
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect()
        };

        Ok(Response::new(proto::ServiceConfiguration {
            hosts,
            property_mapping_namespaces,
        }))
    }

    async fn get_metadata(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<Response<proto::ServiceMetadata>> {
        let peer_svc = svc_mtls_auth(&self.ctx, request.extensions(), &[]).await?;
        let label = find_service_label_by_eid(self.ctx.get_db(), peer_svc.eid)
            .await
            .map_err(grpc_db_err)?
            .ok_or_else(|| tonic::Status::internal("no service label"))?;

        let namespaces = service_db::list_service_namespace_with_metadata(
            self.ctx.get_db(),
            peer_svc.eid,
            self.ctx.get_builtins(),
        )
        .await
        .map_err(grpc_db_err)?;

        Ok(Response::new(proto::ServiceMetadata {
            entity_id: peer_svc.eid.to_array_dynamic().to_vec(),
            label,
            namespaces: metadata::namespaces_with_metadata_to_proto(namespaces),
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
                &self.ctx,
                request.extensions(),
                &[BuiltinAttr::AuthlyRoleGetAccessToken],
            ),
            async {
                let session = session_auth(&self.ctx, request.metadata())
                    .await
                    .map_err(tonic::Status::unauthenticated)?;

                let user_attrs = entity_db::list_entity_attrs(self.ctx.get_db(), session.eid)
                    .await
                    .map_err(grpc_db_err)?;

                let token = access_token::create_access_token(
                    &session,
                    user_attrs,
                    &self.ctx.get_instance(),
                )
                .map_err(|_| tonic::Status::internal("access token error"))?;

                Result::<_, tonic::Status>::Ok(proto::AccessToken {
                    token,
                    entity_id: session.eid.to_array_dynamic().to_vec(),
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
            self.ctx.get_db(),
            peer_svc_eid,
            PropertyKind::Resource,
        )
        .await
        .map_err(grpc_db_err)?;

        let response = proto::PropertyMappingsResponse {
            namespaces: resource_property_mapping
                .into_iter()
                .map(|(label, properties)| proto::PropertyMappingNamespace {
                    label,
                    properties: properties
                        .into_iter()
                        .map(|(label, attributes)| proto::PropertyMapping {
                            label,
                            attributes: attributes
                                .into_iter()
                                .map(|(label, attr_id)| proto::AttributeMapping {
                                    label,
                                    obj_id: attr_id.to_array_dynamic().to_vec(),
                                })
                                .collect(),
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
        let opt_user_claims = get_access_token_opt(&self.ctx, request.metadata())?;

        let mut params = AccessControlParams::default();

        let request = request.into_inner();

        // resource attributes
        for resource_attr in request.resource_attributes {
            params.resource_attrs.insert(id_from_proto(&resource_attr)?);
        }

        // user attributes from access token
        if let Some(user_claims) = opt_user_claims {
            for attr in user_claims.authly.entity_attributes {
                params.subject_attrs.insert(attr);
            }

            params
                .subject_eids
                .insert(BuiltinProp::Entity.into(), user_claims.authly.entity_id);
        }

        // additional subject attributes
        for subject_attr in request.peer_entity_attributes {
            params.subject_attrs.insert(id_from_proto(&subject_attr)?);
        }

        // resolve attributes of all of the peers of the peer service
        // TODO: improve concurrency?
        for subject_entity_id in request.peer_entity_ids {
            let subject_entity_id: ServiceId = id_from_proto(&subject_entity_id)?;

            let subject_entity_property_mapping = service_db::get_service_property_mapping(
                self.ctx.get_db(),
                subject_entity_id,
                PropertyKind::Entity,
            )
            .await
            .map_err(grpc_db_err)?;

            for (_, properties) in subject_entity_property_mapping {
                for (_, attributes) in properties {
                    for (_, attribute) in attributes {
                        params.subject_attrs.insert(attribute);
                    }
                }
            }
        }

        // TODO: Should definitely cache service policy engine in memory
        let policy_engine = policy_db::load_svc_policy_engine(self.ctx.get_db(), peer_svc_eid)
            .await
            .map_err(grpc_db_err)?;

        let value = match policy_engine.eval(&params, &mut NoOpPolicyTracer) {
            Ok(value) => {
                if matches!(value, PolicyValue::Allow) {
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

        Ok(Response::new(proto::AccessControlResponse { value }))
    }

    async fn sign_certificate(
        &self,
        request: Request<proto::CertificateSigningRequest>,
    ) -> tonic::Result<Response<proto::Certificate>> {
        let peer_svc_eid = svc_mtls_auth_trivial(request.extensions())?;

        let csr_params = CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(request.into_inner().der),
        )
        .map_err(|_err| tonic::Status::invalid_argument("invalid Certificate Signing Request"))?;

        let csr_entity_id = {
            let entity_unique_id = csr_params
                .params
                .distinguished_name
                .get(&DnType::from_oid(
                    authly_common::certificate::oid::ENTITY_UNIQUE_IDENTIFIER,
                ))
                .ok_or_else(|| tonic::Status::invalid_argument("CSR missing Entity ID"))?;

            match entity_unique_id {
                rcgen::DnValue::PrintableString(printable_string) => printable_string.as_str(),
                rcgen::DnValue::Utf8String(string) => string.as_str(),
                _ => return Err(tonic::Status::invalid_argument("CSR missing Entity ID")),
            }
        };

        if csr_entity_id != peer_svc_eid.to_string() {
            return Err(tonic::Status::invalid_argument(
                "CSR entity ID does not match peer identity",
            ));
        }

        // verify alt names
        {
            let valid_hosts = service::get_service_hosts(&self.ctx, peer_svc_eid)
                .await
                .map_err(grpc_db_err)?;

            for alt_name_san in &csr_params.params.subject_alt_names {
                match alt_name_san {
                    SanType::DnsName(ia5_string) => {
                        if !valid_hosts.iter().any(|valid| valid == ia5_string.as_str()) {
                            return Err(tonic::Status::invalid_argument(format!(
                                "invalid alt name: {}",
                                ia5_string.as_str()
                            )));
                        }
                    }
                    _ => return Err(tonic::Status::invalid_argument("invalid alt name")),
                }
            }
        }

        let instance = self.ctx.get_instance();

        let certificate = csr_params
            .signed_by(&instance.local_ca().params, instance.private_key())
            .map_err(|err| {
                warn!(?err, "unable to sign service certificate");
                tonic::Status::invalid_argument("Certificate signing problem")
            })?;

        Ok(Response::new(proto::Certificate {
            der: certificate.der().to_vec(),
        }))
    }

    async fn messages(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<tonic::Response<Self::MessagesStream>> {
        let eid = svc_mtls_auth_trivial(request.extensions())?;
        let remote_addr = svc_remote_addr(request.extensions())?;

        info!(?eid, ?remote_addr, "service subscribing to messages");

        let (sender, receiver) = tokio::sync::mpsc::channel(8);

        self.ctx.service_subscribe(
            eid,
            ServiceMessageConnection {
                sender,
                addr: remote_addr,
            },
        );

        use proto::service_message::ServiceMessageKind;

        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(receiver)
                .map(|msg| {
                    let kind = match msg {
                        ServiceMessage::ReloadCa => ServiceMessageKind::ReloadCa(proto::Empty {}),
                        ServiceMessage::ReloadCache => {
                            ServiceMessageKind::ReloadCache(proto::Empty {})
                        }
                        ServiceMessage::Ping => ServiceMessageKind::Ping(proto::Empty {}),
                    };

                    Ok(proto::ServiceMessage {
                        service_message_kind: Some(kind),
                    })
                })
                .boxed(),
        ))
    }

    async fn pong(
        &self,
        request: Request<proto::Empty>,
    ) -> tonic::Result<tonic::Response<proto::Empty>> {
        let eid = svc_mtls_auth_trivial(request.extensions())?;
        let remote_addr = svc_remote_addr(request.extensions())?;

        info!(?eid, ?remote_addr, "received pong");

        Ok(tonic::Response::new(proto::Empty {}))
    }
}

/// Just extract the peer entity id without checking any required roles
fn svc_mtls_auth_trivial(extensions: &tonic::Extensions) -> tonic::Result<ServiceId> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEntity>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    Ok(peer_svc_eid.0)
}

fn svc_remote_addr(extensions: &tonic::Extensions) -> tonic::Result<SocketAddr> {
    let remote_addr = extensions
        .get::<RemoteAddr>()
        .ok_or_else(|| tonic::Status::unknown("remote addr missing"))?;

    Ok(remote_addr.0)
}

/// Authenticate and authorize the client
async fn svc_mtls_auth(
    deps: &impl GetDb,
    extensions: &tonic::Extensions,
    required_roles: &[BuiltinAttr],
) -> tonic::Result<AuthorizedPeerService> {
    let peer_svc_eid = extensions
        .get::<PeerServiceEntity>()
        .ok_or_else(|| tonic::Status::unauthenticated("invalid service identity"))?;

    let authorized = access_control::authorize_peer_service(deps, peer_svc_eid.0, required_roles)
        .await
        .map_err(|_| {
            tonic::Status::unauthenticated("the service does not have the required role")
        })?;

    Ok(authorized)
}

async fn session_auth(deps: &impl GetDb, metadata: &MetadataMap) -> Result<Session, &'static str> {
    let session_cookie = find_session_cookie(
        metadata
            .get_all(COOKIE.as_str())
            .iter()
            .filter_map(|data| data.to_str().ok()),
    )?;

    authenticate_session_cookie(deps, &session_cookie).await
}

fn get_access_token_opt(
    deps: &dyn GetInstance,
    metadata: &MetadataMap,
) -> tonic::Result<Option<AuthlyAccessTokenClaims>> {
    let Some(authorization) = metadata.get(AUTHORIZATION.as_str()) else {
        return Ok(None);
    };
    let claims = verify_bearer(deps, authorization)?;
    Ok(Some(claims))
}

#[expect(unused)]
fn get_access_token(
    deps: &dyn GetInstance,
    metadata: &MetadataMap,
) -> tonic::Result<AuthlyAccessTokenClaims> {
    verify_bearer(
        deps,
        metadata
            .get(AUTHORIZATION.as_str())
            .ok_or_else(|| tonic::Status::unauthenticated("access token is missing"))?,
    )
}

fn verify_bearer(
    deps: &dyn GetInstance,
    value: &tonic::metadata::MetadataValue<Ascii>,
) -> tonic::Result<AuthlyAccessTokenClaims> {
    let token = value
        .to_str()
        .ok()
        .and_then(|bearer| bearer.strip_prefix("Bearer "))
        .ok_or_else(|| tonic::Status::unauthenticated("invalid access token encoding"))?;

    access_token::verify_access_token(token, &deps.get_instance())
        .map_err(|_| tonic::Status::unauthenticated("access token not verified"))
}

fn id_from_proto<T: Id128DynamicArrayConv>(bytes: &[u8]) -> tonic::Result<T> {
    T::try_from_bytes_dynamic(bytes).ok_or_else(|| tonic::Status::invalid_argument("invalid ID"))
}

mod metadata {
    use prost_types::{value::Kind, ListValue, Struct, Value as PValue};
    use serde_json::Value as JValue;

    use super::*;

    pub fn namespaces_with_metadata_to_proto(
        input: Vec<SvcNamespaceWithMetadata>,
    ) -> Vec<proto::NamespaceMetadata> {
        input
            .into_iter()
            .map(|ns| proto::NamespaceMetadata {
                namespace_id: ns.id.to_array_dynamic().to_vec(),
                label: ns.label,
                metadata: ns.metadata.map(json_object_to_proto),
            })
            .collect()
    }

    fn json_object_to_proto(object: serde_json::Map<String, JValue>) -> Struct {
        let mut ztruct = Struct::default();

        for (key, value) in object {
            ztruct.fields.insert(key, json_value_to_proto(value));
        }

        ztruct
    }

    fn json_value_to_proto(value: serde_json::Value) -> PValue {
        let kind = match value {
            JValue::Null => Some(Kind::NullValue(0)),
            JValue::Bool(b) => Some(Kind::BoolValue(b)),
            JValue::Number(n) => n.as_f64().map(Kind::NumberValue),
            JValue::String(s) => Some(Kind::StringValue(s)),
            JValue::Array(vec) => Some(Kind::ListValue(ListValue {
                values: vec.into_iter().map(json_value_to_proto).collect(),
            })),
            JValue::Object(map) => Some(Kind::StructValue(json_object_to_proto(map))),
        };

        PValue { kind }
    }
}
