//! trait implementations for AuthlyCtx

use std::{fs, sync::Arc};

use authly_common::id::{PersonaId, ServiceId};
use authly_domain::{
    builtins::Builtins,
    bus::{service_events::ServiceEventDispatcher, BusError, ClusterMessage},
    cert::{client_cert, CertificateParamsExt},
    ctx::{
        ClusterBus, Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance,
        HostsConfig, KubernetesConfig, LoadInstance, RedistributeCertificates, ServiceBus,
        SetInstance, WebAuthn,
    },
    directory::PersonaDirectory,
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
    webauthn::{
        PasskeyAuthentication, PasskeyRegistration, Webauthn, WebauthnBuilder, WebauthnError,
    },
};
use authly_hiqlite::HiqliteClient;
use http::Uri;
use indexmap::IndexMap;
use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::{platform::CertificateDistributionPlatform, AuthlyCtx, CacheEntry};

impl GetDb for AuthlyCtx {
    type Db = HiqliteClient;

    fn get_db(&self) -> &Self::Db {
        &self.hql
    }
}

impl GetBuiltins for AuthlyCtx {
    fn get_builtins(&self) -> &Builtins {
        &self.state.builtins
    }
}

impl GetHttpClient for AuthlyCtx {
    fn get_internet_http_client(&self) -> reqwest::Client {
        self.internet_http_client.clone()
    }
}

impl GetInstance for AuthlyCtx {
    fn get_instance(&self) -> arc_swap::Guard<Arc<AuthlyInstance>> {
        self.instance.load()
    }
}

impl LoadInstance for AuthlyCtx {
    fn load_instance(&self) -> Arc<AuthlyInstance> {
        self.instance.load_full()
    }
}

impl SetInstance for AuthlyCtx {
    fn set_instance(&self, _instance: AuthlyInstance) {
        todo!()
    }
}

impl GetDecryptedDeks for AuthlyCtx {
    fn get_decrypted_deks(&self) -> arc_swap::Guard<Arc<DecryptedDeks>> {
        self.deks.load()
    }

    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks> {
        self.deks.load_full()
    }
}

impl ClusterBus for AuthlyCtx {
    async fn broadcast_to_cluster(&self, message: ClusterMessage) -> Result<(), BusError> {
        crate::cluster_bus::authly_ctx_notify_cluster_wide(self, message).await
    }

    async fn broadcast_to_cluster_if_leader(
        &self,
        message: ClusterMessage,
    ) -> Result<(), BusError> {
        if self.hql.is_leader_db().await {
            self.broadcast_to_cluster(message).await
        } else {
            Ok(())
        }
    }
}

impl ServiceBus for AuthlyCtx {
    fn service_event_dispatcher(&self) -> &ServiceEventDispatcher {
        &self.svc_event_dispatcher
    }
}

impl RedistributeCertificates for AuthlyCtx {
    async fn redistribute_certificates_if_leader(&self) {
        crate::platform::redistribute_certificates(self).await;
    }
}

impl Directories for AuthlyCtx {
    fn load_persona_directories(&self) -> Arc<IndexMap<String, PersonaDirectory>> {
        self.persona_directories.load_full()
    }

    fn handle_service_tls_reexport_to_file(&self, service_ids: Vec<ServiceId>) {
        if self.export_tls_to_etc {
            for svc_eid in service_ids {
                if let Err(err) = export_service_identity(svc_eid, self) {
                    error!(?err, ?svc_eid, "unable to export identity");
                }
            }
        }
    }
}

impl HostsConfig for AuthlyCtx {
    fn authly_hostname(&self) -> &str {
        &self.state.hostname
    }

    fn is_k8s(&self) -> bool {
        matches!(
            self.state.cert_distribution_platform,
            CertificateDistributionPlatform::KubernetesConfigMap
        )
    }
}

impl KubernetesConfig for AuthlyCtx {
    fn authly_local_k8s_namespace(&self) -> &str {
        &self.state.k8s_local_namespace
    }
}

/// Each webauthn session is cached for 10 minutes
const WEBAUTHN_TTL_SECS: i64 = 10 * 60;

/// WebAuthn caching uses the CBOR serialization format,
/// because it's known to work well and supported upstream (webauthn-rs).
/// postcard/bincode does not work.
impl WebAuthn for AuthlyCtx {
    /// Here we just store a new Webauthn for every public URL.
    /// That might not be a sufficient strategy if subdomains are part of the picture.
    /// In that case the "relying party" should be the common domain of all the supported subdomains.
    fn get_webauthn(&self, public_uri: &Uri) -> Result<Arc<Webauthn>, WebauthnError> {
        let mut map = self.webauthn_per_uri.lock().unwrap();
        if let Some(webauthn) = map.get(public_uri) {
            return Ok(webauthn.clone());
        }

        let Some(authority) = public_uri.authority() else {
            error!("can't create webauthn: public uri has no authority");
            return Err(WebauthnError::NotSupported);
        };

        // This is where we should possibly not use the whole hostname:
        let relying_party_id = authority.host();

        let mut rp_origin = String::new();
        if let Some(scheme) = public_uri.scheme_str() {
            rp_origin.push_str(&format!("{scheme}://"));
        }

        rp_origin.push_str(authority.host());

        if let Some(port) = authority.port() {
            rp_origin.push(':');
            rp_origin.push_str(&format!("{port}"));
        }

        let rp_origin = Url::parse(&rp_origin).map_err(|err| {
            error!(?err, "unable to parse webauthn Url");
            WebauthnError::NotSupported
        })?;

        let webauthn = Arc::new(WebauthnBuilder::new(relying_party_id, &rp_origin)?.build()?);
        map.insert(public_uri.clone(), webauthn.clone());

        Ok(webauthn)
    }

    async fn cache_passkey_registration(
        &self,
        persona_id: authly_common::id::PersonaId,
        pk: PasskeyRegistration,
    ) {
        if let Some(cbor) = to_cbor(&pk) {
            self.hql
                .put_bytes(
                    CacheEntry::WebAuthnRegistration,
                    format!("{persona_id}"),
                    cbor,
                    Some(WEBAUTHN_TTL_SECS),
                )
                .await
                .map_err(|err| {
                    error!(?err, "put passkey reg");
                })
                .ok();
        }
    }

    async fn yank_passkey_registration(
        &self,
        persona_id: authly_common::id::PersonaId,
    ) -> Option<PasskeyRegistration> {
        let cbor = self
            .hql
            .get_bytes(CacheEntry::WebAuthnRegistration, format!("{persona_id}"))
            .await
            .map_err(|err| {
                error!(?err, "get passkey reg");
            })
            .ok()??;

        self.hql
            .delete(CacheEntry::WebAuthnRegistration, format!("{persona_id}"))
            .await
            .map_err(|err| {
                error!(?err, "delete passkey reg");
            })
            .ok()?;

        from_cbor(&cbor)
    }

    async fn cache_passkey_authentication(
        &self,
        login_session_id: Uuid,
        value: (PersonaId, PasskeyAuthentication),
    ) {
        if let Some(cbor) = to_cbor(&value) {
            self.hql
                .put_bytes(
                    CacheEntry::WebAuthnAuth,
                    format!("{login_session_id}"),
                    cbor,
                    Some(WEBAUTHN_TTL_SECS),
                )
                .await
                .map_err(|err| {
                    error!(?err, "put passkey auth");
                })
                .ok();
        }
    }

    async fn yank_passkey_authentication(
        &self,
        login_session_id: uuid::Uuid,
    ) -> Option<(PersonaId, PasskeyAuthentication)> {
        let cbor = self
            .hql
            .get_bytes(CacheEntry::WebAuthnAuth, format!("{login_session_id}"))
            .await
            .map_err(|err| {
                error!(?err, "get passkey auth");
            })
            .ok()??;

        self.hql
            .delete(CacheEntry::WebAuthnAuth, format!("{login_session_id}"))
            .await
            .map_err(|err| {
                error!(?err, "delete passkey auth");
            })
            .ok()?;

        from_cbor(&cbor)
    }
}

fn export_service_identity(svc_eid: ServiceId, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let pem = ctx
        .get_instance()
        .sign_with_local_ca(
            client_cert("service", svc_eid, time::Duration::days(7)).with_new_key_pair(),
        )
        .certificate_and_key_pem();

    let path = ctx.etc_dir.join(format!("service/{svc_eid}/identity.pem"));
    fs::create_dir_all(path.parent().unwrap())?;

    std::fs::write(path, pem)?;

    Ok(())
}

fn to_cbor<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    match serde_cbor_2::to_vec(value) {
        Ok(buf) => Some(buf),
        Err(err) => {
            error!(?err, "cbor serialization failed");
            None
        }
    }
}

fn from_cbor<T: DeserializeOwned>(buf: &[u8]) -> Option<T> {
    match serde_cbor_2::from_slice(buf) {
        Ok(value) => Some(value),
        Err(err) => {
            error!(?err, "cbor deserialization failed");
            None
        }
    }
}
