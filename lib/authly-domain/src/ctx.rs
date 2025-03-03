use std::{future::Future, sync::Arc};

use authly_common::id::{PersonaId, ServiceId};
use authly_db::Db;
use http::Uri;
use indexmap::IndexMap;
use uuid::Uuid;
use webauthn_rs::{
    prelude::{PasskeyAuthentication, PasskeyRegistration},
    Webauthn,
};

use crate::{
    builtins::Builtins,
    bus::{service_events::ServiceEventDispatcher, BusError, ClusterMessage},
    directory::PersonaDirectory,
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
    webauthn::WebauthnError,
};

/// Trait for getting the "database".
///
/// This trait can be used with in "entrait-pattern" style dependency injection.
pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}

pub trait GetBuiltins {
    fn get_builtins(&self) -> &Builtins;
}

pub trait GetInstance {
    // Gets cheap read guard for the AuthlyInstance
    fn get_instance(&self) -> arc_swap::Guard<Arc<AuthlyInstance>>;
}

pub trait LoadInstance {
    // Get full load of AuthlyInstance
    fn load_instance(&self) -> Arc<AuthlyInstance>;
}

pub trait SetInstance {
    // Sets a new AuthlyInstance
    fn set_instance(&self, instance: AuthlyInstance);
}

pub trait ClusterBus {
    /// Send broadcast message to the Authly cluster unconditionally
    fn broadcast_to_cluster(
        &self,
        message: ClusterMessage,
    ) -> impl Future<Output = Result<(), BusError>> + Send;

    /// Send broadcast message to the Authly cluster, if this node is the leader
    fn broadcast_to_cluster_if_leader(
        &self,
        message: ClusterMessage,
    ) -> impl Future<Output = Result<(), BusError>> + Send;
}

pub trait ServiceBus {
    fn service_event_dispatcher(&self) -> &ServiceEventDispatcher;
}

pub trait GetHttpClient {
    fn get_internet_http_client(&self) -> reqwest::Client;
}

pub trait GetDecryptedDeks {
    fn get_decrypted_deks(&self) -> arc_swap::Guard<Arc<DecryptedDeks>>;
    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks>;
}

pub trait Directories {
    fn load_persona_directories(&self) -> Arc<IndexMap<String, PersonaDirectory>>;

    /// Optionally handle service TLS export to file when the service IDs have changed
    fn handle_service_tls_reexport_to_file(&self, _service_ids: Vec<ServiceId>) {}
}

pub trait RedistributeCertificates {
    fn redistribute_certificates_if_leader(&self) -> impl Future<Output = ()>;
}

pub trait HostsConfig {
    fn authly_hostname(&self) -> &str;
    fn is_k8s(&self) -> bool;
}

pub trait KubernetesConfig {
    fn authly_local_k8s_namespace(&self) -> &str;
}

pub trait WebAuthn {
    /// Get the Webauthn "site".
    fn get_webauthn(&self, public_uri: &Uri) -> Result<Arc<Webauthn>, WebauthnError>;

    /// Temporarily store a passkey registration session
    fn cache_passkey_registration(
        &self,
        persona_id: PersonaId,
        pk: PasskeyRegistration,
    ) -> impl Future<Output = ()> + Send;

    /// Yank passkey registration state out of the cache
    fn yank_passkey_registration(
        &self,
        persona_id: PersonaId,
    ) -> impl Future<Output = Option<PasskeyRegistration>> + Send;

    /// Temporarily store passkey authentication state in the cache
    fn cache_passkey_authentication(
        &self,
        login_session_id: Uuid,
        value: (PersonaId, PasskeyAuthentication),
    ) -> impl Future<Output = ()> + Send;

    /// Yank passkey authentication state from the cache
    fn yank_passkey_authentication(
        &self,
        login_session_id: Uuid,
    ) -> impl Future<Output = Option<(PersonaId, PasskeyAuthentication)>> + Send;
}
