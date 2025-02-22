use std::{future::Future, sync::Arc};

use authly_db::Db;
use indexmap::IndexMap;

use crate::{
    builtins::Builtins, directory::PersonaDirectory, encryption::DecryptedDeks,
    instance::AuthlyInstance,
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

pub trait GetHttpClient {
    fn get_internet_http_client(&self) -> reqwest::Client;
}

pub trait GetDecryptedDeks {
    fn get_decrypted_deks(&self) -> arc_swap::Guard<Arc<DecryptedDeks>>;
    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks>;
}

pub trait Directories {
    fn load_persona_directories(&self) -> Arc<IndexMap<String, PersonaDirectory>>;
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
