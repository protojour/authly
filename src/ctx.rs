//! Traits for abstracting away application context

use std::{future::Future, sync::Arc};

use authly_common::id::ServiceId;
use authly_domain::{
    builtins::Builtins,
    ctx::{
        Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance, HostsConfig,
        KubernetesConfig, LoadInstance, RedistributeCertificates, SetInstance,
    },
    directory::PersonaDirectory,
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
};
use indexmap::IndexMap;

use crate::{
    bus::{
        message::{ClusterMessage, ServiceMessage},
        service_events::ServiceMessageConnection,
        BusError,
    },
    platform::CertificateDistributionPlatform,
    AuthlyCtx,
};

pub trait ClusterBus {
    /// Send broadcast message to the Authly cluster unconditionally
    fn broadcast_to_cluster(
        &self,
        message: ClusterMessage,
    ) -> impl Future<Output = Result<(), BusError>>;

    /// Send broadcast message to the Authly cluster, if this node is the leader
    fn broadcast_to_cluster_if_leader(
        &self,
        message: ClusterMessage,
    ) -> impl Future<Output = Result<(), BusError>>;
}

pub trait ServiceBus {
    /// Register a subscriber for service messages.
    fn service_subscribe(&self, svc_id: ServiceId, connection: ServiceMessageConnection);

    fn service_broadcast(&self, svc_id: ServiceId, msg: ServiceMessage);

    fn service_broadcast_all(&self, msg: ServiceMessage);
}

impl GetDb for AuthlyCtx {
    type Db = hiqlite::Client;

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
        crate::bus::cluster::authly_ctx_notify_cluster_wide(self, message).await
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
    fn service_subscribe(&self, svc_eid: ServiceId, connection: ServiceMessageConnection) {
        self.state
            .svc_event_dispatcher
            .subscribe(svc_eid, connection);
    }

    fn service_broadcast_all(&self, msg: ServiceMessage) {
        self.state.svc_event_dispatcher.broadcast_all(msg);
    }

    fn service_broadcast(&self, svc_eid: ServiceId, msg: ServiceMessage) {
        self.state.svc_event_dispatcher.broadcast(svc_eid, msg);
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

/// test context
pub mod test {}
