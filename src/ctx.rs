//! Traits for abstracting away application context

use std::{future::Future, sync::Arc};

use authly_common::id::ServiceId;
use authly_db::Db;

use crate::{
    bus::{
        message::{ClusterMessage, ServiceMessage},
        service_events::ServiceMessageConnection,
        BusError,
    },
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
    AuthlyCtx,
};

/// Trait for getting the "database".
///
/// This trait can be used with in "entrait-pattern" style dependency injection.
pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
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

pub trait GetDecryptedDeks {
    fn get_decrypted_deks(&self) -> arc_swap::Guard<Arc<DecryptedDeks>>;
    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks>;
}

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

pub trait RedistributeCertificates {
    fn redistribute_certificates_if_leader(&self) -> impl Future<Output = ()>;
}

impl GetDb for AuthlyCtx {
    type Db = hiqlite::Client;

    fn get_db(&self) -> &Self::Db {
        &self.hql
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

/// test context
pub mod test {}
