//! Traits for abstracting away application context

use std::{future::Future, sync::Arc};

use authly_db::Db;

use crate::{
    bus::broadcast::{BroadcastError, BroadcastMsgKind},
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

pub trait SendBroadcast {
    // Send broadcast message to the Authly cluster
    fn send_broadcast(
        &self,
        message_kind: BroadcastMsgKind,
    ) -> impl Future<Output = Result<(), BroadcastError>>;
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

impl SendBroadcast for AuthlyCtx {
    async fn send_broadcast(&self, message_kind: BroadcastMsgKind) -> Result<(), BroadcastError> {
        crate::bus::broadcast::application::authly_ctx_send_broadcast(self, message_kind).await
    }
}

/// test context
pub mod test {}
