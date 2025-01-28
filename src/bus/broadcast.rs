use authly_common::id::Eid;
use authly_db::IsLeaderDb;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{
    ctx::{GetDb, GetDecryptedDeks, SetInstance},
    db::cryptography_db::load_authly_instance,
    AuthlyCtx,
};

/// Message type used by the Authly message bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum BroadcastMsgKind {
    /// The AuthlyInstance has been rewritten in the database.
    /// This should trigger:
    /// 1. Re-load of AuthlyInstance
    /// 2. Certificate redistribution
    /// 3. Notify all connected clients
    InstanceChanged,

    /// An directory caused a change to the database.
    /// It can also mean the directory was added or removed.
    DirectoryChanged {
        /// The directory ID that changed
        did: Eid,
    },
}

#[derive(Serialize, Deserialize)]
pub struct BroadcastMsg {
    /// The kind of message
    pub kind: BroadcastMsgKind,
    pub meta: BroadcastMeta,
}

#[derive(Serialize, Deserialize)]
pub struct BroadcastMeta {
    /// The last db log index observed after the directory changed
    pub last_log_index: Option<u64>,
}

#[derive(thiserror::Error, Debug)]
pub enum BroadcastError {
    #[error("broadcast send error: {0}")]
    Send(hiqlite::Error),
}

/// Generic broadcast handler
pub async fn authly_handle_broadcast(
    deps: &(impl GetDb + GetDecryptedDeks + SetInstance),
    message_kind: &BroadcastMsgKind,
) -> anyhow::Result<()> {
    match message_kind {
        BroadcastMsgKind::InstanceChanged => {
            // step 1: re-load instance
            // IsLeaderDb is not important when not starting up the first time
            let deks = deps.load_decrypted_deks();
            let new_instance = load_authly_instance(IsLeaderDb(true), deps.get_db(), &deks).await?;
            deps.set_instance(new_instance);
        }
        BroadcastMsgKind::DirectoryChanged { did } => {
            info!(?did, "directory changed");
        }
    }

    Ok(())
}

/// Broadcast for the real application
pub mod application {
    use super::*;

    pub(crate) async fn authly_ctx_send_broadcast(
        ctx: &AuthlyCtx,
        message_kind: BroadcastMsgKind,
    ) -> Result<(), BroadcastError> {
        let metrics_db = ctx.metrics_db().await;

        ctx.hql
            .notify(&BroadcastMsg {
                kind: message_kind,
                meta: BroadcastMeta {
                    last_log_index: metrics_db.last_log_index,
                },
            })
            .await
            .map_err(BroadcastError::Send)?;

        Ok(())
    }

    /// Spawn the hiqlite notify (broadcast) handler.
    /// There should only be one global handler running per cluster node.
    pub(crate) fn spawn_global_message_handler(ctx: &AuthlyCtx) {
        tokio::spawn(message_handler(ctx.clone()));
    }

    async fn message_handler(ctx: AuthlyCtx) {
        loop {
            tokio::select! {
                listen_result = ctx.hql.listen::<BroadcastMsg>() => {
                    match listen_result {
                        Ok(bus_msg) => {
                            handle_msg(bus_msg, &ctx).await;
                        }
                        Err(err) => {
                            error!(?err, "message bus handler error");
                        }
                    }
                }
                _ = ctx.shutdown.cancelled() => {
                    info!("exiting message handler");
                    return;
                }
            }
        }
    }

    async fn handle_msg(BroadcastMsg { kind, meta }: BroadcastMsg, ctx: &AuthlyCtx) {
        check_db_metrics(ctx, &kind, &meta).await;

        if let Err(err) = super::authly_handle_broadcast(ctx, &kind).await {
            error!(?err, ?kind, "Failed to handle broadcast message");
        }
    }

    async fn check_db_metrics(ctx: &AuthlyCtx, kind: &BroadcastMsgKind, meta: &BroadcastMeta) {
        let metrics = ctx.metrics_db().await;

        if meta.last_log_index > metrics.last_log_index {
            error!(
                ?kind,
                ?metrics,
                ?meta.last_log_index,
                "FIXME: received broadcast message before log was written: Put into local queue"
            );
        }
    }
}
