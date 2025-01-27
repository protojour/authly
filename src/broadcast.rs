use authly_common::id::Eid;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::AuthlyCtx;

#[derive(Serialize, Deserialize)]
pub struct BroadcastMsg {
    /// The kind of message
    pub kind: BroadcastMsgKind,
    pub meta: BroadcastMeta,
}

/// Message type used by the Authly message bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Serialize, Deserialize)]
pub enum BroadcastMsgKind {
    /// An directory caused a change to the database.
    /// It can also mean the directory was added or removed.
    DirectoryChanged {
        /// The directory ID that changed
        did: Eid,
    },
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

impl AuthlyCtx {
    /// Send broadcast message to the whole cluster
    pub async fn send_broadcast(
        &self,
        message_kind: BroadcastMsgKind,
    ) -> Result<(), BroadcastError> {
        let metrics_db = self.metrics_db().await;

        self.hql
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
}

/// Spawn the hiqlite notify (broadcast) handler.
/// There should only be one global handler running per cluster node.
pub fn spawn_global_message_handler(ctx: &AuthlyCtx) {
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
    match kind {
        BroadcastMsgKind::DirectoryChanged { did } => {
            let metrics = ctx.metrics_db().await;

            if meta.last_log_index > metrics.last_log_index {
                error!(
                    ?did,
                    ?metrics,
                    ?meta.last_log_index,
                    "FIXME: received directory changed before log was written: Put into local queue"
                );
            } else {
                info!(?did, ?meta.last_log_index, "directory changed");
            }
        }
    }
}
