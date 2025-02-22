use authly_domain::bus::{BusError, ClusterMessage};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::AuthlyCtx;

/// Message type used by the Authly cluster-wide broadcast bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Serialize, Deserialize)]
pub struct ClusterMessageWithMeta {
    /// The kind of message
    pub message: ClusterMessage,
    pub meta: ClusterMsgMeta,
}

#[derive(Serialize, Deserialize)]
pub struct ClusterMsgMeta {
    /// The last db log index observed after the directory changed
    pub last_log_index: Option<u64>,
}

/// Broadcast a message to the whole cluster
pub(crate) async fn authly_ctx_notify_cluster_wide(
    ctx: &AuthlyCtx,
    message: ClusterMessage,
) -> Result<(), BusError> {
    let metrics_db = ctx.metrics_db().await;

    ctx.hql
        .notify(&ClusterMessageWithMeta {
            message,
            meta: ClusterMsgMeta {
                last_log_index: metrics_db.last_log_index,
            },
        })
        .await
        .map_err(|err| BusError::Notify(err.into()))?;

    Ok(())
}

/// Spawn the hiqlite notify (broadcast) handler.
/// There should only be one global handler running per cluster node.
pub(crate) fn spawn_global_cluster_message_handler(ctx: &AuthlyCtx) {
    tokio::spawn(message_handler(ctx.clone()));
}

async fn message_handler(ctx: AuthlyCtx) {
    loop {
        tokio::select! {
            listen_result = ctx.hql.listen::<ClusterMessageWithMeta>() => {
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

async fn handle_msg(
    ClusterMessageWithMeta { message, meta }: ClusterMessageWithMeta,
    ctx: &AuthlyCtx,
) {
    check_db_metrics(ctx, &message, &meta).await;

    if let Err(err) =
        super::handler::authly_node_handle_incoming_message(ctx, message.clone()).await
    {
        error!(?err, ?message, "Failed to handle broadcast message");
    }
}

async fn check_db_metrics(ctx: &AuthlyCtx, message: &ClusterMessage, meta: &ClusterMsgMeta) {
    let metrics = ctx.metrics_db().await;

    if meta.last_log_index > metrics.last_log_index {
        error!(
            ?message,
            ?metrics,
            ?meta.last_log_index,
            "FIXME: received broadcast message before log was written: Put into local queue"
        );
    }
}
