use authly_common::Eid;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::AuthlyCtx;

/// Message type used by the Authly message bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Serialize, Deserialize)]
pub enum BroadcastMsg {
    /// An authority caused a change to the database.
    /// It can also mean the authority was added or removed.
    AuthorityChanged { aid: Eid },
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
            _ = ctx.cancel.cancelled() => {
                info!("exiting message handler");
                return;
            }
        }
    }
}

async fn handle_msg(msg: BroadcastMsg, _ctx: &AuthlyCtx) {
    match msg {
        BroadcastMsg::AuthorityChanged { aid } => {
            info!(?aid, "authority changed");
        }
    }
}
