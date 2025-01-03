use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::AuthlyCtx;

pub fn spawn_kubernetes_manager(ctx: AuthlyCtx) {
    tokio::spawn(async move {
        let mut manager_task = None;
        let mut cancel = CancellationToken::default();

        loop {
            let is_leader = ctx.db.is_leader_db().await;

            if is_leader && manager_task.is_none() {
                info!("is leader, setting up kubernetes manager");
                cancel = CancellationToken::default();
                manager_task = Some(tokio::spawn(kubernetes_manager_impl(
                    ctx.clone(),
                    cancel.clone(),
                )));
            } else if !is_leader && manager_task.is_some() {
                info!("no longer the leader, cancelling kubernetes manager");
                cancel.cancel();
                manager_task = None;
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

async fn kubernetes_manager_impl(ctx: AuthlyCtx, cancel: CancellationToken) {}
