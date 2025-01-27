use std::time::Duration;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::{
    api::{ObjectMeta, Patch, PatchParams},
    Api, Client,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::AuthlyCtx;

pub async fn spawn_k8s_manager(ctx: AuthlyCtx) {
    let client = Client::try_default().await.unwrap();

    tokio::spawn(async move {
        let mut manager_task = None;
        let mut cancel = CancellationToken::default();

        loop {
            let is_leader = ctx.hql.is_leader_db().await;

            if is_leader && manager_task.is_none() {
                info!(
                    "is leader, starting kubernetes manager, namespace={}",
                    client.default_namespace()
                );
                cancel = CancellationToken::default();
                manager_task = Some(tokio::spawn(k8s_manager_task(
                    client.clone(),
                    cancel.clone(),
                    ctx.clone(),
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

async fn k8s_manager_task(client: Client, _cancel: CancellationToken, ctx: AuthlyCtx) {
    if let Err(err) = write_client_configmap(client, &ctx).await {
        tracing::error!(?err, "could not create authly-client ConfigMap");
    }
}

async fn write_client_configmap(client: Client, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), client.default_namespace());
    let name = "authly-local-ca.crt";
    let configmap = ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(client.default_namespace().into()),
            annotations: Some(
                [(
                    "kubernetes.io/description".to_string(),
                    "CA bundle to verify the local Authly instance".to_string(),
                )]
                .into(),
            ),
            ..Default::default()
        },
        binary_data: None,
        data: Some(
            [(
                "ca.crt".to_string(),
                ctx.instance.trust_root_ca().certificate_pem(),
            )]
            .into(),
        ),
        immutable: None,
    };

    configmap_api
        .patch(
            name,
            &PatchParams::apply("authly"),
            &Patch::Apply(configmap),
        )
        .await?;

    Ok(())
}
