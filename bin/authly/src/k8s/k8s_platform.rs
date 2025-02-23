use authly_domain::ctx::GetInstance;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{
    api::{ObjectMeta, Patch, PatchParams},
    Api, Client,
};

use crate::AuthlyCtx;

pub async fn k8s_redistribute_certificates(ctx: AuthlyCtx) {
    let client = Client::try_default().await.unwrap();

    if let Err(err) = write_client_configmap(client, &ctx).await {
        tracing::error!(?err, "could not create authly-client ConfigMap");
    }
}

async fn write_client_configmap(client: Client, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), client.default_namespace());
    let name = "authly-certs.crt";
    let instance = ctx.get_instance();
    let configmap = ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(client.default_namespace().into()),
            annotations: Some(
                [(
                    "kubernetes.io/description".to_string(),
                    "CA bundle for verifying Authly".to_string(),
                )]
                .into(),
            ),
            ..Default::default()
        },
        binary_data: None,
        data: Some(
            [
                (
                    "root.crt".to_string(),
                    instance.trust_root_ca().certificate_pem(),
                ),
                (
                    "local.crt".to_string(),
                    instance.local_ca().certificate_pem(),
                ),
            ]
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
