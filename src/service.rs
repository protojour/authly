//! service utilities

use authly_common::id::ServiceId;
use authly_db::DbError;
use tracing::info;

use crate::{
    ctx::{GetBuiltins, GetDb, HostsConfig},
    db::service_db,
};

pub async fn get_service_hosts(
    deps: &(impl GetDb + GetBuiltins + HostsConfig),
    svc_eid: ServiceId,
) -> anyhow::Result<Vec<String>, DbError> {
    let base_hosts = service_db::list_service_hosts(deps.get_db(), svc_eid).await?;

    let mut hosts = base_hosts.clone();

    if !base_hosts.is_empty() && deps.is_k8s() {
        if let Some((namespace, _)) =
            service_db::get_svc_local_k8s_account_name(deps.get_db(), svc_eid, deps.get_builtins())
                .await?
        {
            for base_host in base_hosts {
                hosts.push(format!("{base_host}.{namespace}.svc.cluster.local"));
            }
        }
    }

    // hack for "localhost" run, all services will validate to "localhost"
    if deps.authly_hostname() == "localhost" {
        hosts.push("localhost".to_string());
    }

    info!(?svc_eid, ?hosts, "computed service hosts");

    Ok(hosts)
}
