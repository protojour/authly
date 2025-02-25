//! trait implementations for AuthlyCtx

use std::{fs, sync::Arc};

use authly_common::id::ServiceId;
use authly_domain::{
    builtins::Builtins,
    bus::{service_events::ServiceEventDispatcher, BusError, ClusterMessage},
    cert::{client_cert, CertificateParamsExt},
    ctx::{
        ClusterBus, Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance,
        HostsConfig, KubernetesConfig, LoadInstance, RedistributeCertificates, ServiceBus,
        SetInstance,
    },
    directory::PersonaDirectory,
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
};
use authly_hiqlite::HiqliteClient;
use indexmap::IndexMap;
use tracing::error;

use crate::{platform::CertificateDistributionPlatform, AuthlyCtx};

impl GetDb for AuthlyCtx {
    type Db = HiqliteClient;

    fn get_db(&self) -> &Self::Db {
        &self.hql
    }
}

impl GetBuiltins for AuthlyCtx {
    fn get_builtins(&self) -> &Builtins {
        &self.state.builtins
    }
}

impl GetHttpClient for AuthlyCtx {
    fn get_internet_http_client(&self) -> reqwest::Client {
        self.internet_http_client.clone()
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
        crate::cluster_bus::authly_ctx_notify_cluster_wide(self, message).await
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
    fn service_event_dispatcher(&self) -> &ServiceEventDispatcher {
        &self.svc_event_dispatcher
    }
}

impl RedistributeCertificates for AuthlyCtx {
    async fn redistribute_certificates_if_leader(&self) {
        crate::platform::redistribute_certificates(self).await;
    }
}

impl Directories for AuthlyCtx {
    fn load_persona_directories(&self) -> Arc<IndexMap<String, PersonaDirectory>> {
        self.persona_directories.load_full()
    }

    fn handle_service_tls_reexport_to_file(&self, service_ids: Vec<ServiceId>) {
        if self.export_tls_to_etc {
            for svc_eid in service_ids {
                if let Err(err) = export_service_identity(svc_eid, self) {
                    error!(?err, ?svc_eid, "unable to export identity");
                }
            }
        }
    }
}

impl HostsConfig for AuthlyCtx {
    fn authly_hostname(&self) -> &str {
        &self.state.hostname
    }

    fn is_k8s(&self) -> bool {
        matches!(
            self.state.cert_distribution_platform,
            CertificateDistributionPlatform::KubernetesConfigMap
        )
    }
}

impl KubernetesConfig for AuthlyCtx {
    fn authly_local_k8s_namespace(&self) -> &str {
        &self.state.k8s_local_namespace
    }
}

fn export_service_identity(svc_eid: ServiceId, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let pem = ctx
        .get_instance()
        .sign_with_local_ca(
            client_cert("service", svc_eid, time::Duration::days(7)).with_new_key_pair(),
        )
        .certificate_and_key_pem();

    let path = ctx.etc_dir.join(format!("service/{svc_eid}/identity.pem"));
    fs::create_dir_all(path.parent().unwrap())?;

    std::fs::write(path, pem)?;

    Ok(())
}
