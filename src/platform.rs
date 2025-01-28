use crate::{k8s::k8s_platform::k8s_redistribute_certificates, AuthlyCtx};

/// How Authly can distribute certificates
pub enum CertificateDistributionPlatform {
    EtcDir,
    KubernetesConfigMap,
}

/// Perform certificate redistribution
pub(crate) async fn redistribute_certificates(ctx: &AuthlyCtx) {
    if !ctx.hql.is_leader_db().await {
        // Let the leader take care of this
        return;
    }

    match ctx.cert_distribution_platform {
        CertificateDistributionPlatform::EtcDir => {
            if let Err(err) = reexport_certs_to_etc(ctx) {
                tracing::error!(
                    ?err,
                    "certificates could not be written to {:?}",
                    ctx.etc_dir
                );
            }
        }
        CertificateDistributionPlatform::KubernetesConfigMap => {
            k8s_redistribute_certificates(ctx.clone()).await;
        }
    }
}

pub(crate) fn reexport_certs_to_etc(ctx: &AuthlyCtx) -> anyhow::Result<()> {
    std::fs::create_dir_all(ctx.etc_dir.join("certs"))?;

    std::fs::write(
        ctx.etc_dir.join("certs/root.crt"),
        ctx.instance
            .load()
            .trust_root_ca()
            .certificate_pem()
            .as_bytes(),
    )?;
    std::fs::write(
        ctx.etc_dir.join("certs/local.crt"),
        ctx.instance.load().local_ca().certificate_pem().as_bytes(),
    )?;

    Ok(())
}
