use std::{any::Any, fs};

use authly_common::id::ServiceId;
use authly_domain::{
    audit::Actor,
    bus::ClusterMessage,
    cert::{client_cert, CertificateParamsExt},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance},
    directory::DirectoryError,
    document::compiled_document::CompiledDocument,
    repo::document_repo::DocumentTransaction,
};
use tracing::error;

use crate::AuthlyCtx;

/// Apply (write or overwrite) a document directory, publish change message
pub async fn apply_document(
    deps: &(impl GetDb + GetDecryptedDeks + ClusterBus + Any),
    compiled_doc: CompiledDocument,
    actor: Actor,
) -> Result<(), DirectoryError> {
    let dir_id = compiled_doc.dir_id;

    let service_ids: Vec<_> = compiled_doc.data.services.keys().copied().collect();

    let deks = deps.load_decrypted_deks();

    DocumentTransaction::new(compiled_doc, actor)
        .execute(deps.get_db(), &deks)
        .await?;

    if let Some(authly_ctx) = (deps as &dyn Any).downcast_ref::<AuthlyCtx>() {
        if authly_ctx.export_tls_to_etc {
            for svc_eid in service_ids {
                if let Err(err) = export_service_identity(svc_eid, authly_ctx) {
                    error!(?err, ?svc_eid, "unable to export identity");
                }
            }
        }
    }

    deps.broadcast_to_cluster(ClusterMessage::DirectoryChanged { dir_id })
        .await?;

    Ok(())
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
