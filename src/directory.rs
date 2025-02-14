use std::{any::Any, fs};

use authly_common::id::ServiceId;
use tracing::error;

use crate::{
    bus::{message::ClusterMessage, BusError},
    cert::{client_cert, CertificateParamsExt},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance},
    db::document_db::{DocumentDbTxnError, DocumentTransaction},
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

#[derive(thiserror::Error, Debug)]
pub enum DirectoryError {
    // #[error("db error: {0}")]
    // Db(#[from] DbError),
    #[error("bus error: {0}")]
    Bus(#[from] BusError),

    #[error("document txn error: {0}")]
    DocumentDbTxn(#[from] DocumentDbTxnError),
}

/// Apply (write or overwrite) a document directory, publish change message
pub async fn apply_document(
    deps: &(impl GetDb + GetDecryptedDeks + ClusterBus + Any),
    compiled_doc: CompiledDocument,
) -> Result<(), DirectoryError> {
    let dir_id = compiled_doc.dir_id;

    let service_ids: Vec<_> = compiled_doc.data.services.keys().copied().collect();

    let deks = deps.load_decrypted_deks();

    DocumentTransaction::new(compiled_doc)
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
