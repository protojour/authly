use std::{any::Any, fs};

use authly_common::id::Eid;
use authly_db::{Db, DbError};
use tracing::error;

use crate::{
    bus::{message::ClusterMessage, BusError},
    cert::{client_cert, CertificateParamsExt},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance},
    db::document_db,
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

#[derive(thiserror::Error, Debug)]
pub enum DirectoryError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("context error: {0}")]
    Context(anyhow::Error),

    #[error("bus error: {0}")]
    Bus(#[from] BusError),

    #[error("transaction statement {0} failed: {1}")]
    DbTransaction(usize, DbError),
}

/// Apply (write or overwrite) a document directory, publish change message
pub async fn apply_document(
    deps: &(impl GetDb + GetDecryptedDeks + ClusterBus + Any),
    compiled_doc: CompiledDocument,
) -> Result<(), DirectoryError> {
    let dir_id = compiled_doc.dir_id;

    let service_ids = compiled_doc.data.service_ids.clone();

    let deks = deps.load_decrypted_deks();

    for (idx, result) in deps
        .get_db()
        .transact(
            document_db::document_txn_statements(compiled_doc, &deks)
                .map_err(DirectoryError::Context)?,
        )
        .await?
        .into_iter()
        .enumerate()
    {
        result.map_err(|err| DirectoryError::DbTransaction(idx, err))?;
    }

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

fn export_service_identity(svc_eid: Eid, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let pem = ctx
        .get_instance()
        .sign_with_local_ca(
            client_cert(&svc_eid.to_string(), time::Duration::days(7)).with_new_key_pair(),
        )
        .certificate_and_key_pem();

    let path = ctx.etc_dir.join(format!("service/{svc_eid}/identity.pem"));
    fs::create_dir_all(path.parent().unwrap())?;

    std::fs::write(path, pem)?;

    Ok(())
}
