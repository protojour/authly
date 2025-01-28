use std::fs;

use authly_common::id::Eid;
use authly_db::{Db, DbError};
use tracing::error;

use crate::{
    bus::{message::ClusterMessage, BusError},
    cert::{client_cert, CertificateParamsExt},
    ctx::{Broadcast, GetDb, GetInstance},
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
}

/// Apply (write or overwrite) a document directory, publish change message
pub async fn apply_document(
    compiled_doc: CompiledDocument,
    ctx: &AuthlyCtx,
) -> Result<(), DirectoryError> {
    let did = compiled_doc.did;

    let service_ids = compiled_doc.data.service_ids.clone();

    let deks = ctx.deks.load_full();

    ctx.get_db()
        .transact(
            document_db::document_txn_statements(compiled_doc, &deks)
                .map_err(DirectoryError::Context)?,
        )
        .await?;

    if ctx.export_tls_to_etc {
        for svc_eid in service_ids {
            if let Err(err) = export_service_identity(svc_eid, ctx) {
                error!(?err, ?svc_eid, "unable to export identity");
            }
        }
    }

    ctx.broadcast_to_cluster(ClusterMessage::DirectoryChanged { did })
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
