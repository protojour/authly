use std::fs;

use authly_common::id::Eid;
use tracing::error;

use crate::{
    broadcast::{BroadcastError, BroadcastMsgKind},
    cert::{client_cert, CertificateParamsExt},
    db::{document_db, DbError},
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

#[derive(thiserror::Error, Debug)]
pub enum AuthorityError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("context error: {0}")]
    Context(anyhow::Error),

    #[error("broadcast error: {0}")]
    Broadcast(#[from] BroadcastError),
}

/// Apply (write or overwrite) a document authority, publish change message
pub async fn apply_document(
    compiled_doc: CompiledDocument,
    ctx: &AuthlyCtx,
) -> Result<(), AuthorityError> {
    let aid = compiled_doc.aid;

    let service_ids = compiled_doc.data.service_ids.clone();

    let deks = ctx.deks.load_full();

    ctx.hql
        .txn(
            document_db::document_txn_statements(compiled_doc, &deks)
                .map_err(AuthorityError::Context)?,
        )
        .await
        .map_err(|err| AuthorityError::Db(err.into()))?;

    if ctx.export_tls_to_etc {
        for svc_eid in service_ids {
            if let Err(err) = export_service_identity(svc_eid, ctx) {
                error!(?err, ?svc_eid, "unable to export identity");
            }
        }
    }

    ctx.send_broadcast(BroadcastMsgKind::AuthorityChanged { aid })
        .await?;

    Ok(())
}

fn export_service_identity(svc_eid: Eid, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let pem = ctx
        .instance
        .sign_with_local_ca(
            client_cert(&svc_eid.to_string(), time::Duration::days(7)).with_new_key_pair(),
        )
        .certificate_and_key_pem();

    let path = ctx.etc_dir.join(format!("service/{svc_eid}/identity.pem"));
    fs::create_dir_all(path.parent().unwrap())?;

    std::fs::write(path, pem)?;

    Ok(())
}
