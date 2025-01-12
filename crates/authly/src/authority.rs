use crate::{
    broadcast::{BroadcastError, BroadcastMsgKind},
    db::{document_db, DbError},
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

#[derive(thiserror::Error, Debug)]
pub enum AuthorityError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("broadcast error: {0}")]
    Broadcast(#[from] BroadcastError),
}

/// Apply (write or overwrite) a document authority, publish change message
pub async fn apply_document(
    compiled_doc: CompiledDocument,
    ctx: &AuthlyCtx,
) -> Result<(), AuthorityError> {
    let aid = compiled_doc.aid;

    ctx.hql
        .txn(document_db::document_txn_statements(compiled_doc))
        .await
        .map_err(|err| AuthorityError::Db(err.into()))?;

    ctx.send_broadcast(BroadcastMsgKind::AuthorityChanged { aid })
        .await?;

    Ok(())
}
