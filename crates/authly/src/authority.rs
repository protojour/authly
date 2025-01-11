use crate::{
    broadcast::BroadcastMsg,
    db::{document_db, DbError},
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

#[derive(thiserror::Error, Debug)]
pub enum AuthorityError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("notify error")]
    Notify(DbError),
}

/// Store (write or overwrite) a document authority, publish change message
pub async fn put_document(
    document: CompiledDocument,
    ctx: &AuthlyCtx,
) -> Result<(), AuthorityError> {
    let aid = document.aid;
    document_db::store_document(ctx, document).await?;

    ctx.hql
        .notify(&BroadcastMsg::AuthorityChanged { aid })
        .await
        .map_err(|err| AuthorityError::Notify(err.into()))?;

    Ok(())
}
