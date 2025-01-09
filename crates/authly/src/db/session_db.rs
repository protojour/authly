use authly_domain::EID;
use hiqlite::{params, Param};
use time::OffsetDateTime;

use crate::{
    session::{Session, SessionToken},
    AuthlyCtx,
};

use super::{Convert, DbError, DbResult};

pub async fn store_session(session: &Session, ctx: &AuthlyCtx) -> DbResult<()> {
    ctx.db
        .execute(
            "INSERT INTO session (token, eid, expires_at) VALUES ($1, $2, $3)",
            params!(
                session.token.0.clone(),
                session.eid.as_param(),
                session.expires_at.unix_timestamp()
            ),
        )
        .await?;

    Ok(())
}

pub async fn get_session(token: SessionToken, ctx: &AuthlyCtx) -> DbResult<Option<Session>> {
    let Some(mut row) = ctx
        .db
        .query_raw(
            "SELECT eid, expires_at FROM session WHERE token = $1",
            params!(token.0.clone()),
        )
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };

    Ok(Some(Session {
        token,
        eid: EID::from_row(&mut row, "eid"),
        expires_at: OffsetDateTime::from_unix_timestamp(row.get("expires_at"))
            .map_err(|_| DbError::Timestamp)?,
    }))
}
