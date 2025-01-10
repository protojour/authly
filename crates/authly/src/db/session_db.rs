use authly_common::Eid;
use hiqlite::{params, Param};
use time::OffsetDateTime;

use crate::session::{Session, SessionToken};

use super::{Convert, Db, DbError, DbResult, Row};

pub async fn store_session(deps: &impl Db, session: &Session) -> DbResult<()> {
    deps.execute(
        "INSERT INTO session (token, eid, expires_at) VALUES ($1, $2, $3)".into(),
        params!(
            session.token.0.clone(),
            session.eid.as_param(),
            session.expires_at.unix_timestamp()
        ),
    )
    .await?;

    Ok(())
}

pub async fn get_session(deps: &impl Db, token: SessionToken) -> DbResult<Option<Session>> {
    let Some(mut row) = deps
        .query_raw(
            "SELECT eid, expires_at FROM session WHERE token = $1".into(),
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
        eid: Eid::from_row(&mut row, "eid"),
        expires_at: OffsetDateTime::from_unix_timestamp(row.get_int("expires_at"))
            .map_err(|_| DbError::Timestamp)?,
    }))
}
