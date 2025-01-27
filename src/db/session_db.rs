use authly_db::{param::AsParam, Db, DbResult, Row};
use hiqlite::{params, Param};

use crate::session::{Session, SessionToken};

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
        eid: row.get_id("eid"),
        expires_at: row.get_datetime("expires_at")?,
    }))
}
