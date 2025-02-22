use authly_common::id::EntityId;
use authly_db::{params, param::ToBlob, Db, DbError, DbResult, Row, TryFromRow};
use time::OffsetDateTime;

use crate::session::{Session, SessionToken};

pub async fn store_session(deps: &impl Db, session: &Session) -> DbResult<()> {
    deps.execute(
        "INSERT INTO session (token, eid, expires_at) VALUES ($1, $2, $3)".into(),
        params!(
            session.token.0.clone(),
            session.eid.to_blob(),
            session.expires_at.unix_timestamp()
        ),
    )
    .await?;

    Ok(())
}

pub async fn get_session(deps: &impl Db, token: SessionToken) -> DbResult<Option<Session>> {
    struct SessionData(EntityId, OffsetDateTime);

    impl TryFromRow for SessionData {
        type Error = DbError;

        fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
            Ok(Self(row.get_id("eid"), row.get_datetime("expires_at")?))
        }
    }

    let Some(SessionData(eid, expires_at)) = deps
        .query_filter_map::<SessionData>(
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
        eid,
        expires_at,
    }))
}
