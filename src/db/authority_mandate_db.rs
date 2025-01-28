use authly_common::id::Eid;
use authly_db::{param::AsParam, Db, DbError, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{audit::Actor, authority_mandate::submission::SUBMISSION_CODE_EXPIRATION};

#[derive(Error, Debug)]
pub enum AmDbError {
    #[error("invalid or expired code")]
    InvalidOrExpiredCode,

    #[error("db error: {0}")]
    Db(#[from] DbError),
}

/// Authority
pub async fn insert_mandate_submission_code(
    deps: &impl Db,
    code_fingerprint: Vec<u8>,
    created_by: Actor,
) -> Result<(), AmDbError> {
    deps.execute(
        "INSERT INTO am_mandate_submission_code (code_fingerprint, created_at, created_by_eid) VALUES ($1, $2, $3)".into(),
        params!(code_fingerprint, time::OffsetDateTime::now_utc().unix_timestamp(), created_by.0.as_param()),
    )
    .await?;
    Ok(())
}

/// Returns the Actor who made the submission code
pub async fn verify_then_invalidate_submission_code(
    deps: &impl Db,
    code_fingerprint: Vec<u8>,
) -> Result<Actor, AmDbError> {
    let (created_at, created_by) = {
        let mut row = deps
            .query_raw(
                "SELECT created_at, created_by_eid FROM am_mandate_submission_code WHERE code_fingerprint = $1"
                    .into(),
                params!(code_fingerprint.clone()),
            )
            .await?
            .into_iter()
            .next()
            .ok_or(AmDbError::InvalidOrExpiredCode)?;

        (
            row.get_datetime("created_at")?,
            Actor(row.get_id("created_by_eid")),
        )
    };

    deps.execute(
        "DELETE FROM am_mandate_submission_code WHERE code_fingerprint = $1".into(),
        params!(code_fingerprint),
    )
    .await?;

    if created_at + SUBMISSION_CODE_EXPIRATION < OffsetDateTime::now_utc() {
        Err(AmDbError::InvalidOrExpiredCode)
    } else {
        Ok(created_by)
    }
}

pub async fn insert_authority_mandate(
    deps: &impl Db,
    mandate_eid: Eid,
    granted_by: Actor,
    public_key: Vec<u8>,
    mandate_type: &'static str,
) -> Result<(), AmDbError> {
    let now = time::OffsetDateTime::now_utc();
    deps.execute(
        indoc! {
            "
            INSERT INTO am_mandate (
                mandate_eid,
                granted_by_eid,
                public_key,
                created_at,
                mandate_type,
                last_connection_time
            ) VALUES ($1, $2, $3, $4, $5, $6)
            "
        }
        .into(),
        params!(
            mandate_eid.as_param(),
            granted_by.0.as_param(),
            public_key,
            now.unix_timestamp(),
            mandate_type,
            now.unix_timestamp()
        ),
    )
    .await?;
    Ok(())
}
