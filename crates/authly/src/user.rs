use argon2::{password_hash::SaltString, Argon2};
use hiqlite::{params, Param};

use crate::{AuthlyCtx, EID};

pub async fn try_register_user(
    username: String,
    password: String,
    ctx: AuthlyCtx,
) -> anyhow::Result<EID> {
    let password_hash = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            argon2::PasswordHash::generate(Argon2::default(), password, &salt)
                .map_err(|e| anyhow::anyhow!("failed to generate password hash: {}", e))?
                .to_string()
                .into(),
        )
    })
    .await??;

    let eid = EID::random();

    ctx.db
        .execute(
            "INSERT INTO user_auth (eid, username, password_hash) VALUES ($1, $2, $3)",
            params!(eid.as_param(), username, password_hash),
        )
        .await?;

    Ok(eid)
}

pub async fn user_count(ctx: AuthlyCtx) -> anyhow::Result<usize> {
    let mut row = ctx
        .db
        .query_raw_one("SELECT count(*) AS count FROM user_auth", params!())
        .await?;

    let count: i64 = row.get("count");
    Ok(count as usize)
}
