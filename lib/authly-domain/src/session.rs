use std::time::Duration;

use authly_common::id::EntityId;
use authly_db::DbResult;
use cookie::{Cookie, Expiration, SameSite};
use rand::Rng;
use time::OffsetDateTime;
use tracing::warn;

use crate::{ctx::GetDb, repo::session_repo};

pub const TOKEN_WIDTH: usize = 20;
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60);

pub const SESSION_COOKIE_NAME: &str = "session-cookie";

pub struct Session {
    pub token: SessionToken,
    pub eid: EntityId,
    pub expires_at: time::OffsetDateTime,
}

impl Session {
    pub fn to_cookie(&self) -> Cookie<'static> {
        let mut cookie = Cookie::new(
            SESSION_COOKIE_NAME,
            format!("{}", hexhex::hex(&self.token.0)),
        );
        cookie.set_path("/");
        // cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_expires(Expiration::DateTime(self.expires_at));
        cookie.set_same_site(SameSite::Strict);
        cookie
    }
}

pub async fn authenticate_session_cookie(
    deps: &impl GetDb,
    session_cookie: &Cookie<'_>,
) -> Result<Session, &'static str> {
    let now = OffsetDateTime::now_utc();

    let token_hex = session_cookie.value();
    let token = SessionToken(hexhex::decode(token_hex).map_err(|_| "invalid session cookie")?);

    let session = session_repo::get_session(deps.get_db(), token)
        .await
        .map_err(|err| {
            warn!(?err, "session lookup error");
            "internal error"
        })?
        .ok_or("no session")?;

    if session.expires_at < now {
        return Err("session expired");
    }

    Ok(session)
}

pub struct SessionToken(pub Vec<u8>);

impl SessionToken {
    pub fn new_random() -> Self {
        Self(rand::thread_rng().r#gen::<[u8; TOKEN_WIDTH]>().to_vec())
    }
}

pub async fn init_session(deps: &impl GetDb, eid: EntityId) -> DbResult<Session> {
    let session = Session {
        token: SessionToken::new_random(),
        eid,
        expires_at: time::OffsetDateTime::now_utc() + SESSION_TTL,
    };

    session_repo::store_session(deps.get_db(), &session).await?;

    Ok(session)
}

pub fn find_session_cookie<'a>(
    cookie_headers: impl Iterator<Item = &'a str>,
) -> Result<Cookie<'a>, &'static str> {
    cookie_headers
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| Cookie::parse_encoded(cookie).ok())
        .find(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        .ok_or("no session cookie")
}
