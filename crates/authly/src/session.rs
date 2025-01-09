use std::time::Duration;

use authly_domain::Eid;
use cookie::{Cookie, CookieJar};
use rand::Rng;
use time::OffsetDateTime;
use tracing::warn;

use crate::{db::session_db, AuthlyCtx};

pub const TOKEN_WIDTH: usize = 20;
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60);

pub struct Session {
    pub token: SessionToken,
    pub eid: Eid,
    pub expires_at: time::OffsetDateTime,
}

pub struct SessionToken(pub Vec<u8>);

impl SessionToken {
    pub fn new_random() -> Self {
        Self(rand::thread_rng().gen::<[u8; TOKEN_WIDTH]>().to_vec())
    }
}

pub async fn authenticate_session_cookie(
    jar: CookieJar,
    ctx: &AuthlyCtx,
) -> Result<Session, &'static str> {
    let session_cookie = jar.get("session-cookie").ok_or("no session cookie")?;

    let now = OffsetDateTime::now_utc();

    let token_hex = session_cookie.value();
    let token = SessionToken(hexhex::decode(token_hex).map_err(|_| "invalid session cookie")?);

    let session = session_db::get_session(ctx, token)
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

pub fn parse_cookie_jar<'a>(cookie_headers: impl Iterator<Item = &'a str>) -> CookieJar {
    let cookies = cookie_headers
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| Cookie::parse_encoded(cookie.to_owned()).ok());

    let mut jar = CookieJar::new();
    for cookie in cookies {
        jar.add_original(cookie);
    }

    jar
}
