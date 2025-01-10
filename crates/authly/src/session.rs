use std::time::Duration;

use authly_domain::Eid;
use cookie::{Cookie, Expiration, SameSite};
use rand::Rng;
use time::OffsetDateTime;
use tracing::warn;

use crate::{db::session_db, AuthlyCtx};

pub const TOKEN_WIDTH: usize = 20;
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60);

pub const SESSION_COOKIE_NAME: &str = "session-cookie";

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

pub fn new_session_cookie(session: &Session) -> Cookie<'static> {
    let mut cookie = Cookie::new(
        SESSION_COOKIE_NAME,
        format!("{}", hexhex::hex(&session.token.0)),
    );
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_expires(Expiration::DateTime(session.expires_at));
    cookie.set_same_site(SameSite::Strict);
    cookie
}

pub(crate) async fn authenticate_session_cookie(
    session_cookie: Cookie<'_>,
    ctx: &AuthlyCtx,
) -> Result<Session, &'static str> {
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

pub fn find_session_cookie<'a>(
    cookie_headers: impl Iterator<Item = &'a str>,
) -> Result<Cookie<'a>, &'static str> {
    cookie_headers
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| Cookie::parse_encoded(cookie).ok())
        .find(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        .ok_or("no session cookie")
}
