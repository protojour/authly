//! A login session is a session valid during a login flow.
//! It does not represent an authenticated user.

use cookie::{Cookie, SameSite};
use http::request::Parts;
use uuid::Uuid;

pub const LOGIN_COOKIE_NAME: &str = "authly-login";

pub struct LoginSession(pub Uuid);

impl LoginSession {
    pub fn to_cookie(&self) -> Cookie<'static> {
        let mut cookie = Cookie::new(LOGIN_COOKIE_NAME, format!("{}", hexhex::hex(&self.0)));
        cookie.set_path("/");
        // cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
        cookie
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for LoginSession {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = axum_extra::extract::CookieJar::from_request_parts(parts, state)
            .await
            .unwrap();

        fn read_cookie(jar: axum_extra::extract::CookieJar) -> Option<LoginSession> {
            let cookie = jar.get(LOGIN_COOKIE_NAME)?;
            let id = Uuid::parse_str(cookie.value_trimmed()).ok()?;
            Some(LoginSession(id))
        }

        match read_cookie(jar) {
            Some(session) => Ok(session),
            None => Ok(LoginSession(Uuid::new_v4())),
        }
    }
}
