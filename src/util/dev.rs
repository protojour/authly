use http::request::Parts;

/// Extension and extractor for doing "lower security" versions of APIs in a dev setting
#[derive(Clone, Copy)]
pub struct IsDev(pub bool);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for IsDev {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(match parts.extensions.get::<IsDev>() {
            Some(is_dev) => *is_dev,
            None => IsDev(false),
        })
    }
}
