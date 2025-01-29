use axum::{response::IntoResponse, routing::get};
use http::{header, StatusCode};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
pub struct Static;

pub fn static_folder() -> axum::Router {
    let mut router = axum::Router::new();
    for path in Static::iter() {
        let path2 = path.clone();
        let mime = mime_guess::from_path(path.as_ref());
        router = router.route(
            &format!("/{}", &path),
            get(move || {
                let path = path2.clone();
                async move {
                    match Static::get(&path) {
                        Some(file) => (
                            [(
                                header::CONTENT_TYPE,
                                mime.first_or_text_plain().essence_str(),
                            )],
                            file.data,
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        );
    }
    router
}

#[test]
fn check_file_contents() {
    let data = Static::get("style.css").unwrap();
    assert!(data.data.starts_with(b"@import"))
}

#[test]
fn check_mime_guess() {
    assert_eq!(
        mime_guess::from_path("style.css")
            .first_or_text_plain()
            .essence_str(),
        "text/css"
    )
}
