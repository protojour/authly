use axum::{extract::State, response::Html, routing::get};
use indoc::indoc;

use crate::AuthlyCtx;

pub fn webauth_router(ctx: AuthlyCtx) -> axum::Router {
    axum::Router::new().route("/", get(index)).with_state(ctx)
}

async fn index(State(_ctx): State<AuthlyCtx>) -> Html<&'static str> {
    Html(indoc! {
        r#"
        <script src="https://unpkg.com/htmx.org@2.0.4"></script>
        <!-- have a button POST a click via AJAX -->
        <button hx-post="/clicked" hx-swap="outerHTML">
            Click Me
        </button>
        "#
    })
}
