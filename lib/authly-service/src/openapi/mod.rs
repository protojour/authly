//! FIXME: figure out if we want "openapi" at all.
//! The web frontend doesn't need to speak JSON, it's a htmx app.
//! Mobile/desktop apps can just use gRPC.

pub mod router;

mod admin;
mod user_auth;
