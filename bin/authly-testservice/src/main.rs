use std::env;
use std::sync::Arc;

use authly_client::{AccessControl, AccessToken};
use authly_common::id::ServiceId;
use authly_common::mtls_server::PeerServiceEntity;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::RequestPartsExt;
use axum::{http::request::Parts, routing::get};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use futures_util::StreamExt;
use indoc::indoc;
use maud::{html, DOCTYPE};
use maud::{Markup, PreEscaped};
use tower_server::Scheme;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct Ctx {
    client: Option<authly_client::Client>,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    info!("HELLO");

    // DISABLE_AUTHLY is nice when only working on the HTML
    if env::var("DISABLE_AUTHLY").is_err() {
        let client_builder = authly_client::Client::builder()
            .from_environment()
            .await
            .unwrap();

        let client = client_builder.connect().await.unwrap();
        let metadata = client.metadata().await.unwrap();
        let entity_id = metadata.entity_id();
        let label = metadata.label();

        info!("client running, entity_id={entity_id} label={label}, binding server to port 443");

        tower_server::Builder::new("0.0.0.0:443".parse().unwrap())
            .with_graceful_shutdown(tower_server::signal::termination_signal())
            .with_tls_connection_middleware(authly_common::mtls_server::MTLSMiddleware)
            .with_scheme(Scheme::Https)
            .with_tls_config(
                client
                    .rustls_server_configurer("testservice")
                    .await
                    .unwrap(),
            )
            .bind()
            .await
            .unwrap()
            .serve(app(Ctx {
                client: Some(client),
            }))
            .await;
    } else {
        info!("authly disabled, binding server to port 3000");

        tower_server::Builder::new("0.0.0.0:3000".parse().unwrap())
            .with_graceful_shutdown(tower_server::signal::termination_signal())
            .bind()
            .await
            .unwrap()
            .serve(app(Ctx { client: None }))
            .await;
    };
}

fn app(ctx: Ctx) -> axum::Router {
    axum::Router::new()
        .route("/", get(index))
        .route("/tab/service", get(tab_service))
        .route("/tab/user", get(tab_user))
        .with_state(ctx)
}

enum Error {
    UserNotAuthenticated,
    Authly(authly_client::Error),
}

impl From<authly_client::Error> for Error {
    fn from(value: authly_client::Error) -> Self {
        Self::Authly(value)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::UserNotAuthenticated => StatusCode::UNAUTHORIZED.into_response(),
            Self::Authly(err) => {
                error!(?err, "authly client error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

async fn index(ctx: HtmlCtx) -> Markup {
    let has_user_session = ctx.access_token.is_some();
    let js = indoc! {
        r#"
        document.body.addEventListener('htmx:responseError', function(evt) {
            if (evt.detail.xhr.status == 401) {
                // redirect to login
                const next = encodeURIComponent(document.location.href);
                window.location.href = `/authly/auth/?next=${next}`;
            } else {
                console.log('unhandled response error');
            }
        });
        "#,
    };

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly Testservice" }
                script src="https://unpkg.com/htmx.org@2.0.4" {}
                script src="https://unpkg.com/htmx-ext-json-enc@2.0.1/json-enc.js" {}
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" {}
            }
            body {
                main class="container" {
                    h1 { "Authly Testservice" }
                    p {
                        "This is the web interface of " code { "authly-testservice" } ". "
                        @if has_user_session {
                            "User session is active."
                        } @else {
                            "No user session available."
                        }
                    }

                    div id="tabs" hx-get={(ctx.prefix)"/tab/service"} hx-trigger="load delay:100ms" hx-target="#tabs" hx-swap="innerHTML";
                }
            }

            script { (PreEscaped(js)) }
        }
    }
}

async fn tab_service(ctx: HtmlCtx) -> Result<Markup, Error> {
    let (entity_id, label) = if let Some(client) = ctx.client.as_ref() {
        let metadata = client.metadata().await?;

        (
            metadata.entity_id().to_string(),
            metadata.label().to_string(),
        )
    } else {
        ("N/A".to_string(), "N/A".to_string())
    };

    let mut properties: Vec<((String, String), Vec<String>)> =
        if let Some(client) = ctx.client.as_ref() {
            client
                .get_resource_property_mapping()
                .as_ref()
                .into_iter()
                .flat_map(|(namespace, props)| {
                    props.into_iter().map(|(property, attrs)| {
                        (
                            (namespace.clone(), property.clone()),
                            attrs
                                .into_iter()
                                .map(|(label, _)| label.clone())
                                .collect::<Vec<_>>(),
                        )
                    })
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

    properties.sort_by(|(ns_prop_a, _), (ns_prop_b, _)| ns_prop_a.cmp(ns_prop_b));

    Ok(html! {
        (render_nav_tab_list(0, &ctx))

        div id="tab-content" role="tabpanel" class="tab-content" {
            table {
                tbody {
                    tr {
                        th { "Service Entity ID " }
                        td { code { (entity_id) } }
                    }
                    tr {
                        th { "Authly label" }
                        td { code { (label) } }
                    }
                }
            }

            h4 { "Mesh" }
            table {
                tbody {
                    tr {
                        th { "Peer Service Entity ID" }
                        td {
                            code {
                                @match ctx.peer_service_entity {
                                    Some(peer_service_entity) => {
                                        (peer_service_entity)
                                    }
                                    None => { "N/A" }
                                }
                            }
                        }
                    }
                }
            }

            h4 { "Resource properties" }
            table {
                thead {
                    tr {
                        th { "Namespace" }
                        th { "Property" }
                        th { "Attributes" }
                    }
                }
                tbody {
                    @for ((namespace, prop_label), attributes) in properties {
                        tr {
                            td { code { (namespace) } }
                            td { code { (prop_label) } }
                            td {
                                @for attribute in attributes {
                                    code { (attribute) }
                                    " "
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

#[derive(Clone, Copy)]
struct ResourceAction(&'static [(&'static str, &'static str, &'static str)]);

fn actions() -> &'static [ResourceAction] {
    &[
        ResourceAction(&[
            ("testservice", "name", "ontology"),
            ("testservice", "ontology/action", "read"),
        ]),
        ResourceAction(&[
            ("testservice", "name", "ontology"),
            ("testservice", "ontology/action", "deploy"),
        ]),
        ResourceAction(&[
            ("testservice", "name", "storage"),
            ("testservice", "bucket/action", "create"),
        ]),
        ResourceAction(&[("this", "doesn't", "exist")]),
    ]
}

async fn tab_user(ctx: HtmlCtx) -> Result<Markup, Error> {
    let Some(access_token) = ctx.access_token.clone() else {
        return Err(Error::UserNotAuthenticated);
    };

    async fn eval_access_control(
        action: ResourceAction,
        client: &authly_client::Client,
        token: Option<Arc<AccessToken>>,
    ) -> Option<bool> {
        let mut req = client.access_control_request();
        if let Some(token) = token {
            req = req.access_token(token);
        }
        for triplet in action.0 {
            req = req.resource_attribute(*triplet).ok()?;
        }

        let value = req.evaluate().await.ok()?;

        Some(value)
    }

    let resource_access_control: Vec<_> = if let Some(client) = ctx.client.as_ref() {
        futures_util::stream::iter(actions())
            .then(|action| async {
                let value = eval_access_control(*action, client, ctx.access_token.clone()).await;
                (*action, value)
            })
            .collect()
            .await
    } else {
        actions().iter().map(|action| (*action, None)).collect()
    };

    Ok(html! {
        (render_nav_tab_list(1, &ctx))

        div id="tab-content" role="tabpanel" class="tab-content" {
            table {
                tbody {
                    tr {
                        th { "User Entity ID " }
                        td { code { (access_token.claims.authly.entity_id) } }
                    }
                }
            }
        }

        h4 { "Access control" }
        table {
            thead {
                tr {
                    th { "Resource" }
                    th { "Value" }
                }
            }
            tbody {
                @for (resource, value) in resource_access_control {
                    tr {
                        td {
                            @for (ns, prop, attr) in resource.0 {
                                code { (ns) ":" (prop) ":" (attr) }
                                " "
                            }
                        }
                        td {
                            @match value {
                                Some(true) => {
                                    code { "allow" }
                                }
                                Some(false) => {
                                    code { "deny" }
                                }
                                None => { "error" }
                            }
                        }
                    }
                }
            }
        }
    })
}

fn render_nav_tab_list(selected: usize, ctx: &HtmlCtx) -> Markup {
    let mut aria_current = [None, None];
    aria_current[selected] = Some("page");

    html! {
        nav {
            ul {
                li {
                    a hx-get={(ctx.prefix)"/tab/service"} aria-current=[aria_current[0]] role="tab" aria-controls="tab-content" {
                        "Service"
                    }
                }
                li {
                    a hx-get={(ctx.prefix)"/tab/user"} aria-current=[aria_current[1]] role="tab" aria-controls="tab-content" {
                        "User"
                    }
                }
            }
        }
    }
}

struct HtmlCtx {
    client: Option<authly_client::Client>,
    peer_service_entity: Option<ServiceId>,
    access_token: Option<Arc<authly_client::AccessToken>>,
    prefix: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<Ctx> for HtmlCtx {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, ctx: &Ctx) -> Result<Self, Self::Rejection> {
        let client = ctx.client.clone();

        let peer_service_entity = parts
            .extensions
            .get::<PeerServiceEntity>()
            .map(|peer_service| peer_service.0);

        let opt_authorization = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .ok();

        let access_token = match (&client, opt_authorization) {
            (Some(client), Some(authorization)) => {
                Some(client.decode_access_token(authorization.token())?)
            }
            _ => None,
        };

        let prefix = parts
            .headers
            .get("x-forwarded-prefix")
            .and_then(|prefix| prefix.to_str().ok())
            .map(ToString::to_string)
            .unwrap_or_default();

        Ok(Self {
            client,
            peer_service_entity,
            access_token,
            prefix,
        })
    }
}
