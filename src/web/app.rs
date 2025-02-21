use maud::{html, Markup, DOCTYPE};

use crate::util::{auth_extract::WebAuth, base_uri::ForwardedPrefix};

/// The "index.html" of the Authly web app
pub async fn index(ForwardedPrefix(prefix): ForwardedPrefix, _auth: WebAuth<()>) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly sign in" }
                script src={(prefix)"/web/static/vendor/htmx.min.js"} {}
                link rel="shortcut icon" href={(prefix)"/web/static/favicon.svg"} type="image/svg+xml";
                link rel="stylesheet" href={(prefix)"/web/static/vendor/pico.classless.min.css"};
                link rel="stylesheet" href={(prefix)"/web/static/style.css"};
                link rel="stylesheet" href={(prefix)"/web/static/app.css"};
            }
            body {
                main {
                    img alt="Authly" src={(prefix)"/web/static/logo.svg"};
                }
            }
        }
    }
}
