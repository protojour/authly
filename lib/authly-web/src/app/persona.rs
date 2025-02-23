use authly_domain::extract::{auth::WebAuth, base_uri::ForwardedPrefix};
use maud::{html, Markup};

use crate::app::tabs::{render_nav_tab_list, Tab};

use super::AppError;

pub async fn persona(
    ForwardedPrefix(prefix): ForwardedPrefix,
    auth: WebAuth<()>,
) -> Result<Markup, AppError> {
    let eid = auth.claims.authly.entity_id;

    Ok(html! {
        (render_nav_tab_list(Tab::Persona, &prefix))

        div id="tab-content" role="tabpanel" class="tab-content" {
            "entity ID: " code { (eid) }
        }
    })
}
