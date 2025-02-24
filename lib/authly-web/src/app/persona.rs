use authly_domain::extract::auth::WebAuth;
use maud::{html, Markup};

use crate::{
    app::tabs::{render_nav_tab_list, Tab},
    Htmx,
};

use super::{render_app_tab, AppError};

pub async fn persona(htmx: Htmx, auth: WebAuth<()>) -> Result<Markup, AppError> {
    let prefix = &htmx.prefix;
    let eid = auth.claims.authly.entity_id;

    Ok(render_app_tab(
        &htmx,
        html! {
            (render_nav_tab_list(Tab::Persona, &prefix))

            div id="tab-content" role="tabpanel" class="tab-content" {
                "entity ID: " code { (eid) }
            }
        },
    ))
}
