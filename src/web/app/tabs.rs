use maud::{html, Markup};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Persona,
}

pub fn render_nav_tab_list(tab: Tab, prefix: &str) -> Markup {
    html! {
        nav {
            ul {
                li {
                    a hx-get={(prefix)"/web/tab/persona"} aria-current=[tab.cur(Tab::Persona)] role="tab" aria-controls="tab-content" {
                        "Persona"
                    }
                }
            }
        }
    }
}

impl Tab {
    fn cur(&self, tab: Tab) -> Option<&'static str> {
        if self == &tab {
            Some("page")
        } else {
            None
        }
    }
}
