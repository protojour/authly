use serde::Deserialize;
use uuid::Uuid;

use crate::EID;

#[derive(Deserialize)]
pub struct Document {
    pub document: DocumentMeta,

    #[serde(default)]
    pub user: Vec<User>,

    #[serde(default)]
    pub group: Vec<Group>,

    #[serde(default)]
    pub service: Vec<Service>,
}

#[derive(Deserialize)]
pub struct DocumentMeta {
    pub id: Uuid,
}

#[derive(Deserialize)]
pub struct User {
    pub eid: EID,
    #[serde(default, rename = "ref")]
    pub _ref: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct Group {
    pub eid: EID,
    pub name: String,
}

#[derive(Deserialize)]
pub struct Service {
    pub eid: EID,
    pub name: String,

    /// FIXME: These should be independent objects,
    /// hierarchies should be avoided as much as possible
    #[serde(default)]
    pub entityprop: Vec<Property>,

    #[serde(default)]
    pub resourceprop: Vec<Property>,
}

#[derive(Deserialize)]
pub struct Property {
    pub name: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    #[test]
    fn test_toml() {
        let toml = indoc! {
            r#"
            [document]
            id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

            [[user]]
            eid = "111111"
            ref = "me"

            # [[user.email]]
            # ident = "me@domain.com"
            # secret = "$argon2id$v=19$m=19456,t=2,p=1$/lj8Yj6ZTJLiqgpYb4Nn0g$z79FFMXstrkY8KmpC0vQWIDcne0lylBbctUAluIVqLk"

            [[group]]
            eid = "222222"
            name = "us"

            [[user]]
            eid = "333333"
            name = "you"

            [[service]]
            eid = "444444"
            ref = "testservice"
            name = "testservice"

            [[service.entityprop]]
            name = "role"
            tags = ["ui_user", "ui_admin"]

            [[service.resourceprop]]
            name = "name"
            tags = ["ontology", "storage"]

            [[service.resourceprop]]
            name = "ontology_action"
            tags = ["read", "deploy", "stop"]

            [[service.resourceprop]]
            name = "buckets.action"
            tags = ["read"]

            [[service.resourceprop]]
            name = "bucket.action"
            tags = ["read", "create", "delete"]

            [[service.resourceprop]]
            name = "object.action"
            tags = ["read", "create", "delete"]
            "#
        };

        let manifest = toml::from_str::<super::Document>(toml).unwrap();

        assert_eq!(manifest.user.len(), 2);
        assert_eq!(manifest.group.len(), 1);
    }
}
