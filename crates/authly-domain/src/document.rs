use serde::Deserialize;
use uuid::Uuid;

use crate::EID;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub document: DocumentMeta,

    #[serde(default)]
    pub user: Vec<User>,

    #[serde(default)]
    pub group: Vec<Group>,

    #[serde(default)]
    pub service: Vec<Service>,

    #[serde(default, rename = "group-membership")]
    pub group_membership: Vec<GroupMembership>,

    #[serde(default, rename = "entity-property")]
    pub entity_property: Vec<EntityProperty>,

    #[serde(default, rename = "resource-property")]
    pub resource_property: Vec<ResourceProperty>,

    #[serde(default)]
    pub policy: Vec<Policy>,

    #[serde(default, rename = "policy-binding")]
    pub policy_binding: Vec<PolicyBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentMeta {
    pub id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub eid: EID,
    #[serde(default, rename = "ref")]
    pub _ref: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub eid: EID,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMembership {
    pub group: String,

    pub members: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityProperty {
    #[serde(default)]
    scope: Option<String>,

    name: String,

    #[serde(default)]
    attributes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub eid: EID,
    pub name: String,

    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProperty {
    scope: String,

    name: String,

    #[serde(default)]
    attributes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    scope: String,
    name: String,

    #[serde(default)]
    allow: Option<String>,

    #[serde(default)]
    deny: Option<String>,
}

#[derive(Deserialize)]
pub struct PolicyBinding {
    scope: String,
    attributes: Vec<String>,
    policies: Vec<String>,
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

            [[group-membership]]
            group = "us"
            members = ["me", "you"]

            [[service]]
            eid = "444444"
            name = "testservice"
            label = "testservice"

            [[entity-property]]
            scope = "testservice"
            name = "role"
            attributes = ["ui:user", "ui:admin"]

            [[resource-property]]
            scope = "testservice"
            name = "name"
            attributes = ["ontology", "storage"]

            [[resource-property]]
            scope = "testservice"
            name = "ontology.action"
            attributes = [""]

            [[resource-property]]
            scope = "testservice"
            name = "name"
            attributes = ["ontology", "storage"]

            [[resource-property]]
            scope = "testservice"
            name = "ontology:action"
            attributes = ["read", "deploy", "stop"]

            [[resource-property]]
            scope = "testservice"
            name = "buckets:action"
            attributes = ["read"]

            [[resource-property]]
            scope = "testservice"
            name = "bucket:action"
            attributes = ["read", "create", "delete"]

            [[resource-property]]
            scope = "testservice"
            name = "object:action"
            attributes = ["read", "create", "delete"]

            [[policy]]
            scope = "testservice"
            name = "allow for main service"
            allow = "subject.entity == label:testservice"

            [[policy]]
            scope = "testservice"
            name = "allow for UI user"
            allow = "subject.role contains role/ui:user"

            [[policy]]
            scope = "testservice"
            name = "allow for UI admin"
            allow = "subject.role contains role/ui:admin"

            [[policy-binding]]
            scope = "testservice"
            attributes = ["ontology:action/read"]
            policies = ["allow for main service", "allow for UI user"]

            [[policy-binding]]
            scope = "testservice"
            attributes = ["ontology:action/deploy"]
            policies = ["allow for main service", "allow for UI admin"]
            "#
        };

        let manifest = toml::from_str::<super::Document>(toml).unwrap();

        assert_eq!(manifest.user.len(), 2);
        assert_eq!(manifest.group.len(), 1);
    }
}
