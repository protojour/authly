use serde::Deserialize;
use toml::Spanned;
use uuid::Uuid;

use crate::EID;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(rename = "authly-document")]
    pub authly_document: AuthlyDocument,

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
pub struct AuthlyDocument {
    /// The ID of this document as an Authly authority
    pub id: Spanned<Uuid>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub eid: Spanned<EID>,
    #[serde(default, rename = "ref")]
    pub _ref: Option<Spanned<String>>,
    #[serde(default)]
    pub name: Option<Spanned<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub eid: Spanned<EID>,
    pub name: Spanned<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GroupMembership {
    pub group: Spanned<String>,

    pub members: Vec<Spanned<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityProperty {
    #[serde(default)]
    pub scope: Option<Spanned<String>>,

    pub name: Spanned<String>,

    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub eid: Spanned<EID>,
    pub name: Spanned<String>,

    #[serde(default)]
    pub label: Option<Spanned<String>>,

    #[serde(default)]
    pub kubernetes: ServiceK8sExt,
}

#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServiceK8sExt {
    #[serde(default, rename = "service-account")]
    pub service_account: Vec<ServiceK8sAccount>,
}

#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServiceK8sAccount {
    pub namespace: String,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProperty {
    pub scope: Spanned<String>,

    pub name: Spanned<String>,

    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub scope: Spanned<String>,
    pub name: Spanned<String>,

    #[serde(default)]
    pub allow: Option<Spanned<String>>,

    #[serde(default)]
    pub deny: Option<Spanned<String>>,
}

#[derive(Deserialize)]
pub struct PolicyBinding {
    pub scope: Spanned<String>,
    pub attributes: Vec<Spanned<String>>,
    pub policies: Vec<Spanned<String>>,
}

impl Document {
    pub fn from_toml(toml: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(toml)?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn testusers_example() {
        let toml = include_str!("../../../examples/testusers.toml");
        let document = super::Document::from_toml(toml).unwrap();

        assert_eq!(document.authly_document.id.span(), 23..61);
        // BUG: The span is off:
        assert_eq!(&toml[26..61], "83648f-e6ac-4492-87f7-43d5e5805d60\"");

        assert_eq!(document.user[0].eid.span(), 78..86);
        assert_eq!(&toml[78..86], "\"111111\"");

        assert_eq!(document.user.len(), 2);
        assert_eq!(document.group.len(), 1);
    }

    #[test]
    fn testservice_example() {
        let toml = include_str!("../../../examples/testservice.toml");
        super::Document::from_toml(toml).unwrap();
    }
}
