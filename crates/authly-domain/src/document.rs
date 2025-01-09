use serde::Deserialize;
use toml::Spanned;
use uuid::Uuid;

use crate::{Eid, QualifiedAttributeName};

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
    pub email: Vec<Email>,

    #[serde(default, rename = "password-hash")]
    pub password_hash: Vec<PasswordHash>,

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
    pub eid: Spanned<Eid>,
    #[serde(default)]
    pub label: Option<Spanned<String>>,

    #[serde(default)]
    pub attributes: Vec<Spanned<QualifiedAttributeName>>,

    #[serde(default)]
    pub username: Option<Spanned<String>>,

    #[serde(default)]
    pub email: Vec<Spanned<String>>,

    #[serde(default, rename = "password-hash")]
    pub password_hash: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Email {
    pub entity: Spanned<String>,
    pub value: Spanned<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PasswordHash {
    pub entity: Spanned<String>,
    pub hash: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub eid: Spanned<Eid>,
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
    pub service: Option<Spanned<String>>,

    pub label: Spanned<String>,

    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub eid: Spanned<Eid>,
    pub label: Spanned<String>,

    #[serde(default)]
    pub attributes: Vec<Spanned<QualifiedAttributeName>>,

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
    pub service: Spanned<String>,

    pub label: Spanned<String>,

    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub service: Spanned<String>,
    pub label: Spanned<String>,

    #[serde(default)]
    pub allow: Option<Spanned<String>>,

    #[serde(default)]
    pub deny: Option<Spanned<String>>,
}

#[derive(Deserialize)]
pub struct PolicyBinding {
    pub service: Spanned<String>,
    pub attributes: Vec<Spanned<String>>,
    pub policies: Vec<Spanned<String>>,
}

impl Document {
    pub fn from_toml(toml: &str) -> anyhow::Result<Self> {
        Ok(preprocess(toml::from_str(toml)?))
    }
}

fn preprocess(mut doc: Document) -> Document {
    for user in &mut doc.user {
        let label = user
            .label
            .get_or_insert_with(|| Spanned::new(0..0, Uuid::new_v4().to_string()));

        for email in std::mem::take(&mut user.email) {
            doc.email.push(Email {
                entity: label.clone(),
                value: email,
            });
        }

        for pw_hash in std::mem::take(&mut user.password_hash) {
            doc.password_hash.push(PasswordHash {
                entity: label.clone(),
                hash: pw_hash,
            });
        }
    }

    doc
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
