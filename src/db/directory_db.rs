//! directory-oriented queries

use std::collections::HashMap;

use authly_common::id::{AnyId, AttrId, DirectoryId, PolicyId, PropId};
use authly_db::{param::AsParam, Db, DbResult, FromRow, Row, TryFromRow};
use hiqlite::{params, Param};
use indoc::indoc;

use super::{
    policy_db::DbPolicy,
    service_db::{ServiceProperty, ServicePropertyKind},
};

pub struct DbDirectoryObjectLabel {
    pub id: AnyId,
    pub label: String,
}

impl FromRow for DbDirectoryObjectLabel {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            id: row.get_id("obj_id"),
            label: row.get_text("label"),
        }
    }
}

impl DbDirectoryObjectLabel {
    pub async fn query(deps: &impl Db, dir_id: DirectoryId) -> DbResult<Vec<Self>> {
        deps.query_map(
            // FIXME: unindexed query
            "SELECT obj_id, label FROM obj_label WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        )
        .await
    }
}

pub struct DbDirectoryPolicy {
    pub id: PolicyId,
    pub policy: DbPolicy,
}

impl TryFromRow for DbDirectoryPolicy {
    type Error = postcard::Error;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.get_id("id"),
            policy: DbPolicy {
                label: row.get_text("label"),
                policy: postcard::from_bytes(&row.get_blob("policy_pc"))?,
            },
        })
    }
}

impl DbDirectoryPolicy {
    pub async fn query(deps: &impl Db, dir_id: DirectoryId) -> DbResult<Vec<Self>> {
        deps.query_filter_map(
            "SELECT id, label, policy_pc FROM policy WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        )
        .await
    }
}

pub async fn list_namespace_properties(
    deps: &impl Db,
    dir_id: DirectoryId,
    ns_id: AnyId,
    property_kind: ServicePropertyKind,
) -> DbResult<Vec<ServiceProperty>> {
    struct Output((PropId, String), (AttrId, String));

    impl FromRow for Output {
        fn from_row(row: &mut impl Row) -> Self {
            Self(
                (row.get_id("pid"), row.get_text("plabel")),
                (row.get_id("attrid"), row.get_text("alabel")),
            )
        }
    }

    let outputs = match property_kind {
        ServicePropertyKind::Entity => {
            deps.query_map::<Output>(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM ns_ent_prop p
                    JOIN ns_ent_attrlabel a ON a.prop_id = p.id
                    WHERE p.dir_id = $1 AND p.ns_id = $2
                    ",
                }
                .into(),
                params!(dir_id.as_param(), ns_id.as_param()),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_map::<Output>(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM ns_res_prop p
                    JOIN ns_res_attrlabel a ON a.prop_id = p.id
                    WHERE p.dir_id = $1 AND p.ns_id = $2
                    ",
                }
                .into(),
                params!(dir_id.as_param(), ns_id.as_param()),
            )
            .await?
        }
    };

    let mut properties: HashMap<PropId, ServiceProperty> = Default::default();

    for Output((prop_id, plabel), (attr_id, alabel)) in outputs {
        let property = properties
            .entry(prop_id)
            .or_insert_with(|| ServiceProperty {
                id: prop_id,
                label: plabel,
                attributes: vec![],
            });

        property.attributes.push((attr_id, alabel));
    }

    Ok(properties.into_values().collect())
}
