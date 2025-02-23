//! directory-oriented queries

use std::collections::HashMap;

use authly_common::id::{AnyId, AttrId, DirectoryId, PolicyId, PropId};
use authly_db::{param::ToBlob, params, Db, DbResult, FromRow, Row, TryFromRow};
use authly_domain::directory::DirKey;
use indoc::indoc;
use serde::{de::value::StringDeserializer, Deserialize};

use crate::directory::DirectoryKind;

use super::{
    policy_db::DbPolicy,
    service_db::{NamespaceProperty, PropertyKind},
};

pub struct DbDirectory {
    pub key: DirKey,
    pub id: DirectoryId,
    pub kind: DirectoryKind,
    pub url: String,
    pub hash: [u8; 32],
    pub label: Option<String>,
}

impl FromRow for DbDirectory {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            key: DirKey(row.get_int("key")),
            id: row.get_id("id"),
            kind: DirectoryKind::deserialize(StringDeserializer::<serde_json::Error>::new(
                row.get_text("kind"),
            ))
            .unwrap(),
            url: row.get_text("url"),
            hash: row.get_blob_array("hash"),
            label: row.get_opt_text("label"),
        }
    }
}

impl DbDirectory {
    pub async fn query_by_kind(deps: &impl Db, kind: DirectoryKind) -> DbResult<Vec<DbDirectory>> {
        deps.query_map(
            "SELECT key, id, kind, url, hash, label FROM directory WHERE kind = $1".into(),
            params!(format!("{kind}")),
        )
        .await
    }
}

pub struct DbDirectoryNamespaceLabel {
    pub id: AnyId,
    pub label: String,
}

impl FromRow for DbDirectoryNamespaceLabel {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            id: row.get_id("id"),
            label: row.get_text("label"),
        }
    }
}

impl DbDirectoryNamespaceLabel {
    pub async fn query(deps: &impl Db, dir_key: DirKey) -> DbResult<Vec<Self>> {
        deps.query_map(
            // FIXME: unindexed query
            "SELECT id, label FROM namespace WHERE dir_key = $1".into(),
            params!(dir_key.0),
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
    pub async fn query(deps: &impl Db, dir_key: DirKey) -> DbResult<Vec<Self>> {
        deps.query_filter_map(
            "SELECT id, label, policy_pc FROM policy WHERE dir_key = $1".into(),
            params!(dir_key.0),
        )
        .await
    }
}

pub async fn list_namespace_properties(
    deps: &impl Db,
    dir_key: DirKey,
    ns_id: AnyId,
) -> DbResult<Vec<NamespaceProperty>> {
    struct Output((PropId, PropertyKind, String), (AttrId, String));

    impl FromRow for Output {
        fn from_row(row: &mut impl Row) -> Self {
            Self(
                (
                    row.get_id("pid"),
                    PropertyKind::deserialize(StringDeserializer::<serde_json::Error>::new(
                        row.get_text("pkind"),
                    ))
                    .unwrap(),
                    row.get_text("plabel"),
                ),
                (row.get_id("attrid"), row.get_text("alabel")),
            )
        }
    }

    let outputs = deps
        .query_map::<Output>(
            indoc! {
                "
                SELECT p.id pid, p.kind pkind, p.label plabel, a.id attrid, a.label alabel
                FROM prop p
                JOIN attr a ON a.prop_key = p.key
                WHERE p.dir_key = $1 AND p.ns_key = (SELECT key FROM namespace WHERE id = $2)
                "
            }
            .into(),
            params!(dir_key.0, ns_id.to_blob()),
        )
        .await?;

    let mut properties: HashMap<PropId, NamespaceProperty> = Default::default();

    for Output((prop_id, kind, plabel), (attr_id, alabel)) in outputs {
        let property = properties
            .entry(prop_id)
            .or_insert_with(|| NamespaceProperty {
                id: prop_id,
                kind,
                label: plabel,
                attributes: vec![],
            });

        property.attributes.push((attr_id, alabel));
    }

    Ok(properties.into_values().collect())
}
