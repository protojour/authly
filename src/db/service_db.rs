use std::fmt::Display;

use authly_common::{
    id::{AnyId, AttrId, PropId, ServiceId},
    service::NamespacePropertyMapping,
};
use authly_db::{param::AsParam, Db, DbResult, FromRow, Row, TryFromRow};
use hiqlite::{params, Param};
use indoc::{formatdoc, indoc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::id::BuiltinProp;

use super::init_db::Builtins;

#[derive(Debug)]
pub struct NamespaceProperty {
    pub id: PropId,
    pub kind: PropertyKind,
    pub label: String,
    pub attributes: Vec<(AttrId, String)>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyKind {
    #[serde(rename = "ent")]
    Entity,
    #[serde(rename = "res")]
    Resource,
}

impl Display for PropertyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.serialize(f)
    }
}

pub async fn find_service_label_by_eid(deps: &impl Db, eid: ServiceId) -> DbResult<Option<String>> {
    struct SvcLabel(String);

    impl FromRow for SvcLabel {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_text("label"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcLabel>(
            "SELECT label FROM namespace WHERE id = $1".into(),
            params!(eid.as_param()),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup service label");
            err
        })?
        .map(|label| label.0))
}

pub async fn find_service_eid_by_k8s_local_service_account_name(
    deps: &impl Db,
    namespace: &str,
    account_name: &str,
    builtins: &Builtins,
) -> DbResult<Option<ServiceId>> {
    struct SvcEid(ServiceId);

    impl FromRow for SvcEid {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_id("obj_id"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcEid>(
            "SELECT obj_id FROM obj_text_attr WHERE prop_key = $1 AND value = $2".into(),
            params!(
                builtins.prop_key(BuiltinProp::K8sLocalServiceAccount),
                format!("{namespace}/{account_name}")
            ),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup entity");
            err
        })?
        .map(|eid| eid.0))
}

pub async fn get_svc_local_k8s_account_name(
    deps: &impl Db,
    svc_eid: ServiceId,
    builtins: &Builtins,
) -> DbResult<Option<(String, String)>> {
    struct SvcK8sAccount(String);

    impl FromRow for SvcK8sAccount {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_text("value"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcK8sAccount>(
            "SELECT value FROM obj_text_attr WHERE obj_id = $1 AND prop_key = $2".into(),
            params!(
                svc_eid.as_param(),
                builtins.prop_key(BuiltinProp::K8sLocalServiceAccount)
            ),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup entity");
            err
        })?
        .and_then(|accout| {
            let (namespace, account) = accout.0.split_once('/')?;
            Some((namespace.to_string(), account.to_string()))
        }))
}

pub async fn get_service_property_mapping(
    deps: &impl Db,
    svc_eid: ServiceId,
    property_kind: PropertyKind,
) -> DbResult<NamespacePropertyMapping> {
    struct TypedRow(String, String, String, AttrId);

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl Row) -> Self {
            Self(
                row.get_text("ns"),
                row.get_text("plabel"),
                row.get_text("alabel"),
                row.get_id("attrid"),
            )
        }
    }

    let rows: Vec<TypedRow> = deps
        .query_map(
            indoc! {
                "
                SELECT ns.label ns, p.id pid, p.label plabel, a.id attrid, a.label alabel
                FROM prop p
                JOIN attr a ON a.prop_key = p.key
                JOIN svc_namespace ON svc_namespace.ns_key = p.ns_key
                JOIN namespace ns ON ns.key = svc_namespace.ns_key
                WHERE svc_namespace.svc_eid = $1 AND p.kind = $2
                "
            }
            .into(),
            params!(svc_eid.as_param(), format!("{property_kind}")),
        )
        .await?;

    let mut mapping = NamespacePropertyMapping::default();

    for TypedRow(ns, plabel, alabel, obj_id) in rows {
        mapping
            .namespace_mut(ns)
            .property_mut(plabel)
            .put(alabel, obj_id);
    }

    Ok(mapping)
}

pub struct SvcNamespaceWithMetadata {
    pub id: AnyId,
    pub label: String,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

impl TryFromRow for SvcNamespaceWithMetadata {
    type Error = anyhow::Error;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.get_id("id"),
            label: row.get_text("label"),
            metadata: match row.get_opt_text("metadata") {
                Some(metadata) => serde_json::from_str(&metadata)?,
                None => None,
            },
        })
    }
}

pub async fn list_service_namespace_with_metadata(
    deps: &impl Db,
    svc_eid: ServiceId,
    builtins: &Builtins,
) -> DbResult<Vec<SvcNamespaceWithMetadata>> {
    deps.query_filter_map(
        formatdoc! {
            "
            SELECT
                namespace.id id,
                namespace.label label,
                obj_text_attr.value metadata
            FROM namespace
            JOIN svc_namespace ON svc_namespace.ns_key = namespace.key
            LEFT JOIN obj_text_attr
                ON obj_text_attr.obj_id = namespace.id
                AND obj_text_attr.prop_key = {metadata}
            WHERE svc_namespace.svc_eid = $1
            ",
            metadata = builtins.prop_key(BuiltinProp::Metadata)
        }
        .into(),
        params!(svc_eid.as_param()),
    )
    .await
}

pub async fn list_service_hosts(deps: &impl Db, svc_eid: ServiceId) -> DbResult<Vec<String>> {
    struct TypedRow {
        hosts_json: String,
    }

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl Row) -> Self {
            Self {
                hosts_json: row.get_text("hosts_json"),
            }
        }
    }

    let Some(row) = deps
        .query_map_opt::<TypedRow>(
            "SELECT hosts_json FROM svc WHERE svc_eid = $1".into(),
            params!(svc_eid.as_param()),
        )
        .await?
    else {
        return Ok(vec![]);
    };

    Ok(serde_json::from_str(&row.hosts_json).unwrap_or_default())
}
