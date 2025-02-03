use authly_common::{
    id::{AttrId, PropId},
    service::NamespacePropertyMapping,
};
use authly_db::{param::AsParam, Db, DbResult, FromRow, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::{id::BuiltinProp, Eid};

#[derive(Debug)]
pub struct ServiceProperty {
    pub id: PropId,
    pub label: String,
    pub attributes: Vec<(AttrId, String)>,
}

pub enum ServicePropertyKind {
    Entity,
    Resource,
}

pub async fn find_service_label_by_eid(deps: &impl Db, eid: Eid) -> DbResult<Option<String>> {
    struct SvcLabel(String);

    impl FromRow for SvcLabel {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_text("label"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcLabel>(
            "SELECT label FROM obj_label WHERE obj_id = $1".into(),
            params!(eid.as_param()),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup service label");
            err
        })?
        .map(|label| label.0))
}

pub async fn find_service_eid_by_k8s_service_account_name(
    deps: &impl Db,
    namespace: &str,
    account_name: &str,
) -> DbResult<Option<Eid>> {
    struct SvcEid(Eid);

    impl FromRow for SvcEid {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_id("obj_id"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcEid>(
            "SELECT obj_id FROM obj_text_attr WHERE prop_id = $1 AND value = $2".into(),
            params!(
                PropId::from(BuiltinProp::K8sServiceAccount).as_param(),
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

pub async fn get_service_property_mapping(
    deps: &impl Db,
    svc_eid: Eid,
    property_kind: ServicePropertyKind,
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

    let rows: Vec<TypedRow> = match property_kind {
        ServicePropertyKind::Entity => {
            deps.query_map(
                indoc! {
                    "
                    SELECT nslab.label ns, p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM ns_ent_prop p
                    JOIN ns_ent_attrlabel a ON a.prop_id = p.id
                    JOIN svc_namespace ON svc_namespace.ns_id = p.ns_id
                    JOIN obj_label nslab ON nslab.obj_id = p.ns_id
                    WHERE svc_namespace.svc_eid = $1
                    ",
                }
                .into(),
                params!(svc_eid.as_param()),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_map(
                indoc! {
                    "
                    SELECT nslab.label ns, p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM ns_res_prop p
                    JOIN ns_res_attrlabel a ON a.prop_id = p.id
                    JOIN svc_namespace ON svc_namespace.ns_id = p.ns_id
                    JOIN obj_label nslab ON nslab.obj_id = p.ns_id
                    WHERE svc_namespace.svc_eid = $1
                    ",
                }
                .into(),
                params!(svc_eid.as_param()),
            )
            .await?
        }
    };

    let mut mapping = NamespacePropertyMapping::default();

    for TypedRow(ns, plabel, alabel, obj_id) in rows {
        mapping
            .namespace_mut(ns)
            .property_mut(plabel)
            .put(alabel, obj_id);
    }

    Ok(mapping)
}
