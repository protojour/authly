use authly_common::{id::ObjId, service::NamespacePropertyMapping};
use authly_db::{literal::Literal, param::AsParam, Db, DbResult, FromRow, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::{id::BuiltinID, Eid};

#[derive(Debug)]
pub struct ServiceProperty {
    pub id: ObjId,
    pub label: String,
    pub attributes: Vec<(ObjId, String)>,
}

pub enum ServicePropertyKind {
    Entity,
    Resource,
}

pub async fn find_service_label_by_eid(deps: &impl Db, eid: Eid) -> DbResult<Option<String>> {
    struct SvcLabel(String);

    impl FromRow for SvcLabel {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_text("value"))
        }
    }

    Ok(deps
        .query_map_opt::<SvcLabel>(
            format!(
                "SELECT value FROM obj_text_attr WHERE obj_id = $1 AND prop_id = {prop_id}",
                prop_id = BuiltinID::PropLabel.to_obj_id().literal()
            )
            .into(),
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
                BuiltinID::PropK8sServiceAccount.to_obj_id().as_param(),
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
    struct TypedRow(String, String, String, ObjId);

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
                    SELECT ns.value ns, p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM dom_ent_prop p
                    JOIN dom_ent_attrlabel a ON a.prop_id = p.id
                    JOIN svc_domain ON svc_domain.dom_id = p.dom_id
                    JOIN obj_text_attr ns ON ns.obj_id = p.dom_id
                    WHERE svc_domain.svc_eid = $1 AND ns.prop_id = $2
                    ",
                }
                .into(),
                params!(
                    svc_eid.as_param(),
                    BuiltinID::PropLabel.to_obj_id().as_param()
                ),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_map(
                indoc! {
                    "
                    SELECT ns.value ns, p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM dom_res_prop p
                    JOIN dom_res_attrlabel a ON a.prop_id = p.id
                    JOIN svc_domain ON svc_domain.dom_id = p.dom_id
                    JOIN obj_text_attr ns ON ns.obj_id = p.dom_id
                    WHERE svc_domain.svc_eid = $1 AND ns.prop_id = $2
                    ",
                }
                .into(),
                params!(
                    svc_eid.as_param(),
                    BuiltinID::PropLabel.to_obj_id().as_param()
                ),
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
