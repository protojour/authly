use std::borrow::Cow;

use authly_domain::EID;
use hiqlite::{params, Param, Params};
use itertools::Itertools;
use tracing::debug;

use crate::{document::compiled_document::CompiledDocument, AuthlyCtx};

use super::{Convert, Literal};

pub async fn store_document(document: CompiledDocument, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let CompiledDocument { aid, data } = document;

    // TODO: users and groups

    let mut stmts: Vec<(Cow<'static, str>, Params)> = vec![];

    stmts.push((
        "INSERT INTO authority (aid, kind) VALUES ($1, 'document') ON CONFLICT DO NOTHING".into(),
        params!(aid.as_param()),
    ));

    // entity
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_ident WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for id in data.entity_ident {
            stmts.push((
                "INSERT INTO ent_ident (aid, eid, kind, ident) VALUES ($1, $2, $3, $4)".into(),
                params!(aid.as_param(), id.eid.as_param(), id.kind, id.ident),
            ));
        }

        stmts.push(gc(
            "ent_password",
            NotIn(
                "hash",
                data.entity_password.iter().map(|pw| pw.hash.as_str()),
            ),
            aid,
        ));

        for pw in data.entity_password {
            stmts.push((
                "INSERT INTO ent_password (aid, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING".into(),
                params!(aid.as_param(), pw.eid.as_param(), pw.hash),
            ));
        }
    }

    // service
    {
        stmts.push(gc(
            "svc",
            NotIn("eid", data.services.iter().map(|s| *s.eid.as_ref())),
            aid,
        ));
        stmts.push(gc(
            "svc_ext_k8s_service_account",
            NotIn("svc_eid", data.services.iter().map(|s| *s.eid.as_ref())),
            aid,
        ));

        for service in data.services {
            stmts.push((
                "INSERT INTO svc (aid, eid, label) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET label = $3"
                    .into(),
                params!(
                    aid.as_param(),
                    service.eid.as_ref().as_param(),
                    service.label.as_ref()
                ),
            ));

            for sa in service.kubernetes.service_account {
                stmts.push((
                    "INSERT INTO svc_ext_k8s_service_account (aid, svc_eid, namespace, account_name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(aid.as_param(), service.eid.as_ref().as_param(), sa.namespace, sa.name),
                ));
            }
        }
    }

    // service attribute assignment
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_attr WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for assignment in data.entity_attribute_assignments {
            stmts.push((
                "INSERT INTO ent_attr (aid, eid, attrid) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING".into(),
                params!(aid.as_param(), assignment.eid.as_param(), assignment.attrid.as_param()),
            ));
        }
    }

    // service entity props
    {
        stmts.push(gc(
            "svc_ent_prop",
            NotIn("id", data.svc_ent_props.iter().map(|s| s.id)),
            aid,
        ));
        stmts.push(gc(
            "svc_ent_attrlabel",
            NotIn(
                "id",
                data.svc_ent_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id),
            ),
            aid,
        ));

        for eprop in data.svc_ent_props {
            stmts.push((
                "INSERT INTO svc_ent_prop (aid, id, svc_eid, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET label = $4".into(),
                params!(aid.as_param(), eprop.id.as_param(), eprop.svc_eid.as_param(), &eprop.label),
            ));

            for attr in eprop.attributes {
                stmts.push((
                    "INSERT INTO svc_ent_attrlabel (aid, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(aid.as_param(), attr.id.as_param(), eprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service resource props
    {
        stmts.push(gc(
            "svc_res_prop",
            NotIn("id", data.svc_res_props.iter().map(|p| p.id)),
            aid,
        ));
        stmts.push(gc(
            "svc_res_attrlabel",
            NotIn(
                "id",
                data.svc_res_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id),
            ),
            aid,
        ));

        for rprop in data.svc_res_props {
            stmts.push((
                "INSERT INTO svc_res_prop (aid, id, svc_eid, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET label = $4".into(),
                params!(aid.as_param(), rprop.id.as_param(), rprop.svc_eid.as_param(), &rprop.label),
            ));

            for attr in rprop.attributes {
                stmts.push((
                    "INSERT INTO svc_res_attrlabel (aid, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(aid.as_param(), attr.id.as_param(), rprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    for (stmt, _) in &stmts {
        debug!("{stmt}");
    }

    ctx.db.txn(stmts).await?;

    Ok(())
}

struct NotIn<'a, I>(&'a str, I);

fn gc<'a>(
    table: &str,
    NotIn(id, keep): NotIn<impl Iterator<Item = impl Literal>>,
    aid: EID,
) -> (Cow<'static, str>, Vec<Param>) {
    (
        format!(
            "DELETE FROM {table} WHERE aid = $1 AND {id} NOT IN ({})",
            keep.map(|value| value.literal()).format(", ")
        )
        .into(),
        params!(aid.as_param()),
    )
}
