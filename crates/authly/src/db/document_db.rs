use hiqlite::{params, Param, Params};

use crate::{compiler::compiled_document::CompiledDocument, AuthlyCtx};

use super::Convert;

pub async fn store_document(document: CompiledDocument, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let CompiledDocument {
        authority_eid,
        data,
    } = document;

    // TODO: users and groups

    let mut stmts: Vec<(&'static str, Params)> = vec![];

    stmts.push((
        "INSERT INTO authority (eid, kind) VALUES ($1, 'document') ON CONFLICT DO NOTHING",
        params!(authority_eid.as_param()),
    ));

    for service in data.services {
        stmts.push((
            "INSERT INTO svc (authority_eid, eid, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            params!(
                authority_eid.as_param(),
                service.eid.as_ref().as_param(),
                service.name.as_ref()
            ),
        ));

        for sa in service.kubernetes.service_account {
            stmts.push((
                "INSERT INTO svc_ext_k8s_service_account (authority_eid, svc_eid, namespace, account_name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                params!(authority_eid.as_param(), service.eid.as_ref().as_param(), sa.namespace, sa.name),
            ));
        }
    }

    for eprop in data.service_entity_props {
        stmts.push((
            "INSERT INTO svc_eprop (authority_eid, id, svc_eid, name) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET name = $4",
            params!(authority_eid.as_param(), eprop.id.as_param(), eprop.svc_eid.as_param(), &eprop.name),
        ));

        for attr in eprop.attributes {
            stmts.push((
                "INSERT INTO svc_etag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                params!(attr.0.as_param(), eprop.id.as_param(), attr.1)
            ));
        }
    }

    for rprop in data.service_resource_props {
        stmts.push((
            "INSERT INTO svc_rprop (authority_eid, id, svc_eid, name) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET name = $4",
            params!(authority_eid.as_param(), rprop.id.as_param(), rprop.svc_eid.as_param(), &rprop.name),
        ));

        for attr in rprop.attributes {
            stmts.push((
                "INSERT INTO svc_rtag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                params!(attr.0.as_param(), rprop.id.as_param(), attr.1)
            ));
        }
    }

    ctx.db.txn(stmts).await?;

    Ok(())
}
