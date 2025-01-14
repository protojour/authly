use std::borrow::Cow;

use authly_common::id::Eid;
use hiqlite::{params, Param, Params};
use indoc::indoc;
use itertools::Itertools;
use tracing::debug;

use crate::document::compiled_document::CompiledDocument;

use super::{Convert, Db, DbResult, Literal, Row};

pub struct DocumentAuthority {
    pub aid: Eid,
    pub url: String,
    pub hash: [u8; 32],
}

pub async fn get_documents(deps: &impl Db) -> DbResult<Vec<DocumentAuthority>> {
    Ok(deps
        .query_raw(
            "SELECT aid, url, hash FROM authority WHERE kind = 'document'".into(),
            params!(),
        )
        .await?
        .into_iter()
        .map(|mut row| DocumentAuthority {
            aid: Eid::from_row(&mut row, "aid"),
            url: row.get_text("url"),
            hash: {
                row.get_blob("hash")
                    .try_into()
                    .expect("invalid hash length")
            },
        })
        .collect())
}

/// Produce the transaction statements for saving a new document
pub fn document_txn_statements(document: CompiledDocument) -> Vec<(Cow<'static, str>, Params)> {
    let CompiledDocument { aid, meta, data } = document;
    let mut stmts: Vec<(Cow<'static, str>, Params)> = vec![];

    stmts.push((
        "INSERT INTO authority (aid, kind, url, hash) VALUES ($1, 'document', $2, $3) ON CONFLICT DO UPDATE SET url = $2, hash = $3".into(),
        params!(aid.as_param(), meta.url, meta.hash.to_vec()),
    ));

    // entity identifiers and text attributes
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_ident WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for ident in data.entity_ident {
            stmts.push((
                "INSERT INTO ent_ident (aid, eid, prop_id, ident) VALUES ($1, $2, $3, $4)".into(),
                params!(
                    aid.as_param(),
                    ident.eid.as_param(),
                    ident.prop_id.as_param(),
                    ident.ident
                ),
            ));
        }

        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_text_attr WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for text_prop in data.entity_text_attrs {
            stmts.push((
                "INSERT INTO ent_text_attr (aid, eid, prop_id, value) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                params!(aid.as_param(), text_prop.eid.as_param(), text_prop.prop_id.as_param(), text_prop.value),
            ));
        }
    }

    // entity relations
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_rel WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for rel in data.entity_relations {
            stmts.push((
                "INSERT INTO ent_rel (aid, subject_eid, rel_id, object_eid) VALUES ($1, $2, $3, $4)"
                    .into(),
                params!(
                    aid.as_param(),
                    rel.subject.as_param(),
                    rel.relation.as_param(),
                    rel.object.as_param()
                ),
            ));
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
                indoc! {
                    "
                    INSERT INTO svc_res_prop (aid, id, svc_eid, label)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO UPDATE SET label = $4
                    "
                }
                .into(),
                params!(
                    aid.as_param(),
                    rprop.id.as_param(),
                    rprop.svc_eid.as_param(),
                    &rprop.label
                ),
            ));

            for attr in rprop.attributes {
                stmts.push((
                    "INSERT INTO svc_res_attrlabel (aid, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(aid.as_param(), attr.id.as_param(), rprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service policies
    {
        stmts.push(gc(
            "svc_policy",
            NotIn("id", data.svc_policies.iter().map(|p| p.id)),
            aid,
        ));

        for policy in data.svc_policies {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO svc_policy (aid, id, svc_eid, label, policy_pc)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT DO UPDATE SET label = $4, policy_pc = $5
                    "
                }
                .into(),
                params!(
                    aid.as_param(),
                    policy.id.as_param(),
                    policy.svc_eid.as_param(),
                    policy.label,
                    postcard::to_allocvec(&policy.policy).unwrap()
                ),
            ));
        }
    }

    // service policy bindings
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM svc_policy_binding WHERE aid = $1".into(),
            params!(aid.as_param()),
        ));

        for policy_binding in data.svc_policy_bindings {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO svc_policy_binding (aid, svc_eid, attr_matcher_pc, policy_ids_pc)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO NOTHING
                    "
                }
                .into(),
                params!(
                    aid.as_param(),
                    policy_binding.svc_eid.as_param(),
                    postcard::to_allocvec(&policy_binding.attr_matcher).unwrap(),
                    postcard::to_allocvec(&policy_binding.policies).unwrap()
                ),
            ));
        }
    }

    for (stmt, _) in &stmts {
        debug!("{stmt}");
    }

    stmts
}

struct NotIn<'a, I>(&'a str, I);

fn gc(
    table: &str,
    NotIn(id, keep): NotIn<impl Iterator<Item = impl Literal>>,
    aid: Eid,
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
