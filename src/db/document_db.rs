use std::borrow::Cow;

use aes_gcm_siv::aead::Aead;
use authly_common::id::Eid;
use hiqlite::{params, Param, Params};
use indoc::indoc;
use itertools::Itertools;
use tracing::debug;

use crate::{
    document::compiled_document::CompiledDocument,
    encryption::{random_nonce, DecryptedDeks},
};

use super::{AsParam, Db, DbResult, Literal, Row};

pub struct DocumentDirectory {
    pub did: Eid,
    pub url: String,
    pub hash: [u8; 32],
}

pub async fn get_documents(deps: &impl Db) -> DbResult<Vec<DocumentDirectory>> {
    Ok(deps
        .query_raw(
            "SELECT did, url, hash FROM directory WHERE kind = 'document'".into(),
            params!(),
        )
        .await?
        .into_iter()
        .map(|mut row| DocumentDirectory {
            did: row.get_id("did"),
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
pub fn document_txn_statements(
    document: CompiledDocument,
    deks: &DecryptedDeks,
) -> anyhow::Result<Vec<(Cow<'static, str>, Params)>> {
    let CompiledDocument { did, meta, data } = document;
    let mut stmts: Vec<(Cow<'static, str>, Params)> = vec![];

    stmts.push((
        "INSERT INTO directory (did, kind, url, hash) VALUES ($1, 'document', $2, $3) ON CONFLICT DO UPDATE SET url = $2, hash = $3".into(),
        params!(did.as_param(), meta.url, meta.hash.to_vec()),
    ));

    // local settings
    {
        stmts.push((
            "DELETE FROM local_setting WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for (setting, value) in data.settings {
            stmts.push((
                "INSERT INTO local_setting (did, setting, value) VALUES ($1, $2, $3)".into(),
                params!(did.as_param(), setting as i64, value),
            ));
        }
    }

    // entity identifiers and text attributes
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_ident WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for ident in data.entity_ident {
            let dek = deks.get(ident.prop_id)?;

            let fingerprint = dek.fingerprint(ident.ident.as_bytes());
            let nonce = random_nonce();
            let ciph = dek.aes().encrypt(&nonce, ident.ident.as_bytes())?;

            stmts.push((
                "INSERT INTO ent_ident (did, eid, prop_id, fingerprint, nonce, ciph) VALUES ($1, $2, $3, $4, $5, $6)".into(),
                params!(
                    did.as_param(),
                    ident.eid.as_param(),
                    ident.prop_id.as_param(),
                    fingerprint.to_vec(),
                    nonce.to_vec(),
                    ciph
                ),
            ));
        }

        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_text_attr WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for text_prop in data.entity_text_attrs {
            stmts.push((
                "INSERT INTO ent_text_attr (did, eid, prop_id, value) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                params!(did.as_param(), text_prop.eid.as_param(), text_prop.prop_id.as_param(), text_prop.value),
            ));
        }
    }

    // entity relations
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_rel WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for rel in data.entity_relations {
            stmts.push((
                "INSERT INTO ent_rel (did, subject_eid, rel_id, object_eid) VALUES ($1, $2, $3, $4)"
                    .into(),
                params!(
                    did.as_param(),
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
            "DELETE FROM ent_attr WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for assignment in data.entity_attribute_assignments {
            stmts.push((
                "INSERT INTO ent_attr (did, eid, attrid) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING".into(),
                params!(did.as_param(), assignment.eid.as_param(), assignment.attrid.as_param()),
            ));
        }
    }

    // service entity props
    {
        stmts.push(gc(
            "svc_ent_prop",
            NotIn("id", data.svc_ent_props.iter().map(|s| s.id)),
            did,
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
            did,
        ));

        for eprop in data.svc_ent_props {
            stmts.push((
                "INSERT INTO svc_ent_prop (did, id, svc_eid, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET label = $4".into(),
                params!(did.as_param(), eprop.id.as_param(), eprop.svc_eid.as_param(), &eprop.label),
            ));

            for attr in eprop.attributes {
                stmts.push((
                    "INSERT INTO svc_ent_attrlabel (did, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(did.as_param(), attr.id.as_param(), eprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service resource props
    {
        stmts.push(gc(
            "svc_res_prop",
            NotIn("id", data.svc_res_props.iter().map(|p| p.id)),
            did,
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
            did,
        ));

        for rprop in data.svc_res_props {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO svc_res_prop (did, id, svc_eid, label)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO UPDATE SET label = $4
                    "
                }
                .into(),
                params!(
                    did.as_param(),
                    rprop.id.as_param(),
                    rprop.svc_eid.as_param(),
                    &rprop.label
                ),
            ));

            for attr in rprop.attributes {
                stmts.push((
                    "INSERT INTO svc_res_attrlabel (did, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(did.as_param(), attr.id.as_param(), rprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service policies
    {
        stmts.push(gc(
            "svc_policy",
            NotIn("id", data.svc_policies.iter().map(|p| p.id)),
            did,
        ));

        for policy in data.svc_policies {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO svc_policy (did, id, svc_eid, label, policy_pc)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT DO UPDATE SET label = $4, policy_pc = $5
                    "
                }
                .into(),
                params!(
                    did.as_param(),
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
            "DELETE FROM svc_policy_binding WHERE did = $1".into(),
            params!(did.as_param()),
        ));

        for policy_binding in data.svc_policy_bindings {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO svc_policy_binding (did, svc_eid, attr_matcher_pc, policy_ids_pc)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO NOTHING
                    "
                }
                .into(),
                params!(
                    did.as_param(),
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

    Ok(stmts)
}

struct NotIn<'a, I>(&'a str, I);

fn gc(
    table: &str,
    NotIn(id, keep): NotIn<impl Iterator<Item = impl Literal>>,
    did: Eid,
) -> (Cow<'static, str>, Vec<Param>) {
    (
        format!(
            "DELETE FROM {table} WHERE did = $1 AND {id} NOT IN ({})",
            keep.map(|value| value.literal()).format(", ")
        )
        .into(),
        params!(did.as_param()),
    )
}
