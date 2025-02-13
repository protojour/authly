use std::borrow::Cow;

use aes_gcm_siv::aead::Aead;
use authly_common::id::DirectoryId;
use authly_db::{literal::Literal, param::AsParam, Db, DbResult, FromRow, Row};
use hiqlite::{params, Param, Params};
use indoc::indoc;
use itertools::Itertools;
use tracing::debug;

use crate::{
    document::compiled_document::{CompiledDocument, ObjectLabel},
    encryption::{random_nonce, DecryptedDeks},
};

use super::Identified;

/// An Authly directory backed by a document
pub struct DocumentDirectory {
    pub dir_id: DirectoryId,
    pub url: String,
    pub hash: [u8; 32],
}

impl FromRow for DocumentDirectory {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            dir_id: row.get_id("dir_id"),
            url: row.get_text("url"),
            hash: row
                .get_blob("hash")
                .try_into()
                .expect("invalid hash length"),
        }
    }
}

pub async fn get_documents(deps: &impl Db) -> DbResult<Vec<DocumentDirectory>> {
    deps.query_map(
        "SELECT dir_id, url, hash FROM directory WHERE kind = 'document'".into(),
        params!(),
    )
    .await
}

/// Produce the transaction statements for saving a new document
pub fn document_txn_statements(
    document: CompiledDocument,
    deks: &DecryptedDeks,
) -> anyhow::Result<Vec<(Cow<'static, str>, Params)>> {
    let CompiledDocument { dir_id, meta, data } = document;
    let mut stmts: Vec<(Cow<'static, str>, Params)> = vec![];

    stmts.push((
        "INSERT INTO directory (dir_id, kind, url, hash) VALUES ($1, 'document', $2, $3) ON CONFLICT DO UPDATE SET url = $2, hash = $3".into(),
        params!(dir_id.as_param(), meta.url, meta.hash.to_vec()),
    ));

    // local settings
    {
        stmts.push((
            "DELETE FROM local_setting WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for (setting, value) in data.settings {
            stmts.push((
                "INSERT INTO local_setting (dir_id, setting, value) VALUES ($1, $2, $3)".into(),
                params!(dir_id.as_param(), setting as i64, value),
            ));
        }
    }

    // entity identifiers and text attributes
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_ident WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for ident in data.entity_ident {
            let dek = deks.get(ident.prop_id)?;

            let fingerprint = dek.fingerprint(ident.ident.as_bytes());
            let nonce = random_nonce();
            let ciph = dek.aes().encrypt(&nonce, ident.ident.as_bytes())?;

            stmts.push((
                "INSERT INTO ent_ident (dir_id, eid, prop_id, fingerprint, nonce, ciph) VALUES ($1, $2, $3, $4, $5, $6)".into(),
                params!(
                    dir_id.as_param(),
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
            "DELETE FROM obj_text_attr WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for text_prop in data.obj_text_attrs {
            stmts.push((
                "INSERT INTO obj_text_attr (dir_id, obj_id, prop_id, value) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                params!(dir_id.as_param(), text_prop.obj_id.as_param(), text_prop.prop_id.as_param(), text_prop.value),
            ));
        }

        stmts.push(gc(
            "obj_label",
            NotIn("obj_id", data.obj_labels.iter().map(|label| label.obj_id)),
            dir_id,
        ));

        for ObjectLabel { obj_id, label } in data.obj_labels {
            stmts.push((
                "INSERT INTO obj_label (dir_id, obj_id, label) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET label = $3".into(),
                params!(dir_id.as_param(), obj_id.as_param(), label),
            ));
        }
    }

    // entity relations
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_rel WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for rel in data.entity_relations {
            stmts.push((
                "INSERT INTO ent_rel (dir_id, subject_eid, rel_id, object_eid) VALUES ($1, $2, $3, $4)"
                    .into(),
                params!(
                    dir_id.as_param(),
                    rel.subject.as_param(),
                    rel.relation.as_param(),
                    rel.object.as_param()
                ),
            ));
        }
    }

    // service - namespace/domain
    {
        stmts.push(gc(
            "svc",
            NotIn("svc_eid", data.services.keys().copied()),
            dir_id,
        ));

        for (svc_id, svc) in data.services.iter() {
            stmts.push((
                "INSERT INTO svc (dir_id, svc_eid, hosts_json) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hosts_json = $3".into(),
                params!(dir_id.as_param(), svc_id.as_param(), serde_json::to_string(&svc.hosts).unwrap()),
            ));
        }

        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM svc_namespace WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for svc_id in data.services.keys() {
            // the service is in its own namespace
            stmts.push((
                "INSERT INTO svc_namespace (dir_id, svc_eid, ns_id) VALUES ($1, $2, $3)".into(),
                params!(dir_id.as_param(), svc_id.as_param(), svc_id.as_param()),
            ));
        }

        for (svc_id, domain_id) in data.service_domains {
            stmts.push((
                "INSERT INTO svc_namespace (dir_id, svc_eid, ns_id) VALUES ($1, $2, $3)".into(),
                params!(dir_id.as_param(), svc_id.as_param(), domain_id.as_param()),
            ));
        }
    }

    // service attribute assignment
    {
        // not sure how to "GC" this?
        stmts.push((
            "DELETE FROM ent_attr WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for assignment in data.entity_attribute_assignments {
            stmts.push((
                "INSERT INTO ent_attr (dir_id, eid, attrid) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING".into(),
                params!(dir_id.as_param(), assignment.eid.as_param(), assignment.attrid.as_param()),
            ));
        }
    }

    // namespaced entity props
    {
        stmts.push(gc(
            "ns_ent_prop",
            NotIn("id", data.domain_ent_props.iter().map(|s| s.id)),
            dir_id,
        ));
        stmts.push(gc(
            "ns_ent_attrlabel",
            NotIn(
                "id",
                data.domain_ent_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id),
            ),
            dir_id,
        ));

        for eprop in data.domain_ent_props {
            stmts.push((
                "INSERT INTO ns_ent_prop (dir_id, id, ns_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET label = $4".into(),
                params!(dir_id.as_param(), eprop.id.as_param(), eprop.ns_id.as_param(), &eprop.label),
            ));

            for attr in eprop.attributes {
                stmts.push((
                    "INSERT INTO ns_ent_attrlabel (dir_id, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(dir_id.as_param(), attr.id.as_param(), eprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service resource props
    {
        stmts.push(gc(
            "ns_res_prop",
            NotIn("id", data.domain_res_props.iter().map(|p| p.id)),
            dir_id,
        ));
        stmts.push(gc(
            "ns_res_attrlabel",
            NotIn(
                "id",
                data.domain_res_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id),
            ),
            dir_id,
        ));

        for rprop in data.domain_res_props {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO ns_res_prop (dir_id, id, ns_id, label)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO UPDATE SET label = $4
                    "
                }
                .into(),
                params!(
                    dir_id.as_param(),
                    rprop.id.as_param(),
                    rprop.ns_id.as_param(),
                    &rprop.label
                ),
            ));

            for attr in rprop.attributes {
                stmts.push((
                    "INSERT INTO ns_res_attrlabel (dir_id, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
                    params!(dir_id.as_param(), attr.id.as_param(), rprop.id.as_param(), attr.label)
                ));
            }
        }
    }

    // service policies
    {
        stmts.push(gc(
            "policy",
            NotIn("id", data.policies.iter().map(|p| *p.id())),
            dir_id,
        ));

        for Identified(id, policy) in data.policies {
            stmts.push((
                indoc! {
                    "
                    INSERT INTO policy (dir_id, id, label, policy_pc)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO UPDATE SET label = $3, policy_pc = $4
                    "
                }
                .into(),
                params!(
                    dir_id.as_param(),
                    id.as_param(),
                    policy.label,
                    postcard::to_allocvec(&policy.policy).unwrap()
                ),
            ));
        }
    }

    // service policy bindings
    {
        // not sure how to "GC" these?
        stmts.push((
            "DELETE FROM polbind_attr_match WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));
        // not sure how to "GC" these?
        stmts.push((
            "DELETE FROM polbind_policy WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        ));

        for Identified(id, data) in data.policy_bindings {
            for attr in data.attr_matcher {
                stmts.push((
                    "INSERT INTO polbind_attr_match (dir_id, polbind_id, attr_id) VALUES ($1, $2, $3)"
                        .into(),
                    params!(dir_id.as_param(), id.as_param(), attr.as_param()),
                ));
            }
            for policy_id in data.policies {
                stmts.push((
                    "INSERT INTO polbind_policy (dir_id, polbind_id, policy_id) VALUES ($1, $2, $3)"
                        .into(),
                    params!(dir_id.as_param(), id.as_param(), policy_id.as_param()),
                ));
            }
        }
    }

    for (idx, (stmt, _)) in stmts.iter().enumerate() {
        debug!("{idx} {stmt}");
    }

    Ok(stmts)
}

struct NotIn<'a, I>(&'a str, I);

fn gc(
    table: &str,
    NotIn(id, keep): NotIn<impl Iterator<Item = impl Literal>>,
    dir_id: DirectoryId,
) -> (Cow<'static, str>, Vec<Param>) {
    (
        format!(
            "DELETE FROM {table} WHERE dir_id = $1 AND {id} NOT IN ({})",
            keep.map(|value| value.literal()).format(", ")
        )
        .into(),
        params!(dir_id.as_param()),
    )
}
