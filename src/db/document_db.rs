use std::borrow::Cow;

use aes_gcm_siv::aead::Aead;
use authly_common::id::{AnyId, AttrId, DirectoryId, PolicyBindingId, PolicyId, PropId, ServiceId};
use authly_db::{literal::Literal, param::AsParam, Db, DbError, DbResult, FromRow, Row};
use hiqlite::{params, Param, Params};
use indoc::indoc;
use itertools::Itertools;

use crate::{
    document::compiled_document::{
        CompiledDocument, CompiledEntityAttributeAssignment, CompiledEntityRelation,
        CompiledService, DocumentMeta, EntityIdent, ObjectLabel, ObjectTextAttr,
    },
    encryption::{random_nonce, DecryptedDeks},
    settings::Setting,
};

use super::Identified;

#[derive(thiserror::Error, Debug)]
pub enum DocumentDbTxnError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("transaction error: {0:?}")]
    Transaction(Vec<(Stmt, DbError)>),

    #[error("encryption error: {0}")]
    Encryption(anyhow::Error),
}

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

pub struct DocumentTransaction {
    dir_id: DirectoryId,
    stmts: Vec<Stmt>,
}

impl DocumentTransaction {
    pub fn new(document: CompiledDocument) -> Self {
        mk_document_transaction(document)
    }

    pub async fn execute(
        mut self,
        db: &impl Db,
        deks: &DecryptedDeks,
    ) -> Result<(), DocumentDbTxnError> {
        let db_statements: Vec<_> = self
            .stmts
            .iter()
            .map(|stmt| stmt_to_db_stmt(self.dir_id, stmt, deks))
            .try_collect()?;

        let mut errors = vec![];

        for (index, result) in db
            .transact(db_statements)
            .await?
            .into_iter()
            .enumerate()
            // iterate backwards so that swap_remove can be used:
            .rev()
        {
            match result {
                Ok(_) => {}
                Err(err) => {
                    let stmt = self.stmts.swap_remove(index);

                    errors.push((stmt, err));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(DocumentDbTxnError::Transaction(errors))
        }
    }
}

/// High-level description of a Db statement
///
/// This can be extended with Span info later, to track exactly where in a document a constraint has been violated
#[derive(Debug)]
pub enum Stmt {
    DirectoryWrite(DocumentMeta),
    LocalSettingGc,
    LocalSettingWrite {
        setting: Setting,
        value: String,
    },
    EntIdentGc,
    EntIdentWrite(EntityIdent),
    ObjTextAttrGc,
    ObjTextAttrWrite(ObjectTextAttr),
    ObjLabelGc(Vec<AnyId>),
    ObjLabelWrite(ObjectLabel),
    EntRelGc,
    EntRelWrite(CompiledEntityRelation),
    ServiceGc(Vec<ServiceId>),
    ServiceWrite(ServiceId, CompiledService),
    ServiceNamespaceGc,
    ServiceNamespaceWrite(ServiceId, AnyId),
    EntAttrGc,
    EntAttrWrite(CompiledEntityAttributeAssignment),
    NsEntPropGc(Vec<PropId>),
    NsEntAttrLabelGc(Vec<AttrId>),
    NsEntPropWrite {
        id: PropId,
        ns_id: AnyId,
        label: String,
    },
    NsEntAttrLabelWrite {
        id: AttrId,
        prop_id: PropId,
        label: String,
    },
    NsResPropGc(Vec<PropId>),
    NsResAttrLabelGc(Vec<AttrId>),
    NsResPropWrite {
        id: PropId,
        ns_id: AnyId,
        label: String,
    },
    NsResAttrLabelWrite {
        id: AttrId,
        prop_id: PropId,
        label: String,
    },
    PolicyGc(Vec<PolicyId>),
    PolicyWrite {
        id: PolicyId,
        label: String,
        policy_pc: Vec<u8>,
    },
    PolBindAttrMatchGc,
    PolBindPolicyGc,
    PolBindAttrMatchWrite(PolicyBindingId, AttrId),
    PolBindPolicyWrite(PolicyBindingId, PolicyId),
}

fn mk_document_transaction(document: CompiledDocument) -> DocumentTransaction {
    let CompiledDocument { dir_id, meta, data } = document;
    let mut stmts: Vec<Stmt> = vec![];

    stmts.push(Stmt::DirectoryWrite(meta));

    // local settings
    {
        stmts.push(Stmt::LocalSettingGc);

        for (setting, value) in data.settings {
            stmts.push(Stmt::LocalSettingWrite { setting, value });
        }
    }

    // entity identifiers and text attributes
    {
        stmts.push(Stmt::EntIdentGc);

        for ident in data.entity_ident {
            stmts.push(Stmt::EntIdentWrite(ident));
        }

        stmts.push(Stmt::ObjTextAttrGc);

        for text_attr in data.obj_text_attrs {
            stmts.push(Stmt::ObjTextAttrWrite(text_attr));
        }

        stmts.push(Stmt::ObjLabelGc(
            data.obj_labels.iter().map(|label| label.obj_id).collect(),
        ));

        for label in data.obj_labels {
            stmts.push(Stmt::ObjLabelWrite(label));
        }
    }

    // entity relations
    {
        stmts.push(Stmt::EntRelGc);

        for rel in data.entity_relations {
            stmts.push(Stmt::EntRelWrite(rel));
        }
    }

    // service - namespace/domain
    {
        let service_ids: Vec<_> = data.services.keys().copied().collect();

        stmts.push(Stmt::ServiceGc(service_ids.clone()));

        for (id, service) in data.services {
            stmts.push(Stmt::ServiceWrite(id, service));
        }

        stmts.push(Stmt::ServiceNamespaceGc);

        for svc_id in service_ids {
            // the service is in its own namespace
            stmts.push(Stmt::ServiceNamespaceWrite(svc_id, svc_id.upcast()));
        }

        for (svc_id, domain_id) in data.service_domains {
            stmts.push(Stmt::ServiceNamespaceWrite(svc_id, domain_id.upcast()));
        }
    }

    // entity attribute assignment
    {
        // not sure how to "GC" this?
        stmts.push(Stmt::EntAttrGc);

        for assignment in data.entity_attribute_assignments {
            stmts.push(Stmt::EntAttrWrite(assignment));
        }
    }

    // namespaced entity props
    {
        stmts.push(Stmt::NsEntPropGc(
            data.domain_ent_props.iter().map(|s| s.id).collect(),
        ));
        stmts.push(Stmt::NsEntAttrLabelGc(
            data.domain_ent_props
                .iter()
                .flat_map(|p| p.attributes.iter())
                .map(|a| a.id)
                .collect(),
        ));

        for eprop in data.domain_ent_props {
            stmts.push(Stmt::NsEntPropWrite {
                id: eprop.id,
                ns_id: eprop.ns_id,
                label: eprop.label,
            });

            for attr in eprop.attributes {
                stmts.push(Stmt::NsEntAttrLabelWrite {
                    id: attr.id,
                    prop_id: eprop.id,
                    label: attr.label,
                });
            }
        }
    }

    // namespace resource props
    {
        stmts.push(Stmt::NsResPropGc(
            data.domain_res_props.iter().map(|p| p.id).collect(),
        ));
        stmts.push(Stmt::NsResAttrLabelGc(
            data.domain_res_props
                .iter()
                .flat_map(|p| p.attributes.iter())
                .map(|a| a.id)
                .collect(),
        ));

        for rprop in data.domain_res_props {
            stmts.push(Stmt::NsResPropWrite {
                id: rprop.id,
                ns_id: rprop.ns_id,
                label: rprop.label,
            });

            for attr in rprop.attributes {
                stmts.push(Stmt::NsResAttrLabelWrite {
                    id: attr.id,
                    prop_id: rprop.id,
                    label: attr.label,
                });
            }
        }
    }

    // service policies
    {
        stmts.push(Stmt::PolicyGc(
            data.policies.iter().map(|p| *p.id()).collect(),
        ));

        for Identified(id, policy) in data.policies {
            stmts.push(Stmt::PolicyWrite {
                id,
                label: policy.label,
                policy_pc: postcard::to_allocvec(&policy.policy).unwrap(),
            });
        }
    }

    // service policy bindings
    {
        stmts.push(Stmt::PolBindAttrMatchGc);
        stmts.push(Stmt::PolBindPolicyGc);

        for Identified(id, data) in data.policy_bindings {
            for attr_id in data.attr_matcher {
                stmts.push(Stmt::PolBindAttrMatchWrite(id, attr_id));
            }
            for policy_id in data.policies {
                stmts.push(Stmt::PolBindPolicyWrite(id, policy_id));
            }
        }
    }

    DocumentTransaction { dir_id, stmts }
}

fn stmt_to_db_stmt(
    dir_id: DirectoryId,
    stmt: &Stmt,
    deks: &DecryptedDeks,
) -> Result<(Cow<'static, str>, Params), DocumentDbTxnError> {
    let dir = dir_id.as_param();

    let output = match stmt {
        Stmt::DirectoryWrite(meta) => (
            "INSERT INTO directory (dir_id, kind, url, hash) VALUES ($1, 'document', $2, $3) ON CONFLICT DO UPDATE SET url = $2, hash = $3".into(),
            params!(dir, &meta.url, meta.hash.to_vec())
        ),
        Stmt::LocalSettingGc => (
            "DELETE FROM local_setting WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::LocalSettingWrite { setting, value } => (
            "INSERT INTO local_setting (dir_id, setting, value) VALUES ($1, $2, $3)".into(),
            params!(dir, *setting as i64, value),
        ),
        Stmt::EntIdentGc => (
            "DELETE FROM ent_ident WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::EntIdentWrite(ident) => {
            let dek = deks.get(ident.prop_id)
                .map_err(DocumentDbTxnError::Encryption)?;

            let fingerprint = dek.fingerprint(ident.ident.as_bytes());
            let nonce = random_nonce();
            let ciph = dek.aes().encrypt(&nonce, ident.ident.as_bytes())
                .map_err(|err| DocumentDbTxnError::Encryption(err.into()))?;

            (
                "INSERT INTO ent_ident (dir_id, eid, prop_id, fingerprint, nonce, ciph) VALUES ($1, $2, $3, $4, $5, $6)".into(),
                params!(
                    dir,
                    ident.eid.as_param(),
                    ident.prop_id.as_param(),
                    fingerprint.to_vec(),
                    nonce.to_vec(),
                    ciph
                ),
            )
        },
        Stmt::ObjTextAttrGc => (
            "DELETE FROM obj_text_attr WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::ObjTextAttrWrite(attr) => (
            "INSERT INTO obj_text_attr (dir_id, obj_id, prop_id, value) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
            params!(dir, attr.obj_id.as_param(), attr.prop_id.as_param(), &attr.value),
        ),
        Stmt::ObjLabelGc(ids) => {
            gc("obj_label", NotIn("obj_id", ids.iter().copied()), dir_id)
        },
        Stmt::ObjLabelWrite(ObjectLabel { obj_id, label }) => (
            "INSERT INTO obj_label (dir_id, obj_id, label) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET label = $3".into(),
            params!(dir, obj_id.as_param(), label),
        ),
        Stmt::EntRelGc => (
            "DELETE FROM ent_rel WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::EntRelWrite(rel) => (
            "INSERT INTO ent_rel (dir_id, subject_eid, rel_id, object_eid) VALUES ($1, $2, $3, $4)"
                .into(),
            params!(
                dir,
                rel.subject.as_param(),
                rel.relation.as_param(),
                rel.object.as_param()
            ),
        ),
        Stmt::ServiceGc(ids) => gc("svc", NotIn("svc_eid", ids.iter().copied()), dir_id),
        Stmt::ServiceWrite(svc_id, svc) => (
            "INSERT INTO svc (dir_id, svc_eid, hosts_json) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hosts_json = $3".into(),
            params!(dir, svc_id.as_param(), serde_json::to_string(&svc.hosts).unwrap()),
        ),
        Stmt::ServiceNamespaceGc => (
            "DELETE FROM svc_namespace WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::ServiceNamespaceWrite(svc_id, ns_id) => (
            "INSERT INTO svc_namespace (dir_id, svc_eid, ns_id) VALUES ($1, $2, $3)".into(),
            params!(dir, svc_id.as_param(), ns_id.as_param()),
        ),
        Stmt::EntAttrGc => (
            "DELETE FROM ent_attr WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::EntAttrWrite(assignment) => (
            "INSERT INTO ent_attr (dir_id, eid, attrid) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING".into(),
            params!(dir, assignment.eid.as_param(), assignment.attrid.as_param()),
        ),
        Stmt::NsEntPropGc(ids) => gc(
            "ns_ent_prop",
            NotIn("id", ids.iter().copied()),
            dir_id,
        ),
        Stmt::NsEntAttrLabelGc(ids) => gc(
            "ns_ent_attrlabel",
            NotIn(
                "id",
                ids.iter().copied()
            ),
            dir_id,
        ),
        Stmt::NsEntPropWrite { id, ns_id, label } => (
            "INSERT INTO ns_ent_prop (dir_id, id, ns_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET label = $4".into(),
            params!(dir, id.as_param(), ns_id.as_param(), label),
        ),
        Stmt::NsEntAttrLabelWrite { id, prop_id, label } => (
            "INSERT INTO ns_ent_attrlabel (dir_id, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
            params!(dir, id.as_param(), prop_id.as_param(), label)
        ),
        Stmt::NsResPropGc(ids) => gc(
            "ns_res_prop",
            NotIn("id", ids.iter().copied()),
            dir_id,
        ),
        Stmt::NsResAttrLabelGc(ids) => gc(
            "ns_res_attrlabel",
            NotIn(
                "id",
                ids.iter().copied()
            ),
            dir_id,
        ),
        Stmt::NsResPropWrite { id, ns_id, label } => (
            indoc! {
                "
                INSERT INTO ns_res_prop (dir_id, id, ns_id, label)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO UPDATE SET label = $4
                "
            }
            .into(),
            params!(dir, id.as_param(), ns_id.as_param(), label),
        ),
        Stmt::NsResAttrLabelWrite { id, prop_id, label } => (
            "INSERT INTO ns_res_attrlabel (dir_id, id, prop_id, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING".into(),
            params!(dir, id.as_param(), prop_id.as_param(), label)
        ),
        Stmt::PolicyGc(ids) => gc(
            "policy",
            NotIn("id", ids.iter().copied()),
            dir_id,
        ),
        Stmt::PolicyWrite { id, label, policy_pc } => (
            indoc! {
                "
                INSERT INTO policy (dir_id, id, label, policy_pc)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO UPDATE SET label = $3, policy_pc = $4
                "
            }
            .into(),
            params!(dir, id.as_param(), label, policy_pc.as_slice()),
        ),
        Stmt::PolBindAttrMatchGc => (
            "DELETE FROM polbind_attr_match WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::PolBindPolicyGc => (
            "DELETE FROM polbind_policy WHERE dir_id = $1".into(),
            params!(dir),
        ),
        Stmt::PolBindAttrMatchWrite(pb_id, attr_id) => (
            "INSERT INTO polbind_attr_match (dir_id, polbind_id, attr_id) VALUES ($1, $2, $3)"
            .into(),
            params!(dir, pb_id.as_param(), attr_id.as_param()),
        ),
        Stmt::PolBindPolicyWrite(pb_id, pol_id) => (
            "INSERT INTO polbind_policy (dir_id, polbind_id, policy_id) VALUES ($1, $2, $3)"
                .into(),
            params!(dir, pb_id.as_param(), pol_id.as_param()),
        ),
    };

    Ok(output)
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
