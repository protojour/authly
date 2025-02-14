use std::{borrow::Cow, ops::Range};

use aes_gcm_siv::aead::Aead;
use authly_common::id::{AnyId, AttrId, DirectoryId, PolicyBindingId, PolicyId, PropId, ServiceId};
use authly_db::{literal::Literal, param::AsParam, Db, DbError, DbResult, FromRow, Row};
use hiqlite::{params, Param, Params};
use indoc::indoc;
use itertools::Itertools;
use serde_spanned::Spanned;

use crate::{
    document::{
        compiled_document::{
            CompiledDocument, CompiledEntityAttributeAssignment, CompiledEntityRelation,
            CompiledService, DocumentMeta, EntityIdent, ObjectLabel, ObjectTextAttr,
        },
        error::DocError,
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
    Transaction(Vec<Spanned<DocError>>),

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
    spans: Vec<Range<usize>>,
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
                    let span = self.spans.swap_remove(index);

                    let doc_error = txn_error_to_doc_error(stmt, err);

                    errors.push(Spanned::new(span, doc_error));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(DocumentDbTxnError::Transaction(errors))
        }
    }

    fn push(&mut self, stmt: Stmt, span: Range<usize>) {
        self.stmts.push(stmt);
        self.spans.push(span);
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

const NO_SPAN: Range<usize> = 0..0;

fn mk_document_transaction(document: CompiledDocument) -> DocumentTransaction {
    let CompiledDocument { dir_id, meta, data } = document;
    let mut txn = DocumentTransaction {
        dir_id,
        stmts: vec![],
        spans: vec![],
    };

    txn.push(Stmt::DirectoryWrite(meta), NO_SPAN);

    // local settings
    {
        txn.push(Stmt::LocalSettingGc, NO_SPAN);

        for (setting, value) in data.settings {
            txn.push(Stmt::LocalSettingWrite { setting, value }, NO_SPAN);
        }
    }

    // entity identifiers and text attributes
    {
        txn.push(Stmt::EntIdentGc, NO_SPAN);

        for (ident, span) in data.entity_ident {
            txn.push(Stmt::EntIdentWrite(ident), span);
        }

        txn.push(Stmt::ObjTextAttrGc, NO_SPAN);

        for (text_attr, span) in data.obj_text_attrs {
            txn.push(Stmt::ObjTextAttrWrite(text_attr), span);
        }

        txn.push(
            Stmt::ObjLabelGc(
                data.obj_labels
                    .iter()
                    .map(|(label, _)| label.obj_id)
                    .collect(),
            ),
            NO_SPAN,
        );

        for (label, span) in data.obj_labels {
            txn.push(Stmt::ObjLabelWrite(label), span);
        }
    }

    // entity relations
    {
        txn.push(Stmt::EntRelGc, NO_SPAN);

        for rel in data.entity_relations {
            txn.push(Stmt::EntRelWrite(rel), NO_SPAN);
        }
    }

    // service - namespace/domain
    {
        let service_ids: Vec<_> = data.services.keys().copied().collect();

        txn.push(Stmt::ServiceGc(service_ids.clone()), NO_SPAN);

        for (id, service) in data.services {
            txn.push(Stmt::ServiceWrite(id, service), NO_SPAN);
        }

        txn.push(Stmt::ServiceNamespaceGc, NO_SPAN);

        for svc_id in service_ids {
            // the service is in its own namespace
            txn.push(
                Stmt::ServiceNamespaceWrite(svc_id, svc_id.upcast()),
                NO_SPAN,
            );
        }

        for (svc_id, domain_id) in data.service_domains {
            txn.push(
                Stmt::ServiceNamespaceWrite(svc_id, domain_id.upcast()),
                NO_SPAN,
            );
        }
    }

    // entity attribute assignment
    {
        // not sure how to "GC" this?
        txn.push(Stmt::EntAttrGc, NO_SPAN);

        for assignment in data.entity_attribute_assignments {
            txn.push(Stmt::EntAttrWrite(assignment), NO_SPAN);
        }
    }

    // namespaced entity props
    {
        txn.push(
            Stmt::NsEntPropGc(data.domain_ent_props.iter().map(|s| s.id).collect()),
            NO_SPAN,
        );
        txn.push(
            Stmt::NsEntAttrLabelGc(
                data.domain_ent_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id)
                    .collect(),
            ),
            NO_SPAN,
        );

        for eprop in data.domain_ent_props {
            txn.push(
                Stmt::NsEntPropWrite {
                    id: eprop.id,
                    ns_id: eprop.ns_id,
                    label: eprop.label,
                },
                NO_SPAN,
            );

            for attr in eprop.attributes {
                txn.push(
                    Stmt::NsEntAttrLabelWrite {
                        id: attr.id,
                        prop_id: eprop.id,
                        label: attr.label,
                    },
                    NO_SPAN,
                );
            }
        }
    }

    // namespace resource props
    {
        txn.push(
            Stmt::NsResPropGc(data.domain_res_props.iter().map(|p| p.id).collect()),
            NO_SPAN,
        );
        txn.push(
            Stmt::NsResAttrLabelGc(
                data.domain_res_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id)
                    .collect(),
            ),
            NO_SPAN,
        );

        for rprop in data.domain_res_props {
            txn.push(
                Stmt::NsResPropWrite {
                    id: rprop.id,
                    ns_id: rprop.ns_id,
                    label: rprop.label,
                },
                NO_SPAN,
            );

            for attr in rprop.attributes {
                txn.push(
                    Stmt::NsResAttrLabelWrite {
                        id: attr.id,
                        prop_id: rprop.id,
                        label: attr.label,
                    },
                    NO_SPAN,
                );
            }
        }
    }

    // service policies
    {
        txn.push(
            Stmt::PolicyGc(data.policies.iter().map(|p| *p.id()).collect()),
            NO_SPAN,
        );

        for Identified(id, policy) in data.policies {
            txn.push(
                Stmt::PolicyWrite {
                    id,
                    label: policy.label,
                    policy_pc: postcard::to_allocvec(&policy.policy).unwrap(),
                },
                NO_SPAN,
            );
        }
    }

    // service policy bindings
    {
        txn.push(Stmt::PolBindAttrMatchGc, NO_SPAN);
        txn.push(Stmt::PolBindPolicyGc, NO_SPAN);

        for Identified(id, data) in data.policy_bindings {
            for attr_id in data.attr_matcher {
                txn.push(Stmt::PolBindAttrMatchWrite(id, attr_id), NO_SPAN);
            }
            for policy_id in data.policies {
                txn.push(Stmt::PolBindPolicyWrite(id, policy_id), NO_SPAN);
            }
        }
    }

    txn
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

fn txn_error_to_doc_error(_stmt: Stmt, db_error: DbError) -> DocError {
    match db_error {
        DbError::Hiqlite(hiqlite::Error::Sqlite(_)) => DocError::ConstraintViolation,
        DbError::Rusqlite(_) => DocError::ConstraintViolation,
        err => DocError::Db(format!("{err:?}")),
    }
}
