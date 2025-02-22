use std::{borrow::Cow, ops::Range};

use authly_common::id::{AnyId, AttrId, DirectoryId, PolicyId, PropId, ServiceId};
use authly_db::{literal::Literal, param::ToBlob, params, Db, DbError};
use authly_domain::encryption::DecryptedDeks;
use hiqlite::{StmtColumn, StmtIndex};
use indoc::indoc;
use itertools::Itertools;
use serde_spanned::Spanned;
use tracing::info;

use crate::{
    audit::Actor,
    document::{
        compiled_document::{
            CompiledDocument, CompiledEntityAttributeAssignment, CompiledEntityRelation,
            CompiledService, DocumentMeta, ObjectIdent, ObjectTextAttr,
        },
        error::DocError,
    },
    settings::Setting,
};

use super::{cryptography_db::EncryptedObjIdent, service_db::PropertyKind, Identified};

#[derive(thiserror::Error, Debug)]
pub enum DocumentDbTxnError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("transaction error: {0:?}")]
    Transaction(Vec<Spanned<DocError>>),

    #[error("encryption error: {0}")]
    Encryption(anyhow::Error),
}

pub struct DocumentTransaction {
    dir_id: DirectoryId,
    stmts: Vec<Stmt>,
    spans: Vec<Range<usize>>,
}

impl DocumentTransaction {
    pub fn new(document: CompiledDocument, actor: Actor) -> Self {
        mk_document_transaction(document, actor)
    }

    pub async fn execute<D: Db>(
        mut self,
        db: &D,
        deks: &DecryptedDeks,
    ) -> Result<(), DocumentDbTxnError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let db_statements: Vec<_> = self
            .stmts
            .iter()
            .map(|stmt| stmt_to_db_stmt::<D>(self.dir_id, stmt, deks, now))
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

    fn push(&mut self, stmt: Stmt, span: Range<usize>) -> usize {
        let stmt_index = self.stmts.len();
        self.stmts.push(stmt);
        self.spans.push(span);
        stmt_index
    }
}

/// High-level description of a Db statement
///
/// This can be extended with Span info later, to track exactly where in a document a constraint has been violated
#[derive(Debug)]
pub enum Stmt {
    DirectoryWrite(DocumentMeta),
    DirectoryAuditWrite(Actor),
    LocalSettingGc,
    LocalSettingWrite {
        setting: Setting,
        value: String,
    },
    ObjIdentGc,
    ObjIdentWrite(ObjectIdent),
    ObjTextAttrGc,
    ObjTextAttrWrite(ObjectTextAttr),
    EntRelGc,
    EntRelWrite(CompiledEntityRelation),
    NamespaceGc(Vec<AnyId>),
    NamespaceWrite(AnyId, String),
    ServiceGc(Vec<ServiceId>),
    ServiceWrite(ServiceId, CompiledService),
    ServiceNamespaceGc,
    ServiceNamespaceWrite(ServiceId, AnyId),
    NsPropGc(Vec<PropId>),
    NsAttrGc(Vec<AttrId>),
    NsPropWrite {
        id: PropId,
        ns_id: AnyId,
        kind: PropertyKind,
        label: String,
    },
    NsAttrWrite {
        prop_stmt: usize,
        id: AttrId,
        label: String,
    },
    EntAttrAssignmentGc,
    EntAttrAssignmentWrite(CompiledEntityAttributeAssignment),
    PolicyGc(Vec<PolicyId>),
    PolicyWrite {
        id: PolicyId,
        label: String,
        policy_pc: Vec<u8>,
    },
    PolBindGc,
    PolBindWrite,
    PolBindAttrMatchWrite(usize, AttrId),
    PolBindPolicyWrite(usize, PolicyId),
}

const NO_SPAN: Range<usize> = 0..0;

fn mk_document_transaction(document: CompiledDocument, actor: Actor) -> DocumentTransaction {
    let CompiledDocument { dir_id, meta, data } = document;
    let mut txn = DocumentTransaction {
        dir_id,
        stmts: vec![],
        spans: vec![],
    };

    txn.push(Stmt::DirectoryWrite(meta), NO_SPAN);
    txn.push(Stmt::DirectoryAuditWrite(actor), NO_SPAN);

    // local settings
    {
        txn.push(Stmt::LocalSettingGc, NO_SPAN);

        for (setting, value) in data.settings {
            txn.push(Stmt::LocalSettingWrite { setting, value }, NO_SPAN);
        }
    }

    // namespaces
    {
        let namespace_ids: Vec<_> = data.namespaces.keys().copied().collect();
        txn.push(Stmt::NamespaceGc(namespace_ids), NO_SPAN);

        for (namespace_id, (label, span)) in data.namespaces {
            txn.push(Stmt::NamespaceWrite(namespace_id, label), span);
        }
    }

    // entity identifiers and text attributes
    {
        txn.push(Stmt::ObjIdentGc, NO_SPAN);

        for (ident, span) in data.entity_ident {
            txn.push(Stmt::ObjIdentWrite(ident), span);
        }

        txn.push(Stmt::ObjTextAttrGc, NO_SPAN);

        for (text_attr, span) in data.obj_text_attrs {
            txn.push(Stmt::ObjTextAttrWrite(text_attr), span);
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

    // namespaced properties
    {
        txn.push(
            Stmt::NsPropGc(data.domain_props.iter().map(|s| s.id).collect()),
            NO_SPAN,
        );
        txn.push(
            Stmt::NsAttrGc(
                data.domain_props
                    .iter()
                    .flat_map(|p| p.attributes.iter())
                    .map(|a| a.id)
                    .collect(),
            ),
            NO_SPAN,
        );

        for prop in data.domain_props {
            let stmt_index = txn.push(
                Stmt::NsPropWrite {
                    id: prop.id,
                    kind: prop.kind,
                    ns_id: prop.ns_id,
                    label: prop.label,
                },
                NO_SPAN,
            );

            for attr in prop.attributes {
                txn.push(
                    Stmt::NsAttrWrite {
                        prop_stmt: stmt_index,
                        id: attr.id,
                        label: attr.label,
                    },
                    NO_SPAN,
                );
            }
        }
    }

    // entity attribute assignment
    {
        // not sure how to "GC" this?
        txn.push(Stmt::EntAttrAssignmentGc, NO_SPAN);

        for assignment in data.entity_attribute_assignments {
            txn.push(Stmt::EntAttrAssignmentWrite(assignment), NO_SPAN);
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
        txn.push(Stmt::PolBindGc, NO_SPAN);

        for binding in data.policy_bindings {
            let parent_stmt = txn.push(Stmt::PolBindWrite, NO_SPAN);

            for attr_id in binding.attr_matcher {
                txn.push(Stmt::PolBindAttrMatchWrite(parent_stmt, attr_id), NO_SPAN);
            }
            for policy_id in binding.policies {
                txn.push(Stmt::PolBindPolicyWrite(parent_stmt, policy_id), NO_SPAN);
            }
        }
    }

    txn
}

fn stmt_to_db_stmt<D: Db>(
    dir_id: DirectoryId,
    stmt: &Stmt,
    deks: &DecryptedDeks,
    now: i64,
) -> Result<(Cow<'static, str>, Vec<<D as Db>::Param>), DocumentDbTxnError> {
    let dir_key = StmtIndex(0).column(0);

    let output = match stmt {
        Stmt::DirectoryWrite(meta) => (
            "INSERT INTO directory (id, kind, url, hash) VALUES ($1, 'document', $2, $3) ON CONFLICT DO UPDATE SET url = $2, hash = $3 RETURNING key".into(),
            params!(dir_id.to_blob(), meta.url.clone(), meta.hash.to_vec())
        ),
        Stmt::DirectoryAuditWrite(Actor(eid)) => (
            "INSERT INTO directory_audit (dir_key, upd, updated_by_eid) VALUES ($1, $2, $3)".into(),
            params!(dir_key, now, eid.to_blob())
        ),
        Stmt::LocalSettingGc => (
            "DELETE FROM local_setting WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::LocalSettingWrite { setting, value } => (
            "INSERT INTO local_setting (dir_key, upd, setting, value) VALUES ($1, $2, $3, $4)".into(),
            params!(dir_key, now, *setting as i64, value.clone()),
        ),
        Stmt::NamespaceGc(ids) => gc::<D>("namespace", NotIn("id", ids.iter().copied()), dir_key),
        Stmt::NamespaceWrite(id, label) => (
            "INSERT INTO namespace (dir_key, id, upd, label) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET upd = $3, label = $4".into(),
            params!(dir_key, id.to_blob(), now, label.clone())
        ),
        Stmt::ObjIdentGc => (
            "DELETE FROM obj_ident WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::ObjIdentWrite(obj_ident) => {
            EncryptedObjIdent::encrypt(obj_ident.prop_id, &obj_ident.ident, deks)
                .map_err(DocumentDbTxnError::Encryption)?
                .insert_stmt::<D>(dir_key, obj_ident.obj_id, now)
        },
        Stmt::ObjTextAttrGc => (
            "DELETE FROM obj_text_attr WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::ObjTextAttrWrite(attr) => (
            indoc! {
                "INSERT INTO obj_text_attr (dir_key, upd, obj_id, prop_key, value)
                VALUES ($1, $2, $3, (SELECT key FROM prop WHERE id = $4), $5)
                ON CONFLICT DO NOTHING"
            }.into(),
            params!(dir_key, now, attr.obj_id.to_blob(), attr.prop_id.to_blob(), attr.value.clone()),
        ),
        Stmt::EntRelGc => (
            "DELETE FROM ent_rel WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::EntRelWrite(rel) => (
            indoc! {
                "INSERT INTO ent_rel (dir_key, upd, prop_key, subject_eid, object_eid)
                VALUES ($1, $2, (SELECT key FROM prop WHERE id = $3), $4, $5)"
            }.into(),
            params!(
                dir_key,
                now,
                rel.relation.to_blob(),
                rel.subject.to_blob(),
                rel.object.to_blob()
            ),
        ),
        Stmt::ServiceGc(ids) => gc::<D>("svc", NotIn("svc_eid", ids.iter().copied()), dir_key),
        Stmt::ServiceWrite(svc_id, svc) => (
            "INSERT INTO svc (dir_key, upd, svc_eid, hosts_json) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET upd = $2, hosts_json = $4".into(),
            params!(dir_key, now, svc_id.to_blob(), serde_json::to_string(&svc.hosts).unwrap()),
        ),
        Stmt::ServiceNamespaceGc => (
            "DELETE FROM svc_namespace WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::ServiceNamespaceWrite(svc_id, ns_id) => (
            "INSERT INTO svc_namespace (dir_key, upd, svc_eid, ns_key) VALUES ($1, $2, $3, (SELECT key FROM namespace WHERE id = $4))".into(),
            params!(dir_key, now, svc_id.to_blob(), ns_id.to_blob()),
        ),
        Stmt::EntAttrAssignmentGc => (
            "DELETE FROM ent_attr WHERE dir_key = $1".into(),
            params!(dir_key),
        ),
        Stmt::EntAttrAssignmentWrite(assignment) => (
            "INSERT INTO ent_attr (dir_key, upd, eid, attr_key) VALUES ($1, $2, $3, (SELECT key FROM attr WHERE id = $4)) ON CONFLICT DO NOTHING".into(),
            params!(dir_key, now, assignment.eid.to_blob(), assignment.attrid.to_blob()),
        ),
        Stmt::NsPropGc(ids) => gc::<D>(
            "prop",
            NotIn("id", ids.iter().copied()),
            dir_key,
        ),
        Stmt::NsAttrGc(ids) => gc::<D>(
            "attr",
            NotIn("id", ids.iter().copied()),
            dir_key,
        ),
        Stmt::NsPropWrite { id, ns_id, kind, label } => (
            indoc! {
                "
                INSERT INTO prop (dir_key, ns_key, upd, id, kind, label)
                VALUES ($1, (SELECT key FROM namespace WHERE id = $2), $3, $4, $5, $6)
                ON CONFLICT DO UPDATE SET upd = $3, kind = $5, label = $6
                RETURNING key
                "
            }.into(),
            params!(dir_key, ns_id.to_blob(), now, id.to_blob(), format!("{kind}"), label.clone()),
        ),
        Stmt::NsAttrWrite { prop_stmt, id, label } => (
            indoc! {
                "
                INSERT INTO attr (dir_key, prop_key, upd, id, label)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO UPDATE SET upd = $2, label = $5"
            }.into(),
            params!(dir_key, StmtIndex(*prop_stmt).column(0), now, id.to_blob(), label.clone()),
        ),
        Stmt::PolicyGc(ids) => gc::<D>(
            "policy",
            NotIn("id", ids.iter().copied()),
            dir_key,
        ),
        Stmt::PolicyWrite { id, label, policy_pc } => (
            indoc! {
                "
                INSERT INTO policy (dir_key, upd, id, label, policy_pc)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO UPDATE SET upd = $2, label = $4, policy_pc = $5
                "
            }
            .into(),
            params!(dir_key, now, id.to_blob(), label.clone(), policy_pc.clone()),
        ),
        Stmt::PolBindGc => (
            "DELETE FROM polbind WHERE dir_key = $1".into(),
            params!(dir_key)
        ),
        Stmt::PolBindWrite => (
            "INSERT INTO polbind (dir_key, upd) VALUES ($1, $2) RETURNING key".into(),
            params!(dir_key, now)
        ),
        Stmt::PolBindAttrMatchWrite(parent_stmt, attr_id) => (
            "INSERT INTO polbind_attr_match (polbind_key, attr_key) VALUES ($1, (SELECT key FROM attr WHERE id = $2))"
            .into(),
            params!(StmtIndex(*parent_stmt).column(0), attr_id.to_blob()),
        ),
        Stmt::PolBindPolicyWrite(parent_stmt, pol_id) => (
            "INSERT INTO polbind_policy (polbind_key, policy_id) VALUES ($1, $2)"
                .into(),
            params!(StmtIndex(*parent_stmt).column(0), pol_id.to_blob()),
        ),
    };

    Ok(output)
}

struct NotIn<'a, I>(&'a str, I);

fn gc<D: Db>(
    table: &str,
    NotIn(id, keep): NotIn<impl Iterator<Item = impl Literal>>,
    dir_key: StmtColumn<usize>,
) -> (Cow<'static, str>, Vec<<D as Db>::Param>) {
    (
        format!(
            "DELETE FROM {table} WHERE dir_key = $1 AND {id} NOT IN ({})",
            keep.map(|value| value.literal()).format(", ")
        )
        .into(),
        params!(dir_key),
    )
}

fn txn_error_to_doc_error(stmt: Stmt, db_error: DbError) -> DocError {
    info!(?stmt, "doc transaction error");
    match db_error {
        DbError::Hiqlite(hiqlite::Error::Sqlite(_)) => DocError::ConstraintViolation,
        DbError::Rusqlite(_) => DocError::ConstraintViolation,
        err => DocError::Db(format!("{err:?}")),
    }
}
