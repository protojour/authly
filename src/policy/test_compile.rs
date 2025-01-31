use super::compiler::{
    expr::{Expr, Global, Label, Term},
    PolicyCompiler,
};
use authly_common::{
    id::{AnyId, Eid, ObjId},
    policy::code::OpCode,
};

use crate::{
    document::{
        compiled_document::{CompiledAttribute, CompiledDocumentData, CompiledProperty},
        doc_compiler::{NamespaceEntry, NamespaceKind, Namespaces},
    },
    id::BuiltinID,
};

use super::PolicyOutcome;

const SVC: Eid = Eid::from_uint(42);
const ROLE: ObjId = ObjId::from_uint(1337);
const ROLE_ROOT: ObjId = ObjId::from_uint(1338);

fn test_env() -> (Namespaces, CompiledDocumentData) {
    let namespace = Namespaces::from_iter([
        (
            "a".to_string(),
            NamespaceKind::Service(SVC),
            vec![(
                "entity".to_string(),
                NamespaceEntry::PropertyLabel(BuiltinID::PropEntity.to_obj_id()),
            )],
        ),
        (
            "svc".to_string(),
            NamespaceKind::Service(SVC),
            vec![("role".to_string(), NamespaceEntry::PropertyLabel(ROLE))],
        ),
    ]);
    let mut doc_data = CompiledDocumentData::default();
    doc_data.domain_ent_props.push(CompiledProperty {
        id: ROLE,
        dom_id: AnyId::from_array(&SVC.to_bytes()),
        label: "role".to_string(),
        attributes: vec![CompiledAttribute {
            id: ROLE_ROOT,
            label: "root".to_string(),
        }],
    });

    (namespace, doc_data)
}

#[track_caller]
fn to_expr(src: &str) -> Expr {
    let (namespace, doc_data) = test_env();
    PolicyCompiler::new(&namespace, &doc_data, PolicyOutcome::Allow)
        .compile(src)
        .unwrap()
        .0
}

#[track_caller]
fn to_opcodes(src: &str) -> Vec<OpCode> {
    let (namespace, doc_data) = test_env();
    PolicyCompiler::new(&namespace, &doc_data, PolicyOutcome::Allow)
        .compile(src)
        .unwrap()
        .1
}

fn subject_entity_equals_svc() -> Expr {
    Expr::Equals(
        Term::Field(
            Global::Subject,
            Label(BuiltinID::PropEntity.to_obj_id().to_bytes()),
        ),
        Term::Label(Label(SVC.to_bytes())),
    )
}

#[test]
fn test_expr_equals() {
    assert_eq!(
        subject_entity_equals_svc(),
        to_expr("Subject.a:entity == svc")
    );
}

#[test]
fn test_expr_field_attribute() {
    assert_eq!(
        Expr::Contains(
            Term::Field(Global::Subject, Label(ROLE.to_bytes())),
            Term::Attr(Label(ROLE.to_bytes()), Label(ROLE_ROOT.to_bytes()))
        ),
        to_expr("Subject.svc:role contains svc:role:root")
    );
}

#[test]
fn test_expr_not() {
    assert_eq!(
        Expr::not(subject_entity_equals_svc()),
        to_expr("not Subject.a:entity == svc")
    );
}

#[test]
fn test_expr_logical_precedence() {
    assert_eq!(
        Expr::or(
            Expr::and(subject_entity_equals_svc(), subject_entity_equals_svc()),
            subject_entity_equals_svc()
        ),
        to_expr("Subject.a:entity == svc and Subject.a:entity == svc or Subject.a:entity == svc")
    );
}

#[test]
fn test_expr_logical_precedence2() {
    assert_eq!(
        Expr::or(
            subject_entity_equals_svc(),
            Expr::and(subject_entity_equals_svc(), subject_entity_equals_svc()),
        ),
        to_expr("Subject.a:entity == svc or Subject.a:entity == svc and Subject.a:entity == svc")
    );
}

#[test]
fn test_expr_logical_paren() {
    assert_eq!(
        Expr::and(
            subject_entity_equals_svc(),
            Expr::or(subject_entity_equals_svc(), subject_entity_equals_svc()),
        ),
        to_expr("Subject.a:entity == svc and (Subject.a:entity == svc or Subject.a:entity == svc)")
    );
}

#[test]
fn test_opcodes() {
    assert_eq!(
        vec![
            OpCode::LoadSubjectId(BuiltinID::PropEntity.to_obj_id().to_uint()),
            OpCode::LoadConstId(SVC.to_uint()),
            OpCode::IsEq,
            OpCode::LoadSubjectId(BuiltinID::PropEntity.to_obj_id().to_uint()),
            OpCode::LoadConstId(SVC.to_uint()),
            OpCode::IsEq,
            OpCode::And,
            OpCode::LoadSubjectId(BuiltinID::PropEntity.to_obj_id().to_uint()),
            OpCode::LoadConstId(SVC.to_uint()),
            OpCode::IsEq,
            OpCode::Or,
            OpCode::TrueThenAllow,
        ],
        to_opcodes(
            "Subject.a:entity == svc and Subject.a:entity == svc or Subject.a:entity == svc"
        )
    );
}
