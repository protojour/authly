use super::compiler::{
    expr::{Expr, Global, Label, Term},
    PolicyCompiler,
};
use authly_common::{BuiltinID, Eid, ObjId};
use authly_policy::OpCode;

use crate::document::{
    compiled_document::{CompiledAttribute, CompiledDocumentData, CompiledProperty},
    doc_compiler::{Namespace, NamespaceEntry},
};

use super::PolicyOutcome;

const SVC: Eid = Eid::new(42);
const ROLE: ObjId = ObjId::new(1337);
const ROLE_ROOT: ObjId = ObjId::new(1338);

fn test_env() -> (Namespace, CompiledDocumentData) {
    let namespace = Namespace::from_iter([
        (
            "entity".to_string(),
            NamespaceEntry::PropertyLabel(BuiltinID::PropEntity.to_obj_id()),
        ),
        ("svc".to_string(), NamespaceEntry::Service(SVC)),
        ("role".to_string(), NamespaceEntry::PropertyLabel(ROLE)),
    ]);
    let mut doc_data = CompiledDocumentData::default();
    doc_data.svc_ent_props.push(CompiledProperty {
        id: ROLE,
        svc_eid: SVC,
        label: "role".to_string(),
        attributes: vec![CompiledAttribute {
            id: ROLE_ROOT,
            label: "root".to_string(),
        }],
    });

    (namespace, doc_data)
}

fn to_expr(src: &str) -> Expr {
    let (namespace, doc_data) = test_env();
    PolicyCompiler::new(&namespace, &doc_data, PolicyOutcome::Allow)
        .parse_and_check(src)
        .unwrap()
}

fn to_opcodes(src: &str) -> Vec<OpCode> {
    let (namespace, doc_data) = test_env();
    PolicyCompiler::new(&namespace, &doc_data, PolicyOutcome::Allow)
        .compile_opcodes(src)
        .unwrap()
}

fn subject_entity_equals_svc() -> Expr {
    Expr::Equals(
        Term::Field(
            Global::Subject,
            Label(BuiltinID::PropEntity.to_obj_id().value()),
        ),
        Term::Label(Label(SVC.value())),
    )
}

#[test]
fn test_expr_equals() {
    assert_eq!(
        subject_entity_equals_svc(),
        to_expr("Subject.entity == svc")
    );
}

#[test]
fn test_expr_field_attribute() {
    assert_eq!(
        Expr::Contains(
            Term::Field(Global::Subject, Label(ROLE.value())),
            Term::Attr(Label(ROLE.value()), Label(ROLE_ROOT.value()))
        ),
        to_expr("Subject.role contains role/root")
    );
}

#[test]
fn test_expr_not() {
    assert_eq!(
        Expr::not(subject_entity_equals_svc()),
        to_expr("not Subject.entity == svc")
    );
}

#[test]
fn test_expr_logical_precedence() {
    assert_eq!(
        Expr::or(
            Expr::and(subject_entity_equals_svc(), subject_entity_equals_svc()),
            subject_entity_equals_svc()
        ),
        to_expr("Subject.entity == svc and Subject.entity == svc or Subject.entity == svc")
    );
}

#[test]
fn test_expr_logical_precedence2() {
    assert_eq!(
        Expr::or(
            subject_entity_equals_svc(),
            Expr::and(subject_entity_equals_svc(), subject_entity_equals_svc()),
        ),
        to_expr("Subject.entity == svc or Subject.entity == svc and Subject.entity == svc")
    );
}

#[test]
fn test_expr_logical_paren() {
    assert_eq!(
        Expr::and(
            subject_entity_equals_svc(),
            Expr::or(subject_entity_equals_svc(), subject_entity_equals_svc()),
        ),
        to_expr("Subject.entity == svc and (Subject.entity == svc or Subject.entity == svc)")
    );
}

#[test]
fn test_opcodes() {
    assert_eq!(
        vec![
            OpCode::LoadSubjectEid(BuiltinID::PropEntity.to_obj_id().value()),
            OpCode::LoadConstId(SVC.value()),
            OpCode::IsEq,
            OpCode::LoadSubjectEid(BuiltinID::PropEntity.to_obj_id().value()),
            OpCode::LoadConstId(SVC.value()),
            OpCode::IsEq,
            OpCode::And,
            OpCode::LoadSubjectEid(BuiltinID::PropEntity.to_obj_id().value()),
            OpCode::LoadConstId(SVC.value()),
            OpCode::IsEq,
            OpCode::Or,
            OpCode::TrueThenAllow,
        ],
        to_opcodes("Subject.entity == svc and Subject.entity == svc or Subject.entity == svc")
    );
}
