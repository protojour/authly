use super::compiler::{
    expr::{Expr, Global, Label128, Term},
    PolicyCompiler,
};
use authly_common::{
    id::{kind::Kind, AttrId, PropId, ServiceId},
    policy::code::OpCode,
};

use crate::{
    db::service_db::PropertyKind,
    document::{
        compiled_document::{CompiledAttribute, CompiledDocumentData, CompiledProperty},
        doc_compiler::{NamespaceEntry, NamespaceKind, Namespaces},
    },
    id::BuiltinProp,
};

const SVC: ServiceId = ServiceId::from_uint(42);
const ROLE: PropId = PropId::from_uint(1337);
const ROLE_ROOT: AttrId = AttrId::from_uint(1338);

fn test_env() -> (Namespaces, CompiledDocumentData) {
    let namespace = Namespaces::from_iter([
        (
            "a".to_string(),
            NamespaceKind::Service(SVC),
            vec![(
                "entity".to_string(),
                NamespaceEntry::PropertyLabel(BuiltinProp::Entity.into()),
            )],
        ),
        (
            "svc".to_string(),
            NamespaceKind::Service(SVC),
            vec![("role".to_string(), NamespaceEntry::PropertyLabel(ROLE))],
        ),
    ]);
    let mut doc_data = CompiledDocumentData::default();
    doc_data.domain_props.push(CompiledProperty {
        id: ROLE,
        ns_id: SVC.upcast(),
        kind: PropertyKind::Entity,
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
    PolicyCompiler::new(&namespace, &doc_data)
        .compile(src)
        .unwrap()
        .0
}

#[track_caller]
fn to_opcodes(src: &str) -> Vec<OpCode> {
    let (namespace, doc_data) = test_env();
    PolicyCompiler::new(&namespace, &doc_data)
        .compile(src)
        .unwrap()
        .1
}

fn subject_entity_equals_svc() -> Expr {
    Expr::Equals(
        Term::Field(
            Global::Subject,
            Label128(PropId::from(BuiltinProp::Entity).to_raw_array()),
        ),
        Term::Entity(Kind::Service, Label128(SVC.to_raw_array())),
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
            Term::Field(Global::Subject, Label128(ROLE.to_raw_array())),
            Term::Attr(
                Label128(ROLE.to_raw_array()),
                Label128(ROLE_ROOT.to_raw_array())
            )
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
            OpCode::LoadSubjectId(PropId::from(BuiltinProp::Entity)),
            OpCode::LoadConstEntityId(SVC.upcast()),
            OpCode::IsEq,
            OpCode::LoadSubjectId(PropId::from(BuiltinProp::Entity)),
            OpCode::LoadConstEntityId(SVC.upcast()),
            OpCode::IsEq,
            OpCode::And,
            OpCode::LoadSubjectId(PropId::from(BuiltinProp::Entity)),
            OpCode::LoadConstEntityId(SVC.upcast()),
            OpCode::IsEq,
            OpCode::Or,
            OpCode::Return,
        ],
        to_opcodes(
            "Subject.a:entity == svc and Subject.a:entity == svc or Subject.a:entity == svc"
        )
    );
}
