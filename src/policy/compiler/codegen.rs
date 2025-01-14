use authly_common::{
    id::{AnyId, BuiltinID},
    policy::code::OpCode,
};

use crate::policy::PolicyOutcome;

use super::expr::{Expr, Global, Term};

#[derive(Default)]
pub struct Codegen {
    pub ops: Vec<OpCode>,
}

impl Codegen {
    pub fn codegen_expr_root(&mut self, expr: &Expr, outcome: PolicyOutcome) {
        self.codegen_expr(expr);
        self.ops.push(match outcome {
            PolicyOutcome::Allow => OpCode::TrueThenAllow,
            PolicyOutcome::Deny => OpCode::TrueThenDeny,
        });
    }

    pub fn codegen_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Equals(lhs, rhs) => {
                self.codegen_term(lhs);
                self.codegen_term(rhs);

                self.ops.push(OpCode::IsEq);
            }
            Expr::Contains(rhs, lhs) => {
                self.codegen_term(lhs);
                self.codegen_term(rhs);

                self.ops.push(OpCode::IdSetContains);
            }
            Expr::And(lhs, rhs) => {
                self.codegen_expr(lhs);
                self.codegen_expr(rhs);

                // TODO: Make lazy?
                self.ops.push(OpCode::And);
            }
            Expr::Or(lhs, rhs) => {
                self.codegen_expr(lhs);
                self.codegen_expr(rhs);

                // TODO: Make lazy?
                self.ops.push(OpCode::Or);
            }
            Expr::Not(expr) => {
                self.codegen_expr(expr);
                self.ops.push(OpCode::Not);
            }
            Expr::Error => {}
        }
    }

    fn codegen_term(&mut self, term: &Term) {
        match term {
            Term::Label(label) => self
                .ops
                .push(OpCode::LoadConstId(AnyId::from(label.0).to_uint())),
            Term::Field(global, label) => match global {
                Global::Subject => {
                    if label.0 == BuiltinID::PropEntity.to_obj_id().to_bytes() {
                        self.ops.push(OpCode::LoadSubjectId(
                            BuiltinID::PropEntity.to_obj_id().to_uint(),
                        ));
                    } else {
                        self.ops.push(OpCode::LoadSubjectAttrs);
                    }
                }
                Global::Resource => {
                    self.ops.push(OpCode::LoadResourceAttrs);
                }
            },
            Term::Attr(_prop, attr) => self
                .ops
                .push(OpCode::LoadConstId(AnyId::from(attr.0).to_uint())),
            Term::Error => {}
        }
    }
}
