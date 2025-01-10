use authly_common::{policy::code::OpCode, BuiltinID};

use crate::policy::PolicyOutcome;

use super::{
    expr::{Expr, Global, Term},
    PolicyCompiler,
};

impl PolicyCompiler<'_> {
    pub fn codegen_expr_root(&mut self, expr: Expr) {
        self.codegen_expr(expr);
        self.ops.push(match self.outcome {
            PolicyOutcome::Allow => OpCode::TrueThenAllow,
            PolicyOutcome::Deny => OpCode::TrueThenDeny,
        });
    }

    pub fn codegen_expr(&mut self, expr: Expr) {
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
                self.codegen_expr(*lhs);
                self.codegen_expr(*rhs);

                // TODO: Make lazy?
                self.ops.push(OpCode::And);
            }
            Expr::Or(lhs, rhs) => {
                self.codegen_expr(*lhs);
                self.codegen_expr(*rhs);

                // TODO: Make lazy?
                self.ops.push(OpCode::Or);
            }
            Expr::Not(expr) => {
                self.codegen_expr(*expr);
                self.ops.push(OpCode::Not);
            }
            Expr::Error => {}
        }
    }

    fn codegen_term(&mut self, term: Term) {
        match term {
            Term::Label(label) => self.ops.push(OpCode::LoadConstId(label.0)),
            Term::Field(global, label) => match global {
                Global::Subject => {
                    if label.0 == BuiltinID::PropEntity.to_obj_id().value() {
                        self.ops.push(OpCode::LoadSubjectId(
                            BuiltinID::PropEntity.to_obj_id().value(),
                        ));
                    }
                }
                Global::Resource => {
                    self.ops.push(OpCode::LoadResourceAttrs);
                }
            },
            Term::Attr(_prop, attr) => self.ops.push(OpCode::LoadConstId(attr.0)),
            Term::Error => {}
        }
    }
}
