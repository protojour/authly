use authly_common::{
    id::{AttrId, EntityId, PropId},
    policy::code::OpCode,
};
use authly_domain::id::BuiltinProp;

use super::expr::{Expr, Global, Term};

#[derive(Default)]
pub struct Codegen {
    pub ops: Vec<OpCode>,
}

impl Codegen {
    pub fn codegen_expr_root(&mut self, expr: &Expr) {
        self.codegen_expr(expr);
        self.ops.push(OpCode::Return);
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
            Term::Entity(kind, label) => self
                .ops
                .push(OpCode::LoadConstEntityId(EntityId::new(*kind, label.0))),
            Term::Field(global, label) => match global {
                Global::Subject => {
                    if label.0 == PropId::from(BuiltinProp::Entity).to_raw_array() {
                        self.ops
                            .push(OpCode::LoadSubjectId(PropId::from(BuiltinProp::Entity)));
                    } else {
                        self.ops.push(OpCode::LoadSubjectAttrs);
                    }
                }
                Global::Resource => {
                    self.ops.push(OpCode::LoadResourceAttrs);
                }
            },
            Term::Attr(_prop, attr) => self.ops.push(OpCode::LoadConstAttrId(AttrId::from(attr.0))),
            Term::Error => {}
        }
    }
}
