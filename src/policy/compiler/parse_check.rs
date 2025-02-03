//! This module takes the pest parse tree and transforms it into Expr,
//! with basic type checking

use pest::{iterators::Pair, Span};

use crate::{
    document::doc_compiler::{NamespaceEntry, NamespaceKind, NsLookupErr},
    policy::error::{PolicyCompileError, PolicyCompileErrorKind},
};

use super::{
    expr::{Expr, Global, Label, Term},
    parser::Rule,
    ParseCtx, PolicyCompiler,
};

impl PolicyCompiler<'_> {
    /// Parse and check expression, performs name lookups
    pub(super) fn pest_expr(&mut self, pair: Pair<Rule>, ctx: &ParseCtx) -> Expr {
        match pair.as_rule() {
            // parse operator precedence using pratt parser
            Rule::expr => ctx
                .expr_pratt
                .map_primary(|expr_atom| self.pest_expr(expr_atom, ctx))
                .map_prefix(|op, rhs| match op.as_rule() {
                    Rule::unary_not => Expr::Not(Box::new(rhs)),
                    _ => unimplemented!("prefix {op:?}"),
                })
                .map_infix(|lhs, op, rhs| match op.as_rule() {
                    Rule::infix_and => Expr::And(Box::new(lhs), Box::new(rhs)),
                    Rule::infix_or => Expr::Or(Box::new(lhs), Box::new(rhs)),
                    _ => unimplemented!("infix {op:?}"),
                })
                .parse(pair.into_inner()),
            Rule::expr_equals => {
                let mut pairs = pair.into_inner();
                let lhs = self.pest_term(pairs.next().unwrap());
                let rhs = self.pest_term(pairs.next().unwrap());

                Expr::Equals(lhs, rhs)
            }
            Rule::expr_contains => {
                let mut pairs = pair.into_inner();
                let lhs = self.pest_term(pairs.next().unwrap());
                let rhs = self.pest_term(pairs.next().unwrap());

                Expr::Contains(lhs, rhs)
            }
            _ => {
                self.pest_error(
                    pair.as_span(),
                    PolicyCompileErrorKind::Misc("unhandled syntax"),
                );
                Expr::Error
            }
        }
    }

    fn pest_term(&mut self, pair: Pair<Rule>) -> Term {
        match pair.as_rule() {
            Rule::label => {
                let Some(label) = self.pest_any_label(pair) else {
                    return Term::Error;
                };

                Term::Label(label)
            }
            Rule::term_field => {
                let mut pairs = pair.into_inner();
                let global = self.pest_global(pairs.next().unwrap());
                let namespace = pairs.next().unwrap();
                let property = pairs.next().unwrap();
                let Some(label) = self.pest_property_label(namespace, property) else {
                    return Term::Error;
                };

                Term::Field(global, label)
            }
            Rule::term_attr => {
                let span = pair.as_span();
                let mut pairs = pair.into_inner();
                let namespace = pairs.next().unwrap();
                let property = pairs.next().unwrap();
                let Some(property_label) = self.pest_property_label(namespace, property.clone())
                else {
                    return Term::Error;
                };

                let attr_label_str = pairs.next().unwrap().as_str();

                let attr_label = match self
                    .doc_data
                    .find_attribute_by_label(property_label.0.into(), attr_label_str)
                {
                    Ok(id) => Label(id.to_raw_array()),
                    Err(_) => {
                        self.pest_error(
                            span,
                            PolicyCompileErrorKind::UnknownAttribute(
                                property.as_str().to_string(),
                                attr_label_str.to_string(),
                            ),
                        );
                        return Term::Error;
                    }
                };

                Term::Attr(property_label, attr_label)
            }
            _ => {
                unimplemented!("term {pair:?}")
            }
        }
    }

    fn pest_any_label(&mut self, pair: Pair<Rule>) -> Option<Label> {
        let label = pair.as_str();
        let Some(namespace) = self.namespace.get_namespace(label) else {
            self.pest_error(
                pair.as_span(),
                PolicyCompileErrorKind::UnknownLabel(label.to_string()),
            );
            return None;
        };

        match &namespace.kind {
            NamespaceKind::Entity(id) => Some(Label(id.to_raw_array())),
            NamespaceKind::Service(id) => Some(Label(id.to_raw_array())),
            _ => {
                self.pest_error(
                    pair.as_span(),
                    PolicyCompileErrorKind::UnknownLabel(label.to_string()),
                );
                None
            }
        }
    }

    fn pest_property_label(&mut self, namespace: Pair<Rule>, prop: Pair<Rule>) -> Option<Label> {
        let ns_label = namespace.as_str();
        let prop_label = prop.as_str();
        match self.namespace.get_entry(ns_label, prop_label) {
            Ok(NamespaceEntry::PropertyLabel(id)) => Some(Label(id.to_raw_array())),
            Err(NsLookupErr::Namespace) => {
                self.pest_error(
                    namespace.as_span(),
                    PolicyCompileErrorKind::UnknownNamespace(ns_label.to_string()),
                );
                None
            }
            Err(NsLookupErr::Entry) => {
                self.pest_error(
                    prop.as_span(),
                    PolicyCompileErrorKind::UnknownProperty(prop_label.to_string()),
                );
                None
            }
        }
    }

    fn pest_global(&mut self, pair: Pair<Rule>) -> Global {
        match pair.as_rule() {
            Rule::global => match pair.as_str() {
                "Subject" => Global::Subject,
                "Resource" => Global::Resource,
                _ => unimplemented!("{pair:?}"),
            },
            _ => unimplemented!("{pair:?}"),
        }
    }

    fn pest_error(&mut self, span: Span, kind: PolicyCompileErrorKind) {
        self.errors.push(PolicyCompileError {
            span: span.start()..span.end(),
            kind,
        });
    }
}
