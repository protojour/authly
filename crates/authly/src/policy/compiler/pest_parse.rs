use pest::{iterators::Pair, Span};
use pest_derive::Parser;

use crate::{
    document::doc_compiler::NamespaceEntry,
    policy::error::{PolicyCompileError, PolicyCompileErrorKind},
};

use super::{
    expr::{Expr, Global, Label, Term},
    ParseCtx, PolicyCompiler,
};

/// The Authly policy language parser
#[derive(Parser)]
#[grammar = "../grammar/policy.pest"]
pub struct PolicyParser;

impl<'a> PolicyCompiler<'a> {
    /// Parse and check expression, performs name lookups
    pub(super) fn pest_expr(&mut self, pairs: Pair<Rule>, ctx: &ParseCtx, level: usize) -> Expr {
        match pairs.as_rule() {
            Rule::expr => ctx
                .expr_pratt
                .map_primary(|expr_atom| self.pest_expr(expr_atom, ctx, level + 1))
                .map_prefix(|op, rhs| match op.as_rule() {
                    Rule::unary_not => Expr::Not(Box::new(rhs)),
                    _ => unimplemented!("prefix {op:?}"),
                })
                .map_infix(|lhs, op, rhs| match op.as_rule() {
                    Rule::infix_and => Expr::And(Box::new(lhs), Box::new(rhs)),
                    Rule::infix_or => Expr::Or(Box::new(lhs), Box::new(rhs)),
                    _ => unimplemented!("infix {op:?}"),
                })
                .parse(pairs.into_inner()),
            Rule::expr_equals => {
                let mut pairs = pairs.into_inner();
                let lhs = self.pest_term(pairs.next().unwrap());
                let rhs = self.pest_term(pairs.next().unwrap());

                Expr::Equals(lhs, rhs)
            }
            Rule::expr_contains => {
                let mut pairs = pairs.into_inner();
                let lhs = self.pest_term(pairs.next().unwrap());
                let rhs = self.pest_term(pairs.next().unwrap());

                Expr::Contains(lhs, rhs)
            }
            _ => {
                panic!()
            }
        }
    }

    fn pest_term(&mut self, pair: Pair<Rule>) -> Term {
        match pair.as_rule() {
            Rule::label => {
                let Some(label) = self.pest_property_label(pair) else {
                    return Term::Error;
                };

                Term::Label(label)
            }
            Rule::term_field => {
                let mut pairs = pair.into_inner();
                let global = self.pest_global(pairs.next().unwrap());
                let Some(label) = self.pest_property_label(pairs.next().unwrap()) else {
                    return Term::Error;
                };

                Term::Field(global, label)
            }
            Rule::term_attr => {
                let span = pair.as_span();
                let mut pairs = pair.into_inner();
                let pest_property_label = pairs.next().unwrap();
                let Some(property_label) = self.pest_property_label(pest_property_label.clone())
                else {
                    return Term::Error;
                };

                let attr_label_str = pairs.next().unwrap().as_str();
                let compiled_property = self.doc_data.find_property(property_label.0).unwrap();

                let attr_label = match compiled_property
                    .attributes
                    .iter()
                    .find(|attr| attr.label == attr_label_str)
                {
                    Some(compiled_attr) => Label(compiled_attr.id),
                    None => {
                        self.pest_error(
                            span,
                            PolicyCompileErrorKind::UnknownAttribute(
                                pest_property_label.as_str().to_string(),
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

    fn pest_property_label(&mut self, pair: Pair<Rule>) -> Option<Label> {
        let label = pair.as_str();
        match self.namespace.get_entry(label) {
            Some(NamespaceEntry::PropertyLabel(id)) => Some(Label(*id)),
            _ => {
                self.pest_error(
                    pair.as_span(),
                    PolicyCompileErrorKind::UnknownLabel(label.to_string()),
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

#[cfg(test)]
mod policy_tests {
    use pest::{
        iterators::{Pair, Pairs},
        Parser,
    };

    use super::PolicyParser;

    fn parse_policy_ok(input: &str) -> Pair<super::Rule> {
        PolicyParser::parse(super::Rule::policy, input)
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn policy_hmm() {
        PolicyParser::parse(super::Rule::label, "label").unwrap();
        PolicyParser::parse(super::Rule::label, "Global").unwrap_err();
        PolicyParser::parse(super::Rule::global, "Subject").unwrap();
        PolicyParser::parse(super::Rule::term_field, "Subject.label").unwrap();
        PolicyParser::parse(super::Rule::term_field, "Subject").unwrap_err();
        PolicyParser::parse(super::Rule::term_attr, "label/label").unwrap();
        PolicyParser::parse(super::Rule::term_attr, "label/label:label").unwrap();
        PolicyParser::parse(super::Rule::term, "Subject.label").unwrap();
        PolicyParser::parse(super::Rule::term, "label/label").unwrap();
        PolicyParser::parse(super::Rule::term, "label/label ==").unwrap();
    }

    #[test]
    fn policy_field_equals_label() {
        parse_policy_ok("Subject.entity == testservice");
    }

    #[test]
    fn policy_field_contains_attribute() {
        parse_policy_ok("Subject.role contains a/b");
        parse_policy_ok("Subject.role contains foo/bar");
    }

    #[test]
    fn policy_conjunction() {
        parse_policy_ok("Subject.role contains a/b and Resource.name == foo");
    }

    #[test]
    fn policy_disjuction() {
        parse_policy_ok("Subject.role contains a/b or Resource.name == foo");
    }

    #[test]
    fn policy_not() {
        parse_policy_ok("not Subject.role contains a/b");
    }

    #[test]
    fn policy_not_conj() {
        parse_policy_ok("not Subject.role contains a/b and not a == b");
    }

    #[test]
    fn policy_not_conj_parenthesized() {
        parse_policy_ok("(not Subject.role contains a/b) and (not a == b)");
    }

    #[test]
    fn policy_parenthesized() {
        parse_policy_ok(
            "(Subject.role contains a/b and Resource.name == foo) or Subject.b == label",
        );
    }

    #[test]
    fn policy_print_tree() {
        let foo = parse_policy_ok("(not Subject.role contains a/b) and (not a == b)")
            .into_inner()
            .next()
            .unwrap();

        let p = foo.into_inner();

        fn print_rec(pairs: Pairs<super::Rule>, level: usize) {
            for child in pairs {
                for _ in 0..level {
                    print!("  ");
                }

                println!("{:?}", child.as_rule());

                print_rec(child.into_inner(), level + 1);
            }
        }

        print_rec(p, 0);
    }
}
