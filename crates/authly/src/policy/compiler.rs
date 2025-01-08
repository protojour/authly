use pest::{
    error::InputLocation,
    iterators::Pair,
    pratt_parser::{Assoc, Op, PrattParser},
    Parser,
};
use pest_parse::{PolicyParser, Rule};

use crate::document::{compiled_document::CompiledDocumentData, doc_compiler::Namespace};

use super::error::{PolicyCompileError, PolicyCompileErrorKind};

mod expr;
mod pest_parse;

pub struct PolicyCompiler<'a> {
    namespace: &'a Namespace,
    doc_data: &'a CompiledDocumentData,

    errors: Vec<PolicyCompileError>,
}

struct ParseCtx {
    // pratt parser for policy expressions
    expr_pratt: PrattParser<Rule>,
}

impl<'a> PolicyCompiler<'a> {
    pub fn new(namespace: &'a Namespace, doc_data: &'a CompiledDocumentData) -> Self {
        Self {
            namespace,
            doc_data,
            errors: vec![],
        }
    }

    pub fn compile(mut self, input: &str) -> Result<(), Vec<PolicyCompileError>> {
        let expr_root_pair = pest_parse_policy_as_expr(input)?;
        let parse_ctx = ParseCtx {
            expr_pratt: PrattParser::<Rule>::new()
                .op(Op::infix(Rule::infix_or, Assoc::Left))
                .op(Op::infix(Rule::infix_and, Assoc::Left))
                .op(Op::prefix(Rule::unary_not)),
        };

        let expr = self.pest_expr(expr_root_pair, &parse_ctx, 0);

        println!("{expr:#?}");

        if !self.errors.is_empty() {
            Err(self.errors)
        } else {
            Ok(())
        }
    }
}

fn pest_parse_policy_as_expr(input: &str) -> Result<Pair<Rule>, Vec<PolicyCompileError>> {
    let mut ast_root = match PolicyParser::parse(Rule::policy, input) {
        Ok(pairs) => pairs,
        Err(error) => return Err(vec![parse_error(error)]),
    };

    let Some(policy_root) = ast_root.next() else {
        // Cannot happen
        return Err(vec![]);
    };

    let Some(expr_root) = policy_root.into_inner().next() else {
        // Cannot happen
        return Err(vec![]);
    };

    Ok(expr_root)
}

fn parse_error(error: pest::error::Error<Rule>) -> PolicyCompileError {
    let span = match error.location {
        InputLocation::Pos(pos) => pos..(pos + 1),
        InputLocation::Span((start, end)) => start..end,
    };

    PolicyCompileError {
        kind: PolicyCompileErrorKind::Parse(error.variant.message().to_string()),
        span,
    }
}

#[cfg(test)]
mod tests {
    use authly_domain::EID;

    use crate::document::doc_compiler::NamespaceEntry;

    use super::*;

    #[test]
    fn simple() {
        let namespace = Namespace::from_iter([
            ("entity".to_string(), NamespaceEntry::PropertyLabel(EID(1))),
            ("foo".to_string(), NamespaceEntry::PropertyLabel(EID(2))),
        ]);
        let doc_data = CompiledDocumentData::default();

        PolicyCompiler::new(&namespace, &doc_data)
            .compile("Subject.entity == foo")
            .unwrap();
    }
}
