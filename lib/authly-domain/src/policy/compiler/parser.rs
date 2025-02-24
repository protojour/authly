use pest_derive::Parser;

/// The Authly policy language parser
#[derive(Parser)]
#[grammar = "../grammar/policy.pest"]
pub struct PolicyParser;

#[cfg(test)]
mod policy_tests {
    use pest::{
        iterators::{Pair, Pairs},
        Parser,
    };

    use super::super::parser::PolicyParser;

    fn parse_policy_ok(input: &str) -> Pair<super::Rule> {
        PolicyParser::parse(super::Rule::policy, input)
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn policy_field_equals_label() {
        parse_policy_ok("Subject.a:entity == testservice");
    }

    #[test]
    fn policy_field_contains_attribute() {
        parse_policy_ok("Subject.a:role contains a:b:c");
        parse_policy_ok("Subject.a:role contains foo:bar:baz");
    }

    #[test]
    fn policy_conjunction() {
        parse_policy_ok("Subject.a:role contains a:b:c and Resource.a:name == foo");
    }

    #[test]
    fn policy_disjuction() {
        parse_policy_ok("Subject.a:role contains a:b:c or Resource.a:name == foo");
    }

    #[test]
    fn policy_not() {
        parse_policy_ok("not Subject.a:role contains a:b:c");
    }

    #[test]
    fn policy_not_conj() {
        parse_policy_ok("not Subject.a:role contains a:b:c and not a == b");
    }

    #[test]
    fn policy_not_conj_parenthesized() {
        parse_policy_ok("(not Subject.a:role contains a:b:c) and (not a == b)");
    }

    #[test]
    fn policy_parenthesized() {
        parse_policy_ok(
            "(Subject.a:role contains a:b:c and Resource.a:name == foo) or Subject.a:b == label",
        );
    }

    #[test]
    fn policy_print_tree() {
        let foo = parse_policy_ok("(not Subject.a:role contains a:b:c) and (not a == b)")
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
