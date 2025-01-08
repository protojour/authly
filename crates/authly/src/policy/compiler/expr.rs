//! Policy expression after name lookups

use authly_domain::EID;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expr {
    Equals(Term, Term),
    Contains(Term, Term),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Error,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Term {
    Label(Label),
    Field(Global, Label),
    Attr(Label, Label),
    Error,
}

/// A label resolved to an ID
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Label(pub EID);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Global {
    Subject,
    Resource,
}

#[cfg(test)]
impl Expr {
    pub fn and(lhs: Expr, rhs: Expr) -> Self {
        Self::And(Box::new(lhs), Box::new(rhs))
    }

    pub fn or(lhs: Expr, rhs: Expr) -> Self {
        Self::Or(Box::new(lhs), Box::new(rhs))
    }

    pub fn not(expr: Expr) -> Self {
        Self::Not(Box::new(expr))
    }
}
