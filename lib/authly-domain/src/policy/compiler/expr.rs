//! Policy expression after name lookups.
//!
//! The policy expression is stored in serialized form in the database,
//! so it's to be considered a stable format and requires care when extending.

use authly_common::id::kind::Kind;
use serde::{Deserialize, Serialize};

/// Policy expression.
///
/// NB: The order of enum variants matters for postcard deserialization from DB.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Expr {
    Equals(Term, Term),
    Contains(Term, Term),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Error,
}

/// Policy term.
///
/// NB: The order of enum variants matters for postcard deserialization from DB.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Term {
    Entity(Kind, Label128),
    Field(Global, Label128),
    Attr(Label128, Label128),
    Error,
}

/// A label resolved to an ID
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Label128(pub [u8; 16]);

/// Global object.
///
/// NB: The order of enum variants matters for postcard deserialization from DB.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
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

    #[allow(clippy::should_implement_trait)]
    pub fn not(expr: Expr) -> Self {
        Self::Not(Box::new(expr))
    }
}
