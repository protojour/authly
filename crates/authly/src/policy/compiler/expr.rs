//! Policy expression after name lookups

use authly_domain::EID;

#[derive(Debug)]
#[expect(unused)]
pub enum Expr {
    Equals(Term, Term),
    Contains(Term, Term),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Error,
}

#[derive(Debug)]
#[expect(unused)]
pub enum Term {
    Label(Label),
    Field(Global, Label),
    Attr(Label, Label),
    Error,
}

#[derive(Debug)]
pub struct Label(pub EID);

#[derive(Debug)]
pub enum Global {
    Subject,
    Resource,
}
