use std::ops::Range;

use thiserror::Error;

#[derive(Debug)]
pub struct PolicyCompileError {
    pub kind: PolicyCompileErrorKind,
    pub span: Range<usize>,
}

#[derive(Error, Debug)]
pub enum PolicyCompileErrorKind {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("unknown label: {0}")]
    UnknownLabel(String),

    #[error("unknown namespace")]
    UnknownNamespace(String),

    #[error("unknown property")]
    UnknownProperty(String),

    #[error("no attribute {1} in {0}")]
    UnknownAttribute(String, String),

    #[error("compile error: {0}")]
    Misc(&'static str),
}
