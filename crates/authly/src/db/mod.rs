use std::fmt::Display;

use authly_domain::EID;
use hiqlite::Row;

pub mod config_db;
pub mod document_db;
pub mod entity_db;
pub mod service_db;

pub trait Convert: Sized {
    fn from_row(row: &mut Row, idx: &str) -> Self;

    fn as_param(&self) -> hiqlite::Param;
}

impl Convert for EID {
    fn from_row(row: &mut Row, idx: &str) -> Self {
        let postcard: Vec<u8> = row.get(idx);
        Self(postcard::from_bytes(&postcard).unwrap())
    }

    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(postcard::to_allocvec(&self.0).unwrap())
    }
}

pub trait Literal {
    type Lit: Display;

    fn literal(&self) -> Self::Lit;
}

impl Literal for EID {
    type Lit = EIDLiteral;

    fn literal(&self) -> Self::Lit {
        EIDLiteral(postcard::to_allocvec(&self.0).unwrap())
    }
}

pub struct EIDLiteral(Vec<u8>);

impl Display for EIDLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "x'{}'", hexhex::hex(&self.0))
    }
}

impl<'a> Literal for &'a str {
    type Lit = StrLiteral<'a>;

    fn literal(&self) -> Self::Lit {
        StrLiteral(self)
    }
}

pub struct StrLiteral<'a>(&'a str);

impl<'a> Display for StrLiteral<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'")?;

        for char in self.0.chars() {
            if char == '\'' {
                write!(f, "''")?;
            } else {
                write!(f, "{char}")?;
            }
        }

        write!(f, "'")?;

        Ok(())
    }
}
