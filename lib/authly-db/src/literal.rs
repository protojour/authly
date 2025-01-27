use std::fmt::Display;

use authly_common::id::Id128;

pub trait Literal {
    type Lit: Display;

    fn literal(&self) -> Self::Lit;
}

impl<K> Literal for Id128<K> {
    type Lit = IdLiteral;

    fn literal(&self) -> Self::Lit {
        IdLiteral(self.to_bytes())
    }
}

pub struct IdLiteral([u8; 16]);

impl Display for IdLiteral {
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

impl Display for StrLiteral<'_> {
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
