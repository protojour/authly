use serde::{Deserialize, Serialize};

pub mod compiler;
pub mod error;

#[cfg(test)]
mod test_compile;

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub enum PolicyOutcome {
    Allow,
    Deny,
}
