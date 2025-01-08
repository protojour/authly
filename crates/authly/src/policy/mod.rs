pub mod compiler;
pub mod error;

#[cfg(test)]
mod test_compile;

#[derive(Clone, Copy, Debug)]
pub enum PolicyOutcome {
    Allow,
    Deny,
}
