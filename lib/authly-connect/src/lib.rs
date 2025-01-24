pub mod client;
pub mod server;
pub mod tunnel;

/// The fake server name used in the wrapped TLS channel
pub const SERVER_NAME: &str = "authly-connect";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TunnelSecurity {
    Secure,
    MutuallySecure,
}
