use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct RemoteAddr(pub SocketAddr);

pub fn remote_addr_middleware<B>(req: &mut http::Request<B>, addr: SocketAddr) {
    req.extensions_mut().insert(RemoteAddr(addr));
}
