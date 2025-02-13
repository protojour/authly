use std::net::SocketAddr;

use hyper::body::Incoming;

#[derive(Clone, Debug)]
pub struct RemoteAddr(pub SocketAddr);

pub fn remote_addr_middleware(req: &mut http::Request<Incoming>, addr: SocketAddr) {
    req.extensions_mut().insert(RemoteAddr(addr));
}
