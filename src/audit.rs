use authly_common::id::Eid;

/// The response Actor behind some action
#[derive(Clone, Copy)]
pub struct Actor(pub Eid);
