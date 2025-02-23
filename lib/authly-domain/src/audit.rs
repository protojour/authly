use authly_common::id::EntityId;

/// The response Actor behind some action
#[derive(Clone, Copy, Debug)]
pub struct Actor(pub EntityId);
