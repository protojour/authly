use std::{collections::BTreeSet, ops::Range};

use authly_domain::{
    document::{Group, Service, User},
    EID,
};

#[derive(Debug)]
pub enum CompileError {
    NameDefinedMultipleTimes(Range<usize>),
    UnresolvedProfile,
    UnresolvedGroup,
    UnresolvedService,
    Db(String),
}

#[derive(Debug)]
pub struct CompiledDocument {
    pub authority_eid: EID,
    pub data: CompiledDocumentData,
}

#[derive(Default, Debug)]
pub struct CompiledDocumentData {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub services: Vec<Service>,

    pub group_memberships: Vec<CompiledGroupMembership>,

    pub service_entity_props: Vec<CompiledProperty>,
    pub service_resource_props: Vec<CompiledProperty>,
}

#[derive(Debug)]
pub struct CompiledGroupMembership {
    pub group_eid: EID,
    pub members: BTreeSet<EID>,
}

#[derive(Debug)]
pub struct CompiledProperty {
    /// TODO: Is it an entity?
    pub id: EID,
    pub svc_eid: EID,
    pub name: String,

    pub attributes: Vec<(EID, String)>,
}
