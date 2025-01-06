use std::{collections::BTreeSet, ops::Range};

use authly_domain::{
    document::{Group, Service, User},
    EID,
};

#[derive(Debug)]
#[expect(unused)]
pub enum CompileError {
    NameDefinedMultipleTimes(Range<usize>),
    UnresolvedEntity,
    UnresolvedProfile,
    UnresolvedGroup,
    UnresolvedService,
    Db(String),
}

#[derive(Debug)]
pub struct CompiledDocument {
    /// authority ID
    pub aid: EID,
    pub data: CompiledDocumentData,
}

#[derive(Default, Debug)]
pub struct CompiledDocumentData {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub services: Vec<Service>,

    pub entity_ident: Vec<EntityIdent>,
    pub entity_password: Vec<EntityPassword>,

    pub group_memberships: Vec<CompiledGroupMembership>,

    pub svc_ent_props: Vec<CompiledProperty>,
    pub svc_res_props: Vec<CompiledProperty>,
}

#[derive(Debug)]
pub struct EntityIdent {
    pub eid: EID,
    pub kind: String,
    pub ident: String,
}

#[derive(Debug)]
pub struct EntityPassword {
    pub eid: EID,
    pub hash: String,
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
    pub label: String,

    pub attributes: Vec<CompiledAttribute>,
}

#[derive(Debug)]
pub struct CompiledAttribute {
    pub id: EID,
    pub label: String,
}
