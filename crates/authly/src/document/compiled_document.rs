use std::{collections::BTreeSet, ops::Range};

use authly_domain::{
    document::{Group, Service, User},
    EID,
};

use crate::policy::error::PolicyCompileErrorKind;

#[derive(Debug)]
#[expect(unused)]
pub enum CompileError {
    NameDefinedMultipleTimes(Range<usize>, String),
    UnresolvedEntity,
    UnresolvedProfile,
    UnresolvedGroup,
    UnresolvedService,
    PolicyBodyMissing,
    AmbiguousPolicyOutcome,
    Policy(PolicyCompileErrorKind),
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
    #[expect(unused)]
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

impl CompiledDocumentData {
    pub fn find_property(&self, prop_id: EID) -> Option<&CompiledProperty> {
        self.svc_ent_props
            .iter()
            .chain(self.svc_res_props.iter())
            .find(|prop| prop.id == prop_id)
    }
}
