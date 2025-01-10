use std::{collections::BTreeSet, ops::Range};

use authly_domain::{
    document::{Group, Service, User},
    BuiltinID, Eid, ObjId,
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
    UnresolvedProperty,
    UnresolvedAttribute,
    PolicyBodyMissing,
    AmbiguousPolicyOutcome,
    Policy(PolicyCompileErrorKind),
    Db(String),
}

#[derive(Debug)]
pub struct CompiledDocument {
    /// authority ID
    pub aid: Eid,
    pub data: CompiledDocumentData,
}

#[derive(Default, Debug)]
pub struct CompiledDocumentData {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub services: Vec<Service>,

    /// Attributes to set on entities
    pub entity_attribute_assignments: Vec<CompiledEntityAttributeAssignment>,

    pub entity_ident: Vec<EntityIdent>,
    pub entity_password: Vec<EntityPassword>,

    pub group_memberships: Vec<CompiledGroupMembership>,

    pub svc_ent_props: Vec<CompiledProperty>,
    pub svc_res_props: Vec<CompiledProperty>,
}

#[derive(Debug)]
pub struct EntityIdent {
    pub eid: Eid,
    pub kind: String,
    pub ident: String,
}

#[derive(Debug)]
pub struct EntityPassword {
    pub eid: Eid,
    pub hash: String,
}

#[derive(Debug)]
pub struct CompiledEntityAttributeAssignment {
    pub eid: Eid,
    pub attrid: ObjId,
}

#[derive(Debug)]
pub struct CompiledGroupMembership {
    #[expect(unused)]
    pub group_eid: Eid,
    pub members: BTreeSet<Eid>,
}

#[derive(Debug)]
pub struct CompiledProperty {
    pub id: ObjId,
    pub svc_eid: Eid,
    pub label: String,

    pub attributes: Vec<CompiledAttribute>,
}

#[derive(Debug)]
pub struct CompiledAttribute {
    pub id: ObjId,
    pub label: String,
}

pub enum AttrLookupError {
    NoProperty,
    NoAttribute,
}

impl CompiledDocumentData {
    pub fn find_property(&self, prop_id: ObjId) -> Option<&CompiledProperty> {
        self.svc_ent_props
            .iter()
            .chain(self.svc_res_props.iter())
            .find(|prop| prop.id == prop_id)
    }

    pub fn find_attribute_by_label(
        &self,
        prop_id: ObjId,
        attr_label: &str,
    ) -> Result<ObjId, AttrLookupError> {
        match self.find_property(prop_id) {
            Some(property) => property
                .attributes
                .iter()
                .find(|attr| attr.label == attr_label)
                .map(|attr| attr.id)
                .ok_or(AttrLookupError::NoAttribute),
            None => {
                if prop_id == BuiltinID::PropAuthlyRole.to_obj_id() {
                    BuiltinID::PropAuthlyRole
                        .attributes()
                        .iter()
                        .copied()
                        .find(|attr| attr.label() == Some(attr_label))
                        .map(BuiltinID::to_obj_id)
                        .ok_or(AttrLookupError::NoAttribute)
                } else {
                    Err(AttrLookupError::NoProperty)
                }
            }
        }
    }
}
