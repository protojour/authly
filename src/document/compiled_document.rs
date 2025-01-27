use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use authly_common::id::{Eid, ObjId};

use crate::{
    db::service_db, id::BuiltinID, policy::error::PolicyCompileErrorKind, settings::Setting,
};

#[derive(Debug)]
pub enum CompileError {
    LocalSettingNotFound,
    InvalidSettingValue(String),
    NameDefinedMultipleTimes(Range<usize>, String),
    UnresolvedEntity,
    UnresolvedProfile,
    UnresolvedGroup,
    UnresolvedService,
    UnresolvedProperty,
    UnresolvedAttribute,
    UnresolvedPolicy,
    PolicyBodyMissing,
    AmbiguousPolicyOutcome,
    Policy(PolicyCompileErrorKind),
    Db(String),
}

#[derive(Debug)]
pub struct CompiledDocument {
    /// directory ID
    pub did: Eid,
    pub meta: DocumentMeta,
    pub data: CompiledDocumentData,
}

#[derive(Default, Debug)]
pub struct DocumentMeta {
    pub url: String,
    pub hash: [u8; 32],
}

#[derive(Default, Debug)]
pub struct CompiledDocumentData {
    pub settings: BTreeMap<Setting, String>,

    /// Attributes to set on entities
    pub entity_attribute_assignments: Vec<CompiledEntityAttributeAssignment>,

    pub entity_ident: Vec<EntityIdent>,
    pub entity_text_attrs: Vec<EntityTextAttr>,
    pub entity_password: Vec<EntityPassword>,

    pub service_ids: BTreeSet<Eid>,

    pub entity_relations: Vec<CompiledEntityRelation>,

    pub svc_ent_props: Vec<CompiledProperty>,
    pub svc_res_props: Vec<CompiledProperty>,

    pub svc_policies: Vec<service_db::ServicePolicy>,
    pub svc_policy_bindings: Vec<service_db::ServicePolicyBinding>,
}

#[derive(Debug)]
pub struct EntityIdent {
    pub eid: Eid,
    pub prop_id: ObjId,
    pub ident: String,
}

#[derive(Debug)]
pub struct EntityTextAttr {
    pub eid: Eid,
    pub prop_id: ObjId,
    pub value: String,
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
pub struct CompiledEntityRelation {
    pub subject: Eid,
    pub relation: ObjId,
    pub object: Eid,
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
