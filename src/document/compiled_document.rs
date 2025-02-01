use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use authly_common::id::{AnyId, Eid, ObjId};
use authly_db::DbError;

use crate::{
    db::{policy_db, Identified},
    id::BuiltinID,
    policy::error::PolicyCompileErrorKind,
    settings::Setting,
};

#[derive(Debug)]
pub enum CompileError {
    LocalSettingNotFound,
    InvalidSettingValue(String),
    NameDefinedMultipleTimes(Range<usize>, String),
    UnresolvedNamespace,
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

impl From<DbError> for CompileError {
    fn from(value: DbError) -> Self {
        Self::Db(value.to_string())
    }
}

#[derive(Debug)]
pub struct CompiledDocument {
    /// directory ID
    pub dir_id: ObjId,
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
    pub obj_text_attrs: Vec<ObjectTextAttr>,
    pub entity_password: Vec<EntityPassword>,

    pub service_ids: BTreeSet<Eid>,

    // TODO: remove
    pub domains: Vec<Identified<ObjId, String>>,

    pub service_domains: Vec<(Eid, AnyId)>,

    pub entity_relations: Vec<CompiledEntityRelation>,

    pub domain_ent_props: Vec<CompiledProperty>,
    pub domain_res_props: Vec<CompiledProperty>,

    pub policies: Vec<Identified<ObjId, policy_db::DbPolicy>>,
    pub policy_bindings: Vec<Identified<ObjId, policy_db::DbPolicyBinding>>,
}

#[derive(Debug)]
pub struct EntityIdent {
    pub eid: Eid,
    pub prop_id: ObjId,
    pub ident: String,
}

// note: This is not only for entities
#[derive(Debug)]
pub struct ObjectTextAttr {
    pub obj_id: AnyId,
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
    pub dom_id: AnyId,
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
        self.domain_ent_props
            .iter()
            .chain(self.domain_res_props.iter())
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
