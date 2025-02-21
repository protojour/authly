use std::{collections::BTreeMap, ops::Range};

use authly_common::id::{
    AnyId, AttrId, DirectoryId, DomainId, EntityId, PersonaId, PolicyId, PropId, ServiceId,
};

use crate::{
    db::{policy_db, service_db::PropertyKind, Identified},
    id::BuiltinProp,
    settings::Setting,
};

#[derive(Debug)]
pub struct CompiledDocument {
    /// directory ID
    pub dir_id: DirectoryId,
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

    pub entity_ident: Vec<(ObjectIdent, Range<usize>)>,
    pub obj_text_attrs: Vec<(ObjectTextAttr, Range<usize>)>,
    pub entity_password: Vec<EntityPassword>,

    pub namespaces: BTreeMap<AnyId, (String, Range<usize>)>,
    pub services: BTreeMap<ServiceId, CompiledService>,

    pub service_domains: Vec<(ServiceId, DomainId)>,

    pub entity_relations: Vec<CompiledEntityRelation>,

    pub domain_props: Vec<CompiledProperty>,

    pub policies: Vec<Identified<PolicyId, policy_db::DbPolicy>>,
    pub policy_bindings: Vec<policy_db::DbPolicyBinding>,
}

#[derive(Debug)]
pub struct CompiledService {
    pub hosts: Vec<String>,
}

#[derive(Debug)]
pub struct ObjectIdent {
    pub obj_id: AnyId,
    pub prop_id: PropId,
    pub ident: String,
}

#[derive(Debug)]
pub struct ObjectTextAttr {
    pub obj_id: AnyId,
    pub prop_id: PropId,
    pub value: String,
}

#[derive(Debug)]
pub struct ObjectLabel {
    pub obj_id: AnyId,
    pub label: String,
}

#[derive(Debug)]
pub struct EntityPassword {
    pub eid: PersonaId,
    pub hash: String,
}

#[derive(Debug)]
pub struct CompiledEntityAttributeAssignment {
    pub eid: EntityId,
    pub attrid: AttrId,
}

#[derive(Debug)]
pub struct CompiledEntityRelation {
    pub subject: EntityId,
    pub relation: PropId,
    pub object: EntityId,
}

#[derive(Debug)]
pub struct CompiledProperty {
    pub id: PropId,
    pub ns_id: AnyId,
    pub kind: PropertyKind,
    pub label: String,

    pub attributes: Vec<CompiledAttribute>,
}

#[derive(Debug)]
pub struct CompiledAttribute {
    pub id: AttrId,
    pub label: String,
}

pub enum AttrLookupError {
    NoProperty,
    NoAttribute,
}

impl CompiledDocumentData {
    pub fn find_property(&self, prop_id: PropId) -> Option<&CompiledProperty> {
        self.domain_props.iter().find(|prop| prop.id == prop_id)
    }

    pub fn find_attribute_by_label(
        &self,
        prop_id: PropId,
        attr_label: &str,
    ) -> Result<AttrId, AttrLookupError> {
        match self.find_property(prop_id) {
            Some(property) => property
                .attributes
                .iter()
                .find(|attr| attr.label == attr_label)
                .map(|attr| attr.id)
                .ok_or(AttrLookupError::NoAttribute),
            None => {
                if prop_id == PropId::from(BuiltinProp::AuthlyRole) {
                    BuiltinProp::AuthlyRole
                        .attributes()
                        .iter()
                        .copied()
                        .find(|attr| attr.label() == Some(attr_label))
                        .map(AttrId::from)
                        .ok_or(AttrLookupError::NoAttribute)
                } else {
                    Err(AttrLookupError::NoProperty)
                }
            }
        }
    }
}
