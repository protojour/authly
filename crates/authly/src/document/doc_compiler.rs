use std::cmp;
use std::collections::hash_map::Entry;
use std::{collections::HashMap, ops::Range};

use authly_common::{
    document::{Document, EntityProperty, GroupMembership, Policy, ResourceProperty},
    BuiltinID, Eid, ObjId, QualifiedAttributeName,
};
use serde_spanned::Spanned;
use tracing::debug;

use crate::db::service_db::ServicePropertyKind;
use crate::db::service_db::{self, ServiceProperty};
use crate::db::Db;
use crate::document::compiled_document::{
    CompiledEntityAttributeAssignment, EntityIdent, EntityPassword,
};
use crate::policy::compiler::PolicyCompiler;
use crate::policy::PolicyOutcome;

use super::compiled_document::{
    CompileError, CompiledAttribute, CompiledDocument, CompiledDocumentData,
    CompiledGroupMembership, CompiledProperty, DocumentMeta,
};

#[derive(Default)]
pub struct Namespace {
    table: HashMap<String, Spanned<NamespaceEntry>>,
}

impl Namespace {
    pub fn get_entry(&self, key: &str) -> Option<&NamespaceEntry> {
        let spanned = self.table.get(key)?;
        Some(spanned.as_ref())
    }

    fn insert_builtin_property(&mut self, builtin: BuiltinID) {
        self.table.insert(
            builtin.label().unwrap().to_string(),
            Spanned::new(0..0, NamespaceEntry::PropertyLabel(builtin.to_obj_id())),
        );
    }
}

struct CompileCtx {
    /// Authority ID
    aid: Eid,

    namespace: Namespace,

    eprop_cache: HashMap<Eid, Vec<ServiceProperty>>,
    rprop_cache: HashMap<Eid, Vec<ServiceProperty>>,

    errors: Errors,
}

#[derive(Debug)]
pub enum NamespaceEntry {
    User(Eid),
    Group(Eid),
    Service(Eid),
    PropertyLabel(ObjId),
}

#[derive(Default)]
struct Errors {
    errors: Vec<Spanned<CompileError>>,
}

pub async fn compile_doc(
    doc: Document,
    meta: DocumentMeta,
    db: &impl Db,
) -> Result<CompiledDocument, Vec<Spanned<CompileError>>> {
    let mut comp = CompileCtx {
        aid: Eid::new(doc.authly_document.id.get_ref().as_u128()),
        namespace: Default::default(),
        eprop_cache: Default::default(),
        rprop_cache: Default::default(),
        errors: Default::default(),
    };
    let mut data = CompiledDocumentData {
        users: doc.user,
        groups: doc.group,
        services: doc.service,
        ..Default::default()
    };

    seed_namespace(&mut data, &mut comp);

    debug!("namespace: {:#?}", comp.namespace.table);

    for email in doc.email {
        let Some(eid) = comp.ns_entity_lookup(&email.entity) else {
            continue;
        };

        data.entity_ident.push(EntityIdent {
            eid,
            kind: "email".to_string(),
            ident: email.value.into_inner(),
        });
    }

    for hash in doc.password_hash {
        let Some(eid) = comp.ns_entity_lookup(&hash.entity) else {
            continue;
        };

        data.entity_password.push(EntityPassword {
            eid,
            hash: hash.hash,
        });
    }

    process_group_membership(doc.group_membership, &mut data, &mut comp);

    process_service_properties(
        doc.entity_property,
        doc.resource_property,
        &mut data,
        &mut comp,
        db,
    )
    .await;

    process_attribute_assignments(&mut data, &mut comp);
    process_policies(doc.policy, &mut data, &mut comp);

    if !comp.errors.errors.is_empty() {
        Err(comp.errors.errors)
    } else {
        Ok(CompiledDocument {
            aid: comp.aid,
            meta,
            data,
        })
    }
}

fn seed_namespace(data: &mut CompiledDocumentData, comp: &mut CompileCtx) {
    for builtin_prop in [BuiltinID::PropEntity, BuiltinID::PropAuthlyRole] {
        comp.namespace.insert_builtin_property(builtin_prop);
    }

    for user in &mut data.users {
        if let Some(label) = &user.label {
            comp.ns_add(label, NamespaceEntry::User(*user.eid.get_ref()));
        }

        if let Some(username) = user.username.take() {
            data.entity_ident.push(EntityIdent {
                eid: *user.eid.as_ref(),
                kind: "username".to_string(),
                ident: username.into_inner(),
            });
        }
    }

    for group in &data.groups {
        comp.ns_add(&group.name, NamespaceEntry::Group(*group.eid.get_ref()));
    }

    for service in &data.services {
        comp.ns_add(
            &service.label,
            NamespaceEntry::Service(*service.eid.get_ref()),
        );
    }
}

fn process_group_membership(
    memberships: Vec<GroupMembership>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    for gm in memberships {
        let Some(group_eid) = comp.ns_group_lookup(&gm.group) else {
            continue;
        };

        let mut compiled_membership = CompiledGroupMembership {
            group_eid,
            members: Default::default(),
        };

        for member in &gm.members {
            if let Some(profile_eid) = comp.ns_profile_lookup(member) {
                compiled_membership.members.insert(profile_eid);
            };
        }

        data.group_memberships.push(compiled_membership);
    }
}

async fn process_service_properties(
    entity_properties: Vec<EntityProperty>,
    resource_properties: Vec<ResourceProperty>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
    db: &impl Db,
) {
    for doc_eprop in entity_properties {
        if let Some(svc_label) = &doc_eprop.service {
            let Some(svc_eid) = comp.ns_service_lookup(svc_label) else {
                continue;
            };

            if let Some(compiled_property) = compile_service_property(
                svc_eid,
                ServicePropertyKind::Entity,
                &doc_eprop.label,
                doc_eprop.attributes,
                comp,
                db,
            )
            .await
            {
                data.svc_ent_props.push(compiled_property);
            }
        }
    }

    for doc_rprop in resource_properties {
        let Some(svc_eid) = comp.ns_service_lookup(&doc_rprop.service) else {
            continue;
        };

        if let Some(compiled_property) = compile_service_property(
            svc_eid,
            ServicePropertyKind::Resource,
            &doc_rprop.label,
            doc_rprop.attributes,
            comp,
            db,
        )
        .await
        {
            data.svc_res_props.push(compiled_property);
        }
    }
}

async fn compile_service_property(
    svc_eid: Eid,
    property_kind: ServicePropertyKind,
    doc_property_label: &Spanned<String>,
    doc_attributes: Vec<Spanned<String>>,
    comp: &mut CompileCtx,
    db: &impl Db,
) -> Option<CompiledProperty> {
    let db_props_cached = comp
        .db_service_properties_cached(svc_eid, property_kind, db)
        .await?;

    let db_eprop = db_props_cached
        .iter()
        .find(|db_prop| &db_prop.label == doc_property_label.as_ref());

    let mut compiled_property = CompiledProperty {
        id: db_eprop
            .as_ref()
            .map(|db_prop| db_prop.id)
            .unwrap_or_else(ObjId::random),
        svc_eid,
        label: doc_property_label.as_ref().to_string(),
        attributes: vec![],
    };

    for doc_attribute in doc_attributes {
        let db_attr = db_eprop.as_ref().and_then(|db_eprop| {
            db_eprop
                .attributes
                .iter()
                .find(|attr| &attr.1 == doc_attribute.as_ref())
        });

        compiled_property.attributes.push(CompiledAttribute {
            id: db_attr
                .as_ref()
                .map(|attr| attr.0)
                .unwrap_or_else(ObjId::random),
            label: doc_attribute.into_inner(),
        });
    }

    comp.ns_add(
        doc_property_label,
        NamespaceEntry::PropertyLabel(compiled_property.id),
    );

    Some(compiled_property)
}

/// Assign attributes to entities
fn process_attribute_assignments(data: &mut CompiledDocumentData, comp: &mut CompileCtx) {
    let mut assignments: Vec<(Eid, Spanned<QualifiedAttributeName>)> = vec![];

    for user in &mut data.users {
        for attribute in std::mem::take(&mut user.attributes) {
            assignments.push((*user.eid.get_ref(), attribute));
        }
    }

    for service in &mut data.services {
        for attribute in std::mem::take(&mut service.attributes) {
            assignments.push((*service.eid.get_ref(), attribute));
        }
    }

    for (eid, spanned_qattr) in assignments {
        let Some(prop_id) = comp.ns_property_lookup(&Spanned::new(
            spanned_qattr.span(),
            &spanned_qattr.as_ref().property,
        )) else {
            continue;
        };

        match data.find_attribute_by_label(prop_id, &spanned_qattr.get_ref().attribute) {
            Ok(attrid) => {
                data.entity_attribute_assignments
                    .push(CompiledEntityAttributeAssignment { eid, attrid });
            }
            Err(_) => {
                comp.errors
                    .push(spanned_qattr.span(), CompileError::UnresolvedAttribute);
            }
        }
    }
}

fn process_policies(policies: Vec<Policy>, data: &mut CompiledDocumentData, comp: &mut CompileCtx) {
    for policy in policies {
        let (src, outcome) = match (policy.allow, policy.deny) {
            (Some(src), None) => (src, PolicyOutcome::Allow),
            (None, Some(src)) => (src, PolicyOutcome::Deny),
            (Some(allow), Some(deny)) => {
                let span = cmp::min(allow.span().start, deny.span().start)
                    ..cmp::max(allow.span().end, deny.span().end);

                comp.errors.push(span, CompileError::AmbiguousPolicyOutcome);
                continue;
            }
            (None, None) => {
                comp.errors
                    .push(policy.label.span(), CompileError::PolicyBodyMissing);
                continue;
            }
        };

        let _compiled_policy =
            match PolicyCompiler::new(&comp.namespace, data, outcome).compile(src.as_ref()) {
                Ok(compiled_policy) => compiled_policy,
                Err(errors) => {
                    for error in errors {
                        // translate the policy error span into the document
                        let mut error_span = error.span;
                        error_span.start += src.span().start;
                        error_span.end += src.span().end;

                        comp.errors
                            .push(error_span, CompileError::Policy(error.kind));
                    }

                    continue;
                }
            };
    }
}

impl CompileCtx {
    fn ns_add(&mut self, name: &Spanned<String>, entry: NamespaceEntry) -> bool {
        if let Some(entry) = self
            .namespace
            .table
            .insert(name.get_ref().to_string(), Spanned::new(name.span(), entry))
        {
            self.errors.errors.push(Spanned::new(
                name.span(),
                CompileError::NameDefinedMultipleTimes(entry.span(), name.get_ref().to_string()),
            ));

            false
        } else {
            true
        }
    }

    fn ns_entity_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<Eid> {
        match self.ns_lookup(key, CompileError::UnresolvedEntity)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            NamespaceEntry::User(eid) => Some(*eid),
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => None,
        }
    }

    fn ns_profile_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<Eid> {
        match self.ns_lookup(key, CompileError::UnresolvedProfile)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            NamespaceEntry::User(eid) => Some(*eid),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedProfile);
                None
            }
        }
    }

    fn ns_group_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<Eid> {
        match self.ns_lookup(key, CompileError::UnresolvedGroup)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            _ => {
                self.errors.push(key.span(), CompileError::UnresolvedGroup);
                None
            }
        }
    }

    fn ns_service_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<Eid> {
        match self.ns_lookup(key, CompileError::UnresolvedService)? {
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedService);
                None
            }
        }
    }

    fn ns_property_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<ObjId> {
        match self.ns_lookup(key, CompileError::UnresolvedProperty)? {
            NamespaceEntry::PropertyLabel(objid) => Some(*objid),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedProperty);
                None
            }
        }
    }

    fn ns_lookup(
        &mut self,
        key: &Spanned<impl AsRef<str>>,
        error: CompileError,
    ) -> Option<&NamespaceEntry> {
        match self.namespace.table.get(key.get_ref().as_ref()) {
            Some(entry) => Some(entry.get_ref()),
            None => {
                self.errors.push(key.span(), error);
                None
            }
        }
    }

    async fn db_service_properties_cached<'s>(
        &'s mut self,
        svc_eid: Eid,
        property_kind: ServicePropertyKind,
        db: &impl Db,
    ) -> Option<&'s Vec<ServiceProperty>> {
        let cache = match property_kind {
            ServicePropertyKind::Entity => &mut self.eprop_cache,
            ServicePropertyKind::Resource => &mut self.rprop_cache,
        };

        match cache.entry(svc_eid) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_props =
                    match service_db::list_service_properties(db, self.aid, svc_eid, property_kind)
                        .await
                    {
                        Ok(db_props) => db_props,
                        Err(e) => {
                            self.errors.push(0..0, CompileError::Db(e.to_string()));
                            return None;
                        }
                    };

                Some(vacant.insert(db_props))
            }
        }
    }
}

impl Errors {
    fn push(&mut self, span: Range<usize>, error: CompileError) {
        self.errors.push(Spanned::new(span, error));
    }
}

impl FromIterator<(String, Spanned<NamespaceEntry>)> for Namespace {
    fn from_iter<T: IntoIterator<Item = (String, Spanned<NamespaceEntry>)>>(iter: T) -> Self {
        Self {
            table: FromIterator::from_iter(iter),
        }
    }
}

impl FromIterator<(String, NamespaceEntry)> for Namespace {
    fn from_iter<T: IntoIterator<Item = (String, NamespaceEntry)>>(iter: T) -> Self {
        Self {
            table: FromIterator::from_iter(
                iter.into_iter()
                    .map(|(key, entry)| (key, Spanned::new(0..0, entry))),
            ),
        }
    }
}
