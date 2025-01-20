use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::{cmp, mem};
use std::{collections::HashMap, ops::Range};

use authly_common::{
    document,
    id::{BuiltinID, Eid, ObjId},
    property::QualifiedAttributeName,
};
use serde::de::value::StrDeserializer;
use serde::Deserialize;
use serde_spanned::Spanned;
use tracing::debug;

use crate::db::service_db;
use crate::db::Db;
use crate::document::compiled_document::{
    CompiledEntityAttributeAssignment, EntityIdent, EntityTextAttr,
};
use crate::policy::compiler::PolicyCompiler;
use crate::policy::PolicyOutcome;
use crate::settings::{Setting, Settings};

use super::compiled_document::{
    CompileError, CompiledAttribute, CompiledDocument, CompiledDocumentData,
    CompiledEntityRelation, CompiledProperty, DocumentMeta,
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

    eprop_cache: HashMap<Eid, Vec<service_db::ServiceProperty>>,
    rprop_cache: HashMap<Eid, Vec<service_db::ServiceProperty>>,
    policy_cache: HashMap<Eid, Vec<service_db::ServicePolicy>>,

    errors: Errors,
}

#[derive(Debug)]
pub enum NamespaceEntry {
    Entity(Eid),
    Service(Eid),
    PropertyLabel(ObjId),
    PolicyLabel(ObjId),
}

#[derive(Default)]
struct Errors {
    errors: Vec<Spanned<CompileError>>,
}

pub async fn compile_doc(
    mut doc: document::Document,
    meta: DocumentMeta,
    db: &impl Db,
) -> Result<CompiledDocument, Vec<Spanned<CompileError>>> {
    let mut comp = CompileCtx {
        aid: Eid::from_uint(doc.authly_document.id.get_ref().as_u128()),
        namespace: Default::default(),
        eprop_cache: Default::default(),
        rprop_cache: Default::default(),
        policy_cache: Default::default(),
        errors: Default::default(),
    };
    let mut data = CompiledDocumentData {
        // entities: doc.entity,
        // service_entities: doc.service_entity,
        ..Default::default()
    };

    if let Some(settings) = mem::take(&mut doc.local_settings) {
        let mut test_settings = Settings::default();

        for (key, value) in settings {
            let setting =
                match Setting::deserialize(StrDeserializer::<serde_json::Error>::new(key.as_ref()))
                {
                    Ok(setting) => setting,
                    Err(_) => {
                        comp.errors
                            .push(key.span(), CompileError::LocalSettingNotFound);
                        continue;
                    }
                };

            if let Err(err) = test_settings.try_set(setting, Cow::Borrowed(value.as_ref())) {
                comp.errors.push(
                    value.span(),
                    CompileError::InvalidSettingValue(format!("{err}")),
                );
                continue;
            }

            data.settings.insert(setting, value.into_inner());
        }
    }

    seed_namespace(&doc, &mut comp);

    debug!("namespace: {:#?}", comp.namespace.table);

    for entity in &mut doc.entity {
        if let Some(username) = entity.username.take() {
            data.entity_ident.push(EntityIdent {
                eid: *entity.eid.as_ref(),
                prop_id: BuiltinID::PropUsername.to_obj_id(),
                ident: username.into_inner(),
            });
        }
    }

    for entity in &mut doc.service_entity {
        let eid = *entity.eid.as_ref();
        if let Some(label) = &entity.label {
            data.entity_text_attrs.push(EntityTextAttr {
                eid,
                prop_id: BuiltinID::PropLabel.to_obj_id(),
                value: label.as_ref().to_string(),
            });
        }

        if let Some(k8s) = mem::take(&mut entity.kubernetes_account) {
            data.entity_text_attrs.push(EntityTextAttr {
                eid,
                prop_id: BuiltinID::PropK8sServiceAccount.to_obj_id(),
                value: format!("{}/{}", k8s.namespace, k8s.name),
            });
        }

        data.service_ids.insert(eid);
    }

    for email in mem::take(&mut doc.email) {
        let Some(eid) = comp.ns_entity_lookup(&email.entity) else {
            continue;
        };

        data.entity_ident.push(EntityIdent {
            eid,
            prop_id: BuiltinID::PropEmail.to_obj_id(),
            ident: email.value.into_inner(),
        });
    }

    for hash in mem::take(&mut doc.password_hash) {
        let Some(eid) = comp.ns_entity_lookup(&hash.entity) else {
            continue;
        };

        data.entity_text_attrs.push(EntityTextAttr {
            eid,
            prop_id: BuiltinID::PropPasswordHash.to_obj_id(),
            value: hash.hash,
        });
    }

    process_members(mem::take(&mut doc.members), &mut data, &mut comp);

    process_service_properties(
        mem::take(&mut doc.entity_property),
        mem::take(&mut doc.resource_property),
        &mut data,
        &mut comp,
        db,
    )
    .await;

    process_attribute_assignments(&mut doc, &mut data, &mut comp);
    process_policies(doc.policy, &mut data, &mut comp, db).await;
    process_policy_bindings(doc.policy_binding, &mut data, &mut comp);

    process_entity_attribute_bindings(
        mem::take(&mut doc.entity_attribute_binding),
        &mut data,
        &mut comp,
        db,
    )
    .await;

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

fn seed_namespace(doc: &document::Document, comp: &mut CompileCtx) {
    for builtin_prop in [BuiltinID::PropEntity, BuiltinID::PropAuthlyRole] {
        comp.namespace.insert_builtin_property(builtin_prop);
    }

    for entity in &doc.entity {
        if let Some(label) = &entity.label {
            comp.ns_add(label, NamespaceEntry::Entity(*entity.eid.get_ref()));
        }
    }

    for entity in &doc.service_entity {
        if let Some(label) = &entity.label {
            comp.ns_add(label, NamespaceEntry::Service(*entity.eid.get_ref()));
        }
    }
}

fn process_members(
    members_list: Vec<document::Members>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    for members in members_list {
        let Some(subject_eid) = comp.ns_entity_lookup(&members.entity) else {
            continue;
        };

        for member in &members.members {
            if let Some(member_eid) = comp.ns_entity_lookup(member) {
                data.entity_relations.push(CompiledEntityRelation {
                    subject: subject_eid,
                    relation: BuiltinID::RelEntityMembership.to_obj_id(),
                    object: member_eid,
                });
            };
        }
    }
}

async fn process_entity_attribute_bindings(
    bindings: Vec<document::EntityAttributeBinding>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
    // TODO: Use the database
    _db: &impl Db,
) {
    for binding in bindings {
        let eid = match (binding.eid, binding.label) {
            (Some(eid), None) => eid.into_inner(),
            (None, Some(label)) => {
                let Some(eid) = comp.ns_entity_lookup(&label) else {
                    continue;
                };
                eid
            }
            _ => {
                if let Some(first_attr) = binding.attributes.first() {
                    comp.errors
                        .push(first_attr.span(), CompileError::UnresolvedEntity);
                }

                continue;
            }
        };

        // TODO: Somehow check eid exists?

        for spanned_qattr in binding.attributes {
            let Some(prop_id) = comp.ns_property_lookup(&Spanned::new(
                spanned_qattr.span(),
                &spanned_qattr.as_ref().property,
            )) else {
                continue;
            };

            let attrid =
                match data.find_attribute_by_label(prop_id, &spanned_qattr.get_ref().attribute) {
                    Ok(attr_id) => attr_id,
                    Err(_) => {
                        comp.errors
                            .push(spanned_qattr.span(), CompileError::UnresolvedAttribute);
                        continue;
                    }
                };

            data.entity_attribute_assignments
                .push(CompiledEntityAttributeAssignment { eid, attrid });
        }
    }
}

async fn process_service_properties(
    entity_properties: Vec<document::EntityProperty>,
    resource_properties: Vec<document::ResourceProperty>,
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
                service_db::ServicePropertyKind::Entity,
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
            service_db::ServicePropertyKind::Resource,
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
    property_kind: service_db::ServicePropertyKind,
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
fn process_attribute_assignments(
    doc: &mut document::Document,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    let mut assignments: Vec<(Eid, Spanned<QualifiedAttributeName>)> = vec![];

    for entity in &mut doc.entity {
        for attribute in std::mem::take(&mut entity.attributes) {
            assignments.push((*entity.eid.get_ref(), attribute));
        }
    }

    for entity in &mut doc.service_entity {
        for attribute in std::mem::take(&mut entity.attributes) {
            assignments.push((*entity.eid.get_ref(), attribute));
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

async fn process_policies(
    policies: Vec<document::Policy>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
    db: &impl Db,
) {
    for policy in policies {
        let Some(svc_eid) = comp.ns_service_lookup(&policy.service) else {
            continue;
        };

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

        let mut policy_compiler = PolicyCompiler::new(&comp.namespace, data, outcome);

        let (expr, _bytecode) = match policy_compiler.compile(src.as_ref()) {
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

        let db_cache = comp.db_service_policies_cached(svc_eid, db).await;
        let cached_policy = db_cache
            .iter()
            .flat_map(|c| c.iter())
            .find(|db_policy| &db_policy.label == policy.label.as_ref());

        let policy_postcard = service_db::PolicyPostcard { outcome, expr };

        let namespace_label = policy.label.as_ref().to_string();
        let label_span = policy.label.span();

        let service_policy = if let Some(cached_policy) = cached_policy {
            service_db::ServicePolicy {
                id: cached_policy.id,
                svc_eid,
                label: policy.label.into_inner(),
                policy: policy_postcard,
            }
        } else {
            service_db::ServicePolicy {
                id: ObjId::random(),
                svc_eid,
                label: policy.label.into_inner(),
                policy: policy_postcard,
            }
        };

        comp.namespace.table.insert(
            namespace_label,
            Spanned::new(label_span, NamespaceEntry::PolicyLabel(service_policy.id)),
        );

        data.svc_policies.push(service_policy);
    }
}

fn process_policy_bindings(
    policy_bindings: Vec<document::PolicyBinding>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    for binding in policy_bindings {
        let Some(svc_eid) = comp.ns_service_lookup(&binding.service) else {
            continue;
        };

        let mut svc_policy_binding = service_db::ServicePolicyBinding {
            svc_eid,
            attr_matcher: Default::default(),
            policies: Default::default(),
        };

        for spanned_qattr in binding.attributes {
            let Some(prop_id) = comp.ns_property_lookup(&Spanned::new(
                spanned_qattr.span(),
                &spanned_qattr.as_ref().property,
            )) else {
                continue;
            };

            let attr_id =
                match data.find_attribute_by_label(prop_id, &spanned_qattr.get_ref().attribute) {
                    Ok(attr_id) => attr_id,
                    Err(_) => {
                        comp.errors
                            .push(spanned_qattr.span(), CompileError::UnresolvedAttribute);
                        continue;
                    }
                };

            svc_policy_binding.attr_matcher.insert(attr_id);
        }

        for spanned_policy in binding.policies {
            let Some(policy_id) = comp.ns_policy_lookup(&spanned_policy) else {
                continue;
            };

            svc_policy_binding.policies.insert(policy_id);
        }

        data.svc_policy_bindings.push(svc_policy_binding);
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
            NamespaceEntry::Entity(eid) => Some(*eid),
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => None,
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

    fn ns_policy_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<ObjId> {
        match self.ns_lookup(key, CompileError::UnresolvedProperty)? {
            NamespaceEntry::PolicyLabel(objid) => Some(*objid),
            _ => {
                self.errors.push(key.span(), CompileError::UnresolvedPolicy);
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
        property_kind: service_db::ServicePropertyKind,
        db: &impl Db,
    ) -> Option<&'s Vec<service_db::ServiceProperty>> {
        let cache = match property_kind {
            service_db::ServicePropertyKind::Entity => &mut self.eprop_cache,
            service_db::ServicePropertyKind::Resource => &mut self.rprop_cache,
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

    async fn db_service_policies_cached<'s>(
        &'s mut self,
        svc_eid: Eid,
        db: &impl Db,
    ) -> Option<&'s Vec<service_db::ServicePolicy>> {
        let cache = &mut self.policy_cache;

        match cache.entry(svc_eid) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_props = match service_db::list_service_policies(db, self.aid, svc_eid).await
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
