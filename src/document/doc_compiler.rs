use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::{cmp, mem};
use std::{collections::HashMap, ops::Range};

use authly_common::id::AnyId;
use authly_common::{
    document,
    id::{Eid, ObjId},
    property::QualifiedAttributeName,
};
use authly_db::{Db, DbError};
use serde::de::value::StrDeserializer;
use serde::Deserialize;
use serde_spanned::Spanned;
use tracing::debug;

use crate::db::policy_db::DbPolicy;
use crate::db::{directory_db, policy_db, service_db, Identified};
use crate::document::compiled_document::{
    CompiledEntityAttributeAssignment, EntityIdent, ObjectTextAttr,
};
use crate::id::BuiltinID;
use crate::policy::compiler::PolicyCompiler;
use crate::policy::PolicyOutcome;
use crate::settings::{Setting, Settings};
use crate::util::error::{HandleError, ResultExt};

use super::compiled_document::{
    CompileError, CompiledAttribute, CompiledDocument, CompiledDocumentData,
    CompiledEntityRelation, CompiledProperty, DocumentMeta,
};

#[derive(Default)]
pub struct Namespaces {
    // table: HashMap<String, Spanned<NamespaceEntry>>,
    table: HashMap<String, Spanned<Namespace>>,
}

impl Namespaces {
    pub fn get_namespace(&self, ns: &str) -> Option<&Namespace> {
        let spanned = self.table.get(ns)?;
        Some(spanned.as_ref())
    }

    pub fn get_entry(&self, ns: &str, key: &str) -> Result<&NamespaceEntry, NsLookupErr> {
        let namespace = self.table.get(ns).ok_or(NsLookupErr::Namespace)?;
        let spanned = namespace
            .as_ref()
            .entries
            .get(key)
            .ok_or(NsLookupErr::Entry)?;
        Ok(spanned.as_ref())
    }

    fn insert_builtin_property(&mut self, builtin: BuiltinID) {
        let namespace = self.table.get_mut("authly").unwrap();
        namespace.as_mut().entries.insert(
            builtin.label().unwrap().to_string(),
            Spanned::new(0..0, NamespaceEntry::PropertyLabel(builtin.to_obj_id())),
        );
    }
}

pub enum NsLookupErr {
    Namespace,
    Entry,
}

#[derive(Debug)]
pub struct Namespace {
    pub kind: NamespaceKind,
    pub entries: HashMap<String, Spanned<NamespaceEntry>>,
}

#[derive(Debug)]
pub enum NamespaceKind {
    Authly,
    Entity(Eid),
    Service(Eid),
    Domain(ObjId),
    Policy(ObjId),
}

struct CompileCtx {
    /// Directory ID
    dir_id: ObjId,

    namespaces: Namespaces,

    eprop_cache: HashMap<AnyId, Vec<service_db::ServiceProperty>>,
    rprop_cache: HashMap<AnyId, Vec<service_db::ServiceProperty>>,
    policy_cache: HashMap<ObjId, Vec<Identified<ObjId, policy_db::DbPolicy>>>,
    domain_cache: Option<HashMap<String, ObjId>>,

    errors: Errors,
}

#[derive(Debug)]
pub enum NamespaceEntry {
    PropertyLabel(ObjId),
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
        dir_id: ObjId::from_uint(doc.authly_document.id.get_ref().as_u128()),
        namespaces: Default::default(),
        eprop_cache: Default::default(),
        rprop_cache: Default::default(),
        policy_cache: Default::default(),
        domain_cache: Default::default(),
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

    {
        seed_namespace(&doc, &mut comp);

        for domain in mem::take(&mut doc.domain) {
            let Some(cache) = comp.db_directory_domains_cache(db).await else {
                continue;
            };

            let id = cache
                .get(domain.label.as_ref())
                .copied()
                .unwrap_or_else(ObjId::random);

            comp.ns_add(&domain.label, NamespaceKind::Domain(id));

            data.obj_text_attrs.push(ObjectTextAttr {
                obj_id: AnyId::from_array(&id.to_bytes()),
                prop_id: BuiltinID::PropLabel.to_obj_id(),
                value: domain.label.as_ref().to_string(),
            });
            data.domains.push(Identified(id, domain.label.into_inner()));
        }
    }

    debug!("namespace: {:#?}", comp.namespaces.table);

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
            data.obj_text_attrs.push(ObjectTextAttr {
                obj_id: AnyId::from_array(&eid.to_bytes()),
                prop_id: BuiltinID::PropLabel.to_obj_id(),
                value: label.as_ref().to_string(),
            });
        }

        if let Some(k8s) = mem::take(&mut entity.kubernetes_account) {
            data.obj_text_attrs.push(ObjectTextAttr {
                obj_id: AnyId::from_array(&eid.to_bytes()),
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

        data.obj_text_attrs.push(ObjectTextAttr {
            obj_id: AnyId::from_array(&eid.to_bytes()),
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

    for doc_svc_domain in doc.service_domain {
        if let (Some(svc_eid), Some(dom_id)) = (
            comp.ns_entity_lookup(&doc_svc_domain.service),
            comp.ns_domain_lookup(&doc_svc_domain.domain),
        ) {
            data.service_domains.push((svc_eid, dom_id));
        }
    }

    if !comp.errors.errors.is_empty() {
        Err(comp.errors.errors)
    } else {
        Ok(CompiledDocument {
            dir_id: comp.dir_id,
            meta,
            data,
        })
    }
}

fn seed_namespace(doc: &document::Document, comp: &mut CompileCtx) {
    comp.namespaces.table.insert(
        "authly".to_string(),
        Spanned::new(
            0..0,
            Namespace {
                kind: NamespaceKind::Authly,
                entries: Default::default(),
            },
        ),
    );
    for builtin_prop in [BuiltinID::PropEntity, BuiltinID::PropAuthlyRole] {
        comp.namespaces.insert_builtin_property(builtin_prop);
    }

    for entity in &doc.entity {
        if let Some(label) = &entity.label {
            comp.ns_add(label, NamespaceKind::Entity(*entity.eid.get_ref()));
        }
    }

    for entity in &doc.service_entity {
        if let Some(label) = &entity.label {
            comp.ns_add(label, NamespaceKind::Service(*entity.eid.get_ref()));
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
            let Some(prop_id) = comp.ns_property_lookup(
                &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().namespace),
                &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().property),
            ) else {
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
        if let Some(domain_label) = &doc_eprop.domain {
            let Some(svc_eid) = comp.ns_domain_lookup(domain_label) else {
                continue;
            };

            if let Some(compiled_property) = compile_service_property(
                domain_label,
                svc_eid,
                service_db::ServicePropertyKind::Entity,
                &doc_eprop.label,
                doc_eprop.attributes,
                comp,
                db,
            )
            .await
            {
                data.domain_ent_props.push(compiled_property);
            }
        }
    }

    for doc_rprop in resource_properties {
        let Some(domain_eid) = comp.ns_domain_lookup(&doc_rprop.domain) else {
            continue;
        };

        if let Some(compiled_property) = compile_service_property(
            &doc_rprop.domain,
            domain_eid,
            service_db::ServicePropertyKind::Resource,
            &doc_rprop.label,
            doc_rprop.attributes,
            comp,
            db,
        )
        .await
        {
            data.domain_res_props.push(compiled_property);
        }
    }
}

async fn compile_service_property(
    svc_namespace: &Spanned<String>,
    dom_id: AnyId,
    property_kind: service_db::ServicePropertyKind,
    doc_property_label: &Spanned<String>,
    doc_attributes: Vec<Spanned<String>>,
    comp: &mut CompileCtx,
    db: &impl Db,
) -> Option<CompiledProperty> {
    let db_props_cached = comp
        .db_domain_properties_cached(dom_id, property_kind, db)
        .await?;

    let db_eprop = db_props_cached
        .iter()
        .find(|db_prop| &db_prop.label == doc_property_label.as_ref());

    let mut compiled_property = CompiledProperty {
        id: db_eprop
            .as_ref()
            .map(|db_prop| db_prop.id)
            .unwrap_or_else(ObjId::random),
        dom_id,
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

    comp.ns_add_entry(
        svc_namespace,
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
        let Some(prop_id) = comp.ns_property_lookup(
            &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().namespace),
            &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().property),
        ) else {
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

        let mut policy_compiler = PolicyCompiler::new(&comp.namespaces, data, outcome);

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

        let db_cache = comp.db_directory_policies_cached(db).await;
        let cached_policy = db_cache
            .iter()
            .flat_map(|c| c.iter())
            .find(|db_policy| &db_policy.data().label == policy.label.as_ref());

        let policy_postcard = policy_db::PolicyPostcard { outcome, expr };

        let namespace_label = policy.label.as_ref().to_string();
        let label_span = policy.label.span();

        let service_policy: Identified<ObjId, DbPolicy> = if let Some(cached_policy) = cached_policy
        {
            Identified(
                *cached_policy.id(),
                policy_db::DbPolicy {
                    label: policy.label.into_inner(),
                    policy: policy_postcard,
                },
            )
        } else {
            Identified(
                ObjId::random(),
                policy_db::DbPolicy {
                    label: policy.label.into_inner(),
                    policy: policy_postcard,
                },
            )
        };

        comp.namespaces.table.insert(
            namespace_label,
            Spanned::new(
                label_span,
                Namespace {
                    kind: NamespaceKind::Policy(*service_policy.id()),
                    entries: Default::default(),
                },
            ),
        );

        data.policies.push(service_policy);
    }
}

fn process_policy_bindings(
    policy_bindings: Vec<document::PolicyBinding>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    for binding in policy_bindings {
        let mut policy_binding = Identified(
            ObjId::random(),
            policy_db::DbPolicyBinding {
                attr_matcher: Default::default(),
                policies: Default::default(),
            },
        );

        for spanned_qattr in binding.attributes {
            let Some(prop_id) = comp.ns_property_lookup(
                &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().namespace),
                &Spanned::new(spanned_qattr.span(), &spanned_qattr.as_ref().property),
            ) else {
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

            policy_binding.data_mut().attr_matcher.insert(attr_id);
        }

        for spanned_policy in binding.policies {
            let Some(policy_id) = comp.ns_policy_lookup(&spanned_policy) else {
                continue;
            };

            policy_binding.data_mut().policies.insert(policy_id);
        }

        data.policy_bindings.push(policy_binding);
    }
}

impl CompileCtx {
    fn ns_add(&mut self, namespace: &Spanned<String>, kind: NamespaceKind) -> bool {
        if let Some(entry) = self.namespaces.table.insert(
            namespace.get_ref().to_string(),
            Spanned::new(
                namespace.span(),
                Namespace {
                    kind,
                    entries: Default::default(),
                },
            ),
        ) {
            self.errors.errors.push(Spanned::new(
                namespace.span(),
                CompileError::NameDefinedMultipleTimes(
                    entry.span(),
                    namespace.get_ref().to_string(),
                ),
            ));

            false
        } else {
            true
        }
    }

    fn ns_add_entry(
        &mut self,
        namespace: &Spanned<String>,
        key: &Spanned<String>,
        entry: NamespaceEntry,
    ) -> bool {
        let Some(namespace) = self.namespaces.table.get_mut(namespace.as_ref()) else {
            self.errors.errors.push(Spanned::new(
                namespace.span(),
                CompileError::UnresolvedNamespace,
            ));

            return false;
        };

        if let Some(entry) = namespace
            .as_mut()
            .entries
            .insert(key.get_ref().to_string(), Spanned::new(key.span(), entry))
        {
            self.errors.errors.push(Spanned::new(
                namespace.span(),
                CompileError::NameDefinedMultipleTimes(entry.span(), key.get_ref().to_string()),
            ));

            false
        } else {
            true
        }
    }

    fn ns_entity_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<Eid> {
        match self.ns_lookup_kind(key, CompileError::UnresolvedEntity)? {
            NamespaceKind::Entity(eid) => Some(*eid),
            NamespaceKind::Service(eid) => Some(*eid),
            _ => None,
        }
    }

    fn ns_domain_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<AnyId> {
        match self.ns_lookup_kind(key, CompileError::UnresolvedService)? {
            NamespaceKind::Service(eid) => Some(AnyId::from_array(&eid.to_bytes())),
            NamespaceKind::Domain(dom_id) => Some(AnyId::from_array(&dom_id.to_bytes())),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedService);
                None
            }
        }
    }

    fn ns_property_lookup(
        &mut self,
        namespace: &Spanned<impl AsRef<str>>,
        key: &Spanned<impl AsRef<str>>,
    ) -> Option<ObjId> {
        match self.ns_lookup_entry(namespace, key, CompileError::UnresolvedProperty)? {
            NamespaceEntry::PropertyLabel(obj_id) => Some(*obj_id),
        }
    }

    fn ns_policy_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<ObjId> {
        match self.ns_lookup_kind(key, CompileError::UnresolvedProperty)? {
            NamespaceKind::Policy(obj_id) => Some(*obj_id),
            _ => {
                self.errors.push(key.span(), CompileError::UnresolvedPolicy);
                None
            }
        }
    }

    fn ns_lookup_kind(
        &mut self,
        key: &Spanned<impl AsRef<str>>,
        error: CompileError,
    ) -> Option<&NamespaceKind> {
        match self.namespaces.table.get(key.get_ref().as_ref()) {
            Some(namespace) => Some(&namespace.get_ref().kind),
            None => {
                self.errors.push(key.span(), error);
                None
            }
        }
    }

    fn ns_lookup_entry(
        &mut self,
        namespace: &Spanned<impl AsRef<str>>,
        key: &Spanned<impl AsRef<str>>,
        error: CompileError,
    ) -> Option<&NamespaceEntry> {
        match self
            .namespaces
            .get_entry(namespace.as_ref().as_ref(), key.as_ref().as_ref())
        {
            Ok(entry) => Some(entry),
            Err(NsLookupErr::Namespace) => {
                self.errors
                    .push(namespace.span(), CompileError::UnresolvedNamespace);
                None
            }
            Err(NsLookupErr::Entry) => {
                self.errors.push(key.span(), error);
                None
            }
        }
    }

    async fn db_domain_properties_cached<'s>(
        &'s mut self,
        dom_id: AnyId,
        property_kind: service_db::ServicePropertyKind,
        db: &impl Db,
    ) -> Option<&'s Vec<service_db::ServiceProperty>> {
        let cache = match property_kind {
            service_db::ServicePropertyKind::Entity => &mut self.eprop_cache,
            service_db::ServicePropertyKind::Resource => &mut self.rprop_cache,
        };

        match cache.entry(dom_id) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_props =
                    directory_db::list_domain_properties(db, self.dir_id, dom_id, property_kind)
                        .await
                        .handle_err(&mut self.errors)?;
                Some(vacant.insert(db_props))
            }
        }
    }

    async fn db_directory_policies_cached<'s>(
        &'s mut self,
        db: &impl Db,
    ) -> Option<&'s Vec<Identified<ObjId, policy_db::DbPolicy>>> {
        let cache = &mut self.policy_cache;

        match cache.entry(self.dir_id) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_policies = directory_db::directory_list_policies(db, self.dir_id)
                    .await
                    .handle_err(&mut self.errors)?;

                Some(vacant.insert(db_policies))
            }
        }
    }

    async fn db_directory_domains_cache<'s>(
        &'s mut self,
        db: &impl Db,
    ) -> Option<&'s HashMap<String, ObjId>> {
        if self.domain_cache.is_some() {
            Some(self.domain_cache.as_mut().unwrap())
        } else {
            let db_domains = directory_db::directory_list_domains(db, self.dir_id)
                .await
                .handle_err(&mut self.errors)?;

            Some(
                self.domain_cache.insert(
                    db_domains
                        .into_iter()
                        .map(|Identified(id, label)| (label, id))
                        .collect(),
                ),
            )
        }
    }
}

impl Errors {
    fn push(&mut self, span: Range<usize>, error: CompileError) {
        self.errors.push(Spanned::new(span, error));
    }
}

impl HandleError<DbError> for Errors {
    fn handle(&mut self, error: DbError) {
        self.push(0..0, CompileError::from(error));
    }
}

impl FromIterator<(String, NamespaceKind, Vec<(String, NamespaceEntry)>)> for Namespaces {
    fn from_iter<T: IntoIterator<Item = (String, NamespaceKind, Vec<(String, NamespaceEntry)>)>>(
        iter: T,
    ) -> Self {
        Self {
            table: FromIterator::from_iter(iter.into_iter().map(|(key, kind, entries)| {
                (
                    key,
                    Spanned::new(
                        0..0,
                        Namespace {
                            kind,
                            entries: entries
                                .into_iter()
                                .map(|(key, entry)| (key, Spanned::new(0..0, entry)))
                                .collect(),
                        },
                    ),
                )
            })),
        }
    }
}
