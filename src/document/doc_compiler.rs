use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::str::FromStr;
use std::{cmp, mem};
use std::{collections::HashMap, ops::Range};

use authly_common::id::{
    AnyId, AttrId, DirectoryId, DomainId, EntityId, PolicyId, PropId, ServiceId,
};
use authly_common::policy::code::PolicyValue;
use authly_common::{document, property::QualifiedAttributeName};
use authly_db::{Db, DbError};
use authly_domain::ctx::GetDb;
use authly_domain::directory::DirKey;
use authly_domain::id::BuiltinProp;
use serde::de::value::StrDeserializer;
use serde::Deserialize;
use serde_spanned::Spanned;
use tracing::debug;

use crate::ctx::KubernetesConfig;
use crate::db::directory_db::{query_dir_key, DbDirectoryNamespaceLabel, DbDirectoryPolicy};
use crate::db::policy_db::DbPolicy;
use crate::db::{directory_db, policy_db, service_db, Identified};
use crate::document::compiled_document::{
    CompiledEntityAttributeAssignment, CompiledService, ObjectIdent, ObjectTextAttr,
};
use crate::policy::compiler::PolicyCompiler;
use crate::settings::{Setting, Settings};
use crate::util::error::{HandleError, ResultExt};

use super::compiled_document::{
    CompiledAttribute, CompiledDocument, CompiledDocumentData, CompiledEntityRelation,
    CompiledProperty, DocumentMeta,
};
use super::error::DocError;

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

    fn insert_builtin_property(&mut self, builtin: BuiltinProp) {
        let namespace = self.table.get_mut("authly").unwrap();
        namespace.as_mut().entries.insert(
            builtin.label().unwrap().to_string(),
            Spanned::new(0..0, NamespaceEntry::PropertyLabel(builtin.into())),
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
    Entity(EntityId),
    Service(ServiceId),
    Domain(DomainId),
    Policy(PolicyId),
}

struct CompileCtx {
    dir_key: DirKey,
    dir_id: DirectoryId,

    namespaces: Namespaces,

    prop_cache: HashMap<AnyId, Vec<service_db::NamespaceProperty>>,
    policy_cache: HashMap<DirectoryId, Vec<DbDirectoryPolicy>>,
    label_cache: Option<HashMap<String, AnyId>>,

    errors: Errors,
}

#[derive(Debug)]
pub enum NamespaceEntry {
    PropertyLabel(PropId),
}

#[derive(Default)]
struct Errors {
    errors: Vec<Spanned<DocError>>,
}

pub async fn compile_doc(
    deps: &(impl GetDb + KubernetesConfig),
    mut doc: document::Document,
    meta: DocumentMeta,
) -> Result<CompiledDocument, Vec<Spanned<DocError>>> {
    let db = deps.get_db();
    let dir_id = DirectoryId::from_uint(doc.authly_document.id.get_ref().as_u128());
    let dir_key = query_dir_key(db, dir_id)
        .await
        .map_err(|err| vec![Spanned::new(0..0, DocError::Db(err.to_string()))])?
        .unwrap_or(DirKey(-1));

    let mut comp = CompileCtx {
        dir_key,
        dir_id,
        namespaces: Default::default(),
        prop_cache: Default::default(),
        policy_cache: Default::default(),
        label_cache: Default::default(),
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
                        comp.errors.push(key.span(), DocError::LocalSettingNotFound);
                        continue;
                    }
                };

            if let Err(err) = test_settings.try_set(setting, Cow::Borrowed(value.as_ref())) {
                comp.errors.push(
                    value.span(),
                    DocError::InvalidSettingValue(format!("{err}")),
                );
                continue;
            }

            data.settings.insert(setting, value.into_inner());
        }
    }

    {
        seed_namespace(&doc, &mut comp);

        for domain in mem::take(&mut doc.domain) {
            let Some(cache) = comp.db_directory_namespace_labels_cached(db).await else {
                continue;
            };

            let id = cache
                .get(domain.label.as_ref())
                .copied()
                .and_then(|id| DomainId::try_from(id).ok())
                .unwrap_or_else(DomainId::random);

            comp.ns_add(&domain.label, NamespaceKind::Domain(id));

            data.namespaces.insert(
                id.upcast(),
                (domain.label.as_ref().to_string(), domain.label.span()),
            );

            if let Some(metadata) = domain.metadata {
                let span = metadata.span();
                data.obj_text_attrs.push((
                    ObjectTextAttr {
                        obj_id: id.upcast(),
                        prop_id: PropId::from(BuiltinProp::Metadata),
                        value: serde_json::to_string(&metadata).expect("already valid json"),
                    },
                    span,
                ));
            }
        }
    }

    debug!("namespace: {:#?}", comp.namespaces.table);

    for entity in &mut doc.entity {
        if let Some(username) = entity.username.take() {
            let span = username.span();
            data.entity_ident.push((
                ObjectIdent {
                    obj_id: entity.eid.as_ref().upcast(),
                    prop_id: BuiltinProp::Username.into(),
                    ident: username.into_inner(),
                },
                span,
            ));
        }

        if let Some(metadata) = entity.metadata.take() {
            comp.errors
                .push(metadata.span(), DocError::MetadataNotSupported);
        }
    }

    for entity in &mut doc.service_entity {
        let Ok(svc_eid) = ServiceId::try_from(*entity.eid.as_ref()) else {
            comp.errors
                .push(entity.eid.span(), DocError::MustBeAServiceId);
            continue;
        };

        if let Some(label) = &entity.label {
            data.namespaces
                .insert(svc_eid.upcast(), (label.as_ref().to_string(), label.span()));
        }

        if let Some(k8s) = mem::take(&mut entity.kubernetes_account) {
            data.obj_text_attrs.push((
                ObjectTextAttr {
                    obj_id: svc_eid.upcast(),
                    prop_id: BuiltinProp::K8sConfiguredServiceAccount.into(),
                    value: format!(
                        "{namespace}/{account}",
                        namespace = k8s.namespace.as_deref().unwrap_or("*"),
                        account = k8s.name
                    ),
                },
                0..0,
            ));
            data.obj_text_attrs.push((
                ObjectTextAttr {
                    obj_id: svc_eid.upcast(),
                    prop_id: BuiltinProp::K8sLocalServiceAccount.into(),
                    value: format!(
                        "{namespace}/{account}",
                        namespace = k8s
                            .namespace
                            .as_deref()
                            .unwrap_or(deps.authly_local_k8s_namespace()),
                        account = k8s.name
                    ),
                },
                0..0,
            ));
        }

        let service = CompiledService {
            hosts: mem::take(&mut entity.hosts),
        };

        data.services.insert(svc_eid, service);

        if let Some(metadata) = entity.metadata.take() {
            let span = metadata.span();
            data.obj_text_attrs.push((
                ObjectTextAttr {
                    obj_id: svc_eid.upcast(),
                    prop_id: PropId::from(BuiltinProp::Metadata),
                    value: serde_json::to_string(&metadata).expect("already valid json"),
                },
                span,
            ));
        }
    }

    for email in mem::take(&mut doc.email) {
        let Some(eid) = comp.ns_entity_lookup(&email.entity) else {
            continue;
        };

        let span = email.value.span();
        data.entity_ident.push((
            ObjectIdent {
                obj_id: eid.upcast(),
                prop_id: BuiltinProp::Email.into(),
                ident: email.value.into_inner(),
            },
            span,
        ));
    }

    for hash in mem::take(&mut doc.password_hash) {
        let Some(eid) = comp.ns_entity_lookup(&hash.entity) else {
            continue;
        };

        data.obj_text_attrs.push((
            ObjectTextAttr {
                obj_id: eid.upcast(),
                prop_id: BuiltinProp::PasswordHash.into(),
                value: hash.hash,
            },
            0..0,
        ));
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

    process_entity_attribute_assignments(
        mem::take(&mut doc.entity_attribute_assignment),
        &mut data,
        &mut comp,
    )
    .await;

    for doc_svc_domain in doc.service_domain {
        if let (Some(svc_eid), Some(dom_id)) = (
            comp.ns_service_lookup(&doc_svc_domain.service),
            comp.ns_dyn_namespace_lookup(&doc_svc_domain.domain),
        ) {
            match DomainId::try_from(dom_id) {
                Ok(domain_id) => {
                    data.service_domains.push((svc_eid, domain_id));
                }
                Err(_) => {
                    comp.errors
                        .push(doc_svc_domain.domain.span(), DocError::UnresolvedDomain);
                }
            }
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
    for builtin_prop in [BuiltinProp::Entity, BuiltinProp::AuthlyRole] {
        comp.namespaces.insert_builtin_property(builtin_prop);
    }

    for entity in &doc.entity {
        if let Some(label) = &entity.label {
            comp.ns_add(label, NamespaceKind::Entity(*entity.eid.get_ref()));
        }
    }

    for entity in &doc.service_entity {
        if let Some(label) = &entity.label {
            // this is error-checked elsewhere
            if let Ok(svc_id) = ServiceId::try_from(*entity.eid.get_ref()) {
                comp.ns_add(label, NamespaceKind::Service(svc_id));
            }
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
                    relation: BuiltinProp::RelEntityMembership.into(),
                    object: member_eid,
                });
            };
        }
    }
}

async fn process_entity_attribute_assignments(
    assignments: Vec<document::EntityAttributeAssignment>,
    data: &mut CompiledDocumentData,
    comp: &mut CompileCtx,
) {
    for binding in assignments {
        let Some(eid) = comp.ns_entity_lookup(&binding.entity) else {
            continue;
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
                            .push(spanned_qattr.span(), DocError::UnresolvedAttribute);
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
        let Some(ns_id) = comp.ns_dyn_namespace_lookup(&doc_eprop.namespace) else {
            continue;
        };

        if let Some(compiled_property) = compile_ns_property(
            &doc_eprop.namespace,
            ns_id,
            service_db::PropertyKind::Entity,
            &doc_eprop.label,
            doc_eprop.attributes,
            comp,
            db,
        )
        .await
        {
            data.domain_props.push(compiled_property);
        }
    }

    for doc_rprop in resource_properties {
        let Some(ns_id) = comp.ns_dyn_namespace_lookup(&doc_rprop.namespace) else {
            continue;
        };

        if let Some(compiled_property) = compile_ns_property(
            &doc_rprop.namespace,
            ns_id,
            service_db::PropertyKind::Resource,
            &doc_rprop.label,
            doc_rprop.attributes,
            comp,
            db,
        )
        .await
        {
            data.domain_props.push(compiled_property);
        }
    }
}

async fn compile_ns_property(
    namespace: &Spanned<String>,
    ns_id: AnyId,
    property_kind: service_db::PropertyKind,
    doc_property_label: &Spanned<String>,
    doc_attributes: Vec<Spanned<String>>,
    comp: &mut CompileCtx,
    db: &impl Db,
) -> Option<CompiledProperty> {
    let db_props_cached = comp.db_namespace_properties_cached(ns_id, db).await?;

    let db_eprop = db_props_cached.iter().find(|db_prop| {
        db_prop.kind == property_kind && &db_prop.label == doc_property_label.as_ref()
    });

    let mut compiled_property = CompiledProperty {
        id: db_eprop
            .as_ref()
            .map(|db_prop| db_prop.id)
            .unwrap_or_else(PropId::random),
        ns_id,
        kind: property_kind,
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
                .unwrap_or_else(AttrId::random),
            label: doc_attribute.into_inner(),
        });
    }

    comp.ns_add_entry(
        namespace,
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
    let mut assignments: Vec<(EntityId, Spanned<QualifiedAttributeName>)> = vec![];

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
                    .push(spanned_qattr.span(), DocError::UnresolvedAttribute);
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
        let (src, class) = match (policy.allow, policy.deny) {
            (Some(src), None) => (src, PolicyValue::Allow),
            (None, Some(src)) => (src, PolicyValue::Deny),
            (Some(allow), Some(deny)) => {
                let span = cmp::min(allow.span().start, deny.span().start)
                    ..cmp::max(allow.span().end, deny.span().end);

                comp.errors.push(span, DocError::AmbiguousPolicyOutcome);
                continue;
            }
            (None, None) => {
                comp.errors
                    .push(policy.label.span(), DocError::PolicyBodyMissing);
                continue;
            }
        };

        let mut policy_compiler = PolicyCompiler::new(&comp.namespaces, data);

        let (expr, _bytecode) = match policy_compiler.compile(src.as_ref()) {
            Ok(compiled_policy) => compiled_policy,
            Err(errors) => {
                for error in errors {
                    // translate the policy error span into the document
                    let mut error_span = error.span;
                    error_span.start += src.span().start;
                    error_span.end += src.span().end;

                    comp.errors.push(error_span, DocError::Policy(error.kind));
                }

                continue;
            }
        };

        let db_cache = comp.db_directory_policies_cached(db).await;
        let cached_policy = db_cache
            .iter()
            .flat_map(|c| c.iter())
            .find(|db_policy| &db_policy.policy.label == policy.label.as_ref());

        let policy_postcard = policy_db::PolicyPostcard { class, expr };

        let namespace_label = policy.label.as_ref().to_string();
        let label_span = policy.label.span();

        let service_policy: Identified<PolicyId, DbPolicy> =
            if let Some(cached_policy) = cached_policy {
                Identified(
                    cached_policy.id,
                    policy_db::DbPolicy {
                        label: policy.label.into_inner(),
                        policy: policy_postcard,
                    },
                )
            } else {
                Identified(
                    PolicyId::random(),
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
        let mut policy_binding = policy_db::DbPolicyBinding {
            attr_matcher: Default::default(),
            policies: Default::default(),
        };

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
                            .push(spanned_qattr.span(), DocError::UnresolvedAttribute);
                        continue;
                    }
                };

            policy_binding.attr_matcher.insert(attr_id);
        }

        for spanned_policy in binding.policies {
            let Some(policy_id) = comp.ns_policy_lookup(&spanned_policy) else {
                continue;
            };

            policy_binding.policies.insert(policy_id);
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
                DocError::NameDefinedMultipleTimes(entry.span(), namespace.get_ref().to_string()),
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
                DocError::UnresolvedNamespace,
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
                DocError::NameDefinedMultipleTimes(entry.span(), key.get_ref().to_string()),
            ));

            false
        } else {
            true
        }
    }

    fn ns_entity_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<EntityId> {
        if let Ok(entity_id) = EntityId::from_str(key.as_ref().as_ref()) {
            return Some(entity_id);
        }

        match self.ns_lookup_kind(key, DocError::UnresolvedEntity)? {
            NamespaceKind::Entity(eid) => Some(*eid),
            NamespaceKind::Service(eid) => Some(eid.upcast()),
            _ => None,
        }
    }

    fn ns_service_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<ServiceId> {
        if let Ok(svc_id) = ServiceId::from_str(key.as_ref().as_ref()) {
            return Some(svc_id);
        }

        match self.ns_lookup_kind(key, DocError::UnresolvedEntity)? {
            NamespaceKind::Service(eid) => Some(*eid),
            _ => None,
        }
    }

    fn ns_dyn_namespace_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<AnyId> {
        if let Ok(entity_id) = EntityId::from_str(key.as_ref().as_ref()) {
            return Some(entity_id.upcast());
        }

        match self.ns_lookup_kind(key, DocError::UnresolvedService)? {
            NamespaceKind::Service(eid) => Some(eid.upcast()),
            NamespaceKind::Domain(dom_id) => Some(dom_id.upcast()),
            _ => {
                self.errors.push(key.span(), DocError::UnresolvedService);
                None
            }
        }
    }

    fn ns_property_lookup(
        &mut self,
        namespace: &Spanned<impl AsRef<str>>,
        key: &Spanned<impl AsRef<str>>,
    ) -> Option<PropId> {
        match self.ns_lookup_entry(namespace, key, DocError::UnresolvedProperty)? {
            NamespaceEntry::PropertyLabel(prop_id) => Some(*prop_id),
        }
    }

    fn ns_policy_lookup(&mut self, key: &Spanned<impl AsRef<str>>) -> Option<PolicyId> {
        match self.ns_lookup_kind(key, DocError::UnresolvedProperty)? {
            NamespaceKind::Policy(policy_id) => Some(*policy_id),
            _ => {
                self.errors.push(key.span(), DocError::UnresolvedPolicy);
                None
            }
        }
    }

    fn ns_lookup_kind(
        &mut self,
        key: &Spanned<impl AsRef<str>>,
        error: DocError,
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
        error: DocError,
    ) -> Option<&NamespaceEntry> {
        match self
            .namespaces
            .get_entry(namespace.as_ref().as_ref(), key.as_ref().as_ref())
        {
            Ok(entry) => Some(entry),
            Err(NsLookupErr::Namespace) => {
                self.errors
                    .push(namespace.span(), DocError::UnresolvedNamespace);
                None
            }
            Err(NsLookupErr::Entry) => {
                self.errors.push(key.span(), error);
                None
            }
        }
    }

    async fn db_namespace_properties_cached<'s>(
        &'s mut self,
        ns_id: AnyId,
        db: &impl Db,
    ) -> Option<&'s Vec<service_db::NamespaceProperty>> {
        match self.prop_cache.entry(ns_id) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_props = directory_db::list_namespace_properties(db, self.dir_key, ns_id)
                    .await
                    .handle_err(&mut self.errors)?;
                Some(vacant.insert(db_props))
            }
        }
    }

    async fn db_directory_policies_cached<'s>(
        &'s mut self,
        db: &impl Db,
    ) -> Option<&'s Vec<DbDirectoryPolicy>> {
        let cache = &mut self.policy_cache;

        match cache.entry(self.dir_id) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_policies = DbDirectoryPolicy::query(db, self.dir_key)
                    .await
                    .handle_err(&mut self.errors)?;

                Some(vacant.insert(db_policies))
            }
        }
    }

    async fn db_directory_namespace_labels_cached<'s>(
        &'s mut self,
        db: &impl Db,
    ) -> Option<&'s HashMap<String, AnyId>> {
        if self.label_cache.is_some() {
            Some(self.label_cache.as_mut().unwrap())
        } else {
            let db_domains = DbDirectoryNamespaceLabel::query(db, self.dir_key)
                .await
                .handle_err(&mut self.errors)?;

            Some(
                self.label_cache.insert(
                    db_domains
                        .into_iter()
                        .map(|DbDirectoryNamespaceLabel { id, label }| (label, id))
                        .collect(),
                ),
            )
        }
    }
}

impl Errors {
    fn push(&mut self, span: Range<usize>, error: DocError) {
        self.errors.push(Spanned::new(span, error));
    }
}

impl HandleError<DbError> for Errors {
    fn handle(&mut self, error: DbError) {
        self.push(0..0, DocError::from(error));
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
