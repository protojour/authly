use std::cmp;
use std::collections::hash_map::Entry;
use std::{collections::HashMap, ops::Range};

use authly_domain::BuiltinID;
use authly_domain::{document::Document, EID};
use serde_spanned::Spanned;
use tracing::debug;

use crate::db::service_db::ServicePropertyKind;
use crate::document::compiled_document::{EntityIdent, EntityPassword};
use crate::policy::compiler::PolicyCompiler;
use crate::policy::PolicyOutcome;
use crate::{
    db::service_db::{self, ServiceProperty},
    AuthlyCtx,
};

use super::compiled_document::{
    CompileError, CompiledAttribute, CompiledDocument, CompiledDocumentData,
    CompiledGroupMembership, CompiledProperty,
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
}

struct CompileCtx {
    /// Authority ID
    aid: EID,

    namespace: Namespace,

    eprop_cache: HashMap<EID, Vec<ServiceProperty>>,
    rprop_cache: HashMap<EID, Vec<ServiceProperty>>,

    errors: Errors,
}

#[derive(Debug)]
pub enum NamespaceEntry {
    User(EID),
    Group(EID),
    Service(EID),
    PropertyLabel(EID),
}

#[derive(Default)]
struct Errors {
    errors: Vec<Spanned<CompileError>>,
}

pub async fn compile_doc(
    doc: Document,
    ctx: &AuthlyCtx,
) -> Result<CompiledDocument, Vec<Spanned<CompileError>>> {
    let mut comp = CompileCtx {
        aid: EID(doc.authly_document.id.get_ref().as_u128()),
        namespace: Default::default(),
        eprop_cache: Default::default(),
        rprop_cache: Default::default(),
        errors: Default::default(),
    };
    let mut data = CompiledDocumentData::default();

    // setup namespace
    comp.namespace.table.insert(
        "entity".to_string(),
        Spanned::new(
            0..0,
            NamespaceEntry::PropertyLabel(BuiltinID::PropEntity.to_eid()),
        ),
    );

    data.users = doc.user;
    data.groups = doc.group;
    data.services = doc.service;

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

    for gm in doc.group_membership {
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

    for doc_eprop in doc.entity_property {
        if let Some(svc_label) = &doc_eprop.service {
            let Some(svc_eid) = comp.ns_service_lookup(svc_label) else {
                continue;
            };

            if let Some(compiled_property) = compile_service_property(
                svc_eid,
                ServicePropertyKind::Entity,
                &doc_eprop.label,
                doc_eprop.attributes,
                &mut comp,
                ctx,
            )
            .await
            {
                data.svc_ent_props.push(compiled_property);
            }
        }
    }

    for doc_rprop in doc.resource_property {
        let Some(svc_eid) = comp.ns_service_lookup(&doc_rprop.service) else {
            continue;
        };

        if let Some(compiled_property) = compile_service_property(
            svc_eid,
            ServicePropertyKind::Resource,
            &doc_rprop.label,
            doc_rprop.attributes,
            &mut comp,
            ctx,
        )
        .await
        {
            data.svc_res_props.push(compiled_property);
        }
    }

    for policy in doc.policy {
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
            match PolicyCompiler::new(&comp.namespace, &data, outcome).compile(src.as_ref()) {
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

    if !comp.errors.errors.is_empty() {
        Err(comp.errors.errors)
    } else {
        Ok(CompiledDocument {
            aid: comp.aid,
            data,
        })
    }
}

async fn compile_service_property(
    svc_eid: EID,
    property_kind: ServicePropertyKind,
    doc_property_label: &Spanned<String>,
    doc_attributes: Vec<Spanned<String>>,
    comp: &mut CompileCtx,
    ctx: &AuthlyCtx,
) -> Option<CompiledProperty> {
    let Some(db_props_cached) = comp
        .db_service_properties_cached(svc_eid, property_kind, ctx)
        .await
    else {
        return None;
    };

    let db_eprop = db_props_cached
        .iter()
        .find(|db_prop| &db_prop.label == doc_property_label.as_ref());

    let mut compiled_property = CompiledProperty {
        id: db_eprop
            .as_ref()
            .map(|db_prop| db_prop.id)
            .unwrap_or_else(EID::random),
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
                .unwrap_or_else(EID::random),
            label: doc_attribute.into_inner(),
        });
    }

    comp.ns_add(
        doc_property_label,
        NamespaceEntry::PropertyLabel(compiled_property.id),
    );

    Some(compiled_property)
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

    fn ns_entity_lookup(&mut self, key: &Spanned<String>) -> Option<EID> {
        match self.ns_lookup(key, CompileError::UnresolvedEntity)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            NamespaceEntry::User(eid) => Some(*eid),
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => None,
        }
    }

    fn ns_profile_lookup(&mut self, key: &Spanned<String>) -> Option<EID> {
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

    fn ns_group_lookup(&mut self, key: &Spanned<String>) -> Option<EID> {
        match self.ns_lookup(key, CompileError::UnresolvedGroup)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            _ => {
                self.errors.push(key.span(), CompileError::UnresolvedGroup);
                None
            }
        }
    }

    fn ns_service_lookup(&mut self, key: &Spanned<String>) -> Option<EID> {
        match self.ns_lookup(key, CompileError::UnresolvedService)? {
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedService);
                None
            }
        }
    }

    fn ns_lookup(&mut self, key: &Spanned<String>, error: CompileError) -> Option<&NamespaceEntry> {
        match self.namespace.table.get(key.get_ref().as_str()) {
            Some(entry) => Some(entry.get_ref()),
            None => {
                self.errors.push(key.span(), error);
                None
            }
        }
    }

    async fn db_service_properties_cached<'s>(
        &'s mut self,
        svc_eid: EID,
        property_kind: ServicePropertyKind,
        ctx: &AuthlyCtx,
    ) -> Option<&'s Vec<ServiceProperty>> {
        let cache = match property_kind {
            ServicePropertyKind::Entity => &mut self.eprop_cache,
            ServicePropertyKind::Resource => &mut self.rprop_cache,
        };

        match cache.entry(svc_eid) {
            Entry::Occupied(occupied) => Some(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let db_props = match service_db::list_service_properties(
                    self.aid,
                    svc_eid,
                    property_kind,
                    ctx,
                )
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
