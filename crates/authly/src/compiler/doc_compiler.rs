use std::collections::hash_map::Entry;
use std::{collections::HashMap, ops::Range};

use authly_domain::{document::Document, EID};
use serde_spanned::Spanned;
use tracing::info;

use crate::db::service_db::ServicePropertyKind;
use crate::{
    db::service_db::{self, ServiceProperty},
    AuthlyCtx,
};

use super::compiled_document::{
    CompileError, CompiledDocument, CompiledDocumentData, CompiledGroupMembership, CompiledProperty,
};

struct CompileCtx<'a> {
    authority_eid: EID,

    namespace: HashMap<&'a str, Spanned<NamespaceEntry>>,

    eprop_cache: HashMap<EID, Vec<ServiceProperty>>,
    rprop_cache: HashMap<EID, Vec<ServiceProperty>>,

    errors: Errors,
}

#[derive(Debug)]
enum NamespaceEntry {
    User(EID),
    Group(EID),
    Service(EID),
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
        authority_eid: EID(doc.authly_document.id.get_ref().as_u128()),
        namespace: Default::default(),
        eprop_cache: Default::default(),
        rprop_cache: Default::default(),
        errors: Default::default(),
    };
    let mut data = CompiledDocumentData::default();

    data.users = doc.user;
    data.groups = doc.group;
    data.services = doc.service;

    for user in &data.users {
        if let Some(name) = &user.name {
            comp.ns_add(name, NamespaceEntry::User(*user.eid.get_ref()));
        }
    }

    for group in &data.groups {
        comp.ns_add(&group.name, NamespaceEntry::Group(*group.eid.get_ref()));
    }

    for service in &data.services {
        if let Some(label) = &service.label {
            comp.ns_add(&label, NamespaceEntry::Service(*service.eid.get_ref()));
        }
    }

    info!("namespace: {:#?}", comp.namespace);

    for gm in &doc.group_membership {
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

    for doc_eprop in &doc.entity_property {
        if let Some(scope) = &doc_eprop.scope {
            let Some(svc_eid) = comp.ns_service_lookup(scope) else {
                continue;
            };

            if let Some(compiled_property) = compile_service_property(
                svc_eid,
                ServicePropertyKind::Entity,
                doc_eprop.name.as_ref(),
                &doc_eprop.attributes,
                &mut comp,
                ctx,
            )
            .await
            {
                data.service_entity_props.push(compiled_property);
            }
        }
    }

    for doc_rprop in &doc.resource_property {
        let Some(svc_eid) = comp.ns_service_lookup(&doc_rprop.scope) else {
            continue;
        };

        if let Some(compiled_property) = compile_service_property(
            svc_eid,
            ServicePropertyKind::Resource,
            doc_rprop.name.as_ref(),
            &doc_rprop.attributes,
            &mut comp,
            ctx,
        )
        .await
        {
            data.service_resource_props.push(compiled_property);
        }
    }

    if !comp.errors.errors.is_empty() {
        Err(comp.errors.errors)
    } else {
        Ok(CompiledDocument {
            authority_eid: comp.authority_eid,
            data,
        })
    }
}

async fn compile_service_property<'a>(
    svc_eid: EID,
    property_kind: ServicePropertyKind,
    doc_property_name: &str,
    doc_attributes: &[Spanned<String>],
    comp: &mut CompileCtx<'a>,
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
        .find(|db_prop| &db_prop.name == doc_property_name);

    let mut compiled_property = CompiledProperty {
        id: db_eprop
            .as_ref()
            .map(|db_prop| db_prop.id)
            .unwrap_or_else(EID::random),
        svc_eid,
        name: doc_property_name.to_string(),
        attributes: vec![],
    };

    for doc_attribute in doc_attributes {
        let db_attr = db_eprop.as_ref().and_then(|db_eprop| {
            db_eprop
                .attributes
                .iter()
                .find(|attr| &attr.1 == doc_attribute.as_ref())
        });

        compiled_property.attributes.push((
            db_attr
                .as_ref()
                .map(|attr| attr.0)
                .unwrap_or_else(EID::random),
            doc_attribute.get_ref().to_string(),
        ));
    }

    Some(compiled_property)
}

impl<'a> CompileCtx<'a> {
    fn ns_add(&mut self, name: &'a Spanned<String>, entry: NamespaceEntry) -> bool {
        if let Some(entry) = self
            .namespace
            .insert(name.get_ref().as_str(), Spanned::new(name.span(), entry))
        {
            self.errors.errors.push(Spanned::new(
                name.span(),
                CompileError::NameDefinedMultipleTimes(entry.span()),
            ));

            false
        } else {
            true
        }
    }

    fn ns_profile_lookup(&mut self, key: &'a Spanned<String>) -> Option<EID> {
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

    fn ns_group_lookup(&mut self, key: &'a Spanned<String>) -> Option<EID> {
        match self.ns_lookup(key, CompileError::UnresolvedGroup)? {
            NamespaceEntry::Group(eid) => Some(*eid),
            _ => {
                self.errors.push(key.span(), CompileError::UnresolvedGroup);
                None
            }
        }
    }

    fn ns_service_lookup(&mut self, key: &'a Spanned<String>) -> Option<EID> {
        match self.ns_lookup(key, CompileError::UnresolvedService)? {
            NamespaceEntry::Service(eid) => Some(*eid),
            _ => {
                self.errors
                    .push(key.span(), CompileError::UnresolvedService);
                None
            }
        }
    }

    fn ns_lookup(
        &mut self,
        key: &'a Spanned<String>,
        error: CompileError,
    ) -> Option<&NamespaceEntry> {
        match self.namespace.get(key.get_ref().as_str()) {
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
                    self.authority_eid,
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
