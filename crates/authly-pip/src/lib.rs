#![allow(unused)]

use std::collections::{BTreeSet, HashMap, HashSet};

use authly_domain::Eid;
use authly_policy::OpCode;
use rand::Rng;

fn random_id() -> u128 {
    loop {
        let id = rand::thread_rng().gen();
        // low IDs are reserved for builtin/fixed
        if id > 32767 {
            return id;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PropId(pub u128);

impl PropId {
    pub fn random() -> Self {
        Self(random_id())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjId(pub u128);

impl ObjId {
    pub fn random() -> Self {
        Self(random_id())
    }
}

mod builtin {
    use super::*;

    pub const EID: PropId = PropId(0);
    pub const EMAIL: PropId = PropId(1);
    pub const SUBTYPE: PropId = PropId(2);
    pub const MEMBER: PropId = PropId(3);
    pub const USERNAME: PropId = PropId(4);
    pub const PASSWORD: PropId = PropId(5);
    pub const SERVICE_NAME: PropId = PropId(6);

    pub const SUBTYPE_USER: ObjId = ObjId(0);
    pub const SUBTYPE_GROUP: ObjId = ObjId(1);
    pub const SUBTYPE_SERVICE: ObjId = ObjId(2);
}

#[derive(Default, Debug)]
pub struct Model {
    entity_attrs: Vec<Attribute>,
    entity_rels: Vec<Relationship>,
    entity_tags: HashMap<Eid, BTreeSet<ObjId>>,
    services: HashMap<Eid, Service>,
    policies: HashMap<Eid, HashMap<ObjId, Policy>>,
    tag_policies: HashMap<ObjId, HashSet<ObjId>>,

    properties: Properties,
}

impl Model {
    fn add_user(&mut self, data: UserData) -> Eid {
        let eid = Eid::random();
        self.entity_tags
            .entry(eid)
            .or_default()
            .insert(builtin::SUBTYPE_USER);
        self.entity_attrs.extend([
            Attribute {
                subject: eid,
                property: builtin::EMAIL,
                value: AttrValue::Text(data.email),
            },
            Attribute {
                subject: eid,
                property: builtin::USERNAME,
                value: AttrValue::Text(data.username),
            },
            Attribute {
                subject: eid,
                property: builtin::PASSWORD,
                value: AttrValue::Text(data.password),
            },
        ]);
        for tag in data.tags {
            self.entity_tags.entry(eid).or_default().insert(tag);
        }
        eid
    }

    fn add_group(&mut self, name: impl Into<String>) -> Eid {
        let eid = Eid::random();
        self.entity_tags
            .entry(eid)
            .or_default()
            .insert(builtin::SUBTYPE_GROUP);
        eid
    }

    fn set_membership(&mut self, subject: Eid, object: Eid) {
        self.entity_rels.push(Relationship {
            subject,
            property: builtin::MEMBER,
            object,
        });
    }

    fn add_service(&mut self, name: impl Into<String>) -> Eid {
        let eid = Eid::random();
        self.entity_tags
            .entry(eid)
            .or_default()
            .insert(builtin::SUBTYPE_SERVICE);
        self.entity_attrs.extend([Attribute {
            subject: eid,
            property: builtin::SERVICE_NAME,
            value: AttrValue::Text(name.into()),
        }]);
        self.services.insert(
            eid,
            Service {
                encryption_key: rand::thread_rng().gen(),
            },
        );
        eid
    }

    fn add_policy(&mut self, svc: Eid, name: impl Into<String>, opcodes: Vec<OpCode>) -> ObjId {
        let id = ObjId::random();
        self.policies.entry(svc).or_default().insert(
            id,
            Policy {
                name: name.into(),
                opcodes,
            },
        );
        id
    }

    fn bind_tag_policies(&mut self, items: impl IntoIterator<Item = (ObjId, ObjId)>) {
        for (tag_id, policy_id) in items {
            self.tag_policies
                .entry(tag_id)
                .or_default()
                .insert(policy_id);
        }
    }
}

#[derive(Debug)]
struct Attribute {
    pub subject: Eid,
    pub property: PropId,
    pub value: AttrValue,
}

#[derive(Debug)]
struct Relationship {
    pub subject: Eid,
    pub property: PropId,
    pub object: Eid,
}

#[derive(Debug)]
enum AttrValue {
    Text(String),
    SecretText(String),
    SecretBytes(Vec<u8>),
}

struct UserData {
    pub username: String,
    pub password: String,
    pub email: String,
    pub tags: BTreeSet<ObjId>,
}

#[derive(Debug)]
struct Service {
    pub encryption_key: u128,
}

#[derive(Default, Debug)]
struct Properties {
    properties: Vec<Property>,
}

impl Properties {
    pub fn svc_entity_tags(&mut self, name: impl Into<String>, entity: Eid) -> (PropId, &mut Tags) {
        self.new_attr(name, PropertyScope::ServiceEntity(entity))
    }

    pub fn svc_resource_tags(
        &mut self,
        name: impl Into<String>,
        service: Eid,
    ) -> (PropId, &mut Tags) {
        self.new_attr(name, PropertyScope::ServiceResource(service))
    }

    pub fn new_attr(
        &mut self,
        name: impl Into<String>,
        scope: PropertyScope,
    ) -> (PropId, &mut Tags) {
        let id = PropId::random();
        self.properties.push(Property {
            id,
            name: name.into(),
            scope,
            kind: PropertyKind::Tags(Default::default()),
        });
        let last = self.properties.last_mut().unwrap();
        match &mut last.kind {
            PropertyKind::Tags(attrs) => (id, attrs),
            _ => panic!(),
        }
    }
}

#[derive(Debug)]
struct Property {
    pub id: PropId,
    pub name: String,
    pub scope: PropertyScope,
    pub kind: PropertyKind,
}

#[derive(Debug)]
enum PropertyScope {
    GlobalEntities,
    ServiceEntity(Eid),
    ServiceResource(Eid),
}

#[derive(Debug)]
enum PropertyKind {
    Eid,
    Tags(Tags),
}

#[derive(Default, Debug)]
struct Tags {
    pub tags: Vec<Tag>,
}

impl Tags {
    fn add(&mut self, name: impl Into<String>) -> ObjId {
        let id = ObjId::random();
        self.tags.push(Tag {
            id,
            name: name.into(),
        });
        id
    }
}

#[derive(Debug)]
struct Tag {
    pub id: ObjId,
    pub name: String,
}

#[derive(Debug)]
struct Policy {
    name: String,
    opcodes: Vec<OpCode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoriam_model() {
        let mut model = Model::default();

        let svc_memoriam = model.add_service("memoriam");

        let (_, role) = model.properties.svc_entity_tags("role", svc_memoriam);
        let role_onto_admin = role.add("onto_admin");
        let role_onto_user = role.add("onto_user");

        let (_, resource_name) = model.properties.svc_resource_tags("name", svc_memoriam);
        let resource_name_ontology = resource_name.add("ontology");
        let resource_name_storage = resource_name.add("storage");

        let (_, ontology_action) = model
            .properties
            .svc_resource_tags("ontology_action", svc_memoriam);
        let ontology_read = ontology_action.add("read");
        let ontology_deploy = ontology_action.add("deploy");
        let ontology_stop = ontology_action.add("stop");

        let (_, buckets_action) = model
            .properties
            .svc_resource_tags("buckets_action", svc_memoriam);
        let buckets_read = buckets_action.add("read");

        let (_, bucket_action) = model
            .properties
            .svc_resource_tags("bucket_action", svc_memoriam);
        let bucket_read = bucket_action.add("read");
        let bucket_create = bucket_action.add("create");
        let bucket_delete = bucket_action.add("delete");

        let (_, object_action) = model
            .properties
            .svc_entity_tags("object_action", svc_memoriam);
        let object_read = object_action.add("read");
        let object_create = object_action.add("create");
        let object_delete = object_action.add("delete");

        let plc_allow_onto_users = model.add_policy(
            svc_memoriam,
            "allow for onto users",
            vec![
                OpCode::LoadSubjectTags,
                OpCode::LoadConstId(role_onto_user.0),
                OpCode::ContainsTag,
                OpCode::TrueThenAllow,
            ],
        );
        let plc_allow_onto_admin = model.add_policy(
            svc_memoriam,
            "allow for onto admin",
            vec![
                OpCode::LoadSubjectTags,
                OpCode::LoadConstId(role_onto_admin.0),
                OpCode::ContainsTag,
                OpCode::TrueThenAllow,
            ],
        );
        let plc_allow_memoriam = model.add_policy(
            svc_memoriam,
            "allow for memoriam",
            vec![
                OpCode::LoadSubjectEid(builtin::EID.0),
                OpCode::LoadConstId(svc_memoriam.value()),
                OpCode::IsEq,
                OpCode::TrueThenAllow,
            ],
        );

        model.bind_tag_policies([
            (ontology_read, plc_allow_memoriam),
            (ontology_read, plc_allow_onto_users),
            (ontology_deploy, plc_allow_memoriam),
            (ontology_deploy, plc_allow_onto_admin),
            (ontology_stop, plc_allow_memoriam),
            (ontology_stop, plc_allow_onto_admin),
            (buckets_read, plc_allow_onto_users),
            (bucket_read, plc_allow_onto_users),
            (bucket_create, plc_allow_onto_users),
            (bucket_delete, plc_allow_onto_users),
            (object_read, plc_allow_onto_users),
            (object_create, plc_allow_onto_users),
            (object_delete, plc_allow_onto_users),
        ]);

        let user_root = model.add_user(UserData {
            username: "root".to_string(),
            password: "secret".to_string(),
            email: "root@protojour.com".to_string(),
            tags: [role_onto_admin, role_onto_user].into(),
        });

        let user_testadmin = model.add_user(UserData {
            username: "testadmin".to_string(),
            password: "secret".to_string(),
            email: "admin@protojour.com".to_string(),
            tags: [role_onto_admin, role_onto_user].into(),
        });

        let user_testuser = model.add_user(UserData {
            username: "testuser".to_string(),
            password: "secret".to_string(),
            email: "testuser@protojour.com".to_string(),
            tags: [role_onto_admin].into(),
        });

        let users = model.add_group("users");

        model.set_membership(users, user_root);
        model.set_membership(users, user_testadmin);
        model.set_membership(users, user_testuser);

        let admins = model.add_group("admins");
        model.set_membership(admins, user_testadmin);

        println!("model: {model:#?}");
    }
}
