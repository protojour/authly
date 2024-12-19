pub enum Outcome {
    Allow,
    Deny,
    Error,
}

pub mod opcode {
    pub const LOAD_SUBJECT_EID: u8 = 0;
    pub const LOAD_SUBJECT_TAGS: u8 = 1;
    pub const LOAD_RESOURCE_EID: u8 = 2;
    pub const LOAD_RESOURCE_TAGS: u8 = 3;
    pub const LOAD_CONST_ID: u8 = 4;
    pub const IS_EQ: u8 = 6;
    pub const SUPERSET_OF: u8 = 7;
    pub const CONTAINS_TAG: u8 = 8;
    pub const TRUE_THEN_ALLOW: u8 = 9;
    pub const TRUE_THEN_DENY: u8 = 10;
    pub const FALSE_THEN_ALLOW: u8 = 11;
    pub const FALSE_THEN_DENY: u8 = 12;
}

#[derive(Debug)]
pub enum OpCode {
    LoadSubjectEid(u128),
    LoadSubjectTags,
    LoadResourceEid(u128),
    LoadResourceTags,
    LoadConstId(u128),
    IsEq,
    SupersetOf,
    ContainsTag,
    TrueThenAllow,
    TrueThenDeny,
    FalseThenAllow,
    FalseThenDeny,
}

pub fn to_bytecode(opcodes: &[OpCode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(opcodes.len());
    use opcode::*;

    for opcode in opcodes {
        match opcode {
            OpCode::LoadSubjectEid(eid) => {
                out.push(LOAD_SUBJECT_EID);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadSubjectTags => {
                out.push(LOAD_SUBJECT_TAGS);
            }
            OpCode::LoadResourceEid(eid) => {
                out.push(LOAD_RESOURCE_EID);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadResourceTags => {
                out.push(LOAD_RESOURCE_TAGS);
            }
            OpCode::LoadConstId(id) => {
                out.push(LOAD_CONST_ID);
                out.extend(unsigned_varint::encode::u128(*id, &mut Default::default()));
            }
            OpCode::IsEq => {
                out.push(IS_EQ);
            }
            OpCode::SupersetOf => {
                out.push(SUPERSET_OF);
            }
            OpCode::ContainsTag => {
                out.push(CONTAINS_TAG);
            }
            OpCode::TrueThenAllow => {
                out.push(TRUE_THEN_ALLOW);
            }
            OpCode::TrueThenDeny => {
                out.push(TRUE_THEN_DENY);
            }
            OpCode::FalseThenAllow => {
                out.push(FALSE_THEN_ALLOW);
            }
            OpCode::FalseThenDeny => {
                out.push(FALSE_THEN_DENY);
            }
        }
    }

    out
}
