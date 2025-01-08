use int_enum::IntEnum;

pub enum Outcome {
    Allow,
    Deny,
    Error,
}

#[derive(PartialEq, Eq, Debug)]
pub enum OpCode {
    LoadSubjectEid(u128),
    LoadSubjectTags,
    LoadResourceEid(u128),
    LoadResourceTags,
    LoadConstId(u128),
    IsEq,
    SupersetOf,
    ContainsTag,
    And,
    Or,
    Not,
    TrueThenAllow,
    TrueThenDeny,
    FalseThenAllow,
    FalseThenDeny,
}

#[repr(u8)]
#[derive(IntEnum)]
pub enum Bytecode {
    LoadSubjectEid = 0,
    LoadSubjectTags = 1,
    LoadResourceEid = 2,
    LoadResourceTags = 3,
    LoadConstId = 4,
    IsEq = 5,
    SupersetOf = 6,
    ContainsTag = 7,
    And = 8,
    Or = 9,
    Not = 10,
    TrueThenAllow = 11,
    TrueThenDeny = 12,
    FalseThenAllow = 13,
    FalseThenDeny = 14,
}

pub fn to_bytecode(opcodes: &[OpCode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(opcodes.len());

    for opcode in opcodes {
        match opcode {
            OpCode::LoadSubjectEid(eid) => {
                out.push(Bytecode::LoadSubjectEid as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadSubjectTags => {
                out.push(Bytecode::LoadSubjectTags as u8);
            }
            OpCode::LoadResourceEid(eid) => {
                out.push(Bytecode::LoadResourceEid as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadResourceTags => {
                out.push(Bytecode::LoadResourceTags as u8);
            }
            OpCode::LoadConstId(id) => {
                out.push(Bytecode::LoadConstId as u8);
                out.extend(unsigned_varint::encode::u128(*id, &mut Default::default()));
            }
            OpCode::IsEq => {
                out.push(Bytecode::IsEq as u8);
            }
            OpCode::SupersetOf => {
                out.push(Bytecode::SupersetOf as u8);
            }
            OpCode::ContainsTag => {
                out.push(Bytecode::ContainsTag as u8);
            }
            OpCode::And => {
                out.push(Bytecode::And as u8);
            }
            OpCode::Or => {
                out.push(Bytecode::Or as u8);
            }
            OpCode::Not => {
                out.push(Bytecode::Not as u8);
            }
            OpCode::TrueThenAllow => {
                out.push(Bytecode::TrueThenAllow as u8);
            }
            OpCode::TrueThenDeny => {
                out.push(Bytecode::TrueThenDeny as u8);
            }
            OpCode::FalseThenAllow => {
                out.push(Bytecode::FalseThenAllow as u8);
            }
            OpCode::FalseThenDeny => {
                out.push(Bytecode::FalseThenDeny as u8);
            }
        }
    }

    out
}
