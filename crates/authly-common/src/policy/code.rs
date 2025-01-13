use int_enum::IntEnum;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum Outcome {
    Allow,
    Deny,
}

#[derive(PartialEq, Eq, Debug)]
pub enum OpCode {
    LoadSubjectId(u128),
    LoadSubjectAttrs,
    LoadResourceId(u128),
    LoadResourceAttrs,
    LoadConstId(u128),
    IsEq,
    SupersetOf,
    IdSetContains,
    And,
    Or,
    Not,
    TrueThenAllow,
    TrueThenDeny,
    FalseThenAllow,
    FalseThenDeny,
}

#[repr(u8)]
#[derive(IntEnum, Debug)]
pub enum Bytecode {
    LoadSubjectId = 0,
    LoadSubjectAttrs = 1,
    LoadResourceId = 2,
    LoadResourceAttrs = 3,
    LoadConstId = 4,
    IsEq = 5,
    SupersetOf = 6,
    IdSetContains = 7,
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
            OpCode::LoadSubjectId(eid) => {
                out.push(Bytecode::LoadSubjectId as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadSubjectAttrs => {
                out.push(Bytecode::LoadSubjectAttrs as u8);
            }
            OpCode::LoadResourceId(eid) => {
                out.push(Bytecode::LoadResourceId as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadResourceAttrs => {
                out.push(Bytecode::LoadResourceAttrs as u8);
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
            OpCode::IdSetContains => {
                out.push(Bytecode::IdSetContains as u8);
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
