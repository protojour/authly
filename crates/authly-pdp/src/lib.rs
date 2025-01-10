use std::collections::HashMap;

use authly_common::policy::code::{Bytecode, Outcome};
use bit_set::BitSet;

#[expect(unused)]
pub struct PolicyEngine {
    triggers: Vec<PolicyTrigger>,
    policies: HashMap<u64, Policy>,
}

#[expect(unused)]
struct PolicyTrigger {
    mask: BitSet,
    negative: bool,
    policy_id: u64,
}

#[expect(unused)]
struct Policy {
    bytecode: Vec<u8>,
}

pub struct PolicyEnv {
    subject_eids: HashMap<u128, u128>,
    subject_flags: BitSet,
    resource_eids: HashMap<u128, u128>,
    resource_flags: BitSet,
}

#[derive(PartialEq, Eq)]
enum StackItem<'a> {
    Uint(u64),
    Tags(&'a BitSet),
    Id(u128),
}

pub fn eval_policy(mut pc: &[u8], env: &PolicyEnv) -> Outcome {
    let mut stack: Vec<StackItem> = vec![];

    while let Some(code) = pc.first() {
        pc = &pc[1..];

        let Ok(code) = Bytecode::try_from(*code) else {
            return Outcome::Error;
        };

        match code {
            Bytecode::LoadSubjectEid => {
                let Ok((key, next)) = unsigned_varint::decode::u128(pc) else {
                    return Outcome::Error;
                };
                let Some(eid) = env.subject_eids.get(&key) else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Id(*eid));
                pc = next;
            }
            Bytecode::LoadSubjectTags => {
                stack.push(StackItem::Tags(&env.subject_flags));
            }
            Bytecode::LoadResourceEid => {
                let Ok((key, next)) = unsigned_varint::decode::u128(pc) else {
                    return Outcome::Error;
                };
                let Some(eid) = env.resource_eids.get(&key) else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Id(*eid));
                pc = next;
            }
            Bytecode::LoadResourceTags => {
                stack.push(StackItem::Tags(&env.resource_flags));
            }
            Bytecode::LoadConstId => {
                let Ok((id, next)) = unsigned_varint::decode::u128(pc) else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Id(id));
                pc = next;
            }
            Bytecode::IsEq => {
                let Some(a) = stack.pop() else {
                    return Outcome::Error;
                };
                let Some(b) = stack.pop() else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Uint(if a == b { 1 } else { 0 }));
            }
            Bytecode::SupersetOf => {
                let Some(StackItem::Tags(a)) = stack.pop() else {
                    return Outcome::Error;
                };
                let Some(StackItem::Tags(b)) = stack.pop() else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Uint(if a.is_superset(b) { 1 } else { 0 }));
            }
            Bytecode::ContainsTag => {
                let Some(StackItem::Tags(a)) = stack.pop() else {
                    return Outcome::Error;
                };
                let Some(StackItem::Id(f)) = stack.pop() else {
                    return Outcome::Error;
                };
                // BUG: Does not support u128
                stack.push(StackItem::Uint(if a.contains(f as usize) { 1 } else { 0 }));
            }
            Bytecode::And => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Outcome::Error;
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Uint(if rhs > 0 && lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Or => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Outcome::Error;
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Uint(if rhs > 0 || lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Not => {
                let Some(StackItem::Uint(val)) = stack.pop() else {
                    return Outcome::Error;
                };
                stack.push(StackItem::Uint(if val > 0 { 0 } else { 1 }));
            }
            Bytecode::TrueThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Outcome::Error;
                };
                if u > 0 {
                    return Outcome::Allow;
                }
            }
            Bytecode::TrueThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Outcome::Error;
                };
                if u > 0 {
                    return Outcome::Deny;
                }
            }
            Bytecode::FalseThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Outcome::Error;
                };
                if u == 0 {
                    return Outcome::Allow;
                }
            }
            Bytecode::FalseThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Outcome::Error;
                };
                if u == 0 {
                    return Outcome::Deny;
                }
            }
        }
    }

    Outcome::Deny
}
