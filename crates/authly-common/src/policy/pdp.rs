//! Policy Decision Point

use std::collections::{BTreeSet, HashMap};

use fnv::{FnvHashMap, FnvHashSet};

use super::code::{Bytecode, Outcome};

pub enum PdpError {
    Bug,
}

pub struct PolicyEngine {
    attr_triggers: FnvHashMap<u128, BTreeSet<u64>>,
    policies: HashMap<u64, Policy>,
}

struct Policy {
    bytecode: Vec<u8>,
}

pub struct PolicyEnv {
    subject_eids: FnvHashMap<u128, u128>,
    subject_attrs: FnvHashSet<u128>,
    resource_eids: FnvHashMap<u128, u128>,
    resource_attrs: FnvHashSet<u128>,
}

#[derive(PartialEq, Eq)]
enum StackItem<'a> {
    Uint(u64),
    IdSet(&'a FnvHashSet<u128>),
    Id(u128),
}

pub fn eval(engine: &PolicyEngine, env: &PolicyEnv) -> Result<Outcome, PdpError> {
    let mut outcomes: Vec<Outcome> = vec![];

    for attr in &env.subject_attrs {
        eval_triggers(*attr, engine, env, &mut outcomes)?;
    }

    for attr in &env.resource_attrs {
        eval_triggers(*attr, engine, env, &mut outcomes)?;
    }

    if outcomes.is_empty() {
        // idea: Fallback mode, no policies matched
        for subj_attr in &env.subject_attrs {
            if env.resource_attrs.contains(subj_attr) {
                return Ok(Outcome::Allow);
            }
        }

        Ok(Outcome::Deny)
    } else if outcomes
        .iter()
        .any(|outcome| matches!(outcome, Outcome::Deny))
    {
        Ok(Outcome::Deny)
    } else {
        Ok(Outcome::Allow)
    }
}

fn eval_triggers(
    attr: u128,
    engine: &PolicyEngine,
    env: &PolicyEnv,
    outcomes: &mut Vec<Outcome>,
) -> Result<(), PdpError> {
    if let Some(policy_indexes) = engine.attr_triggers.get(&attr) {
        for idx in policy_indexes {
            let Some(policy) = engine.policies.get(idx) else {
                continue;
            };

            outcomes.push(eval_policy(&policy.bytecode, env)?);
        }
    }

    Ok(())
}

pub fn eval_policy(mut pc: &[u8], env: &PolicyEnv) -> Result<Outcome, PdpError> {
    let mut stack: Vec<StackItem> = Vec::with_capacity(16);

    while let Some(code) = pc.first() {
        pc = &pc[1..];

        let Ok(code) = Bytecode::try_from(*code) else {
            return Err(PdpError::Bug);
        };

        match code {
            Bytecode::LoadSubjectId => {
                let Ok((key, next)) = unsigned_varint::decode::u128(pc) else {
                    return Err(PdpError::Bug);
                };
                let Some(eid) = env.subject_eids.get(&key) else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Id(*eid));
                pc = next;
            }
            Bytecode::LoadSubjectAttrs => {
                stack.push(StackItem::IdSet(&env.subject_attrs));
            }
            Bytecode::LoadResourceId => {
                let Ok((key, next)) = unsigned_varint::decode::u128(pc) else {
                    return Err(PdpError::Bug);
                };
                let Some(eid) = env.resource_eids.get(&key) else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Id(*eid));
                pc = next;
            }
            Bytecode::LoadResourceAttrs => {
                stack.push(StackItem::IdSet(&env.resource_attrs));
            }
            Bytecode::LoadConstId => {
                let Ok((id, next)) = unsigned_varint::decode::u128(pc) else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Id(id));
                pc = next;
            }
            Bytecode::IsEq => {
                let Some(a) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                let Some(b) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Uint(if a == b { 1 } else { 0 }));
            }
            Bytecode::SupersetOf => {
                let Some(StackItem::IdSet(a)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                let Some(StackItem::IdSet(b)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Uint(if a.is_superset(b) { 1 } else { 0 }));
            }
            Bytecode::IdSetContains => {
                let Some(StackItem::IdSet(set)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                let Some(StackItem::Id(arg)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                // BUG: Does not support u128
                stack.push(StackItem::Uint(if set.contains(&arg) { 1 } else { 0 }));
            }
            Bytecode::And => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Uint(if rhs > 0 && lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Or => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Uint(if rhs > 0 || lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Not => {
                let Some(StackItem::Uint(val)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Uint(if val > 0 { 0 } else { 1 }));
            }
            Bytecode::TrueThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                if u > 0 {
                    return Err(PdpError::Bug);
                }
            }
            Bytecode::TrueThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                if u > 0 {
                    return Ok(Outcome::Deny);
                }
            }
            Bytecode::FalseThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                if u == 0 {
                    return Ok(Outcome::Allow);
                }
            }
            Bytecode::FalseThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(PdpError::Bug);
                };
                if u == 0 {
                    return Ok(Outcome::Deny);
                }
            }
        }
    }

    Ok(Outcome::Deny)
}
