//! Policy Decision Point

use std::collections::BTreeSet;

use fnv::{FnvHashMap, FnvHashSet};
use tracing::error;

use super::code::{Bytecode, Outcome};

#[derive(Debug)]
pub enum PdpError {
    Bug,
}

/// The parameters to an policy-based access control evaluation.
#[derive(Default)]
pub struct AccessControlParams {
    pub subject_eids: FnvHashMap<u128, u128>,
    pub subject_attrs: FnvHashSet<u128>,
    pub resource_eids: FnvHashMap<u128, u128>,
    pub resource_attrs: FnvHashSet<u128>,
}

/// The state of the policy engine.
///
/// Contains compiled policies and their triggers.
#[derive(Default)]
pub struct PolicyEngine {
    policies: FnvHashMap<PolicyId, Policy>,

    /// Policy triggers: The hash map is keyed by the smallest attribute in the match set
    policy_triggers: FnvHashMap<u128, PolicyTrigger>,
}

/// The policy trigger maps a set of attributes to a policy.
struct PolicyTrigger {
    /// The set of attributes that has to match for this policy to trigger
    pub attr_matcher: BTreeSet<u128>,

    /// The policy which gets triggered by this attribute matcher
    pub policy_id: PolicyId,
}

/// A placeholder for how to refer to a local policy
type PolicyId = u128;

pub struct Policy {
    bytecode: Vec<u8>,
}

#[derive(PartialEq, Eq)]
enum StackItem<'a> {
    Uint(u64),
    IdSet(&'a FnvHashSet<u128>),
    Id(u128),
}

struct EvalCtx {
    outcomes: Vec<Outcome>,
    evaluated_policies: FnvHashSet<PolicyId>,
}

impl PolicyEngine {
    pub fn add_policy(&mut self, id: PolicyId, policy_bytecode: Vec<u8>) {
        self.policies.insert(
            id,
            Policy {
                bytecode: policy_bytecode,
            },
        );
    }

    pub fn add_policy_trigger(&mut self, attr_matcher: BTreeSet<u128>, policy_id: PolicyId) {
        if let Some(first_attr) = attr_matcher.iter().next() {
            self.policy_triggers.insert(
                *first_attr,
                PolicyTrigger {
                    attr_matcher,
                    policy_id,
                },
            );
        }
    }

    pub fn eval(&self, params: &AccessControlParams) -> Result<Outcome, PdpError> {
        let mut eval_ctx = EvalCtx {
            outcomes: vec![],
            evaluated_policies: Default::default(),
        };

        for attr in &params.subject_attrs {
            self.eval_triggers(*attr, params, &mut eval_ctx)?;
        }

        for attr in &params.resource_attrs {
            self.eval_triggers(*attr, params, &mut eval_ctx)?;
        }

        if eval_ctx.outcomes.is_empty() {
            // idea: Fallback mode, no policies matched
            for subj_attr in &params.subject_attrs {
                if params.resource_attrs.contains(subj_attr) {
                    return Ok(Outcome::Allow);
                }
            }

            Ok(Outcome::Deny)
        } else if eval_ctx
            .outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Deny))
        {
            Ok(Outcome::Deny)
        } else {
            Ok(Outcome::Allow)
        }
    }

    fn eval_triggers(
        &self,
        attr: u128,
        params: &AccessControlParams,
        eval_ctx: &mut EvalCtx,
    ) -> Result<(), PdpError> {
        if let Some(policy_trigger) = self.policy_triggers.get(&attr) {
            if eval_ctx
                .evaluated_policies
                .contains(&policy_trigger.policy_id)
            {
                // already evaluated
                return Ok(());
            }

            let mut n_matches = 0;

            for attrs in [&params.subject_attrs, &params.resource_attrs] {
                for attr in attrs {
                    if policy_trigger.attr_matcher.contains(attr) {
                        n_matches += 1;
                    }
                }
            }

            if n_matches < policy_trigger.attr_matcher.len() {
                // not a match; no policy evaluated
                return Ok(());
            }

            let policy_id = policy_trigger.policy_id;

            let Some(policy) = self.policies.get(&policy_id) else {
                error!(?policy_id, "policy is missing");

                // internal error, which is not exposed
                return Ok(());
            };

            // register this policy as evaluated, to avoid re-triggering
            eval_ctx.evaluated_policies.insert(policy_trigger.policy_id);

            // evaluate policy outcome
            eval_ctx
                .outcomes
                .push(eval_policy(&policy.bytecode, params)?);
        }

        Ok(())
    }
}

fn eval_policy(mut pc: &[u8], params: &AccessControlParams) -> Result<Outcome, PdpError> {
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
                let Some(id) = params.subject_eids.get(&key) else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Id(*id));
                pc = next;
            }
            Bytecode::LoadSubjectAttrs => {
                stack.push(StackItem::IdSet(&params.subject_attrs));
            }
            Bytecode::LoadResourceId => {
                let Ok((key, next)) = unsigned_varint::decode::u128(pc) else {
                    return Err(PdpError::Bug);
                };
                let Some(id) = params.resource_eids.get(&key) else {
                    return Err(PdpError::Bug);
                };
                stack.push(StackItem::Id(*id));
                pc = next;
            }
            Bytecode::LoadResourceAttrs => {
                stack.push(StackItem::IdSet(&params.resource_attrs));
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
