//! Class rules, templates, standard interfaces and conditions.
//!
//! A class rule is a pure function. It reads the class slice, the asset
//! slice and one verb, and either accepts the transition or refuses it. It
//! never reads the registry, the clock or any other class (N-2, N-12).
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::core::address::Address;
use crate::object_layer::ids::{AssetClassId, HomeIdentity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The audited template list. Closed: a new template is a
/// protocol change, not a registration parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TemplateId {
    FungibleV1,
    UniqueV1,
    /// Single-holder record object template (step 9).
    RecordV1,
}

/// Template parameters. Each names a class-slice field the home contract
/// keeps, so the template enforces the home rule instead of inventing one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateParams {
    /// The slice field that holds the home contract's pause flag
    /// (`Pausable.paused()`, a frozen mint authority, ...). When the field
    /// is non-zero every transfer is refused, as it is at home.
    #[serde(default)]
    pub pause_field: Option<String>,
    /// An informational royalty field (ERC-2981 and the like). Carried for
    /// display only: `UniqueV1` does not enforce it, because the home
    /// contract does not either.
    #[serde(default)]
    pub info_royalty_field: Option<String>,
}

/// The kinds of class rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassRule {
    /// A Budlum module's own code (BUD, SocialFi NFT, BNS name, data asset).
    Native,
    Template {
        id: TemplateId,
        params: TemplateParams,
    },
    /// UOL-K3: closed gate.
    Program,
    /// UOL-K4: closed gate.
    Replica,
}

impl ClassRule {
    /// Whether the rule may be registered today. `Program` and `Replica`
    /// are closed gates; `FungibleV1`, `UniqueV1`, and `RecordV1` are open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Template {
                id: TemplateId::FungibleV1 | TemplateId::UniqueV1 | TemplateId::RecordV1,
                ..
            }
        )
    }
}

/// The class slice: the home contract's fields the rule reads, by name. The
/// first slice is loaded with an account and storage proof or from an
/// endpoint event (the family decides); later values come from home events.
pub type ClassSlice = BTreeMap<String, Vec<u8>>;

/// Who holds a value inside the object layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Holder {
    /// A Budlum account (post-quantum keys).
    Account(Address),
    /// A home identity: acts only by home call.
    Home(HomeIdentity),
}

/// The standard interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Interface {
    Fungible,
    Unique,
    Record,
}

impl TemplateId {
    #[must_use]
    pub fn interface(&self) -> Interface {
        match self {
            Self::FungibleV1 => Interface::Fungible,
            Self::UniqueV1 => Interface::Unique,
            Self::RecordV1 => Interface::Record,
        }
    }
}

/// The closed condition list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    Payment {
        class: AssetClassId,
        to: Holder,
        min_amount: u128,
    },
    Holds {
        class: AssetClassId,
        holder: Holder,
    },
    SignedBy {
        signer: Holder,
    },
    EscapeAddress {
        holder: Holder,
        home: Vec<u8>,
    },
}

/// The part of the asset state one verb touches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetSlice {
    Fungible { balances: BTreeMap<Holder, u128> },
    Unique { holder: Holder },
}

/// The verbs of the standard interfaces that change state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    /// `Fungible.transfer(from, to, amount)`; `Unique.transfer(from, to)`
    /// with `amount == 1`.
    Transfer {
        from: Holder,
        to: Holder,
        amount: u128,
    },
}

/// An accepted transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub asset_slice: AssetSlice,
    pub requirements: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleRefusal {
    ClosedRule,
    Paused,
    WrongShape,
    NotHolder,
    BalanceTooLow,
    ZeroAmount,
    Overflow,
}

fn is_set(slice: &ClassSlice, field: &Option<String>) -> bool {
    field
        .as_ref()
        .and_then(|f| slice.get(f))
        .is_some_and(|v| v.iter().any(|b| *b != 0))
}

/// Run one verb under a class rule. Pure: the same inputs always give the
/// same output, on every node.
pub fn apply_rule(
    rule: &ClassRule,
    class_slice: &ClassSlice,
    before: &AssetSlice,
    verb: &Verb,
) -> Result<Transition, RuleRefusal> {
    let ClassRule::Template { id, params } = rule else {
        return Err(RuleRefusal::ClosedRule);
    };
    if is_set(class_slice, &params.pause_field) {
        return Err(RuleRefusal::Paused);
    }
    let Verb::Transfer { from, to, amount } = verb;
    match (id, before) {
        (TemplateId::FungibleV1, AssetSlice::Fungible { balances }) => {
            if *amount == 0 {
                return Err(RuleRefusal::ZeroAmount);
            }
            let mut balances = balances.clone();
            let have = balances.get(from).copied().unwrap_or(0);
            let left = have
                .checked_sub(*amount)
                .ok_or(RuleRefusal::BalanceTooLow)?;
            if left == 0 {
                balances.remove(from);
            } else {
                balances.insert(*from, left);
            }
            let got = balances.get(to).copied().unwrap_or(0);
            balances.insert(*to, got.checked_add(*amount).ok_or(RuleRefusal::Overflow)?);
            Ok(Transition {
                asset_slice: AssetSlice::Fungible { balances },
                requirements: vec![Condition::SignedBy { signer: *from }],
            })
        }
        (TemplateId::UniqueV1 | TemplateId::RecordV1, AssetSlice::Unique { holder }) => {
            if *amount != 1 {
                return Err(RuleRefusal::WrongShape);
            }
            if holder != from {
                return Err(RuleRefusal::NotHolder);
            }
            // The informational royalty field is deliberately not read here.
            Ok(Transition {
                asset_slice: AssetSlice::Unique { holder: *to },
                requirements: vec![Condition::SignedBy { signer: *from }],
            })
        }
        _ => Err(RuleRefusal::WrongShape),
    }
}

/// One reference transition sample: the slice before, the
/// verbs the home domain ran, and the slice after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceSample {
    pub class_slice: ClassSlice,
    pub before: AssetSlice,
    pub verbs: Vec<Verb>,
    pub after: AssetSlice,
}

/// Run every sample under the rule. The output must equal the recorded
/// after-slice byte for byte (compared in the canonical encoding).
pub fn verify_samples(rule: &ClassRule, samples: &[ReferenceSample]) -> Result<(), usize> {
    for (index, sample) in samples.iter().enumerate() {
        let mut slice = sample.before.clone();
        for verb in &sample.verbs {
            slice = apply_rule(rule, &sample.class_slice, &slice, verb)
                .map_err(|_| index)?
                .asset_slice;
        }
        let got = postcard::to_allocvec(&slice).map_err(|_| index)?;
        let want = postcard::to_allocvec(&sample.after).map_err(|_| index)?;
        if got != want {
            return Err(index);
        }
    }
    Ok(())
}

/// The commitment a class registration binds its samples under
/// (`class_sample_commitment_is_bound`).
#[must_use]
pub fn sample_commitment(samples: &[ReferenceSample]) -> [u8; 32] {
    let encoded = postcard::to_allocvec(samples).unwrap_or_default();
    crate::core::hash::hash_fields_bytes(&[b"BDLM_OBJECT_LAYER_SAMPLES_V1", &encoded])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(b: u8) -> Holder {
        Holder::Account(Address([b; 32]))
    }

    fn fungible() -> ClassRule {
        ClassRule::Template {
            id: TemplateId::FungibleV1,
            params: TemplateParams {
                pause_field: Some("paused".into()),
                info_royalty_field: None,
            },
        }
    }

    fn unique() -> ClassRule {
        ClassRule::Template {
            id: TemplateId::UniqueV1,
            params: TemplateParams {
                pause_field: None,
                info_royalty_field: Some("royalty".into()),
            },
        }
    }

    #[test]
    fn fungible_template_matches_reference_samples() {
        let before = AssetSlice::Fungible {
            balances: [(acct(1), 10)].into_iter().collect(),
        };
        let after = AssetSlice::Fungible {
            balances: [(acct(1), 3), (acct(2), 7)].into_iter().collect(),
        };
        let sample = ReferenceSample {
            class_slice: ClassSlice::new(),
            before,
            verbs: vec![
                Verb::Transfer {
                    from: acct(1),
                    to: acct(2),
                    amount: 5,
                },
                Verb::Transfer {
                    from: acct(1),
                    to: acct(2),
                    amount: 2,
                },
            ],
            after,
        };
        assert_eq!(verify_samples(&fungible(), &[sample]), Ok(()));
    }

    #[test]
    fn class_admission_refuses_mismatched_sample() {
        let sample = ReferenceSample {
            class_slice: ClassSlice::new(),
            before: AssetSlice::Fungible {
                balances: [(acct(1), 10)].into_iter().collect(),
            },
            verbs: vec![Verb::Transfer {
                from: acct(1),
                to: acct(2),
                amount: 5,
            }],
            after: AssetSlice::Fungible {
                balances: [(acct(1), 4), (acct(2), 6)].into_iter().collect(),
            },
        };
        assert_eq!(verify_samples(&fungible(), &[sample]), Err(0));
    }

    #[test]
    fn unique_template_does_not_enforce_info_royalty() {
        let mut slice = ClassSlice::new();
        slice.insert("royalty".into(), vec![0, 0, 0, 250]);
        let t = apply_rule(
            &unique(),
            &slice,
            &AssetSlice::Unique { holder: acct(1) },
            &Verb::Transfer {
                from: acct(1),
                to: acct(2),
                amount: 1,
            },
        )
        .unwrap();
        assert_eq!(t.asset_slice, AssetSlice::Unique { holder: acct(2) });
        // No payment requirement appears for the royalty.
        assert!(!t
            .requirements
            .iter()
            .any(|c| matches!(c, Condition::Payment { .. })));
    }

    #[test]
    fn paused_home_contract_refuses_transfer() {
        let mut slice = ClassSlice::new();
        slice.insert("paused".into(), vec![1]);
        let before = AssetSlice::Fungible {
            balances: [(acct(1), 10)].into_iter().collect(),
        };
        let verb = Verb::Transfer {
            from: acct(1),
            to: acct(2),
            amount: 1,
        };
        assert_eq!(
            apply_rule(&fungible(), &slice, &before, &verb),
            Err(RuleRefusal::Paused)
        );
    }

    #[test]
    fn unique_transfer_needs_the_holder() {
        let verb = Verb::Transfer {
            from: acct(2),
            to: acct(3),
            amount: 1,
        };
        assert_eq!(
            apply_rule(
                &unique(),
                &ClassSlice::new(),
                &AssetSlice::Unique { holder: acct(1) },
                &verb
            ),
            Err(RuleRefusal::NotHolder)
        );
    }

    #[test]
    fn closed_rules_refuse_every_transition() {
        let verb = Verb::Transfer {
            from: acct(1),
            to: acct(2),
            amount: 1,
        };
        let before = AssetSlice::Unique { holder: acct(1) };
        for rule in [ClassRule::Program, ClassRule::Replica, ClassRule::Native] {
            assert!(!matches!(rule, ClassRule::Native) || !rule.is_open());
            assert_eq!(
                apply_rule(&rule, &ClassSlice::new(), &before, &verb),
                Err(RuleRefusal::ClosedRule)
            );
        }
        assert!(!ClassRule::Program.is_open());
        assert!(!ClassRule::Replica.is_open());
    }

    #[test]
    fn class_sample_commitment_is_bound() {
        let a = ReferenceSample {
            class_slice: ClassSlice::new(),
            before: AssetSlice::Unique { holder: acct(1) },
            verbs: vec![Verb::Transfer {
                from: acct(1),
                to: acct(2),
                amount: 1,
            }],
            after: AssetSlice::Unique { holder: acct(2) },
        };
        let mut b = a.clone();
        b.after = AssetSlice::Unique { holder: acct(3) };
        assert_ne!(
            sample_commitment(std::slice::from_ref(&a)),
            sample_commitment(&[b])
        );
        assert_eq!(
            sample_commitment(std::slice::from_ref(&a)),
            sample_commitment(&[a])
        );
    }
}
