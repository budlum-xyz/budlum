//! `ObjectLayerTx` and the activation gate.
//!
//! The enum carries every planned variant, in a fixed order, so the
//! wire codes are fixed from the first release. Variants whose step has not
//! landed are refused with [`TxRefusal::StepNotOpen`].
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass` and `bud_getAsset`.
//! State is held by `SettlementRegistries::object_layer`; public testnet is
//! closed by `ACTIVATION`, and variants still marked `StepNotOpen` remain
//! closed on every network.

use crate::core::address::Address;
use crate::domain::types::{DomainId, Hash32};
use crate::object_layer::charter::{CodeProof, DomainCharter};
use crate::object_layer::ids::{AssetClassId, DependencyId};
use crate::object_layer::registry::{
    Call, ClassRegistration, HomeEventProof, HomeFinality, ObjectLayerRegistry, Phase, Refusal,
};
use crate::object_layer::rule::{ClassSlice, Condition, Holder};
use serde::{Deserialize, Serialize};

/// When the object layer opens. `None`: closed on this chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLayerActivation {
    pub height: Option<u64>,
}

impl ObjectLayerActivation {
    #[must_use]
    pub fn is_open_at(&self, height: u64) -> bool {
        self.height.is_some_and(|h| height >= h)
    }
}

/// TESTNET-DEFAULT: closed. The activation height is set after launch (M7).
pub const ACTIVATION: ObjectLayerActivation = ObjectLayerActivation { height: None };

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectLayerTx {
    Charter {
        domain: DomainId,
        charter: DomainCharter,
        proof: CodeProof,
    },
    RegisterClass(ClassRegistration),
    RefreshClass {
        class: AssetClassId,
        updates: ClassSlice,
        phase: Phase,
    },
    AuditCode {
        class: AssetClassId,
    },
    AuditCustody {
        class: AssetClassId,
        home_custody: u128,
    },
    Arrive(HomeEventProof),
    Resolve {
        dependency: Hash32,
    },
    Call {
        calls: Vec<Call>,
    },
    Offer {
        calls: Vec<Call>,
        wants: Vec<Condition>,
        expiry: u64,
    },
    Accept {
        offer: Hash32,
        calls: Vec<Call>,
    },
    HomeCall(HomeEventProof),
    Depart {
        class: AssetClassId,
        native_id: Vec<u8>,
        amount: u128,
        home_to: Vec<u8>,
    },
    ConfirmDeparture(HomeEventProof),
    SetEscapeAddress {
        home: Vec<u8>,
    },
    SetTentativeConsent {
        consent: bool,
    },
    Adopt {
        home: Vec<u8>,
    },
    Challenge {
        class: AssetClassId,
    },
    Rebut {
        class: AssetClassId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TxRefusal {
    /// The object layer is not active at this height.
    Closed,
    /// The variant's step has not landed.
    StepNotOpen,
    Refused(Refusal),
}

impl From<Refusal> for TxRefusal {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

/// What the block executor hands the object layer with one transaction.
pub struct TxContext<'a> {
    pub height: u64,
    pub signer: Address,
    pub activation: ObjectLayerActivation,
    pub finality: &'a dyn HomeFinality,
    /// Whether the charter's domain is active in the external intake.
    pub domain_active: &'a dyn Fn(DomainId) -> bool,
}

impl ObjectLayerTx {
    /// Apply one transaction. N-8: this is the only door to the registry.
    pub fn apply(
        &self,
        registry: &mut ObjectLayerRegistry,
        ctx: &TxContext<'_>,
    ) -> Result<(), TxRefusal> {
        if !ctx.activation.is_open_at(ctx.height) {
            return Err(TxRefusal::Closed);
        }
        let me = Holder::Account(ctx.signer);
        match self {
            Self::Charter {
                domain,
                charter,
                proof,
            } => {
                registry.charter(
                    *domain,
                    charter.clone(),
                    proof,
                    (ctx.domain_active)(*domain),
                )?;
            }
            Self::RegisterClass(reg) => {
                registry.register_class(ctx.signer, reg.clone())?;
            }
            Self::RefreshClass {
                class,
                updates,
                phase,
            } => {
                registry.refresh_class(*class, updates.clone(), *phase)?;
            }
            Self::AuditCustody {
                class,
                home_custody,
            } => {
                registry.audit_custody(*class, *home_custody)?;
            }
            Self::Arrive(proof) => {
                registry.arrive(proof, ctx.finality)?;
            }
            Self::Call { calls } => registry.call(me, calls)?,
            Self::Offer {
                calls,
                wants,
                expiry,
            } => {
                registry.offer(me, calls.clone(), wants.clone(), *expiry)?;
            }
            Self::Accept { offer, calls } => registry.accept(me, *offer, calls, ctx.height)?,
            Self::HomeCall(proof) => {
                registry.home_call(proof, ctx.finality)?;
            }
            Self::Depart {
                class,
                native_id,
                amount,
                home_to,
            } => {
                registry.depart(me, *class, native_id, *amount, home_to.clone(), ctx.height)?;
            }
            Self::ConfirmDeparture(proof) => {
                registry.confirm_departure(proof, ctx.finality)?;
            }
            Self::AuditCode { class } => {
                registry.audit_code(*class)?;
            }
            Self::Resolve { dependency } => {
                registry.resolve(DependencyId(*dependency))?;
            }
            Self::SetEscapeAddress { home } => {
                registry.set_escape_address(ctx.signer, home.clone())?;
            }
            Self::SetTentativeConsent { consent } => {
                registry.set_tentative_consent(ctx.signer, *consent);
            }
            Self::Adopt { home } => {
                registry.adopt(ctx.signer, home)?;
            }
            Self::Challenge { class } => {
                registry.challenge(ctx.signer, *class, ctx.height)?;
            }
            Self::Rebut { class } => {
                registry.rebut(ctx.signer, *class, ctx.height)?;
            }
        }
        Ok(())
    }
}
