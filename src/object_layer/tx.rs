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
use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};
use crate::object_layer::charter::{CodeProof, DomainCharter};
use crate::object_layer::ids::{AssetClassId, DependencyId};
use crate::object_layer::registry::{
    Call, ClassRegistration, HomeEventProof, HomeFinality, HomeSliceProof, ObjectLayerRegistry,
    Phase, Refusal,
};
use crate::object_layer::rule::{ClassSlice, Condition, Holder};
use serde::{Deserialize, Serialize};

/// Supported home-chain classical key schemes for `UOL-K1` gasless stipends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HomeKeyScheme {
    EthereumSecp256k1 = 0,
    SolanaEd25519 = 1,
    AptosEd25519 = 2,
    CosmosSecp256k1 = 3,
}

/// Classical-signed gasless home-key stipend authorization (`UOL-K1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeKeyStipendAuth {
    pub scheme: HomeKeyScheme,
    pub home_address: Vec<u8>,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: u64,
    pub requested_stipend_attos: u128,
}

/// Classical home-key signature & PQ-ceiling verifier supplied by the
/// execution coordinator (`UOL-K1`). Keeping verification behind this trait
/// ensures `object_layer` enforces replay/cap bounds without embedding
/// classical primitives outside `execution/coordinator/foreign`.
pub trait HomeStipendVerifier {
    /// Verifies the classical signature, address binding, PQ holding cap, and
    /// Quantum Alert status for `HomeStipendCall`.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] when verification fails or the alert gate blocks it.
    fn verify_stipend(
        &self,
        domain: DomainId,
        auth: &HomeKeyStipendAuth,
        action_digest: &Hash32,
    ) -> Result<(), Refusal>;
}

/// Domain-separated hash commitment of the inner action inside `HomeStipendCall`.
///
/// # Errors
///
/// Returns [`Refusal::Overflow`] if postcard serialization fails.
pub fn home_stipend_action_digest(action: &ObjectLayerTx) -> Result<Hash32, Refusal> {
    let encoded = postcard::to_allocvec(action).map_err(|_| Refusal::Overflow)?;
    Ok(hash_fields_bytes(&[
        b"BDLM_UOL_HOME_STIPEND_ACTION_V1",
        &encoded,
    ]))
}

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

    #[must_use]
    pub fn is_open_for_chain_at(&self, chain_id: u64, height: u64) -> bool {
        chain_id
            != crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
            && self.is_open_at(height)
    }
}

/// Active on testnet (`45261`) and devnet (`45262`) from genesis (height 0);
/// mainnet (`45260`) stays gated by chain-id check until launch sign-off.
pub const ACTIVATION: ObjectLayerActivation = ObjectLayerActivation { height: Some(0) };

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
        #[serde(default)]
        state_proof: Option<HomeSliceProof>,
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
    GuestPlace {
        class: AssetClassId,
        native_id: Vec<u8>,
        guest_domain: DomainId,
        guest_holder: Holder,
    },
    GuestReturn {
        class: AssetClassId,
        native_id: Vec<u8>,
        recipient: Holder,
        proof: HomeEventProof,
    },
    /// `UOL-K1`: gasless home-key action signed by the home chain's key within
    /// a bounded stipend and PQ holding ceiling (closed at Quantum Alert >= 2).
    HomeStipendCall {
        domain: DomainId,
        auth: HomeKeyStipendAuth,
        action: Box<ObjectLayerTx>,
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
    /// Optional finalized home-chain state root lookup for state-proof doors.
    pub home_state_root: Option<&'a dyn Fn(DomainId) -> Option<Hash32>>,
    /// Whether `Charter`, `RegisterClass`, and `RefreshClass` require
    /// proven home-chain state inclusion (always `true` on consensus).
    pub require_home_state_proofs: bool,
    /// Verifier for `UOL-K1` (`HomeStipendCall`). `None` fails closed.
    pub home_stipend_verifier: Option<&'a dyn HomeStipendVerifier>,
}

impl ObjectLayerTx {
    /// Apply one transaction. N-8: this is the only door to the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn apply(
        &self,
        registry: &mut ObjectLayerRegistry,
        ctx: &TxContext<'_>,
    ) -> Result<(), TxRefusal> {
        if !ctx.activation.is_open_at(ctx.height) {
            return Err(TxRefusal::Closed);
        }
        let me = Holder::Account(ctx.signer);
        let state_root_for =
            |id: DomainId| -> Option<Hash32> { ctx.home_state_root.and_then(|lookup| lookup(id)) };
        match self {
            Self::Charter {
                domain,
                charter,
                proof,
            } => {
                registry.charter_verified(
                    *domain,
                    charter.clone(),
                    proof,
                    (ctx.domain_active)(*domain),
                    state_root_for(*domain),
                    ctx.require_home_state_proofs,
                )?;
            }
            Self::RegisterClass(reg) => {
                registry.register_class_verified(
                    ctx.signer,
                    reg.clone(),
                    state_root_for(reg.home_domain),
                    ctx.require_home_state_proofs,
                )?;
            }
            Self::RefreshClass {
                class,
                updates,
                phase,
                state_proof,
            } => {
                let domain = registry
                    .classes
                    .get(class)
                    .map(|c| c.home_domain)
                    .ok_or(TxRefusal::Refused(Refusal::UnknownClass))?;
                registry.refresh_class_verified(
                    ctx.signer,
                    *class,
                    updates.clone(),
                    *phase,
                    (
                        state_proof.as_ref(),
                        state_root_for(domain),
                        ctx.require_home_state_proofs,
                    ),
                )?;
            }
            Self::AuditCustody {
                class,
                home_custody,
            } => {
                registry.audit_custody(ctx.signer, *class, *home_custody)?;
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
                if let Ok(proof) = postcard::from_bytes::<HomeEventProof>(home) {
                    registry.adopt_with_proof(ctx.signer, &proof, ctx.finality)?;
                } else {
                    registry.adopt(ctx.signer, home)?;
                }
            }
            Self::Challenge { class } => {
                registry.challenge(ctx.signer, *class, ctx.height)?;
            }
            Self::Rebut { class } => {
                registry.rebut(ctx.signer, *class, ctx.height)?;
            }
            Self::GuestPlace {
                class,
                native_id,
                guest_domain,
                guest_holder,
            } => {
                registry.guest_place(me, *class, native_id, *guest_domain, *guest_holder)?;
            }
            Self::GuestReturn {
                class,
                native_id,
                recipient,
                proof,
            } => {
                registry.guest_return(*class, native_id, *recipient, proof, ctx.finality)?;
            }
            Self::HomeStipendCall {
                domain,
                auth,
                action,
            } => {
                registry.home_stipend_call(
                    *domain,
                    auth,
                    action,
                    ctx.height,
                    ctx.home_stipend_verifier,
                )?;
            }
        }
        Ok(())
    }
}
