//! The external-domain adapter interface: the contract a third party writes
//! against when they want Budlum to read finality from their system.
//!
//! # The abstraction level, and why it sits where it does
//!
//! The interface is deliberately *not* "give us your block header". A header
//! is a format, and formats are what change: a hard fork renames fields, a
//! new client serialises differently, a proof system changes its encoding. An
//! adapter that is handed a header must be updated for every such change, and
//! every update is a Budlum release.
//!
//! It is also not "give us a boolean". A boolean hides the security backing,
//! and the backing is the only thing a reader needs in order to price risk.
//!
//! So the boundary is exactly one step above both: an adapter takes **raw
//! evidence** (opaque bytes it alone understands, plus the two facts Budlum
//! needs in order to index it) and returns a **finality attestation** - a
//! height, a state root, a timestamp in the external system's own unit, and a
//! machine-readable statement of *what is backing this claim*. Everything
//! about the external system's internals stays inside the adapter; everything
//! a consumer needs stays in the attestation.
//!
//! # What the interface refuses to include
//!
//! - **No opinion about the domain.** Budlum does not decide whether a domain
//!   is good. It decides whether the evidence is a valid proof under the
//!   adapter's own declared rules. The profile a user sees
//!   (see [`crate::cross_domain::external::profile`]) is read off the domain's
//!   own registration; none of it is a score computed by us.
//! - **No fallback to "assume valid".** Every refusal path in this module
//!   returns an error. There is no `unwrap_or(default)`, no
//!   `unwrap_or_else(|| true)`, and no branch that treats an unparsable
//!   payload as an empty-but-acceptable one.
//! - **No version drift.** An adapter declares the evidence versions it
//!   accepts. An unknown version is a hard refusal, never a best-effort
//!   reinterpretation - see [`crate::cross_domain::external::versioning`].

use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// The identity of an adapter. Stable across upgrades of the adapter itself,
/// because it is the key the domain registry and every stored attestation
/// point at. Changing it is a new adapter, not a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdapterId(pub [u8; 32]);

impl AdapterId {
    /// Derives an id from a human-readable name. Two adapters that want the
    /// same id must want the same name; the derivation is public so anybody
    /// can check that a registration means what it says.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        Self(crate::core::hash::hash_fields_bytes(&[
            b"bud-external-adapter-id-v1",
            name.as_bytes(),
        ]))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The identity of a registered external domain. Distinct from [`AdapterId`]:
/// one adapter can serve many domains (one Ethereum verifier, ten networks),
/// and the bond, the profile and the status all live per domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DomainKey(pub [u8; 32]);

impl DomainKey {
    #[must_use]
    pub fn from_parts(adapter: &AdapterId, network: &str) -> Self {
        Self(crate::core::hash::hash_fields_bytes(&[
            b"bud-external-domain-v1",
            adapter.as_bytes(),
            network.as_bytes(),
        ]))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// What the external system hands over. `payload` is opaque to Budlum: only
/// the adapter that declares itself for it knows how to read it. The two
/// declared fields beside it exist so the network can index, deduplicate and
/// replay evidence without invoking the adapter at all.
///
/// A lying `declared_height` or `declared_root` is not a vulnerability - the
/// adapter must derive both from the payload and refuse a mismatch, which
/// [`VerificationPolicy::require_declared_match`] turns from a convention
/// into a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawConsensusEvidence {
    pub adapter: AdapterId,
    /// The evidence format's own version. Carried in the envelope rather than
    /// sniffed from the payload: a version that has to be guessed is a version
    /// that can be guessed wrong, and a wrong guess is a silent
    /// reinterpretation of somebody else's consensus.
    pub evidence_version: u32,
    /// The external network this evidence is from, so one adapter binary can
    /// serve several networks without ambiguity.
    pub network: String,
    pub payload: Vec<u8>,
    pub declared_height: u64,
    pub declared_root: [u8; 32],
    /// Who carried this evidence in. Bonding and slashability attach to this
    /// address, never to the adapter's author.
    pub submitter: Address,
}

impl RawConsensusEvidence {
    /// The digest this evidence is identified by. Everything that must not
    /// be replayed - attestations, receipts, slashings - commits to this, not
    /// to the payload bytes, so that a re-encoding of the same evidence
    /// cannot become a second event.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"bud-external-evidence-v1",
            self.adapter.as_bytes(),
            &self.evidence_version.to_le_bytes(),
            self.network.as_bytes(),
            &self.declared_height.to_le_bytes(),
            &self.declared_root,
            self.submitter.as_bytes(),
        ]);
        acc = crate::core::hash::hash_fields_bytes(&[&acc, &self.payload]);
        acc
    }
}

/// What is actually holding a claim up. This is the field a consumer reads in
/// order to price risk, and the reason it is an enum rather than a number: a
/// "security score" would let us rank a 512-validator committee against a
/// million-validator set, and we would be wrong in a way nobody could check.
///
/// Each variant states its own unit, so a reader never has to guess whether
/// `threshold` means signatures, stake or work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityBacking {
    /// A signature set over the claim. `signers` counts distinct signers, and
    /// `required` is the threshold the external protocol itself defines.
    /// `slashable` is carried because it is the difference between "the
    /// signers lose money if they lie" and "the signers lose nothing": an
    /// Ethereum sync committee is the second, and a reader is entitled to know
    /// that without having to read the Altair spec.
    SignatureSet {
        signers: u64,
        required: u64,
        total_weight: u128,
        slashable: bool,
    },
    /// Accumulated proof of work above the claimed height.
    Work { difficulty_bits: u32 },
    /// A validity proof. `system` names the proof system so a consumer can
    /// look up its assumptions rather than trust ours.
    Zk {
        system: ProofSystem,
        public_inputs_digest: [u8; 32],
    },
    /// A fixed, permissioned authority set.
    Authority { count: u64 },
    /// Nothing cryptographic: the domain has not yet produced backing this
    /// cycle. Carried rather than omitted so "no backing yet" is a visible
    /// state and not a zero that looks like a small amount of backing.
    None,
}

/// Proof systems this chain can reason about by name. Closed on purpose: an
/// unnamed proof system is one whose assumptions nobody has read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    /// The chain's own STARK-based zkVM.
    BudlumZkVm,
    /// Groth16 over BN254: cheap to verify on an EVM chain, trusted setup.
    Groth16,
    /// PLONK-family: universal setup, larger proofs.
    Plonk,
    /// STARK: transparent setup, larger proofs, no trusted ceremony.
    Stark,
}

/// What Budlum commits to. Uniform across every external system, which is the
/// whole point: the global header, the cross-domain message lifecycle and the
/// presentation layer all consume this and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAttestation {
    pub adapter: AdapterId,
    pub domain: DomainKey,
    /// Height in the external system's own numbering. Never rescaled into
    /// Budlum heights: two chains with different block times have no honest
    /// exchange rate, and a rescaled height silently invents one.
    pub height: u64,
    /// The external state root the evidence commits to.
    pub state_root: [u8; 32],
    /// Finality time in the external system's own unit (slot, epoch, round),
    /// plus the unit's name so nobody has to guess.
    pub finalized_at: u64,
    pub time_unit: TimeUnit,
    pub security: SecurityBacking,
    /// The evidence this attestation was derived from.
    pub evidence_digest: [u8; 32],
    /// The adapter version that produced it. An attestation stays verifiable
    /// after the adapter upgrades, because the version travels with it.
    pub adapter_version: u32,
    pub evidence_version: u32,
}

/// Named so a reader can tell "slot 4" from "epoch 4" from "round 4".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUnit {
    Slot,
    Epoch,
    Round,
    Height,
    UnixSeconds,
}

impl TimeUnit {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Slot => "slot",
            Self::Epoch => "epoch",
            Self::Round => "round",
            Self::Height => "height",
            Self::UnixSeconds => "unix-seconds",
        }
    }
}

/// What an adapter declares about itself, at registration time. Everything a
/// third party must commit to before anybody trusts an attestation from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterDescriptor {
    pub id: AdapterId,
    /// Human-readable name. Not the id; the id is derived from it.
    pub name: String,
    /// The adapter's own version. Independent of the evidence version: an
    /// adapter can be rewritten without the evidence format changing, and the
    /// evidence format can fork without the adapter changing.
    pub adapter_version: u32,
    /// Evidence versions this adapter will accept. Declared, not sniffed.
    pub accepted_evidence_versions: Vec<u32>,
    /// What kind of consensus the target system runs, in the target's own
    /// words. Carried for the profile; not used to decide anything.
    pub consensus_kind: String,
    /// What kind of finality the target offers.
    pub finality_kind: FinalityKind,
    /// How deep the adapter insists on going before it will call a height
    /// final. Declared so a consumer can see the depth before relying on it.
    pub required_depth: u64,
    /// The time unit the attestation's `finalized_at` is expressed in.
    pub time_unit: TimeUnit,
    /// Whether the adapter's proofs are checkable by anybody with the
    /// evidence, or require a trusted party. This is the single most
    /// important line in the profile.
    pub trust_model: TrustModel,
}

/// What the target system's finality actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityKind {
    /// Probabilistic: deep enough that reversal is uneconomic, never
    /// impossible.
    Probabilistic,
    /// Economic: reversal costs a bonded amount.
    EconomicFinality,
    /// Protocol: the protocol itself marks the height irreversible.
    ProtocolFinality,
    /// Validity-proven: a proof, not a vote.
    Proven,
}

/// Who has to be honest for the attestation to be true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustModel {
    /// Anybody with the evidence can check it. No honest party is assumed.
    Trustless,
    /// An honest majority of a known, bounded set is assumed.
    HonestMajority { set_size: u64 },
    /// A specific party must behave. Named, not hidden.
    TrustedParty,
}

/// Rules the caller imposes on a verification. Separated from the adapter so
/// that a domain can be read more strictly than its adapter requires - a
/// bridge holding funds wants more depth than a display surface does - without
/// the adapter having to know who is asking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Refuse unless the evidence reaches at least this depth.
    pub min_depth: u64,
    /// Refuse unless the evidence's declared height and root match what the
    /// adapter derives from the payload. On by default in every caller here:
    /// the declaration is the only thing the network indexed before invoking
    /// the adapter, so a mismatch means the index and the truth disagree.
    pub require_declared_match: bool,
    /// Refuse evidence older than this many of the target's time units.
    pub max_age: u64,
    /// The target's current time, supplied by the caller so the adapter has
    /// no clock of its own. An adapter that reads a wall clock cannot be
    /// replayed deterministically, and cannot be tested.
    pub now: u64,
    /// Refuse unless the backing reaches this shape. Lets a caller say "I
    /// will not accept an unslashable signature set" without naming a system.
    pub require_slashable: bool,
}

impl VerificationPolicy {
    /// The policy every caller in this tree starts from. Deliberately strict:
    /// a caller loosens it on purpose, in writing, at the call site.
    ///
    /// For **vote-based** domains. Depth is a proxy for security in a system
    /// whose finality is a vote; a proven domain does not need the proxy, and
    /// asking one for depth makes it refuse - see [`Self::proven`].
    #[must_use]
    pub fn strict(now: u64) -> Self {
        Self {
            min_depth: 1,
            require_declared_match: true,
            max_age: 0,
            now,
            require_slashable: false,
        }
    }

    /// The policy for a **proven** domain: one whose finality is a validity
    /// proof rather than a vote.
    ///
    /// `min_depth` is zero because depth is not a property of a proof - it is
    /// valid or it is not. A proven adapter refuses a non-zero `min_depth`
    /// rather than ignoring it, so that a caller who asks for depth is told
    /// they are asking for something this attestation cannot give instead of
    /// silently receiving an attestation without it.
    ///
    /// `require_slashable` is false for the same reason: there is nobody to
    /// slash.
    #[must_use]
    pub fn proven(now: u64) -> Self {
        Self {
            min_depth: 0,
            require_declared_match: true,
            max_age: 0,
            now,
            require_slashable: false,
        }
    }
}

/// Why a verification was refused. Every variant names the rule, so a refusal
/// can be logged, metered and tested without reading the adapter's source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// The evidence names an adapter that is not this one.
    #[error("evidence names adapter {found}, this adapter is {expected}")]
    WrongAdapter { expected: String, found: String },
    /// The evidence format version is not one this adapter accepts.
    #[error("evidence version {version} is not accepted; accepted: {accepted}")]
    UnsupportedEvidenceVersion { version: u32, accepted: String },
    /// The payload could not be read at all.
    #[error("payload is unreadable at offset {offset}: {reason}")]
    Malformed { offset: usize, reason: String },
    /// The payload was read but does not satisfy the target's own rules.
    #[error("consensus rule refused: {rule}")]
    ConsensusRule { rule: String },
    /// The declared height or root disagrees with the derived one.
    #[error("declared {field} does not match what the payload derives")]
    DeclarationMismatch { field: &'static str },
    /// Not deep enough for the caller's policy.
    #[error("depth {observed} is below the required {required}")]
    InsufficientDepth { observed: u64, required: u64 },
    /// Older than the caller allows.
    #[error("evidence age {age} exceeds the allowed {max_age}")]
    Stale { age: u64, max_age: u64 },
    /// The backing is not slashable and the caller required slashable backing.
    #[error("the caller requires slashable backing; this evidence's backing is not")]
    UnslashableBacking,
    /// A cryptographic check failed.
    #[error("cryptographic verification failed: {what}")]
    Crypto { what: String },
    /// The adapter itself is in a state where it must refuse - for example a
    /// build without the crypto feature it needs. Refusing is the behaviour;
    /// guessing would be the bug.
    #[error("adapter cannot serve this request: {reason}")]
    Unavailable { reason: String },
}

/// The interface itself. Four required methods and one optional, and the
/// optional one is the reason a third-party adapter can be admitted without
/// anybody reading its source.
pub trait ExternalFinalityAdapter: Send + Sync {
    /// Who this adapter says it is. Read at registration and compared on every
    /// call, so an adapter cannot be swapped under a domain that already
    /// points at an id.
    fn descriptor(&self) -> AdapterDescriptor;

    /// Reads raw evidence and produces the attestation Budlum commits to.
    ///
    /// # Errors
    ///
    /// Any [`AdapterError`]. Implementations must refuse rather than
    /// approximate: there is no partial attestation.
    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError>;

    /// The negative cases this adapter must refuse. Data, not code - see
    /// [`crate::cross_domain::external::selftest`] for why that distinction is
    /// the whole admission model.
    fn fault_probes(&self) -> Vec<crate::cross_domain::external::selftest::FaultProbe>;

    /// A canonical, known-good evidence sample for the current version. Used
    /// by the self-test harness to prove the adapter accepts what it should,
    /// so a probe suite that refuses everything is caught as the failure it
    /// is rather than passing by refusing.
    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        None
    }
}
