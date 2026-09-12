//! Adapter admission: how an adapter proves it refuses what it must, before
//! anybody routes value through it.
//!
//! # The model in one sentence
//!
//! An adapter ships a list of **fault probes** - data describing how to
//! corrupt a known-good evidence sample - and admission runs every probe
//! against the adapter and requires a refusal.
//!
//! # Why probes are data and not code
//!
//! The obvious design is a callback: `probes: Vec<Box<dyn Fn(&mut Evidence)>>`.
//! That design cannot be admitted on a chain, because the chain cannot run a
//! callback it did not compile, and it cannot let a third party submit one. It
//! also cannot be replayed: a callback's behaviour can change when the adapter
//! binary is rebuilt, so "it passed admission in March" stops being a
//! statement about the binary running in September.
//!
//! A probe as data is a patch: an offset, a length, replacement bytes. Any
//! node can apply it, run the adapter, and check the refusal - now, later, or
//! against a version the probe author has never seen. The probe set becomes
//! part of the adapter's registration and therefore part of what the bond
//! covers.
//!
//! # Why a golden sample is required
//!
//! A probe suite that refuses everything passes every probe. An adapter whose
//! `verify` always returns `Err` is perfectly self-test-compliant and
//! completely useless. So the harness runs the golden sample first and
//! requires success; only then do the probes mean anything.
//!
//! # What this model does not prove
//!
//! It proves the adapter refuses the faults its author thought of. It does not
//! prove the adapter is correct - no self-test can. That gap is what the bond
//! and the slashing in
//! [`crate::cross_domain::external::prover`] are for: correctness is bought
//! with money at risk, self-tests only make the cheap mistakes expensive to
//! ship.

use crate::core::address::Address;
use crate::cross_domain::external::spec::{
    AdapterError, ExternalFinalityAdapter, RawConsensusEvidence, VerificationPolicy,
};
use serde::{Deserialize, Serialize};

/// One corruption, expressed as data so any node can apply and replay it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultProbe {
    /// Human-readable name. Ends up in the admission report, so it should say
    /// what rule is being probed, not how the bytes are edited.
    pub name: String,
    /// Where the corruption goes.
    pub patch: BytePatch,
    /// What the adapter must answer. A probe that expects a specific variant
    /// is stronger than one that expects "any error": it pins the rule.
    pub expect: ExpectedRefusal,
}

/// A byte-level edit to the evidence envelope.
///
/// Three kinds, because the three ways evidence goes wrong are structurally
/// different: the payload is corrupted, the declaration stops matching the
/// payload, or the envelope metadata is lied about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BytePatch {
    /// Overwrite `bytes` at `offset` inside `payload`. An offset past the end
    /// is itself a probe of the parser's bounds handling, so it is allowed
    /// rather than rejected here.
    InPayload { offset: usize, bytes: Vec<u8> },
    /// Truncate the payload. Probes that a short read is a refusal and not a
    /// partial parse.
    TruncatePayload { keep: usize },
    /// Change the declared height, leaving the payload alone. Probes that the
    /// adapter derives the height instead of believing the envelope.
    DeclaredHeight { value: u64 },
    /// Change the declared root, leaving the payload alone.
    DeclaredRoot { value: [u8; 32] },
    /// Change the evidence version. Probes the version gate specifically: an
    /// adapter that sniffs the format instead of reading the version will
    /// happily parse this.
    EvidenceVersion { value: u32 },
    /// Swap the submitter. Proves that whatever the adapter says about the
    /// submitter is actually enforced, or that it honestly ignores it.
    Submitter { value: Address },
    /// Swap the network label. Probes that one adapter binary cannot be
    /// pointed at a different network and still produce attestations.
    Network { value: String },
}

/// What a probe requires the adapter to answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedRefusal {
    /// Any [`AdapterError`] at all.
    Any,
    /// A specific rule must fire. Strongest form; preferred.
    Kind(RefusalKind),
}

/// The refusal categories a probe can pin, mirrored from [`AdapterError`] but
/// stable across message wording changes: a probe that matched on an English
/// sentence would break the day somebody improved the sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalKind {
    WrongAdapter,
    UnsupportedEvidenceVersion,
    Malformed,
    ConsensusRule,
    DeclarationMismatch,
    InsufficientDepth,
    Stale,
    UnslashableBacking,
    Crypto,
    Unavailable,
}

impl RefusalKind {
    #[must_use]
    pub fn of(err: &AdapterError) -> Self {
        match err {
            AdapterError::WrongAdapter { .. } => Self::WrongAdapter,
            AdapterError::UnsupportedEvidenceVersion { .. } => Self::UnsupportedEvidenceVersion,
            AdapterError::Malformed { .. } => Self::Malformed,
            AdapterError::ConsensusRule { .. } => Self::ConsensusRule,
            AdapterError::DeclarationMismatch { .. } => Self::DeclarationMismatch,
            AdapterError::InsufficientDepth { .. } => Self::InsufficientDepth,
            AdapterError::Stale { .. } => Self::Stale,
            AdapterError::UnslashableBacking => Self::UnslashableBacking,
            AdapterError::Crypto { .. } => Self::Crypto,
            AdapterError::Unavailable { .. } => Self::Unavailable,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WrongAdapter => "wrong-adapter",
            Self::UnsupportedEvidenceVersion => "unsupported-evidence-version",
            Self::Malformed => "malformed",
            Self::ConsensusRule => "consensus-rule",
            Self::DeclarationMismatch => "declaration-mismatch",
            Self::InsufficientDepth => "insufficient-depth",
            Self::Stale => "stale",
            Self::UnslashableBacking => "unslashable-backing",
            Self::Crypto => "crypto",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The outcome of running one probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeOutcome {
    /// The adapter refused, as required.
    Refused { kind: RefusalKind },
    /// The adapter accepted corrupted evidence. This is the failure the whole
    /// harness exists to catch.
    Accepted,
    /// The adapter refused, but for a different rule than the probe pinned.
    /// Counted as a failure: an adapter that refuses for the wrong reason is
    /// usually refusing for an accidental one, and the accident will move.
    WrongRefusal { got: RefusalKind, wanted: RefusalKind },
    /// The probe could not be applied - for example a truncation longer than
    /// the payload. Recorded rather than skipped, because a probe that
    /// silently stops applying is a probe that stops protecting.
    Unappliable { reason: String },
}

impl ProbeOutcome {
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

/// The whole admission run, as a record. Stored against the domain so a
/// consumer can see not just "admitted" but *what was probed* - an admission
/// over three probes and one over thirty are not the same assurance, and a
/// boolean would hide that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReport {
    pub adapter_version: u32,
    pub evidence_version: u32,
    /// Whether the golden sample verified. If this is false, everything below
    /// is meaningless and `admitted` must be false.
    pub golden_verified: bool,
    pub probes: Vec<(String, ProbeOutcome)>,
    pub admitted: bool,
}

impl AdmissionReport {
    #[must_use]
    pub fn passed(&self) -> usize {
        self.probes.iter().filter(|(_, o)| o.passed()).count()
    }

    #[must_use]
    pub fn total(&self) -> usize {
        self.probes.len()
    }

    /// The digest a registration commits to. A domain's bond covers this
    /// digest, so changing the probe set after admission is a new admission,
    /// not an edit.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"bud-adapter-admission-v1",
            &self.adapter_version.to_le_bytes(),
            &self.evidence_version.to_le_bytes(),
            &[u8::from(self.golden_verified)],
            &self.probes.len().to_le_bytes(),
        ]);
        for (name, outcome) in &self.probes {
            acc = crate::core::hash::hash_fields_bytes(&[
                &acc,
                name.as_bytes(),
                outcome_label(outcome).as_bytes(),
            ]);
        }
        acc
    }
}

/// A short stable label for an outcome, so the digest does not depend on
/// `Debug` formatting.
#[must_use]
fn outcome_label(outcome: &ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::Refused { kind } => format!("refused:{}", kind.as_str()),
        ProbeOutcome::Accepted => "accepted".to_string(),
        ProbeOutcome::WrongRefusal { got, wanted } => {
            format!("wrong:{}!={}", got.as_str(), wanted.as_str())
        }
        ProbeOutcome::Unappliable { .. } => "unappliable".to_string(),
    }
}

/// Applies a patch to an evidence sample, producing the corrupted copy.
///
/// Returns the sample or a reason it could not be applied. Never panics and
/// never silently does nothing: an unappliable patch is reported so the
/// harness can record it.
#[must_use]
pub fn apply_patch(
    evidence: &RawConsensusEvidence,
    patch: &BytePatch,
) -> Result<RawConsensusEvidence, String> {
    let mut out = evidence.clone();
    match patch {
        BytePatch::InPayload { offset, bytes } => {
            let end = offset.saturating_add(bytes.len());
            if end > out.payload.len() {
                return Err(format!(
                    "patch {offset}..{end} is past the payload's {} bytes",
                    out.payload.len()
                ));
            }
            let Some(window) = out.payload.get_mut(*offset..end) else {
                return Err("payload window is not in range".to_string());
            };
            window.copy_from_slice(bytes);
        }
        BytePatch::TruncatePayload { keep } => {
            if *keep > out.payload.len() {
                return Err(format!(
                    "cannot keep {keep} of {} bytes",
                    out.payload.len()
                ));
            }
            out.payload.truncate(*keep);
        }
        BytePatch::DeclaredHeight { value } => out.declared_height = *value,
        BytePatch::DeclaredRoot { value } => out.declared_root = *value,
        BytePatch::EvidenceVersion { value } => out.evidence_version = *value,
        BytePatch::Submitter { value } => out.submitter = *value,
        BytePatch::Network { value } => out.network = value.clone(),
    }
    Ok(out)
}

/// Runs one probe against an adapter.
#[must_use]
pub fn run_probe(
    adapter: &dyn ExternalFinalityAdapter,
    golden: &RawConsensusEvidence,
    probe: &FaultProbe,
    policy: &VerificationPolicy,
) -> ProbeOutcome {
    let corrupted = match apply_patch(golden, &probe.patch) {
        Ok(c) => c,
        Err(reason) => {
            return ProbeOutcome::Unappliable { reason };
        }
    };
    match adapter.verify(&corrupted, policy) {
        Ok(_) => ProbeOutcome::Accepted,
        Err(err) => {
            let got = RefusalKind::of(&err);
            match &probe.expect {
                ExpectedRefusal::Any => ProbeOutcome::Refused { kind: got },
                ExpectedRefusal::Kind(wanted) => {
                    if got == *wanted {
                        ProbeOutcome::Refused { kind: got }
                    } else {
                        ProbeOutcome::WrongRefusal {
                            got,
                            wanted: *wanted,
                        }
                    }
                }
            }
        }
    }
}

/// The full admission run.
///
/// The golden check comes first and gates everything: without it, an adapter
/// that refuses every input passes every probe.
#[must_use]
pub fn admit(
    adapter: &dyn ExternalFinalityAdapter,
    policy: &VerificationPolicy,
) -> AdmissionReport {
    let descriptor = adapter.descriptor();
    let evidence_version = descriptor
        .accepted_evidence_versions
        .first()
        .copied()
        .unwrap_or(0);

    let Some(golden) = adapter.golden_evidence() else {
        return AdmissionReport {
            adapter_version: descriptor.adapter_version,
            evidence_version,
            golden_verified: false,
            probes: Vec::new(),
            admitted: false,
        };
    };

    // The golden sample must verify. This is the check that makes the probe
    // results mean anything.
    let golden_verified = adapter.verify(&golden, policy).is_ok();

    let mut probes = Vec::with_capacity(adapter.fault_probes().len());
    for probe in adapter.fault_probes() {
        let outcome = run_probe(adapter, &golden, &probe, policy);
        probes.push((probe.name.clone(), outcome));
    }

    let all_passed = probes.iter().all(|(_, o)| o.passed());
    AdmissionReport {
        adapter_version: descriptor.adapter_version,
        evidence_version,
        golden_verified,
        admitted: golden_verified && all_passed && !probes.is_empty(),
        probes,
    }
}
