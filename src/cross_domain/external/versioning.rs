//! Version and fork management for external adapters.
//!
//! # The problem
//!
//! An external chain hard-forks. Its evidence format changes. There are now
//! two formats in the world at once - old nodes still produce the old one,
//! new nodes produce the new one - and an adapter that "handles both" has to
//! decide which one it is looking at.
//!
//! Every silent-corruption bug in this area comes from that decision being
//! made by *sniffing the payload*: a length field that happens to be valid in
//! both formats, a magic number reused, an optional field that is absent in
//! one and zero in the other. The adapter then parses a new-format payload as
//! old format, produces an attestation that verifies, and commits a state root
//! that means something else than everybody thinks.
//!
//! # The rule this module enforces
//!
//! **The version is declared in the envelope and trusted only as far as the
//! gate; it is never inferred from the payload.** An unknown version is a hard
//! refusal. A version past its sunset height is a hard refusal. An adapter
//! that accepts a version it did not declare is failing its own descriptor,
//! which admission tests for.
//!
//! # What happens at a fork, step by step
//!
//! 1. The adapter's author publishes a new adapter version whose
//!    `accepted_evidence_versions` includes the new format. Registration is
//!    permissionless, so this is a transaction, not a Budlum release.
//! 2. The domain's operator records a **fork schedule**: at external height H,
//!    version V becomes valid, and version V-1 sunsets at H + grace.
//! 3. During the grace window both versions verify, and every attestation
//!    carries the version that produced it. Two attestations at the same
//!    height from different versions are both stored; the global header
//!    commits to the version, so a consumer can see the disagreement instead
//!    of inheriting a silent merge.
//! 4. After the sunset height, the old version is refused. Not deprecated -
//!    refused.

use crate::cross_domain::external::spec::{AdapterError, AdapterId};
use serde::{Deserialize, Serialize};

/// One entry in a domain's fork schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionWindow {
    /// The evidence format version.
    pub version: u32,
    /// The external height from which this version may appear. Evidence
    /// declaring this version below this height is refused: a format cannot
    /// exist before the fork that introduced it, and a payload claiming
    /// otherwise is a lie about the chain's history.
    pub valid_from_height: u64,
    /// The external height after which this version is refused. `None` means
    /// "current, no sunset".
    pub sunset_height: Option<u64>,
}

impl VersionWindow {
    /// Whether this window covers a claim at `height`.
    #[must_use]
    pub fn covers(&self, height: u64) -> bool {
        height >= self.valid_from_height && self.sunset_height.is_none_or(|sunset| height <= sunset)
    }

    /// Whether this window is still open at `height` - the same question as
    /// [`Self::covers`] but phrased for the "is the old format dead yet"
    /// caller, kept separate because the two read differently in a log line.
    #[must_use]
    pub fn is_active_at(&self, height: u64) -> bool {
        self.covers(height)
    }
}

/// A domain's complete version policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionPolicy {
    pub adapter: AdapterId,
    /// Every version this domain has ever accepted, with its window. Kept
    /// after sunset so a historical attestation can still be explained -
    /// "this was valid under version 3, which sunset at height 900" is an
    /// answer, and "unknown version" would not be.
    pub windows: Vec<VersionWindow>,
    /// How many heights of overlap a fork is allowed. Declared so a grace
    /// window cannot be opened indefinitely, which would be a way of keeping
    /// an old, weaker format alive forever.
    pub max_grace_heights: u64,
}

impl VersionPolicy {
    /// The policy for a domain that has never forked: one version, valid from
    /// genesis, no sunset.
    #[must_use]
    pub fn single(adapter: AdapterId, version: u32, max_grace_heights: u64) -> Self {
        Self {
            adapter,
            windows: vec![VersionWindow {
                version,
                valid_from_height: 0,
                sunset_height: None,
            }],
            max_grace_heights,
        }
    }

    /// The window for a version, if this domain has one.
    #[must_use]
    pub fn window(&self, version: u32) -> Option<&VersionWindow> {
        self.windows.iter().find(|w| w.version == version)
    }

    /// The version a caller should expect right now, for logging and for the
    /// profile. The highest version whose window is open; `None` if the
    /// schedule is empty or everything has sunset, which is itself a state a
    /// domain should not be in.
    #[must_use]
    pub fn current_version_at(&self, height: u64) -> Option<u32> {
        self.windows
            .iter()
            .filter(|w| w.is_active_at(height))
            .map(|w| w.version)
            .max()
    }

    /// Records a fork: version `new_version` becomes valid at
    /// `fork_height`, and `old_version` sunsets `grace_heights` later.
    ///
    /// # Errors
    ///
    /// A fork into an already-known version, a fork height in the past
    /// relative to the version it replaces, or a grace window wider than the
    /// domain allows.
    pub fn schedule_fork(
        &mut self,
        old_version: u32,
        new_version: u32,
        fork_height: u64,
        grace_heights: u64,
    ) -> Result<(), ForkError> {
        if old_version == new_version {
            return Err(ForkError::SameVersion {
                version: new_version,
            });
        }
        if self.window(new_version).is_some() {
            return Err(ForkError::VersionAlreadyScheduled {
                version: new_version,
            });
        }
        if grace_heights > self.max_grace_heights {
            return Err(ForkError::GraceTooWide {
                requested: grace_heights,
                allowed: self.max_grace_heights,
            });
        }
        let sunset = fork_height.saturating_add(grace_heights);

        // The outgoing version's window must end. Leaving it open would mean
        // the fork never actually happened and both formats are current
        // forever - which is the state that produces silent divergence.
        let Some(old) = self.windows.iter_mut().find(|w| w.version == old_version) else {
            return Err(ForkError::UnknownOldVersion {
                version: old_version,
            });
        };
        if old.valid_from_height > fork_height {
            return Err(ForkError::ForkBeforeValidity {
                version: old_version,
                valid_from: old.valid_from_height,
                fork_height,
            });
        }
        old.sunset_height = Some(sunset);

        self.windows.push(VersionWindow {
            version: new_version,
            valid_from_height: fork_height,
            sunset_height: None,
        });
        self.windows.sort_by_key(|w| w.version);
        Ok(())
    }

    /// The gate every adapter call passes through.
    ///
    /// # Errors
    ///
    /// [`AdapterError::UnsupportedEvidenceVersion`] for a version this domain
    /// never scheduled, or one whose window does not cover the claimed height.
    pub fn gate(&self, evidence_version: u32, height: u64) -> Result<(), AdapterError> {
        let Some(window) = self.window(evidence_version) else {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence_version,
                accepted: self.accepted_list(),
            });
        };
        if !window.covers(height) {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence_version,
                accepted: format!(
                    "{} (window {}..{} does not cover height {height})",
                    evidence_version,
                    window.valid_from_height,
                    window
                        .sunset_height
                        .map_or("open".to_string(), |s| s.to_string())
                ),
            });
        }
        Ok(())
    }

    /// The versions this policy knows, for an error message a human can act
    /// on. Sorted, so the message is stable across runs.
    #[must_use]
    pub fn accepted_list(&self) -> String {
        let mut versions: Vec<u32> = self.windows.iter().map(|w| w.version).collect();
        versions.sort_unstable();
        versions
            .iter()
            .map(u32::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// Whether this policy is in a state that can serve at all: at least one
    /// open window, and no two windows for the same version.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        let mut seen: Vec<u32> = Vec::with_capacity(self.windows.len());
        for window in &self.windows {
            if seen.contains(&window.version) {
                return false;
            }
            seen.push(window.version);
        }
        true
    }
}

/// Why a fork schedule was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ForkError {
    #[error("a fork cannot be from version {version} to itself")]
    SameVersion { version: u32 },
    #[error("version {version} is already scheduled")]
    VersionAlreadyScheduled { version: u32 },
    #[error("the outgoing version {version} was never scheduled")]
    UnknownOldVersion { version: u32 },
    #[error("a grace window of {requested} heights exceeds the domain's limit of {allowed}")]
    GraceTooWide { requested: u64, allowed: u64 },
    #[error(
        "version {version} only becomes valid at height {valid_from}, after the fork height {fork_height}"
    )]
    ForkBeforeValidity {
        version: u32,
        valid_from: u64,
        fork_height: u64,
    },
}
