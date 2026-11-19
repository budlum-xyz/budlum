//! Phase 3 `Shadow` mode auditor (`AggMode::Shadow`).
//!
//! Runs side-by-side parity checks between native transaction signature
//! verification and aggregation claim derivation without altering block
//! validity, publishing frames, or changing consensus rules.
//!
//! WIRING: Node shadow-mode block hooks invoke `ShadowAuditor::audit_block`
//! when `AggParams::mode == AggMode::Shadow` to verify zero divergence across
//! live blocks before flipping a network to `AggMode::On`.

use super::chain::{account_claim, claim_domain, claim_signature};
use super::object::derive_claim;
use super::params::{AggMode, AggParams};
use crate::core::block::Block;
use crate::core::transaction::{Transaction, SIGNATURE_VERSION_V5};
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::DomainId;

/// Cumulative telemetry collected across audited blocks in `AggMode::Shadow`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShadowReport {
    /// Number of blocks audited.
    pub blocks_audited: u64,
    /// Number of inline PQ-signed transactions checked.
    pub txs_checked: u64,
    /// Number of transactions where native and aggregation agreed.
    pub matches: u64,
    /// Number of divergences between native verification and claim derivation.
    pub mismatches: u64,
}

/// Side-by-side shadow auditor for [`AggMode::Shadow`].
#[derive(Debug, Clone)]
pub struct ShadowAuditor {
    registry: SchemeStatusRegistry,
    params: AggParams,
    report: ShadowReport,
}

impl ShadowAuditor {
    /// Creates a new `ShadowAuditor`.
    #[must_use]
    pub const fn new(registry: SchemeStatusRegistry, params: AggParams) -> Self {
        Self {
            registry,
            params,
            report: ShadowReport {
                blocks_audited: 0,
                txs_checked: 0,
                matches: 0,
                mismatches: 0,
            },
        }
    }

    /// Returns the cumulative shadow audit report.
    #[must_use]
    pub const fn report(&self) -> &ShadowReport {
        &self.report
    }

    /// Audits one block without affecting consensus.
    ///
    /// Returns `Ok(true)` if every transaction in `block` matched between
    /// native signature verification (including `tx.chain_id == block.chain_id`)
    /// and full aggregation claim admission (envelope domain match, `derive_claim`,
    /// and Rule-6 account-claim digest binding against `tx.from`), or
    /// `Ok(false)` if any mismatch was recorded.
    ///
    /// # Errors
    ///
    /// Returns an error if `block.chain_id` does not fit a `DomainId`.
    pub fn audit_block(&mut self, block: &Block) -> Result<bool, String> {
        if self.params.mode != AggMode::Shadow {
            return Ok(true);
        }
        let domain = claim_domain(block.chain_id)
            .ok_or_else(|| format!("shadow: chain_id {} does not fit DomainId", block.chain_id))?;

        let mut all_matched = true;
        for tx in &block.transactions {
            let is_inline_v5 = tx.signature_version == SIGNATURE_VERSION_V5
                && tx.authorization.is_none()
                && tx.signature.is_some()
                && !tx.is_claimed();
            if !is_inline_v5 {
                continue;
            }
            self.report.txs_checked = self.report.txs_checked.saturating_add(1);
            let matched = self.audit_tx(tx, block.chain_id, domain);
            if matched {
                self.report.matches = self.report.matches.saturating_add(1);
            } else {
                self.report.mismatches = self.report.mismatches.saturating_add(1);
                all_matched = false;
            }
        }
        self.report.blocks_audited = self.report.blocks_audited.saturating_add(1);
        Ok(all_matched)
    }

    fn audit_tx(&self, tx: &Transaction, block_chain_id: u64, domain: DomainId) -> bool {
        let native_ok = tx.chain_id == block_chain_id && tx.verify_in(&self.registry);
        let agg_ok = claim_signature(tx).is_some_and(|(claimed, env)| {
            if env.domain != domain || !claimed.claimed_shape_is_canonical() {
                return false;
            }
            let Some(expected) = account_claim(&claimed) else {
                return false;
            };
            let expected_digest = expected.digest(domain);
            if claimed.auth_claim != Some(expected_digest) {
                return false;
            }
            derive_claim(&self.registry, &env).is_ok_and(|derived| {
                derived == expected && derived.digest(domain) == expected_digest
            })
        });
        native_ok == agg_ok
    }
}
