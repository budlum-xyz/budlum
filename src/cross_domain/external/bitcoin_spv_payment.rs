//! WIRING: unwired - standalone Bitcoin SPV raw-transaction and confirmed-payment
//! Merkle verifiers await the BTC bridge redemption transaction door.

use super::{
    compute_next_work_required_with_limit, median_time_past_floor, meets_target, sha256d,
    target_from_bits, verify_spv_tx_inclusion, ChainWork256, VerifiedBitcoinChain,
    VerifiedBitcoinHeader, VerifiedSpvTransaction, DIFFICULTY_ADJUSTMENT_INTERVAL,
    FORBIDDEN_INNER_NODE_TX_BYTES, MAINNET_POW_LIMIT_BITS, MAX_HEADERS, MAX_STRIPPED_TX_BYTES,
    REGTEST_POW_LIMIT_BITS,
};
use crate::cross_domain::external::spec::{AdapterError, DomainKey, SecurityBacking, TimeUnit};

/// Verify inclusion of a raw stripped Bitcoin transaction against `merkle_root`.
///
/// Enforces CVE-2017-12842 (forbidding 64-byte stripped transactions) and
/// CVE-2012-2459 (duplicate-branch guard in [`verify_spv_tx_inclusion`]).
///
/// # Errors
///
/// Returns [`AdapterError`] if `stripped_tx` exceeds bounds, measures
/// exactly 64 bytes, violates coinbase position rules, or fails Merkle proof
/// verification against `merkle_root`.
///
/// Convenience: kept for the CLI and bridge Bitcoin payment settlement callers.
pub fn verify_spv_raw_tx_inclusion(
    stripped_tx: &[u8],
    merkle_root: &[u8; 32],
    tx_index: u32,
    branch: &[[u8; 32]],
    expect_coinbase: bool,
) -> Result<VerifiedSpvTransaction, AdapterError> {
    if stripped_tx.is_empty() || stripped_tx.len() > MAX_STRIPPED_TX_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!(
                "stripped Bitcoin tx length {} is outside 1..={MAX_STRIPPED_TX_BYTES}",
                stripped_tx.len()
            ),
        });
    }
    if stripped_tx.len() == FORBIDDEN_INNER_NODE_TX_BYTES {
        return Err(AdapterError::ConsensusRule {
            rule: "64-byte stripped Bitcoin tx refused (CVE-2017-12842 inner-node guard)"
                .to_string(),
        });
    }
    let is_coinbase = tx_index == 0;
    if expect_coinbase != is_coinbase {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin coinbase flag mismatch: expect_coinbase={expect_coinbase} at tx_index={tx_index}"
            ),
        });
    }
    let txid = sha256d(stripped_tx);
    if !verify_spv_tx_inclusion(&txid, merkle_root, tx_index, branch) {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin SPV Merkle branch does not verify against header merkle_root"
                .to_string(),
        });
    }
    Ok(VerifiedSpvTransaction {
        txid,
        tx_index,
        is_coinbase,
        confirmations: 1,
    })
}

fn verify_single_header_step(
    idx: usize,
    headers: &[VerifiedBitcoinHeader],
    hdr: &VerifiedBitcoinHeader,
    expected_height: u64,
    expected_parent: &[u8; 32],
    active_bits: &mut u32,
    pow_limit_bits: u32,
) -> Result<ChainWork256, AdapterError> {
    if hdr.height != expected_height {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin header height {} breaks contiguous progression at {expected_height}",
                hdr.height
            ),
        });
    }
    if hdr.parent_hash != *expected_parent {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin header does not link to its parent".to_string(),
        });
    }
    let pow_limit_target = target_from_bits(pow_limit_bits)?;
    let hdr_target = target_from_bits(hdr.bits)?;
    if hdr_target > pow_limit_target {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin header nBits {:08x} exceeds network powLimit {pow_limit_bits:08x}",
                hdr.bits
            ),
        });
    }
    if hdr.height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
        if let Ok(epoch_span) = usize::try_from(DIFFICULTY_ADJUSTMENT_INTERVAL) {
            if idx >= epoch_span {
                if let (Some(first_hdr), Some(last_hdr)) =
                    (headers.get(idx - epoch_span), headers.get(idx - 1))
                {
                    let expected_bits = compute_next_work_required_with_limit(
                        first_hdr.timestamp,
                        last_hdr.timestamp,
                        *active_bits,
                        pow_limit_bits,
                    )?;
                    if hdr.bits != expected_bits {
                        return Err(AdapterError::ConsensusRule {
                            rule: format!(
                                "Bitcoin retarget at height {} expected nBits {expected_bits:08x}, found {:08x}",
                                hdr.height, hdr.bits
                            ),
                        });
                    }
                }
            }
        }
        *active_bits = hdr.bits;
    } else if hdr.bits != *active_bits {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin header nBits {:08x} leaves active difficulty epoch {:08x}",
                hdr.bits, *active_bits
            ),
        });
    }
    if !verify_spv_tx_inclusion(&hdr.merkle_root, &hdr.merkle_root, 0, &[]) {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin header carries an empty zero merkle_root".to_string(),
        });
    }
    if !meets_target(&hdr.hash, &hdr_target) {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin header hash does not meet the nBits target".to_string(),
        });
    }
    let expected_work = ChainWork256::from_bits(hdr.bits)?;
    if hdr.block_work != expected_work {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin header block_work does not match its nBits target".to_string(),
        });
    }
    Ok(expected_work)
}

impl VerifiedBitcoinChain {
    fn pow_limit_bits(&self) -> u32 {
        let regtest_domain = DomainKey::from_parts(&self.attestation.adapter, "regtest");
        if self.attestation.domain == regtest_domain {
            REGTEST_POW_LIMIT_BITS
        } else {
            MAINNET_POW_LIMIT_BITS
        }
    }

    fn verify_chain_continuity(&self) -> Result<(), AdapterError> {
        if self.headers.is_empty() || self.headers.len() > MAX_HEADERS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "verified Bitcoin header slice length {} is outside 1..={MAX_HEADERS}",
                    self.headers.len()
                ),
            });
        }
        let pow_limit_bits = self.pow_limit_bits();
        let pow_limit_target = target_from_bits(pow_limit_bits)?;
        if target_from_bits(self.anchor_bits)? > pow_limit_target {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "anchor nBits {:08x} exceeds network powLimit {pow_limit_bits:08x}",
                    self.anchor_bits
                ),
            });
        }
        let mut expected_parent = self.anchor_hash;
        let mut prev_height = self.anchor_height;
        let mut active_bits = self.anchor_bits;
        let mut seen_timestamps = Vec::with_capacity(self.headers.len());
        let mut prev_cum_work: Option<ChainWork256> = None;

        for (idx, hdr) in self.headers.iter().enumerate() {
            let expected_height =
                prev_height
                    .checked_add(1)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: "Bitcoin header height overflows u64".to_string(),
                    })?;
            if let Some(floor) = median_time_past_floor(&seen_timestamps) {
                if hdr.timestamp <= floor {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin header timestamp {} does not exceed BIP-113 MTP floor {floor}",
                            hdr.timestamp
                        ),
                    });
                }
            }
            let expected_work = verify_single_header_step(
                idx,
                &self.headers,
                hdr,
                expected_height,
                &expected_parent,
                &mut active_bits,
                pow_limit_bits,
            )?;
            if let Some(prev_cw) = prev_cum_work {
                // Exact arithmetic: a saturated step would let two different
                // header sets claim the same cumulative work at the 256-bit
                // ceiling, which is precisely the tie the fork choice must be
                // able to break.
                let expected_cum = prev_cw.checked_add(expected_work).ok_or_else(|| {
                    AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin header cumulative_work overflows 256 bits at height {}",
                            hdr.height
                        ),
                    }
                })?;
                if hdr.cumulative_work != expected_cum {
                    return Err(AdapterError::ConsensusRule {
                        rule: "Bitcoin header cumulative_work breaks chainwork progression"
                            .to_string(),
                    });
                }
            } else if hdr.cumulative_work < expected_work {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin initial header cumulative_work underflows block_work"
                        .to_string(),
                });
            }
            prev_height = expected_height;
            expected_parent = hdr.hash;
            prev_cum_work = Some(hdr.cumulative_work);
            seen_timestamps.push(hdr.timestamp);
        }

        let tip = self
            .headers
            .last()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "verified Bitcoin header chain has no tip".to_string(),
            })?;
        self.verify_tip_attestation_binding(tip)
    }

    fn verify_tip_attestation_binding(
        &self,
        tip: &VerifiedBitcoinHeader,
    ) -> Result<(), AdapterError> {
        if tip.height != self.attestation.height {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Bitcoin chain tip height {} does not match attestation height {}",
                    tip.height, self.attestation.height
                ),
            });
        }
        if self.attestation.state_root != tip.hash
            || self.attestation.attested_block_hash != Some(tip.hash)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin chain tip hash does not match attested block hash".to_string(),
            });
        }
        if self.attestation.attested_tx_root != Some(tip.merkle_root) {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin chain tip merkle_root does not match attested_tx_root".to_string(),
            });
        }
        if self.attestation.finalized_at != u64::from(tip.timestamp)
            || self.attestation.time_unit != TimeUnit::UnixSeconds
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin chain tip timestamp does not match attestation finalized_at"
                    .to_string(),
            });
        }
        if !matches!(
            self.attestation.security,
            SecurityBacking::Work { difficulty_bits } if difficulty_bits > 0
        ) {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin finality attestation lacks non-zero Work security backing"
                    .to_string(),
            });
        }
        if self.total_chainwork != tip.cumulative_work {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin total_chainwork does not match tip cumulative_work".to_string(),
            });
        }
        Ok(())
    }

    /// Verify a raw stripped transaction inside `block_hash` with at least
    /// `min_confirmations` proof-of-work confirmations on this verified chain.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if header-chain continuity or tip-attestation
    /// binding fails, `block_hash` is absent, confirmation depth is below
    /// `min_confirmations`, or Merkle inclusion fails.
    ///
    /// Convenience: kept for the CLI and bridge Bitcoin payment verifiers.
    pub fn verify_confirmed_payment(
        &self,
        block_hash: &[u8; 32],
        stripped_tx: &[u8],
        tx_index: u32,
        branch: &[[u8; 32]],
        expect_coinbase: bool,
        min_confirmations: u64,
    ) -> Result<VerifiedSpvTransaction, AdapterError> {
        self.verify_chain_continuity()?;
        let (target_idx, header) = self
            .headers
            .iter()
            .enumerate()
            .find(|(_, h)| h.hash == *block_hash)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Bitcoin payment block hash is not part of the verified chain".to_string(),
            })?;
        let remaining_headers = self.headers.len().checked_sub(target_idx).ok_or_else(|| {
            AdapterError::ConsensusRule {
                rule: "Bitcoin confirmation slice index out of bounds".to_string(),
            }
        })?;
        let confirmations =
            u64::try_from(remaining_headers).map_err(|_| AdapterError::ConsensusRule {
                rule: "Bitcoin confirmation depth overflows u64".to_string(),
            })?;
        let required = min_confirmations.max(1);
        if confirmations < required {
            return Err(AdapterError::InsufficientDepth {
                observed: confirmations,
                required,
            });
        }
        let mut verified = verify_spv_raw_tx_inclusion(
            stripped_tx,
            &header.merkle_root,
            tx_index,
            branch,
            expect_coinbase,
        )?;
        verified.confirmations = confirmations;
        Ok(verified)
    }
}

#[cfg(test)]
mod rejection_tests {
    //! Rejection and continuity proofs for raw stripped transactions and
    //! confirmed-payment verification over [`VerifiedBitcoinChain`].

    use super::{
        sha256d, verify_spv_raw_tx_inclusion, AdapterError, VerifiedBitcoinChain,
        FORBIDDEN_INNER_NODE_TX_BYTES, MAX_STRIPPED_TX_BYTES,
    };
    use crate::core::address::Address;
    use crate::cross_domain::external::bitcoin_spv::{
        BitcoinSpvAdapter, PinnedBitcoinAnchor, HEADER_LEN, REGTEST_POW_LIMIT_BITS,
    };
    use crate::cross_domain::external::spec::{
        DomainKey, ExternalFinalityAdapter, RawConsensusEvidence, VerificationPolicy,
    };

    fn ordinary_tx() -> Vec<u8> {
        (0u8..100).collect()
    }

    fn mine_regtest_raw_header(
        parent_hash: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: u32,
    ) -> [u8; HEADER_LEN] {
        for nonce in 0u32..100_000 {
            let mut hdr = [0u8; HEADER_LEN];
            let (ver, rem1) = hdr.split_at_mut(4);
            ver.copy_from_slice(&0x2000_0000u32.to_le_bytes());
            let (prev, rem2) = rem1.split_at_mut(32);
            prev.copy_from_slice(&parent_hash);
            let (mr, rem3) = rem2.split_at_mut(32);
            mr.copy_from_slice(&merkle_root);
            let (ts, rem4) = rem3.split_at_mut(4);
            ts.copy_from_slice(&timestamp.to_le_bytes());
            let (nbits, nslot) = rem4.split_at_mut(4);
            nbits.copy_from_slice(&bits.to_le_bytes());
            nslot.copy_from_slice(&nonce.to_le_bytes());
            let mut be = sha256d(&hdr);
            be.reverse();
            if let Some(&msb) = be.first() {
                if msb <= 0x7f {
                    return hdr;
                }
            }
        }
        panic!("regtest header mining exhausted nonce budget");
    }

    fn sample_six_block_chain(payment_tx: &[u8]) -> (VerifiedBitcoinChain, [u8; 32]) {
        let anchor_hash = sha256d(b"spv-payment-continuity-anchor");
        let adapter = BitcoinSpvAdapter::new(
            "regtest",
            Some(PinnedBitcoinAnchor {
                height: 100,
                block_hash: anchor_hash,
                bits: REGTEST_POW_LIMIT_BITS,
            }),
        );
        let payment_root = sha256d(payment_tx);
        let mut raw_headers = Vec::with_capacity(6);
        let mut prev = anchor_hash;
        for step in 0u32..6 {
            let step_byte = u8::try_from(step).unwrap_or(0);
            let mr = if step == 0 {
                payment_root
            } else {
                sha256d(&[0xA5, step_byte])
            };
            let hdr = mine_regtest_raw_header(
                prev,
                mr,
                1_725_000_000 + step * 600,
                REGTEST_POW_LIMIT_BITS,
            );
            prev = sha256d(&hdr);
            raw_headers.push(hdr);
        }
        let first_block_hash = raw_headers.first().map_or([0u8; 32], |h| sha256d(h));
        let tip_hash = raw_headers.last().map_or([0u8; 32], |h| sha256d(h));
        let mut payload = Vec::with_capacity(4 + 6 * HEADER_LEN);
        payload.extend_from_slice(&6u32.to_le_bytes());
        for hdr in &raw_headers {
            payload.extend_from_slice(hdr);
        }
        let evidence = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 1,
            network: "regtest".to_string(),
            payload,
            declared_height: 106,
            declared_root: tip_hash,
            submitter: Address::from([0x42; 32]),
        };
        let policy = VerificationPolicy {
            min_depth: 6,
            require_declared_match: true,
            max_age: 0,
            now: 1_725_010_000,
            require_slashable: false,
        };
        let chain = match adapter.verify_chain(&evidence, &policy) {
            Ok(verified) => verified,
            Err(err) => panic!("honest six-block regtest chain must verify: {err:?}"),
        };
        (chain, first_block_hash)
    }

    #[test]
    fn an_empty_transaction_is_refused() {
        let err = verify_spv_raw_tx_inclusion(&[], &[0u8; 32], 0, &[], true)
            .expect_err("an empty stripped tx must not verify");
        assert!(
            matches!(err, AdapterError::Malformed { offset: 0, .. }),
            "empty tx must be Malformed at offset 0, got {err:?}"
        );
    }

    #[test]
    fn an_oversized_transaction_is_refused() {
        let huge = vec![7u8; MAX_STRIPPED_TX_BYTES + 1];
        let err = verify_spv_raw_tx_inclusion(&huge, &[0u8; 32], 0, &[], true)
            .expect_err("a tx above MAX_STRIPPED_TX_BYTES must not verify");
        assert!(matches!(err, AdapterError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn a_sixty_four_byte_transaction_is_refused() {
        assert_eq!(FORBIDDEN_INNER_NODE_TX_BYTES, 64);
        let tx = vec![9u8; FORBIDDEN_INNER_NODE_TX_BYTES];
        let matching_root = sha256d(&tx);
        let err = verify_spv_raw_tx_inclusion(&tx, &matching_root, 0, &[], true)
            .expect_err("a 64-byte stripped tx must be refused even when its hash matches root");
        assert!(
            matches!(err, AdapterError::ConsensusRule { ref rule } if rule.contains("CVE-2017-12842")),
            "got {err:?}"
        );
    }

    #[test]
    fn a_coinbase_flag_that_contradicts_the_index_is_refused() {
        let tx = ordinary_tx();
        let err = verify_spv_raw_tx_inclusion(&tx, &[0u8; 32], 1, &[], true)
            .expect_err("contradictory coinbase flag must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_branch_that_does_not_reach_the_root_is_refused() {
        let tx = ordinary_tx();
        let wrong_root = [1u8; 32];
        let err = verify_spv_raw_tx_inclusion(&tx, &wrong_root, 0, &[], true)
            .expect_err("a branch that does not reach the root must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_duplicate_sibling_step_is_refused() {
        let tx = ordinary_tx();
        let txid = sha256d(&tx);
        let mut pair = [0u8; 64];
        let (left, right) = pair.split_at_mut(32);
        left.copy_from_slice(&txid);
        right.copy_from_slice(&txid);
        let duplicated_root = sha256d(&pair);
        let err = verify_spv_raw_tx_inclusion(&tx, &duplicated_root, 0, &[txid], true)
            .expect_err("a sibling equal to the accumulator must be refused (CVE-2012-2459)");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_single_leaf_inclusion_verifies() {
        let tx = ordinary_tx();
        let root = sha256d(&tx);
        let verified = match verify_spv_raw_tx_inclusion(&tx, &root, 0, &[], true) {
            Ok(ok) => ok,
            Err(err) => panic!("a single-leaf tree rooted at the txid must verify: {err:?}"),
        };
        assert_eq!(verified.txid, root);
        assert!(verified.is_coinbase);
        assert_eq!(verified.confirmations, 1);
    }

    #[test]
    fn an_honest_six_block_chain_verifies_confirmed_payment() {
        let tx = ordinary_tx();
        let (chain, block_hash) = sample_six_block_chain(&tx);
        let verified = match chain.verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6) {
            Ok(ok) => ok,
            Err(err) => panic!("honest 6-block chain must confirm coinbase payment: {err:?}"),
        };
        assert_eq!(verified.txid, sha256d(&tx));
        assert_eq!(verified.confirmations, 6);
    }

    #[test]
    fn an_inflated_attestation_height_over_a_single_header_is_refused() {
        let tx = ordinary_tx();
        let (mut forged, block_hash) = sample_six_block_chain(&tx);
        forged.headers.truncate(1);
        let err = forged
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("single header with inflated attestation height must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_broken_parent_hash_link_inside_verified_headers_is_refused() {
        let tx = ordinary_tx();
        let (mut forged, block_hash) = sample_six_block_chain(&tx);
        if let Some(third) = forged.headers.get_mut(2) {
            third.parent_hash = [0xEE; 32];
        }
        let err = forged
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("disconnected parent_hash link in upper headers must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_non_contiguous_header_height_gap_is_refused() {
        let tx = ordinary_tx();
        let (mut forged, block_hash) = sample_six_block_chain(&tx);
        let Some(first) = forged.headers.first().cloned() else {
            panic!("missing first header");
        };
        let Some(tip) = forged.headers.last().cloned() else {
            panic!("missing tip header");
        };
        forged.headers = vec![first, tip];
        let err = forged
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("gapped header heights skipping intermediate PoW must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_tip_that_contradicts_the_attested_block_hash_or_pow_is_refused() {
        let tx = ordinary_tx();
        let (mut wrong_tip, block_hash) = sample_six_block_chain(&tx);
        wrong_tip.attestation.attested_block_hash = Some([0xAB; 32]);
        let err_tip = wrong_tip
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("tip mismatching attested_block_hash must be refused");
        assert!(
            matches!(err_tip, AdapterError::ConsensusRule { .. }),
            "got {err_tip:?}"
        );

        let (mut bad_pow, _) = sample_six_block_chain(&tx);
        if let Some(fourth) = bad_pow.headers.get_mut(3) {
            fourth.hash = [0xFF; 32];
            if let Some(fifth) = bad_pow.headers.get_mut(4) {
                fifth.parent_hash = [0xFF; 32];
            }
        }
        let err_pow = bad_pow
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("upper header violating nBits target PoW must be refused");
        assert!(
            matches!(err_pow, AdapterError::ConsensusRule { .. }),
            "got {err_pow:?}"
        );
    }

    #[test]
    fn an_anchor_parent_mismatch_or_regtest_bits_on_mainnet_domain_is_refused() {
        let tx = ordinary_tx();
        let (mut wrong_anchor, block_hash) = sample_six_block_chain(&tx);
        wrong_anchor.anchor_hash = [0x77; 32];
        let err_anchor = wrong_anchor
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("first header not linking to anchor_hash must be refused");
        assert!(
            matches!(err_anchor, AdapterError::ConsensusRule { .. }),
            "got {err_anchor:?}"
        );

        let (mut spoofed_domain, _) = sample_six_block_chain(&tx);
        spoofed_domain.attestation.domain =
            DomainKey::from_parts(&spoofed_domain.attestation.adapter, "mainnet");
        let err_dom = spoofed_domain
            .verify_confirmed_payment(&block_hash, &tx, 0, &[], true, 6)
            .expect_err("regtest nBits headers under mainnet domain must be refused");
        assert!(
            matches!(err_dom, AdapterError::ConsensusRule { .. }),
            "got {err_dom:?}"
        );
    }
}
