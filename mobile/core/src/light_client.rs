//! Post-quantum light-client checkpoint and handoff verifier for the mobile core (K-G.6).
//!
//! Binds the single wire-type and quorum definitions in `budlum_types::checkpoint`
//! and `budlum_types::handoff` to the node's own dual-library ML-DSA-65 verifier
//! mounted at [`crate::crypto::pq`]. There is no permissive or stubbed path:
//! every checkpoint signature verifies under `BDLM/QC/V2` and every handoff
//! committee signature verifies under `BDLM/HANDOFF/V1` through both `ml-dsa`
//! and `libcrux-ml-dsa`.

use crate::crypto::{
    ctx, pq,
    scheme::{SchemeId, SchemeStatusRegistry},
};
pub use budlum_types::checkpoint::{
    is_canonical_hash, pq_signing_message, qc_blob_max_bytes, CheckpointSummary,
    CheckpointVerifyError, FinalityCert, PqSignatureEntry, QcBlob, TrustedCheckpoint,
    ValidatorEntry, ValidatorSetSnapshot, VerifiedCheckpoint,
};
pub use budlum_types::handoff::{
    follow_handoffs_with, handoff_committee, handoff_committee_weighted, member_set_is_valid,
    set_digest, HandoffCertificate, HandoffError, HandoffMember, HandoffSignature, COMMITTEE_SIZE,
};

/// Mobile light client anchored at a single [`TrustedCheckpoint`].
///
/// Follows validator-set rotations across epochs via [`HandoffCertificate`]
/// chains (`BDLM/HANDOFF/V1`) and verifies finalized checkpoints via [`QcBlob`]
/// post-quantum quorums (`BDLM/QC/V2`), honoring the chain's
/// [`SchemeStatusRegistry`].
#[derive(Debug, Clone)]
pub struct MobileLightClient {
    trusted: TrustedCheckpoint,
    chain_id: u64,
    registry: SchemeStatusRegistry,
}

impl MobileLightClient {
    /// Bootstrap a mobile light client from a canonical [`TrustedCheckpoint`].
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointVerifyError::MalformedHash`] if either anchor digest
    /// is not a canonical 64-character lowercase hex string.
    pub fn new(trusted: TrustedCheckpoint, chain_id: u64) -> Result<Self, CheckpointVerifyError> {
        if chain_id == 0 {
            return Err(CheckpointVerifyError::CertificateBinding(
                "chain_id must be non-zero".into(),
            ));
        }
        trusted.validate()?;
        Ok(Self {
            trusted,
            chain_id,
            registry: SchemeStatusRegistry::genesis(),
        })
    }

    /// Pin the chain's consensus [`SchemeStatusRegistry`] so a scheme disabled
    /// on-chain (e.g. via Frost Alarm) is immediately refused on the phone too.
    #[must_use]
    pub fn with_scheme_registry(mut self, registry: SchemeStatusRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Current trusted anchor.
    #[must_use]
    pub const fn trusted(&self) -> &TrustedCheckpoint {
        &self.trusted
    }

    /// Chain identifier bound by this client.
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Verify a post-quantum [`QcBlob`] checkpoint against the current trust
    /// anchor and `snapshot` without mutating state.
    ///
    /// # Errors
    ///
    /// Fails closed on any malformed hash, non-forward height, mismatched
    /// header/blob/snapshot binding, forged snapshot total, disabled scheme,
    /// invalid ML-DSA-65 signature, or quorum shortfall.
    pub fn verify_pq_checkpoint(
        &self,
        header: &CheckpointSummary,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, CheckpointVerifyError> {
        let registry = &self.registry;
        budlum_types::checkpoint::verify_pq_checkpoint_with(
            &self.trusted,
            header,
            blob,
            snapshot,
            |pk, msg, sig| {
                pq::verify_in(registry, SchemeId::ML_DSA_65, pk, msg, ctx::QC_V2, sig)
                    .map_err(|e| e.to_string())
            },
        )
    }

    /// Move the trust anchor strictly forward to `verified` within the currently
    /// trusted validator set.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointVerifyError::NotForward`] if `verified.height` does
    /// not advance, or [`CheckpointVerifyError::SetChanged`] if `verified.set_hash`
    /// differs from the trusted validator set.
    pub fn advance(&mut self, verified: &VerifiedCheckpoint) -> Result<(), CheckpointVerifyError> {
        if !is_canonical_hash(&verified.block_hash) {
            return Err(CheckpointVerifyError::MalformedHash(
                verified.block_hash.clone(),
            ));
        }
        if !is_canonical_hash(&verified.state_root) {
            return Err(CheckpointVerifyError::MalformedHash(
                verified.state_root.clone(),
            ));
        }
        if verified.height <= self.trusted.height {
            return Err(CheckpointVerifyError::NotForward {
                trusted: self.trusted.height,
                candidate: verified.height,
            });
        }
        if verified.set_hash != self.trusted.set_hash {
            return Err(CheckpointVerifyError::SetChanged {
                trusted: self.trusted.set_hash.clone(),
                candidate: verified.set_hash.clone(),
            });
        }
        self.trusted = TrustedCheckpoint {
            height: verified.height,
            block_hash: verified.block_hash.clone(),
            set_hash: verified.set_hash.clone(),
        };
        Ok(())
    }

    /// Verify and advance in one atomic step.
    ///
    /// # Errors
    ///
    /// See [`Self::verify_pq_checkpoint`] and [`Self::advance`].
    pub fn verify_and_advance(
        &mut self,
        header: &CheckpointSummary,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, CheckpointVerifyError> {
        let verified = self.verify_pq_checkpoint(header, blob, snapshot)?;
        self.advance(&verified)?;
        Ok(verified)
    }

    /// Verify a single [`HandoffCertificate`] against `outgoing` and
    /// `epoch_randomness` under `BDLM/HANDOFF/V1`.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError`] on any chain, set, randomness, committee, quorum,
    /// or ML-DSA-65 signature failure.
    pub fn verify_handoff_certificate(
        &self,
        cert: &HandoffCertificate,
        outgoing: &[HandoffMember],
        epoch_randomness: [u8; 32],
    ) -> Result<(), HandoffError> {
        if cert.chain_id != self.chain_id {
            return Err(HandoffError::Chain {
                expected: self.chain_id,
                got: cert.chain_id,
            });
        }
        let registry = &self.registry;
        cert.verify_with(outgoing, epoch_randomness, |pk, msg, sig| {
            pq::verify_in(registry, SchemeId::ML_DSA_65, pk, msg, ctx::HANDOFF_V1, sig)
                .map_err(|e| e.to_string())
        })
    }

    /// Follow a contiguous chain of [`HandoffCertificate`] transitions starting
    /// from the currently trusted `outgoing` [`ValidatorSetSnapshot`].
    ///
    /// Every snapshot's `set_hash` and `total_stake` are recomputed before any
    /// signature check; on success, `trusted.set_hash` rotates to the final
    /// verified snapshot while keeping the anchor height unchanged until a
    /// checkpoint under the new set is verified.
    ///
    /// # Errors
    ///
    /// Fails closed on untrusted outgoing set, malformed snapshot metadata,
    /// non-contiguous epochs, wrong chain ID, wrong randomness, quorum shortfall,
    /// or invalid ML-DSA-65 signature.
    pub fn follow_handoffs(
        &mut self,
        outgoing: &ValidatorSetSnapshot,
        steps: &[(HandoffCertificate, ValidatorSetSnapshot)],
        epoch_randomness: &dyn Fn(u64) -> [u8; 32],
    ) -> Result<u64, CheckpointVerifyError> {
        if outgoing.set_hash != self.trusted.set_hash {
            return Err(CheckpointVerifyError::TrustBinding(
                "the outgoing set is not the trusted set".into(),
            ));
        }
        outgoing
            .validate_metadata()
            .map_err(CheckpointVerifyError::TrustBinding)?;
        let Some((_, last)) = steps.last() else {
            return Ok(outgoing.epoch);
        };
        let mut member_steps = Vec::with_capacity(steps.len());
        for (idx, (cert, snapshot)) in steps.iter().enumerate() {
            snapshot
                .validate_metadata()
                .map_err(CheckpointVerifyError::TrustBinding)?;
            let step_offset = u64::try_from(idx)
                .ok()
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| {
                    CheckpointVerifyError::TrustBinding("handoff epoch overflow".into())
                })?;
            let expected_next_epoch = outgoing.epoch.checked_add(step_offset).ok_or_else(|| {
                CheckpointVerifyError::TrustBinding("handoff epoch overflow".into())
            })?;
            if snapshot.epoch != expected_next_epoch {
                return Err(CheckpointVerifyError::TrustBinding(format!(
                    "handoff snapshot epoch {} does not match expected {}",
                    snapshot.epoch, expected_next_epoch
                )));
            }
            member_steps.push((cert.clone(), snapshot.to_handoff_members()));
        }
        let trusted_members = outgoing.to_handoff_members();
        let registry = &self.registry;
        let (epoch, _) = follow_handoffs_with(
            self.chain_id,
            outgoing.epoch,
            &trusted_members,
            &member_steps,
            epoch_randomness,
            |pk, msg, sig| {
                pq::verify_in(registry, SchemeId::ML_DSA_65, pk, msg, ctx::HANDOFF_V1, sig)
                    .map_err(|e| e.to_string())
            },
        )
        .map_err(|e| CheckpointVerifyError::VerificationFailed(e.to_string()))?;
        self.trusted.set_hash.clone_from(&last.set_hash);
        Ok(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::scheme::SchemeStatus;
    use budlum_types::Address;

    fn deterministic_validator_set(
        epoch: u64,
        count: u8,
        stake: u64,
    ) -> (ValidatorSetSnapshot, Vec<[u8; 32]>) {
        let mut seeds = Vec::new();
        let mut entries = Vec::new();
        for i in 0..count {
            let mut seed = [0u8; 32];
            seed[0] = i.saturating_add(1);
            seed[1] = u8::try_from(epoch).unwrap_or(0);
            let pk = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
            let mut addr_bytes = [0u8; 32];
            addr_bytes[0] = 0xA0 | i;
            addr_bytes[31] = u8::try_from(epoch).unwrap_or(0);
            seeds.push(seed);
            entries.push(ValidatorEntry {
                address: Address::from(addr_bytes),
                stake,
                bls_public_key: vec![i ^ 0x11; 96],
                pop_signature: vec![i ^ 0x22; 48],
                pq_public_key: pk,
            });
        }
        (ValidatorSetSnapshot::new(epoch, entries), seeds)
    }

    fn sign_qc(
        snapshot: &ValidatorSetSnapshot,
        seeds: &[[u8; 32]],
        height: u64,
        block_hash: &str,
        signers: &[usize],
    ) -> QcBlob {
        let mut sigs = Vec::new();
        for &idx in signers {
            let entry = &snapshot.validators[idx];
            let validator_index = u32::try_from(idx).unwrap();
            let msg = pq_signing_message(snapshot.epoch, height, block_hash, validator_index);
            let sig = pq::ml_dsa_sign(
                SchemeId::ML_DSA_65,
                &seeds[idx],
                &msg,
                ctx::QC_V2,
                &[0u8; 32],
            )
            .unwrap();
            sigs.push(PqSignatureEntry {
                validator_index,
                validator_address: entry.address.to_hex(),
                pq_signature: sig,
            });
        }
        QcBlob::new(snapshot.epoch, height, block_hash.to_string(), sigs)
    }

    fn sign_handoff(
        chain_id: u64,
        outgoing: &ValidatorSetSnapshot,
        outgoing_seeds: &[[u8; 32]],
        incoming: &ValidatorSetSnapshot,
        randomness: [u8; 32],
        signers: &[usize],
    ) -> HandoffCertificate {
        let out_members = outgoing.to_handoff_members();
        let in_members = incoming.to_handoff_members();
        let mut cert = HandoffCertificate::unsigned(
            chain_id,
            outgoing.epoch,
            &out_members,
            &in_members,
            randomness,
        );
        let msg = cert.signing_message();
        for &idx in signers {
            let sig = pq::ml_dsa_sign(
                SchemeId::ML_DSA_65,
                &outgoing_seeds[idx],
                &msg,
                ctx::HANDOFF_V1,
                &[0u8; 32],
            )
            .unwrap();
            cert.insert_signature(u32::try_from(idx).unwrap(), sig);
        }
        cert
    }

    #[test]
    fn mobile_light_client_verifies_real_pq_checkpoints_and_rotates_across_handoffs() {
        let chain_id = 45_261;
        let (epoch4, seeds4) = deterministic_validator_set(4, 4, 100);
        let (epoch5, seeds5) = deterministic_validator_set(5, 4, 150);

        let anchor = TrustedCheckpoint {
            height: 100,
            block_hash: "11".repeat(32),
            set_hash: epoch4.set_hash.clone(),
        };
        let mut client = MobileLightClient::new(anchor, chain_id).unwrap();

        let header200 = CheckpointSummary {
            height: 200,
            block_hash: "22".repeat(32),
            state_root: "33".repeat(32),
        };
        let qc200 = sign_qc(&epoch4, &seeds4, 200, &header200.block_hash, &[0, 1, 2]);
        let verified200 = client
            .verify_and_advance(&header200, &qc200, &epoch4)
            .unwrap();
        assert_eq!(verified200.height, 200);
        assert_eq!(verified200.external_root(), Some([0x33; 32]));
        assert_eq!(client.trusted().height, 200);

        // Forged / tampered signature is strictly refused (never an accept-all stub).
        let mut tampered_qc = sign_qc(&epoch4, &seeds4, 300, &"44".repeat(32), &[0, 1, 2]);
        tampered_qc.pq_signatures[0].pq_signature[10] ^= 0xFF;
        tampered_qc.merkle_root = QcBlob::compute_merkle_root(&tampered_qc.pq_signatures);
        let header300 = CheckpointSummary {
            height: 300,
            block_hash: "44".repeat(32),
            state_root: "55".repeat(32),
        };
        assert!(matches!(
            client.verify_pq_checkpoint(&header300, &tampered_qc, &epoch4),
            Err(CheckpointVerifyError::VerificationFailed(_))
        ));

        // Sub-quorum (2 of 4 validators = 50% <= 2/3) is refused.
        let sub_quorum_qc = sign_qc(&epoch4, &seeds4, 300, &header300.block_hash, &[0, 1]);
        assert!(matches!(
            client.verify_pq_checkpoint(&header300, &sub_quorum_qc, &epoch4),
            Err(CheckpointVerifyError::VerificationFailed(_))
        ));

        // Epoch 5 checkpoint before handoff is refused because set_hash changed.
        let qc300_epoch5 = sign_qc(&epoch5, &seeds5, 300, &header300.block_hash, &[0, 1, 2]);
        assert!(matches!(
            client.verify_pq_checkpoint(&header300, &qc300_epoch5, &epoch5),
            Err(CheckpointVerifyError::TrustBinding(_))
        ));

        // Follow signed HandoffCertificate from epoch 4 -> epoch 5, then verify epoch 5 checkpoint.
        let randomness = [0x77; 32];
        let handoff = sign_handoff(chain_id, &epoch4, &seeds4, &epoch5, randomness, &[0, 1, 2]);
        let reached_epoch = client
            .follow_handoffs(&epoch4, &[(handoff, epoch5.clone())], &|_| randomness)
            .unwrap();
        assert_eq!(reached_epoch, 5);
        assert_eq!(client.trusted().set_hash, epoch5.set_hash);
        assert_eq!(client.trusted().height, 200);

        let verified300 = client
            .verify_and_advance(&header300, &qc300_epoch5, &epoch5)
            .unwrap();
        assert_eq!(verified300.height, 300);
        assert_eq!(verified300.epoch, 5);
        assert_eq!(client.trusted().height, 300);
    }

    #[test]
    fn disabled_scheme_in_pinned_registry_stops_verifying_on_mobile() {
        let chain_id = 45_261;
        let (epoch1, seeds1) = deterministic_validator_set(1, 3, 100);
        let anchor = TrustedCheckpoint {
            height: 10,
            block_hash: "aa".repeat(32),
            set_hash: epoch1.set_hash.clone(),
        };
        let (mut schemes, suites) = SchemeStatusRegistry::genesis().entries();
        for (id, status) in &mut schemes {
            if *id == SchemeId::ML_DSA_65.0 {
                *status = SchemeStatus::Disabled.to_byte();
            }
        }
        let disabled = SchemeStatusRegistry::from_entries(&schemes, &suites).unwrap();
        let client = MobileLightClient::new(anchor, chain_id)
            .unwrap()
            .with_scheme_registry(disabled);

        let header20 = CheckpointSummary {
            height: 20,
            block_hash: "bb".repeat(32),
            state_root: "cc".repeat(32),
        };
        let qc20 = sign_qc(&epoch1, &seeds1, 20, &header20.block_hash, &[0, 1, 2]);
        assert!(matches!(
            client.verify_pq_checkpoint(&header20, &qc20, &epoch1),
            Err(CheckpointVerifyError::VerificationFailed(_))
        ));
    }
}
