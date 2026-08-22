//! Succinct light-client verification.
//!
//! Whitepaper v1.1: a light client bootstrapped from a single trusted
//! validator-set commitment, using finality certificates as proofs. A light
//! node holds one trust anchor - a checkpoint height, the block hash at that
//! height, and the hash of the validator set that finalized it - and advances
//! it by verifying finality certificates against that set, without ever
//! downloading or replaying transaction bodies.
//!
//! Two certificate kinds are verified:
//!
//! * [`FinalityCert`] - the BLS aggregate certificate over a stake-weighted
//!   quorum (`LightClient::verify_checkpoint`). This is the whitepaper's
//!   "BLS finality certificates as proofs".
//! * [`QcBlob`] - the post-quantum quorum blob (`LightClient::verify_pq_
//!   checkpoint`), the same attestation layer full nodes import.
//!
//! The verification is transport-agnostic: `LightClient::sync_plan` spells
//! out the wire requests a transport must issue (the existing `GetHeaders`
//! locator and the per-checkpoint QC blob fetch), and the `budlum-light`
//! binary drives it over a chain export. The trust rule is deliberately
//! conservative: the validator set is fixed at bootstrap, so a certificate
//! whose `set_hash` differs from the trusted one is rejected, not silently
//! followed. A set change needs a new trust anchor out-of-band.

use std::fmt;

use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
use crate::consensus::qc::QcBlob;
use crate::core::block::BlockHeader;

/// A 64-character lowercase hex digest.
/// A 64-character lowercase hex digest. `const fn` so the trust-anchor check
/// can run in constant contexts; `u8::is_ascii_hexdigit` is const since Rust
/// 1.87, which this crate's MSRV (1.97) satisfies.
fn is_canonical_hash(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            return false;
        }
        i += 1;
    }
    true
}

/// The single trust anchor a light client is bootstrapped from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    /// Block height of the anchor.
    pub height: u64,
    /// Canonical block hash at `height`.
    pub block_hash: String,
    /// Hash of the validator set that finalized `height`.
    pub set_hash: String,
}

/// A checkpoint that has been cryptographically verified against the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    /// Block height of the verified checkpoint.
    pub height: u64,
    /// Canonical block hash at `height`.
    pub block_hash: String,
    /// Hash of the validator set the certificate was verified against.
    pub set_hash: String,
    /// Epoch the finality certificate belonged to.
    pub epoch: u64,
}

/// Why a checkpoint failed light-client verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightClientError {
    /// A hash string is not a canonical 64-hex digest.
    MalformedHash(String),
    /// The header fails hash self-consistency.
    InvalidHeader(String),
    /// The certificate does not bind to the header it claims to finalize.
    CertificateBinding(String),
    /// The certificate or snapshot does not bind to the trusted validator set.
    TrustBinding(String),
    /// The cryptographic verification (BLS quorum or PQ quorum) failed.
    VerificationFailed(String),
    /// `advance` was asked to move backwards or stay put.
    NotForward { trusted: u64, candidate: u64 },
    /// A verified checkpoint carries a different validator set than the anchor.
    SetChanged { trusted: String, candidate: String },
    /// A header chain is not contiguous and parent-linked.
    HeaderChain(String),
}

impl fmt::Display for LightClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHash(h) => write!(f, "malformed hash: {h}"),
            Self::InvalidHeader(reason) => write!(f, "invalid header: {reason}"),
            Self::CertificateBinding(reason) => {
                write!(f, "certificate does not bind to the header: {reason}")
            }
            Self::TrustBinding(reason) => {
                write!(f, "certificate does not bind to the trusted set: {reason}")
            }
            Self::VerificationFailed(reason) => {
                write!(f, "finality verification failed: {reason}")
            }
            Self::NotForward { trusted, candidate } => write!(
                f,
                "checkpoint must move strictly forward: trusted {trusted}, candidate {candidate}"
            ),
            Self::SetChanged { trusted, candidate } => write!(
                f,
                "validator set changed under the light client: trusted {trusted}, candidate {candidate}"
            ),
            Self::HeaderChain(reason) => write!(f, "header chain invalid: {reason}"),
        }
    }
}

impl std::error::Error for LightClientError {}

/// The wire requests a transport must issue from the current trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightSyncPlan {
    /// `GetHeaders { locator, limit }` starting at the trusted block hash.
    pub headers_locator: Vec<String>,
    /// The next checkpoint height the light client needs a certificate for.
    /// `None` when the anchor already sits at or above the target.
    pub next_checkpoint_height: Option<u64>,
}

/// A light client holding one trusted validator-set commitment.
#[derive(Debug, Clone)]
pub struct LightClient {
    trusted: TrustedCheckpoint,
}

impl LightClient {
    /// Bootstrap from a single trusted checkpoint.
    ///
    /// Both hashes must be canonical 64-hex digests; anything else is a
    /// bootstrap mistake that would poison every later verification.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::MalformedHash`] when either hash is not a
    /// canonical 64-hex digest.
    pub fn new(trusted: TrustedCheckpoint) -> Result<Self, LightClientError> {
        if !is_canonical_hash(&trusted.block_hash) {
            return Err(LightClientError::MalformedHash(format!(
                "block hash {} is not a canonical 64-hex digest",
                trusted.block_hash
            )));
        }
        if !is_canonical_hash(&trusted.set_hash) {
            return Err(LightClientError::MalformedHash(format!(
                "set hash {} is not a canonical 64-hex digest",
                trusted.set_hash
            )));
        }
        Ok(Self { trusted })
    }

    /// The current trust anchor.
    #[must_use]
    pub const fn trusted(&self) -> &TrustedCheckpoint {
        &self.trusted
    }

    /// Reject a snapshot whose metadata is not self-consistent.
    ///
    /// The snapshot arrives with the export, so it is untrusted input. Its
    /// `set_hash` and `total_stake` must be recomputed from the validator
    /// list before they are used to enforce quorum; otherwise a crafted
    /// export could lower `total_stake` and make a minority certificate pass
    /// the light-client quorum check.
    fn validate_snapshot_metadata(snapshot: &ValidatorSetSnapshot) -> Result<(), LightClientError> {
        let computed_set_hash = ValidatorSetSnapshot::compute_hash(&snapshot.validators);
        if snapshot.set_hash != computed_set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot set hash {} != computed set hash {}",
                snapshot.set_hash, computed_set_hash
            )));
        }
        let computed_total_stake = snapshot
            .validators
            .iter()
            .map(|validator| validator.stake)
            .fold(0u64, u64::saturating_add);
        if snapshot.total_stake != computed_total_stake {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot total stake {} != computed total stake {}",
                snapshot.total_stake, computed_total_stake
            )));
        }
        Ok(())
    }

    /// Verify a BLS finality certificate checkpoint against the trusted set.
    ///
    /// The checks run in order, each binding the next layer to the previous
    /// one: the header must hash to itself, the certificate must name exactly
    /// that header, the certificate and the snapshot must carry the trusted
    /// validator-set hash, and finally the BLS aggregate signature must carry
    /// the stake and signer quorum (`FinalityCert::verify`).
    ///
    /// # Errors
    ///
    /// Returns a [`LightClientError`] variant for each failed binding and for
    /// a certificate whose BLS signature fails `FinalityCert::verify`.
    pub fn verify_checkpoint(
        &self,
        header: &BlockHeader,
        cert: &FinalityCert,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        Self::validate_snapshot_metadata(snapshot)?;
        if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
            return Err(LightClientError::InvalidHeader(format!(
                "header hash {} is not self-consistent",
                header.hash
            )));
        }
        if header.index != cert.checkpoint_height {
            return Err(LightClientError::CertificateBinding(format!(
                "header height {} != certificate height {}",
                header.index, cert.checkpoint_height
            )));
        }
        if header.hash != cert.checkpoint_hash {
            return Err(LightClientError::CertificateBinding(format!(
                "header hash {} != certificate hash {}",
                header.hash, cert.checkpoint_hash
            )));
        }
        if cert.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "certificate set hash {} != trusted set hash {}",
                cert.set_hash, self.trusted.set_hash
            )));
        }
        if snapshot.set_hash != cert.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot set hash {} != certificate set hash {}",
                snapshot.set_hash, cert.set_hash
            )));
        }
        cert.verify(snapshot)
            .map_err(LightClientError::VerificationFailed)?;

        Ok(VerifiedCheckpoint {
            height: header.index,
            block_hash: header.hash.clone(),
            set_hash: cert.set_hash.clone(),
            epoch: cert.epoch,
        })
    }

    /// Verify a post-quantum quorum blob checkpoint against the trusted set.
    ///
    /// The same binding chain as [`Self::verify_checkpoint`], with the BLS
    /// aggregate replaced by the PQ quorum: every signature verifies against
    /// the snapshot's PQ public keys, no validator signs twice, and the
    /// unique signers must carry the same stake and count quorum the BLS path
    /// enforces.
    ///
    /// # Errors
    ///
    /// Returns a [`LightClientError`] variant for each failed binding and for
    /// a PQ blob whose signatures, stake quorum or signer count do not clear
    /// `QcBlob::verify_against_snapshot`.
    pub fn verify_pq_checkpoint(
        &self,
        header: &BlockHeader,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        Self::validate_snapshot_metadata(snapshot)?;
        if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
            return Err(LightClientError::InvalidHeader(format!(
                "header hash {} is not self-consistent",
                header.hash
            )));
        }
        if header.index != blob.checkpoint_height {
            return Err(LightClientError::CertificateBinding(format!(
                "header height {} != blob height {}",
                header.index, blob.checkpoint_height
            )));
        }
        if header.hash != blob.checkpoint_hash {
            return Err(LightClientError::CertificateBinding(format!(
                "header hash {} != blob hash {}",
                header.hash, blob.checkpoint_hash
            )));
        }
        if snapshot.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot set hash {} != trusted set hash {}",
                snapshot.set_hash, self.trusted.set_hash
            )));
        }
        if blob.epoch != snapshot.epoch {
            return Err(LightClientError::CertificateBinding(format!(
                "blob epoch {} != snapshot epoch {}",
                blob.epoch, snapshot.epoch
            )));
        }

        let verified = blob
            .verify_against_snapshot(snapshot, None, None)
            .map_err(LightClientError::VerificationFailed)?;

        let voted_stake: u64 = verified
            .iter()
            .filter_map(|idx| snapshot.validators.get(*idx))
            .map(|v| v.stake)
            .fold(0u64, u64::saturating_add);
        if voted_stake < snapshot.quorum_stake() {
            return Err(LightClientError::VerificationFailed(format!(
                "PQ quorum stake {} < required {}",
                voted_stake,
                snapshot.quorum_stake()
            )));
        }
        if verified.len() < snapshot.quorum_count() {
            return Err(LightClientError::VerificationFailed(format!(
                "PQ quorum signers {} < required {}",
                verified.len(),
                snapshot.quorum_count()
            )));
        }

        Ok(VerifiedCheckpoint {
            height: header.index,
            block_hash: header.hash.clone(),
            set_hash: snapshot.set_hash.clone(),
            epoch: blob.epoch,
        })
    }

    /// Verify a headers-only chain segment without any block bodies.
    ///
    /// Every header must hash to itself, consecutive headers must be
    /// contiguous and parent-linked, and the first header must continue the
    /// trust anchor: it sits exactly one height above the anchor and its
    /// parent hash is the anchor's block hash. An unanchored first header
    /// would let a crafted export substitute a self-consistent finalized
    /// segment from an unrelated fork that reuses the same validator set
    /// (Strix CWE-345).
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::HeaderChain`] for a malformed or
    /// disconnected segment and [`LightClientError::NotForward`] for a header
    /// at or below the anchor.
    pub fn verify_header_chain(&self, headers: &[BlockHeader]) -> Result<(), LightClientError> {
        if headers.is_empty() {
            return Err(LightClientError::HeaderChain(
                "no headers supplied".to_string(),
            ));
        }
        let first = &headers[0];
        for header in headers {
            if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
                return Err(LightClientError::HeaderChain(format!(
                    "header {} is not self-consistent",
                    header.index
                )));
            }
            if header.index <= self.trusted.height {
                return Err(LightClientError::NotForward {
                    trusted: self.trusted.height,
                    candidate: header.index,
                });
            }
        }
        if first.index != self.trusted.height.saturating_add(1) {
            return Err(LightClientError::HeaderChain(format!(
                "first header height {} does not continue trusted height {}",
                first.index, self.trusted.height
            )));
        }
        if first.previous_hash != self.trusted.block_hash {
            return Err(LightClientError::HeaderChain(format!(
                "first header previous hash {} != trusted block hash {}",
                first.previous_hash, self.trusted.block_hash
            )));
        }
        for pair in headers.windows(2) {
            if pair[1].index != pair[0].index.saturating_add(1)
                || pair[1].previous_hash != pair[0].hash
            {
                return Err(LightClientError::HeaderChain(format!(
                    "headers {} and {} are not contiguous and parent-linked",
                    pair[0].index, pair[1].index
                )));
            }
        }
        Ok(())
    }

    /// Move the trust anchor to a verified checkpoint.
    ///
    /// Strictly forward, and only within the trusted validator set: a
    /// certificate over a different set is a different chain, and following
    /// it without a new out-of-band anchor would hand the adversary the
    /// light client's trust.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::NotForward`] for a checkpoint at or below
    /// the anchor and [`LightClientError::SetChanged`] for a checkpoint over
    /// a different validator set.
    pub fn advance(&mut self, verified: &VerifiedCheckpoint) -> Result<(), LightClientError> {
        if verified.height <= self.trusted.height {
            return Err(LightClientError::NotForward {
                trusted: self.trusted.height,
                candidate: verified.height,
            });
        }
        if verified.set_hash != self.trusted.set_hash {
            return Err(LightClientError::SetChanged {
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

    /// The next checkpoint height strictly above the anchor, given the chain's
    /// checkpoint interval. `None` when the anchor already sits at a
    /// checkpoint at or beyond `target_height` (i.e. nothing left to fetch).
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn next_checkpoint_height(&self, interval: u64, target_height: u64) -> Option<u64> {
        if interval == 0 || self.trusted.height >= target_height {
            return None;
        }
        let mut height = self.trusted.height.saturating_add(1);
        while height <= target_height {
            if height.is_multiple_of(interval) {
                return Some(height);
            }
            height = height.saturating_add(1);
        }
        None
    }

    /// The wire requests a transport must issue from this anchor: a
    /// `GetHeaders` locator rooted at the trusted hash, and the next
    /// checkpoint height a certificate is needed for.
    #[must_use]
    pub fn sync_plan(&self, interval: u64, target_height: u64) -> LightSyncPlan {
        LightSyncPlan {
            headers_locator: vec![self.trusted.block_hash.clone()],
            next_checkpoint_height: self.next_checkpoint_height(interval, target_height),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::{
        pop_signing_message, sign_bls, sign_bls_pop, FinalityAggregator, Precommit, Prevote,
        ValidatorEntry,
    };
    use crate::consensus::qc::{pq_signing_message, PqSignatureEntry};
    use crate::core::address::Address;
    use crate::core::block::Block;
    use crate::crypto::primitives::{BlsKeypair, PqKeyPair};
    use bls12_381::{G1Affine, G1Projective, Scalar};

    const TEST_CHAIN_ID: u64 = crate::core::transaction::DEFAULT_CHAIN_ID;

    fn make_bls_key(seed: u8) -> BlsKeypair {
        let mut sk_bytes = [0u8; 64];
        sk_bytes[0] = seed + 1;
        BlsKeypair::from_seed(&sk_bytes)
    }

    fn make_bls_snapshot(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
        let mut sks = Vec::new();
        let validators: Vec<ValidatorEntry> = (0..n)
            .map(|i| {
                let key = make_bls_key(u8::try_from(i).expect("test validator count is small"));
                sks.push(key.secret_key);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = u8::try_from(i + 1).expect("test validator count is small");
                let addr = Address::from(addr_bytes);
                let pop_msg = pop_signing_message(TEST_CHAIN_ID, &addr, &key.public_key);
                let pop_sig = sign_bls_pop(&key.secret_key, &pop_msg);
                ValidatorEntry {
                    address: addr,
                    stake: stake_each,
                    bls_public_key: key.public_key,
                    pop_signature: pop_sig,
                    pq_public_key: Vec::new(),
                }
            })
            .collect();
        (ValidatorSetSnapshot::new(1, validators), sks)
    }

    fn make_block_header_at(height: u64, chain_id: u64) -> BlockHeader {
        let block = Block::new_with_chain_id(height, "0".repeat(64), Vec::new(), chain_id);
        BlockHeader::from_block(&block)
    }

    /// Produce a real BLS finality certificate for `header` signed by
    /// `signers` of the snapshot's keys (the first `signers` validators).
    fn make_valid_bls_cert(
        snapshot: &ValidatorSetSnapshot,
        sks: &[Scalar],
        header: &BlockHeader,
        signers: usize,
    ) -> FinalityCert {
        let checkpoint_hash = header.hash.clone();
        let mut agg =
            FinalityAggregator::new(snapshot.epoch, header.index, checkpoint_hash.clone());
        agg.set_validator_snapshot(snapshot.clone());

        for (i, sk) in sks.iter().enumerate().take(signers) {
            let vote = Prevote {
                epoch: snapshot.epoch,
                checkpoint_height: header.index,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: snapshot.validators[i].address,
                sig_bls: vec![],
            };
            let sig = sign_bls(sk, &vote.signing_message());
            let mut signed = vote;
            signed.sig_bls = sig;
            agg.add_prevote(signed).unwrap();
        }

        let mut agg_sig = G1Projective::identity();
        for (i, sk) in sks.iter().enumerate().take(signers) {
            let pc = Precommit {
                epoch: snapshot.epoch,
                checkpoint_height: header.index,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: snapshot.validators[i].address,
                sig_bls: vec![],
            };
            let sig = sign_bls(sk, &pc.signing_message());
            let mut signed = pc;
            signed.sig_bls = sig.clone();
            agg.add_precommit(signed).unwrap();
            let sig_affine = G1Affine::from_compressed(&sig.try_into().unwrap()).unwrap();
            agg_sig += G1Projective::from(sig_affine);
        }

        let mut cert = agg.try_produce_cert().expect("certificate produced");
        cert.agg_sig_bls = G1Affine::from(agg_sig).to_compressed().to_vec();
        cert
    }

    #[test]
    fn bootstrap_rejects_malformed_hashes() {
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "short".into(),
            set_hash: "0".repeat(64),
        })
        .is_err());
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: "not-a-hash".into(),
        })
        .is_err());
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .is_ok());
    }

    #[test]
    fn verifies_a_real_bls_checkpoint_and_advances() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        let verified = client
            .verify_checkpoint(&header, &cert, &snapshot)
            .expect("honest checkpoint verifies");
        assert_eq!(verified.height, 10);
        assert_eq!(verified.block_hash, header.hash);
        assert_eq!(verified.set_hash, snapshot.set_hash);

        let mut client = client;
        client.advance(&verified).expect("advance");
        assert_eq!(client.trusted().height, 10);
        assert_eq!(client.trusted().block_hash, header.hash);
    }

    #[test]
    fn rejects_a_certificate_for_a_different_header() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.checkpoint_hash = "1".repeat(64);

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::CertificateBinding(_))
        ));
    }

    #[test]
    fn rejects_a_certificate_over_a_different_validator_set() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.set_hash = "f".repeat(64);

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::TrustBinding(_))
        ));
    }

    #[test]
    fn rejects_a_certificate_below_the_quorum() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        // Produce a valid three-of-four certificate, then shrink the bitmap
        // to two signers: two of four validators is not a 2/3 quorum, so the
        // certificate must be rejected at the cryptographic step, not the
        // binding steps.
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.bitmap = vec![0b0000_0011];

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::VerificationFailed(_))
        ));
    }

    #[test]
    fn advance_rejects_regression_and_set_change() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        let verified = client
            .verify_checkpoint(&header, &cert, &snapshot)
            .expect("honest checkpoint verifies");

        // Same height is not forward.
        let mut other = client.clone();
        assert!(matches!(
            other.advance(&VerifiedCheckpoint {
                height: 0,
                block_hash: "0".repeat(64),
                set_hash: snapshot.set_hash,
                epoch: 1,
            }),
            Err(LightClientError::NotForward { .. })
        ));

        // A different set hash is a different chain.
        let mut changed = client.clone();
        assert!(matches!(
            changed.advance(&VerifiedCheckpoint {
                height: 1,
                block_hash: "1".repeat(64),
                set_hash: "f".repeat(64),
                epoch: 1,
            }),
            Err(LightClientError::SetChanged { .. })
        ));

        client.advance(&verified).expect("forward advance");
    }

    #[test]
    fn verifies_a_real_pq_checkpoint_and_advances() {
        let (snapshot, keys) = make_pq_snapshot(3, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let blob = make_pq_blob(&snapshot, &keys, &header);

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        let verified = client
            .verify_pq_checkpoint(&header, &blob, &snapshot)
            .expect("honest PQ checkpoint verifies");
        assert_eq!(verified.height, 10);

        let mut client = client;
        client.advance(&verified).expect("advance");
        assert_eq!(client.trusted().height, 10);
    }

    #[test]
    fn pq_path_rejects_a_duplicate_signer_blob() {
        let (snapshot, keys) = make_pq_snapshot(3, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut blob = make_pq_blob(&snapshot, &keys, &header);
        // Duplicate the first signature: the same validator signing twice is
        // one attestation, not two (canary, qcblob_quorum).
        let dup = blob.pq_signatures[0].clone();
        blob.pq_signatures.push(dup);
        blob.merkle_root = QcBlob::compute_merkle_root(&blob.pq_signatures);

        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        assert!(matches!(
            client.verify_pq_checkpoint(&header, &blob, &snapshot),
            Err(LightClientError::VerificationFailed(_))
        ));
    }

    #[test]
    fn header_chain_requires_contiguity_and_forward_motion() {
        let (snapshot, _sks) = make_bls_snapshot(4, 1000);
        let client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash,
        })
        .unwrap();

        let h1 = make_block_header_at(1, TEST_CHAIN_ID);
        let mut h2 = make_block_header_at(2, TEST_CHAIN_ID);
        h2.previous_hash = h1.hash.clone();
        h2.hash = h2.calculate_hash();
        assert!(client.verify_header_chain(&[h1.clone(), h2]).is_ok());

        // A gap breaks the chain.
        let h3 = make_block_header_at(3, TEST_CHAIN_ID);
        let broken = [h1, h3];
        assert!(client.verify_header_chain(&broken).is_err());

        // A header at or below the anchor is not forward.
        let anchor_header = make_block_header_at(0, TEST_CHAIN_ID);
        assert!(matches!(
            client.verify_header_chain(&[anchor_header]),
            Err(LightClientError::NotForward { .. })
        ));
    }

    #[test]
    fn sync_plan_targets_the_next_checkpoint() {
        let client = LightClient::new(TrustedCheckpoint {
            height: 4,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();

        assert_eq!(client.next_checkpoint_height(10, 50), Some(10));
        assert_eq!(client.next_checkpoint_height(10, 9), None);
        assert_eq!(client.next_checkpoint_height(10, 20), Some(10));

        let plan = client.sync_plan(10, 50);
        assert_eq!(plan.headers_locator, vec!["0".repeat(64)]);
        assert_eq!(plan.next_checkpoint_height, Some(10));

        let at_checkpoint = LightClient::new(TrustedCheckpoint {
            height: 10,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();
        assert_eq!(at_checkpoint.next_checkpoint_height(10, 50), Some(20));
    }

    // ---- PQ helpers ----

    fn make_pq_snapshot(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<PqKeyPair>) {
        let mut keys = Vec::new();
        let validators: Vec<ValidatorEntry> = (0..n)
            .map(|i| {
                let key = PqKeyPair::generate();
                keys.push(key);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = u8::try_from(i + 1).expect("test index fits u8");
                ValidatorEntry {
                    address: Address::from(addr_bytes),
                    stake: stake_each,
                    bls_public_key: Vec::new(),
                    pop_signature: Vec::new(),
                    pq_public_key: keys.last().unwrap().public_key_bytes().to_vec(),
                }
            })
            .collect();
        (ValidatorSetSnapshot::new(1, validators), keys)
    }

    fn make_pq_blob(
        snapshot: &ValidatorSetSnapshot,
        keys: &[PqKeyPair],
        header: &BlockHeader,
    ) -> QcBlob {
        let entries: Vec<PqSignatureEntry> = snapshot
            .validators
            .iter()
            .enumerate()
            .map(|(idx, validator)| {
                let message = pq_signing_message(
                    snapshot.epoch,
                    header.index,
                    &header.hash,
                    u32::try_from(idx).expect("test validator count is small"),
                );
                let sig = keys[idx].sign(&message).expect("sign");
                PqSignatureEntry {
                    validator_index: u32::try_from(idx).expect("test validator count is small"),
                    validator_address: validator.address.to_string(),
                    dilithium_signature: sig,
                }
            })
            .collect();
        QcBlob::new(snapshot.epoch, header.index, header.hash.clone(), entries)
    }
}
