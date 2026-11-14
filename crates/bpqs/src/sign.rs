//! Public signing surface: the ceremony types and the three entry points
//!
//! WIRING: every public item here keys the cold-committee anchor flow -
//! reached by `pq_anchor` when research bar item (2) lands (research line
//! F2; crate header carries the full reference).
//! the anchor flow will one day consume (`keygen_root`, `sign_at_height`,
//! `verify_at_height`). RESEARCH ONLY - every call path here returns
//! [`BpqsError`] and never panics, matching the production deny-lints this
//! crate will eventually ship under.
//!
//! ## Ceremony cost, written down for the reviewer
//!
//! Minting the committee key means deriving one Winternitz epoch key per
//! tree leaf - `2^T_LOG2 * LEN * w` hash calls. The canonical rows (T_LOG2 =
//! 16) are ceremony-scale (offline, once per member), not unit tests; the
//! battery exercises the identical code path over the `ParamsTestFast` row
//! (T_LOG2 = 4) and a real-size run is kept as an ignored test for machine
//! lanes.

use alloc::vec::Vec;

use crate::domains;
use crate::epoch::{epoch_of, prf_epoch_seed, EpochWindow};
use crate::error::BpqsError;
use crate::hash::BpqsHash;
use crate::merkle;
use crate::params::BpqsParams;
use crate::wots;

/// The committee member's public anchor: the epoch-tree root plus the epoch
/// window the signatures are read against. Both travel with the keybook
/// entry; the verifier needs no other setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpqsPublicKey<P: BpqsParams> {
    /// Merkle root over this member's per-epoch verification digests
    /// (meaningful prefix: `P::N` bytes).
    pub root: [u8; 32],
    /// Blocks per epoch; verifier-side tempo contract.
    pub window: EpochWindow,
    /// Parameter row marker, so a keybook entry cannot be misread across
    /// security levels (L5 signatures never verify under L3 parameters).
    pub params_name: &'static str,
    _private: core::marker::PhantomData<P>,
}

impl<P: BpqsParams> BpqsPublicKey<P> {
    /// Construct from parts (used by the keybook deserializer in a later
    /// milestone; kept public so external test lanes can mint synthetic keys).
    pub fn from_parts(root: [u8; 32], window: EpochWindow, params_name: &'static str) -> Self {
        BpqsPublicKey {
            root,
            window,
            params_name,
            _private: core::marker::PhantomData,
        }
    }
}

/// A BPQS signature. The epoch is carried explicitly (the verifier refuses
/// any discrepancy with its own derivation - see
/// [`BpqsError::EpochMismatch`]), the Winternitz segments prove knowledge of
/// the epoch secret chains, and the auth path binds the epoch to the
/// committee member's long-term root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpqsSignature<P: BpqsParams> {
    /// Epoch the signature was minted in (`floor(height / window)`).
    pub epoch: u32,
    /// Per-call randomizer (2026-09-22, bar-1 record): 16 bytes derived as
    /// `H(RANDOMIZER, root_seed || epoch_le || count_le || msg)`, bound into
    /// the signed digest (`MESSAGE_BIND_V1`). It is PRF-derived, not
    /// entropy-fresh: deterministic per (signer, epoch, count, message),
    /// so an adaptive attacker steering payloads cannot evaluate the
    /// randomization in advance, while replay/KAT determinism survives.
    pub randomizer: [u8; 16],
    /// Winternitz chain segments: the first `P::LEN` entries carry the
    /// signature, the tail is zero. Each lane holds its meaningful prefix of
    /// `P::N` bytes; the rest is zero padding (module contract, `wots`).
    pub chains: [[u8; 32]; 256],
    /// Auth path, LSB-first; the first `P::T_LOG2` entries are used.
    pub path: [[u8; 32]; 16],
    _private: core::marker::PhantomData<P>,
}

/// The member's working key: root seed plus the materialized epoch tree.
/// Held by cold devices between ceremonies.
pub struct BpqsSigner<P: BpqsParams, H: BpqsHash> {
    levels: merkle::Levels,
    /// Zeroed on drop (F11): the root seed is the master secret of every
    /// epoch key this device will ever mint.
    root_seed: [u8; 32],
    public: BpqsPublicKey<P>,
    /// Signatures minted per epoch. The WOTS one-time property
    /// per (epoch, count) is only safe if a count is never reused, and a
    /// caller-held count nothing persists could not promise that. The device
    /// keeps its own counters, and `sign_at_height` takes `&mut self`.
    ///
    /// THE DUPLICATE HAZARD THIS MAP CANNOT SOLVE BY ITSELF: the map lives in
    /// process memory, so a device that restarts and is rebuilt from the root
    /// seed would start every epoch at zero and draw a one-time Winternitz key
    /// it has already published. The requirement is therefore *durable,
    /// device-side* quota state: the ceremony harness persists
    /// [`BpqsSigner::epoch_counts`] before the process ends and hands it back
    /// through [`BpqsSigner::resume`] before the device mints again.
    ///
    /// `quota_known` is how the signer fails closed when that obligation is
    /// forgotten: a signer that came straight from the seed does not know
    /// whether it has minted, so it refuses to sign at all. Only `resume`
    /// (counters from the device log) and `fresh_device` (the log was read and
    /// holds no mints) mark the state as known.
    per_epoch_counts: alloc::collections::BTreeMap<u32, u32>,
    /// Whether the durable quota state above has been supplied, by `resume`
    /// or by `fresh_device`. `ceremonial_keygen` leaves it false: minting from
    /// a seed alone is the exact restart pattern that reuses an epoch key.
    quota_known: bool,
    /// The highest epoch this signer has minted for. Kept so a resumed signer
    /// cannot walk backwards into an epoch whose quota state was lost.
    highest_epoch_minted: Option<u32>,
    _hash: core::marker::PhantomData<H>,
}

impl<P: BpqsParams, H: BpqsHash> BpqsSigner<P, H> {
    /// Mint the member key. Offline ceremony cost: `2^T_LOG2` epoch-key
    /// derivations plus the tree fold. The caller is a ceremony harness that
    /// must also log the chosen [`EpochWindow`] into the keybook.
    ///
    /// The returned signer cannot mint yet. Deriving the tree from the seed
    /// says nothing about how many signatures this device has already spent -
    /// that is exactly what a restart loses - so the quota starts out
    /// *unknown* and `sign_at_height` refuses until the caller supplies it
    /// through [`BpqsSigner::resume`] (or declares a never-minted device with
    /// [`BpqsSigner::fresh_device`]).
    pub fn ceremonial_keygen(root_seed: [u8; 32], window: EpochWindow) -> Result<Self, BpqsError> {
        let mut vks = Vec::with_capacity(1usize << P::T_LOG2);
        for epoch in 0..(1u32 << P::T_LOG2) {
            let seed = prf_epoch_seed::<H>(&root_seed, epoch);
            let chains = wots::epoch_secret_chains::<H, P>(&seed);
            vks.push(wots::vk_of_chains::<H, P>(&chains));
        }
        let (root, levels) = merkle::build_tree::<H, P>(&vks)?;
        let public = BpqsPublicKey::from_parts(root, window, P::NAME);
        Ok(BpqsSigner {
            levels,
            root_seed,
            public,
            per_epoch_counts: alloc::collections::BTreeMap::new(),
            quota_known: false,
            highest_epoch_minted: None,
            _hash: core::marker::PhantomData,
        })
    }

    /// The explicit never-minted declaration: the ceremony harness has read
    /// the device log it keeps beside the key and found no signature for this
    /// member under any epoch.
    ///
    /// This is the only honest way to start `per_epoch_counts` at zero. It is
    /// separate from [`BpqsSigner::ceremonial_keygen`] on purpose, so the
    /// assumption is written in the code that makes it and cannot be reached
    /// by accident from the seed alone.
    pub fn fresh_device(root_seed: [u8; 32], window: EpochWindow) -> Result<Self, BpqsError> {
        let mut signer = Self::ceremonial_keygen(root_seed, window)?;
        signer.quota_known = true;
        Ok(signer)
    }

    /// Rebuild the signer for an existing committee key, restoring the
    /// per-epoch counts the device already spent.
    ///
    /// This is the restart entry point. `ceremonial_keygen` derives the epoch
    /// tree again from the root seed and starts its quota at zero, which is
    /// only correct for a device that has never minted. A cold device that
    /// has signed, restarts and signs again must come through here with the
    /// counters it persisted, or it draws the same one-time Winternitz key
    /// twice for one epoch - the one outcome the quota exists to prevent.
    ///
    /// `counts` is `(epoch, used)`; an entry for an epoch beyond the tree's
    /// headroom, or a count above `Q_MAX`, is refused rather than clamped. An
    /// empty list is refused too: see the check at the end of the function.
    pub fn resume(
        root_seed: [u8; 32],
        window: EpochWindow,
        counts: impl IntoIterator<Item = (u32, u32)>,
    ) -> Result<Self, BpqsError> {
        let mut signer = Self::ceremonial_keygen(root_seed, window)?;
        for (epoch, used) in counts {
            if epoch >= (1u32 << P::T_LOG2) {
                return Err(BpqsError::Malformed(
                    "resumed quota names an epoch beyond the tree's headroom",
                ));
            }
            if used > P::Q_MAX {
                return Err(BpqsError::Malformed(
                    "resumed quota count is above the few-time ceiling",
                ));
            }
            if used > 0 {
                signer.per_epoch_counts.insert(epoch, used);
                signer.highest_epoch_minted = Some(
                    signer
                        .highest_epoch_minted
                        .map_or(epoch, |highest| highest.max(epoch)),
                );
            }
        }
        // An empty list is not a resume, it is the absence of one. Accepting it
        // would let a restarted device that forgot to read its log re-open the
        // one-time property it just lost, which is the whole defect this API
        // exists to prevent: a never-minted device has to say so through
        // `fresh_device`, which is a different statement from "I read the log
        // and it is empty".
        if signer.per_epoch_counts.is_empty() {
            return Err(BpqsError::Malformed(
                "resume needs the spent epochs; a device that has never minted uses `fresh_device`",
            ));
        }
        signer.quota_known = true;
        Ok(signer)
    }

    /// The counters a caller must persist before the signer is dropped.
    ///
    /// Sorted by epoch, so the same device produces the same bytes on every
    /// export and a caller can commit them as part of a ceremony log.
    pub fn epoch_counts(&self) -> Vec<(u32, u32)> {
        self.per_epoch_counts
            .iter()
            .map(|(epoch, used)| (*epoch, *used))
            .collect()
    }

    /// Sign `msg` for the epoch of `height`, consuming one slot of the
    /// epoch's quota.
    ///
    /// The device counts its own signatures per epoch and refuses the next
    /// mint once `Q_MAX` is reached, so two messages in one epoch can never
    /// draw the same Winternitz key twice - the property the caller-held
    /// counter could not guarantee. `&mut self` is the point: minting is a
    /// state change on the key.
    pub fn sign_at_height(
        &mut self,
        height: u64,
        msg: &[u8],
    ) -> Result<BpqsSignature<P>, BpqsError> {
        // Fail closed: a signer that was not told what the device has already
        // spent cannot promise the one-time property for this epoch, and a
        // zero count is exactly the wrong guess after a restart.
        if !self.quota_known {
            return Err(BpqsError::QuotaStateUnknown);
        }
        let epoch = epoch_of(height, self.public.window)?;
        // Monotonic guard (durable-quota regression): a resumed device that
        // lost an epoch's counters must not walk back into it. Refusing a
        // lower epoch outright is cheaper than trusting a counter that may
        // have been forgotten.
        if self
            .highest_epoch_minted
            .is_some_and(|highest| epoch < highest)
        {
            return Err(BpqsError::Malformed(
                "epoch is below the highest epoch already minted; the resumed quota state is stale",
            ));
        }
        let used = self.per_epoch_counts.get(&epoch).copied().unwrap_or(0);
        if used >= P::Q_MAX {
            return Err(BpqsError::QuotaExceeded {
                epoch,
                // Saturating: `used + 1` overflowed at u32::MAX and
                // aborted a build that promised never to panic.
                attempted: used.saturating_add(1),
            });
        }
        if epoch >= (1u32 << P::T_LOG2) {
            return Err(BpqsError::Malformed(
                "epoch beyond the tree's headroom; committee renewal ceremony required",
            ));
        }
        let epoch_seed = prf_epoch_seed::<H>(&self.root_seed, epoch);
        let chains = wots::epoch_secret_chains::<H, P>(&epoch_seed);
        let r_wide = H::digest32(
            domains::RANDOMIZER,
            &[
                &self.root_seed,
                &epoch.to_le_bytes(),
                &used.to_le_bytes(),
                msg,
            ],
        );
        let mut randomizer = [0u8; 16];
        randomizer.copy_from_slice(&r_wide[..16]);
        let bound = H::digest32(domains::MESSAGE_BIND_V1, &[&randomizer, msg]);
        let mut signature = BpqsSignature {
            epoch,
            randomizer,
            chains: wots::sign_chains::<H, P>(&chains, &bound),
            path: merkle::auth_path::<P>(&self.levels, epoch as usize)?,
            _private: core::marker::PhantomData,
        };
        for lane in signature.chains.iter_mut().skip(P::LEN) {
            *lane = [0u8; 32];
        }
        self.per_epoch_counts.insert(epoch, used.saturating_add(1));
        self.highest_epoch_minted = Some(
            self.highest_epoch_minted
                .map_or(epoch, |highest| highest.max(epoch)),
        );
        Ok(signature)
    }

    /// Borrow the public half for the keybook entry.
    pub fn public(&self) -> &BpqsPublicKey<P> {
        &self.public
    }
}

/// The root-key-only ceremony entry point: builds the signer, returns its
/// public anchor, drops the tree. Callers that only need a keybook entry use
/// this.
pub fn keygen_root<H: BpqsHash, P: BpqsParams>(
    root_seed: [u8; 32],
    window: EpochWindow,
) -> Result<BpqsPublicKey<P>, BpqsError> {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(root_seed, window)?;
    Ok(signer.public().clone())
}

/// Refuse a signature whose unused bytes are not zero. The verifier reads only
/// the first `P::N` bytes of each used lane, the first `P::LEN` chains and the
/// first `P::T_LOG2` path entries. Without this check, the other bytes could be
/// changed with no effect on verification (malleability), and a non-zero lane
/// tail would trip the debug assertion in `wots` instead of returning an error.
fn check_canonical<P: BpqsParams>(sig: &BpqsSignature<P>) -> Result<(), BpqsError> {
    let used_chains = sig.chains.iter().take(P::LEN);
    let used_path = sig.path.iter().take(P::T_LOG2);
    for lane in used_chains.chain(used_path) {
        if lane.iter().skip(P::N).any(|b| *b != 0) {
            return Err(BpqsError::Malformed("non-zero padding in a signature lane"));
        }
    }
    let unused_chains = sig.chains.iter().skip(P::LEN);
    let unused_path = sig.path.iter().skip(P::T_LOG2);
    for lane in unused_chains.chain(unused_path) {
        if lane.iter().any(|b| *b != 0) {
            return Err(BpqsError::Malformed(
                "non-zero bytes in an unused signature lane",
            ));
        }
    }
    Ok(())
}

/// Verify `sig` over `msg` at chain `height` against `public`. The verifier
/// re-derives the epoch (self-timestamping), continues every Winternitz
/// segment to its head, and walks the auth path back to the member's root.
/// Parameter-row misreads (`params_name` mismatch) are refused before any
/// bytes are trusted.
pub fn verify_at_height<H: BpqsHash, P: BpqsParams>(
    public: &BpqsPublicKey<P>,
    height: u64,
    msg: &[u8],
    sig: &BpqsSignature<P>,
) -> Result<(), BpqsError> {
    if public.params_name != P::NAME {
        return Err(BpqsError::Malformed(
            "keybook entry and signature are from different parameter rows",
        ));
    }
    let expected_epoch = epoch_of(height, public.window)?;
    if sig.epoch != expected_epoch {
        return Err(BpqsError::EpochMismatch {
            expected: expected_epoch,
            in_signature: sig.epoch,
        });
    }
    if sig.epoch >= (1u32 << P::T_LOG2) {
        return Err(BpqsError::Malformed("epoch beyond tree headroom"));
    }
    check_canonical::<P>(sig)?;
    let bound = H::digest32(domains::MESSAGE_BIND_V1, &[&sig.randomizer, msg]);
    let rebuilt = wots::verify_chains::<H, P>(&sig.chains, &bound);
    merkle::verify_path::<H, P>(&rebuilt, sig.epoch as usize, &sig.path, &public.root)
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use crate::hash::Sha3_256Hash;
    use crate::params::ParamsTestFast;

    type P = ParamsTestFast;
    type H = Sha3_256Hash;

    fn committee() -> BpqsSigner<P, H> {
        BpqsSigner::<P, H>::fresh_device([42u8; 32], EpochWindow(8))
            .unwrap_or_else(|e| panic!("keygen: {e}"))
    }

    #[test]
    fn roundtrip_across_epochs() {
        let mut signer = committee();
        // One mint per epoch: Q_MAX is 1, and the device now
        // enforces the quota itself.
        for height in [0u64, 8, 16, 24, 32, 40] {
            let sig = signer
                .sign_at_height(height, b"anchor-digest")
                .unwrap_or_else(|e| panic!("sign h={height}: {e}"));
            verify_at_height::<H, P>(signer.public(), height, b"anchor-digest", &sig)
                .unwrap_or_else(|e| panic!("verify h={height}: {e}"));
        }
    }

    #[test]
    fn signature_moved_to_another_epoch_refuses() {
        let mut signer = committee();
        let sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        let out = verify_at_height::<H, P>(signer.public(), 8, b"m", &sig);
        assert_eq!(
            out,
            Err(BpqsError::EpochMismatch {
                expected: 1,
                in_signature: 0
            })
        );
    }

    #[test]
    fn second_signature_in_one_epoch_refuses() {
        let mut signer = committee();
        signer
            .sign_at_height(3, b"m")
            .unwrap_or_else(|e| panic!("first mint of the epoch must sign: {e}"));
        assert_eq!(
            signer.sign_at_height(3, b"m"),
            Err(BpqsError::QuotaExceeded {
                epoch: 0,
                attempted: 2
            })
        );
    }

    /// A signer rebuilt from the seed alone must not mint at all: it cannot
    /// tell a never-minted device from a restarted one, and assuming zero is
    /// the assumption that reuses a one-time key.
    #[test]
    fn a_signer_built_from_the_seed_alone_refuses_to_mint() {
        let mut from_seed = BpqsSigner::<P, H>::ceremonial_keygen([42u8; 32], EpochWindow(8))
            .unwrap_or_else(|e| panic!("keygen: {e}"));
        assert_eq!(
            from_seed.sign_at_height(3, b"m"),
            Err(BpqsError::QuotaStateUnknown)
        );

        // The explicit never-minted declaration is what opens the door.
        let mut declared = BpqsSigner::<P, H>::fresh_device([42u8; 32], EpochWindow(8))
            .unwrap_or_else(|e| panic!("keygen: {e}"));
        assert!(declared.sign_at_height(3, b"m").is_ok());
    }

    /// The restart path: a second signer built from the same root seed can
    /// only be safe if it is told what the first one already spent.
    #[test]
    fn a_resumed_signer_refuses_the_epoch_it_already_signed() {
        let mut first = committee();
        first
            .sign_at_height(3, b"m")
            .unwrap_or_else(|e| panic!("first mint must sign: {e}"));
        first
            .sign_at_height(11, b"m")
            .unwrap_or_else(|e| panic!("second epoch must sign: {e}"));
        let spent = first.epoch_counts();
        assert_eq!(spent, alloc::vec![(0u32, 1u32), (1u32, 1u32)]);

        // A fresh process rebuilt from the seed alone would draw epoch 0's
        // key a second time. Resumed with the counters for epoch 0 only, the
        // quota refuses the second mint in that epoch.
        let mut partial = BpqsSigner::<P, H>::resume([42u8; 32], EpochWindow(8), [(0u32, 1u32)])
            .unwrap_or_else(|e| panic!("resume: {e}"));
        assert_eq!(
            partial.sign_at_height(3, b"m"),
            Err(BpqsError::QuotaExceeded {
                epoch: 0,
                attempted: 2
            })
        );

        // With every spent epoch restored, the monotonic guard refuses a walk
        // back below the highest epoch this device has minted for, and the
        // quota still refuses that epoch itself.
        let mut resumed = BpqsSigner::<P, H>::resume([42u8; 32], EpochWindow(8), spent)
            .unwrap_or_else(|e| panic!("resume: {e}"));
        assert!(matches!(
            resumed.sign_at_height(3, b"m"),
            Err(BpqsError::Malformed(_))
        ));
        assert_eq!(
            resumed.sign_at_height(11, b"m"),
            Err(BpqsError::QuotaExceeded {
                epoch: 1,
                attempted: 2
            })
        );
        // An epoch that was never minted for still signs.
        assert!(resumed.sign_at_height(19, b"m").is_ok());
    }

    /// An empty restore list is not a resume. Treating it as "never minted"
    /// would let a device that lost its log re-open every epoch it spent,
    /// which is exactly the key reuse the durable quota exists to stop.
    #[test]
    fn resume_with_an_empty_list_is_refused() {
        assert!(matches!(
            BpqsSigner::<P, H>::resume([42u8; 32], EpochWindow(8), []),
            Err(BpqsError::Malformed(_))
        ));
    }

    #[test]
    fn wrong_message_refuses() {
        let mut signer = committee();
        let sig = signer
            .sign_at_height(0, b"good")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_at_height::<H, P>(signer.public(), 0, b"evil", &sig).is_err());
    }

    #[test]
    fn wrong_public_key_refuses() {
        let mut signer = committee();
        let other = BpqsSigner::<P, H>::fresh_device([43u8; 32], EpochWindow(8))
            .unwrap_or_else(|e| panic!("keygen: {e}"));
        let sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_at_height::<H, P>(other.public(), 0, b"m", &sig).is_err());
    }

    #[test]
    fn params_name_mismatch_refuses() {
        let mut signer = committee();
        let sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        let mut public = signer.public().clone();
        public.params_name = "another-row";
        assert_eq!(
            verify_at_height::<H, P>(&public, 0, b"m", &sig),
            Err(BpqsError::Malformed(
                "keybook entry and signature are from different parameter rows"
            ))
        );
    }

    #[test]
    fn epoch_beyond_headroom_refuses_at_sign_and_verify() {
        let mut signer = committee();
        let past = (1u64 << P::T_LOG2) * 8;
        assert_eq!(
            signer.sign_at_height(past, b"m"),
            Err(BpqsError::Malformed(
                "epoch beyond the tree's headroom; committee renewal ceremony required"
            ))
        );
        let mut sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        sig.epoch = 1u32 << P::T_LOG2;
        assert_eq!(
            verify_at_height::<H, P>(signer.public(), past, b"m", &sig),
            Err(BpqsError::Malformed("epoch beyond tree headroom"))
        );
    }

    #[test]
    fn height_beyond_u32_epochs_refuses() {
        let mut signer = committee();
        assert!(signer.sign_at_height(u64::MAX, b"m").is_err());
    }

    #[test]
    fn tampered_path_refuses() {
        let mut signer = committee();
        let mut sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        sig.path[0][0] ^= 0x01;
        assert_eq!(
            verify_at_height::<H, P>(signer.public(), 0, b"m", &sig),
            Err(BpqsError::BadAuthPath)
        );
    }

    #[test]
    fn tampered_chain_refuses() {
        let mut signer = committee();
        let mut sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        sig.chains[9][1] ^= 0x01;
        assert!(verify_at_height::<H, P>(signer.public(), 0, b"m", &sig).is_err());
    }

    #[test]
    fn non_zero_unused_chain_refuses() {
        let mut signer = committee();
        let mut sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        sig.chains[P::LEN][0] = 1;
        assert!(matches!(
            verify_at_height::<H, P>(signer.public(), 0, b"m", &sig),
            Err(BpqsError::Malformed(_))
        ));
    }

    #[test]
    fn non_zero_unused_path_entry_refuses() {
        let mut signer = committee();
        let mut sig = signer
            .sign_at_height(0, b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        sig.path[P::T_LOG2][5] = 1;
        assert!(matches!(
            verify_at_height::<H, P>(signer.public(), 0, b"m", &sig),
            Err(BpqsError::Malformed(_))
        ));
    }

    #[test]
    fn non_zero_lane_tail_refuses_without_panic() {
        use crate::params::ParamsL3;
        let mut sig = BpqsSignature::<ParamsL3> {
            epoch: 0,
            randomizer: [0u8; 16],
            chains: [[0u8; 32]; 256],
            path: [[0u8; 32]; 16],
            _private: core::marker::PhantomData,
        };
        assert_eq!(check_canonical::<ParamsL3>(&sig), Ok(()));
        sig.chains[0][ParamsL3::N] = 1;
        assert!(check_canonical::<ParamsL3>(&sig).is_err());
        sig.chains[0][ParamsL3::N] = 0;
        sig.path[0][31] = 1;
        assert!(check_canonical::<ParamsL3>(&sig).is_err());
    }
}

/// F11: zero the root seed when the signer is dropped.
impl<P: BpqsParams, H: BpqsHash> Drop for BpqsSigner<P, H> {
    fn drop(&mut self) {
        for b in &mut self.root_seed {
            *b = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha3_256Hash;
    use crate::params::{BpqsParams, ParamsL3, ParamsTestFast};

    // L3 lanes carry padding (N = 24 of 32); the test-fast row has short
    // auth paths (T_LOG2 = 4 of 16) but full lanes, so each refusal arm is
    // exercised on the row that has the bytes to spare.
    type T = ParamsL3;
    type H = Sha3_256Hash;

    // `check_canonical` is a shape predicate: it reads lane padding and
    // unused entries, never cryptographic validity. Minting the fixture
    // through a real L3 `ceremonial_keygen` costs 2^T_LOG2 epoch keys per
    // test and pushed the debug suite past the CI job timeout (the rest of
    // the suite finishes in well under a minute), so the canonical fixture
    // is built by hand on the same L3 row whose padding is under test. The
    // real signing path stays covered by `sign_tests` on the fast row and
    // by the ignored full-size ceremony test.
    fn canonical_sig() -> BpqsSignature<T> {
        BpqsSignature::<T> {
            epoch: 0,
            randomizer: [0u8; 16],
            chains: [[0u8; 32]; 256],
            path: [[0u8; 32]; 16],
            _private: core::marker::PhantomData,
        }
    }

    fn signed_fast() -> BpqsSignature<ParamsTestFast> {
        let window = EpochWindow(4);
        let mut signer = BpqsSigner::<ParamsTestFast, H>::fresh_device([7u8; 32], window).unwrap();
        signer.sign_at_height(0, b"canonical-check").unwrap()
    }

    // Check_canonical is the malleability gate; every refusal arm
    // and the pass case get a test.
    #[test]
    fn check_canonical_accepts_the_unmodified_signature() {
        assert!(check_canonical(&canonical_sig()).is_ok());
    }

    #[test]
    fn check_canonical_refuses_nonzero_used_lane_padding() {
        let mut sig = canonical_sig();
        sig.chains[0][T::N] = 1;
        assert!(matches!(
            check_canonical(&sig),
            Err(BpqsError::Malformed(_))
        ));
    }

    #[test]
    fn check_canonical_refuses_nonzero_unused_lane() {
        let mut sig = canonical_sig();
        sig.chains[T::LEN][0] = 1;
        assert!(matches!(
            check_canonical(&sig),
            Err(BpqsError::Malformed(_))
        ));
    }

    #[test]
    fn check_canonical_refuses_nonzero_unused_path_entry() {
        let mut sig = signed_fast();
        sig.path[ParamsTestFast::T_LOG2][0] = 1;
        assert!(matches!(
            check_canonical(&sig),
            Err(BpqsError::Malformed(_))
        ));
    }
}
