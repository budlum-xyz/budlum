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
    root_seed: [u8; 32],
    public: BpqsPublicKey<P>,
    _hash: core::marker::PhantomData<H>,
}

impl<P: BpqsParams, H: BpqsHash> BpqsSigner<P, H> {
    /// Mint the member key. Offline ceremony cost: `2^T_LOG2` epoch-key
    /// derivations plus the tree fold. The caller is a ceremony harness that
    /// must also log the chosen [`EpochWindow`] into the keybook.
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
            _hash: core::marker::PhantomData,
        })
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

/// Sign `msg` for the epoch of `height`. `per_epoch_count` is the caller's
/// own count of signatures already minted in this epoch - the device keeps
/// no mutable chain state, so the count lives in the ceremony log, and
/// breaching `q_max` is refused loudly instead of silently degrading toward
/// one-time-key reuse.
pub fn sign_at_height<H: BpqsHash, P: BpqsParams>(
    signer: &BpqsSigner<P, H>,
    height: u64,
    per_epoch_count: u32,
    msg: &[u8],
) -> Result<BpqsSignature<P>, BpqsError> {
    let epoch = epoch_of(height, signer.public.window)?;
    if per_epoch_count >= P::Q_MAX {
        return Err(BpqsError::QuotaExceeded {
            epoch,
            attempted: per_epoch_count + 1,
        });
    }
    if epoch >= (1u32 << P::T_LOG2) {
        return Err(BpqsError::Malformed(
            "epoch beyond the tree's headroom; committee renewal ceremony required",
        ));
    }
    let epoch_seed = prf_epoch_seed::<H>(&signer.root_seed, epoch);
    let chains = wots::epoch_secret_chains::<H, P>(&epoch_seed);
    let r_wide = H::digest32(
        domains::RANDOMIZER,
        &[
            &signer.root_seed,
            &epoch.to_le_bytes(),
            &per_epoch_count.to_le_bytes(),
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
        path: merkle::auth_path::<P>(&signer.levels, epoch as usize)?,
        _private: core::marker::PhantomData,
    };
    for lane in signature.chains.iter_mut().skip(P::LEN) {
        *lane = [0u8; 32];
    }
    Ok(signature)
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
        BpqsSigner::<P, H>::ceremonial_keygen([42u8; 32], EpochWindow(8))
            .unwrap_or_else(|e| panic!("keygen: {e}"))
    }

    #[test]
    fn roundtrip_across_epochs() {
        let signer = committee();
        for height in [0u64, 7, 8, 15, 16, 40] {
            let sig = sign_at_height::<H, P>(&signer, height, 0, b"anchor-digest")
                .unwrap_or_else(|e| panic!("sign h={height}: {e}"));
            verify_at_height::<H, P>(signer.public(), height, b"anchor-digest", &sig)
                .unwrap_or_else(|e| panic!("verify h={height}: {e}"));
        }
    }

    #[test]
    fn signature_moved_to_another_epoch_refuses() {
        let signer = committee();
        let sig = sign_at_height::<H, P>(&signer, 0, 0, b"m").unwrap_or_else(|e| panic!("{e}"));
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
        let signer = committee();
        sign_at_height::<H, P>(&signer, 3, 0, b"m")
            .unwrap_or_else(|e| panic!("first mint of the epoch must sign: {e}"));
        assert_eq!(
            sign_at_height::<H, P>(&signer, 3, 1, b"m"),
            Err(BpqsError::QuotaExceeded {
                epoch: 0,
                attempted: 2
            })
        );
    }

    #[test]
    fn wrong_message_refuses() {
        let signer = committee();
        let sig = sign_at_height::<H, P>(&signer, 0, 0, b"good").unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_at_height::<H, P>(signer.public(), 0, b"evil", &sig).is_err());
    }

    #[test]
    fn tampered_path_refuses() {
        let signer = committee();
        let mut sig = sign_at_height::<H, P>(&signer, 0, 0, b"m").unwrap_or_else(|e| panic!("{e}"));
        sig.path[0][0] ^= 0x01;
        assert_eq!(
            verify_at_height::<H, P>(signer.public(), 0, b"m", &sig),
            Err(BpqsError::BadAuthPath)
        );
    }

    #[test]
    fn tampered_chain_refuses() {
        let signer = committee();
        let mut sig = sign_at_height::<H, P>(&signer, 0, 0, b"m").unwrap_or_else(|e| panic!("{e}"));
        sig.chains[9][1] ^= 0x01;
        assert!(verify_at_height::<H, P>(signer.public(), 0, b"m", &sig).is_err());
    }
}
