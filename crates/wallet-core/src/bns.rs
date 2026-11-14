//! `.bud` recipient classification and Merkle state-proof verification for wallets.
//!
//! exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
//!
//! A wallet sending funds to `ayaz.bud` must never trust an unauthenticated RPC
//! answer: a lying node could substitute an attacker's address and collect the
//! user's signature over it. This module validates `.bud` / `<sub_label>.<label>.bud`
//! recipient syntax client-side and verifies `BnsStateProof` branches directly
//! against a header-committed `bns_v1` root (`BDLM_BNS_REGISTRY_V3`) and epoch.

use sha2::{Digest, Sha256};

/// Maximum `extras_preimage` byte size accepted when opening `BDLM_BNS_EXTRAS_V1`.
pub const MAX_EXTRAS_PREIMAGE_BYTES: usize = 65_536;

/// Parsed transfer recipient input entered by a wallet user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientTarget {
    /// Non-zero 32-byte native address (`0x`-prefixed or bare 64-char hex).
    Direct([u8; 32]),
    /// Canonical lowercase `<label>.bud` or `<sub_label>.<label>.bud` name.
    BudName(String),
}

/// Whether `label` is a valid top-level `.bud` label (`3..=32` lowercase ASCII
/// `[a-z0-9-]`, no leading or trailing `-`).
#[must_use]
pub fn is_valid_bud_label(label: &str) -> bool {
    let len = label.len();
    (3..=32).contains(&len)
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `label` is a valid subdomain label (`1..=32` lowercase ASCII `[a-z0-9-]`,
/// no leading or trailing `-`).
#[must_use]
pub fn is_valid_sub_label(label: &str) -> bool {
    let len = label.len();
    (1..=32).contains(&len)
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `name` is a valid top-level `<label>.bud` name.
#[must_use]
pub fn is_valid_bud_name(name: &str) -> bool {
    name.strip_suffix(".bud").is_some_and(is_valid_bud_label)
}

/// Whether `name` is a valid resolvable `<label>.bud` or two-level `<sub_label>.<label>.bud`.
#[must_use]
pub fn is_valid_resolvable_bud_name(name: &str) -> bool {
    if is_valid_bud_name(name) {
        return true;
    }
    let Some(stem) = name.strip_suffix(".bud") else {
        return false;
    };
    let Some((sub, parent_label)) = stem.split_once('.') else {
        return false;
    };
    !parent_label.contains('.') && is_valid_sub_label(sub) && is_valid_bud_label(parent_label)
}

/// Parse a user-entered recipient string into either a non-zero 32-byte address
/// or a validated `.bud` / `<sub_label>.<label>.bud` name.
///
/// # Errors
///
/// Refuses empty strings, zero addresses, malformed hex, uppercase/homograph
/// `.bud` names, 3+ label hierarchies, and unknown suffixes.
pub fn parse_recipient_input(raw: &str) -> Result<RecipientTarget, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("recipient cannot be empty".into());
    }
    if trimmed.ends_with(".bud") || trimmed.contains('.') {
        if !is_valid_resolvable_bud_name(trimmed) {
            return Err(format!(
                "invalid .bud recipient '{trimmed}': expected <label>.bud (3..=32 lowercase [a-z0-9-]) or <sub>.<label>.bud"
            ));
        }
        return Ok(RecipientTarget::BudName(trimmed.to_string()));
    }
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if clean.len() != 64 {
        return Err(format!(
            "invalid recipient '{trimmed}': expected 64-hex address or <label>.bud"
        ));
    }
    let bytes = hex::decode(clean).map_err(|e| format!("invalid hex recipient: {e}"))?;
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    if addr == [0u8; 32] {
        return Err("recipient address cannot be the zero address".into());
    }
    Ok(RecipientTarget::Direct(addr))
}

/// Compact per-name Merkle proof for wallet-side `.bud` recipient verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBnsProof {
    pub name: String,
    pub owner: [u8; 32],
    pub expires_at: u64,
    pub content_id: Option<[u8; 32]>,
    pub storage_root: Option<[u8; 32]>,
    pub extras_digest: [u8; 32],
    /// Optional raw body committed after `b"BDLM_BNS_EXTRAS_V1"`. When supplied,
    /// `verify_bns_recipient_proof_from_header` verifies the digest against a
    /// trusted header root and extracts the authenticated `record.address`;
    /// when absent, the proof can authenticate `owner` directly.
    pub extras_preimage: Option<Vec<u8>>,
    pub meta_digest: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
    /// The height of the header this proof folds to. Together with a
    /// [`HeaderSource`] the wallet trusts, this is what anchors the proof:
    /// the root and epoch are read from that header, not from the answer.
    pub header_height: u64,
}

/// Compute `BDLM_BNS_LEAF_V1` over the leaf fields, matching `BnsRegistry::compute_leaf_digest`.
#[must_use]
pub fn compute_bns_leaf_digest(
    name: &str,
    owner: &[u8; 32],
    expires_at: u64,
    content_id: Option<&[u8; 32]>,
    storage_root: Option<&[u8; 32]>,
    extras_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_LEAF_V1");
    hasher.update((name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update(owner);
    hasher.update(expires_at.to_le_bytes());
    match content_id {
        Some(cid) => {
            hasher.update([1u8]);
            hasher.update(cid);
        }
        None => hasher.update([0u8]),
    }
    match storage_root {
        Some(sr) => {
            hasher.update([1u8]);
            hasher.update(sr);
        }
        None => hasher.update([0u8]),
    }
    hasher.update(extras_digest);
    hasher.finalize().into()
}

/// Fold a Merkle branch (`BDLM_BNS_NODE_V1`) from `leaf` up to `names_merkle_root`.
#[must_use]
pub fn fold_bns_merkle_branch(
    leaf: [u8; 32],
    siblings: &[[u8; 32]],
    directions: &[bool],
) -> Option<[u8; 32]> {
    if siblings.len() != directions.len() || siblings.len() > 32 {
        return None;
    }
    let mut acc = leaf;
    for (sib, is_right_child) in siblings.iter().zip(directions.iter()) {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_NODE_V1");
        if *is_right_child {
            hasher.update(sib);
            hasher.update(acc);
        } else {
            hasher.update(acc);
            hasher.update(sib);
        }
        acc = hasher.finalize().into();
    }
    Some(acc)
}

/// Combine `(meta_digest, names_merkle_root)` under `BDLM_BNS_REGISTRY_V3`.
#[must_use]
pub fn compute_bns_registry_root(meta_digest: &[u8; 32], names_merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_REGISTRY_V3");
    hasher.update(meta_digest);
    hasher.update(names_merkle_root);
    hasher.finalize().into()
}

fn parse_address_from_extras_preimage(
    preimage: &[u8],
    expected_extras_digest: &[u8; 32],
) -> Result<[u8; 32], String> {
    if preimage.len() > MAX_EXTRAS_PREIMAGE_BYTES {
        return Err("extras_preimage exceeds maximum size".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_EXTRAS_V1");
    hasher.update(preimage);
    let actual: [u8; 32] = hasher.finalize().into();
    if &actual != expected_extras_digest {
        return Err("extras_preimage does not match leaf extras_digest".into());
    }
    // Layout prefix of BDLM_BNS_EXTRAS_V1:
    //   resolver: 0u8 | (1u8 || [u8; 32])
    //   address:  0u8 | (1u8 || [u8; 32])
    let resolver_skip = match preimage.first().copied() {
        Some(0) => 1usize,
        Some(1) => 33usize,
        _ => return Err("malformed resolver tag in extras_preimage".into()),
    };
    if preimage.len() < resolver_skip + 1 {
        return Err("truncated extras_preimage before address tag".into());
    }
    match preimage[resolver_skip] {
        0 => {
            Err("BNS name has no active forwarding target address (record.address is None)".into())
        }
        1 => {
            let start = resolver_skip + 1;
            let end = start + 32;
            let slice = preimage
                .get(start..end)
                .ok_or_else(|| "truncated target address in extras_preimage".to_string())?;
            let mut target = [0u8; 32];
            target.copy_from_slice(slice);
            if target == [0u8; 32] {
                return Err("proven BNS target address is the zero address".into());
            }
            Ok(target)
        }
        _ => Err("malformed address tag in extras_preimage".into()),
    }
}

/// Verify a `.bud` Merkle proof against `expected_bns_root` at `current_epoch`
/// and return the authenticated recipient address.
///
/// This takes the root and the epoch as arguments, so it is only as good as
/// whoever supplied them. It is not public: a root that came from the node's own
/// answer would let a lying node choose the recipient. The only way in from outside
/// the crate is [`verify_bns_recipient_proof_from_header`], which reads both from a
/// header the wallet trusts.
///
/// * If `proof.extras_preimage` is `Some(bytes)`, verifies `BDLM_BNS_EXTRAS_V1`
///   and extracts the authenticated `record.address` forwarding target (failing
///   closed if `record.address` was cleared or zero).
/// * If `proof.extras_preimage` is `None`, returns the authenticated `owner`
///   only when `claimed_target == proof.owner`.
///
/// # Errors
///
/// Refuses invalid names, expired leaves (`expires_at <= current_epoch`), root
/// mismatches, zero addresses, or unauthenticated target substitution.
pub(crate) fn verify_recipient_against_root(
    requested_name: &str,
    claimed_target: &[u8; 32],
    proof: &WalletBnsProof,
    expected_bns_root: &[u8; 32],
    current_epoch: u64,
) -> Result<[u8; 32], String> {
    if !is_valid_bud_name(requested_name) {
        return Err(format!("invalid .bud name '{requested_name}'"));
    }
    if proof.name != requested_name {
        return Err("proof name does not match requested .bud name".into());
    }
    if *claimed_target == [0u8; 32] || proof.owner == [0u8; 32] {
        return Err("BNS owner or target address cannot be the zero address".into());
    }
    if proof.expires_at <= current_epoch {
        return Err("proven .bud name has expired at the verified header epoch".into());
    }
    let leaf = compute_bns_leaf_digest(
        &proof.name,
        &proof.owner,
        proof.expires_at,
        proof.content_id.as_ref(),
        proof.storage_root.as_ref(),
        &proof.extras_digest,
    );
    let names_root = fold_bns_merkle_branch(leaf, &proof.siblings, &proof.directions)
        .ok_or_else(|| "malformed BNS Merkle branch".to_string())?;
    let computed_root = compute_bns_registry_root(&proof.meta_digest, &names_root);
    if &computed_root != expected_bns_root {
        return Err("BNS Merkle proof did not reproduce expected header bns_root".into());
    }

    match &proof.extras_preimage {
        Some(preimage) => {
            let proven_target = parse_address_from_extras_preimage(preimage, &proof.extras_digest)?;
            if &proven_target != claimed_target {
                return Err("claimed recipient address contradicts proven record.address".into());
            }
            Ok(proven_target)
        }
        None => {
            if claimed_target != &proof.owner {
                return Err(
                    "custom forwarding target requires extras_preimage to authenticate record.address"
                        .into(),
                );
            }
            Ok(proof.owner)
        }
    }
}

/// Where the wallet gets the header root a `.bud` proof must fold to.
///
/// A proof is only worth what its anchor is worth. A check that took
/// `expected_bns_root` and `current_epoch` as bare arguments would sell the
/// user's signature for whatever root a node's JSON named. The crate has no such
/// public entry point. A wallet hands a source it trusts (a header it synced, a
/// checkpoint it was compiled with, a light-client follow chain) to this trait,
/// and the root and the epoch the proof is checked against are read out of it,
/// so they come from the header, not from the answer.
///
/// A source that has no header at `height` returns `None`; the verifying
/// entry point refuses a proof rather than guessing.
pub trait HeaderSource {
    /// The committed `.bud` registry root (`bns_v1`) at `height`, and the
    /// epoch that header belongs to.
    fn bns_root_at(&self, height: u64) -> Option<([u8; 32], u64)>;

    /// The highest header this source holds. A proof anchored far below it
    /// replays registry state that a later header has already superseded.
    fn latest_height(&self) -> u64;
}

/// How far below the wallet's own tip a proof's header may sit, in blocks.
///
/// One checkpoint interval at the testnet parameters (five blocks, fifteen
/// seconds): a node and a wallet rarely hold the same newest header, so a
/// proof one checkpoint behind is a race, not a replay. A proof further back
/// is refused, because a name that changed hands since then would still resolve
/// to the previous owner.
const MAX_PROOF_LAG_BLOCKS: u64 = 5;

/// The proof is anchored at a header older than the wallet's own tip allows.
///
/// A distinct type, like [`HeaderUnknown`], so a caller can tell a replayed
/// answer from a wallet that is behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleProofHeader {
    /// The header height the proof names.
    pub anchored_at: u64,
    /// The highest header the wallet holds.
    pub tip: u64,
}

impl std::fmt::Display for StaleProofHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "proof is anchored at header {} but the wallet's tip is {}; a name that changed hands \
             since then would still resolve to its previous owner",
            self.anchored_at, self.tip
        )
    }
}

impl std::error::Error for StaleProofHeader {}

/// Verify a `.bud` recipient proof against the root and epoch of the header it
/// claims to belong to, read from `headers`.
///
/// This is the entry point a wallet should call. The root and the epoch come
/// from `headers`, never from the proof's carrier, so a lying node cannot
/// change what the signature is checked against. What it can still choose is
/// which header height it names, and a wallet that synced history holds old
/// headers too, so the height must also be recent: a proof anchored more than
/// one checkpoint below the wallet's own tip is refused, which stops a node
/// from replaying a header at which the name still pointed at a previous owner.
///
/// # Errors
///
/// Refuses invalid names, expired leaves (`expires_at` at or before the header
/// epoch), root mismatches, zero addresses and unauthenticated target
/// substitution, plus [`HeaderUnknown`] when `headers` has no header at
/// `proof.header_height` and [`StaleProofHeader`] when that header is older than
/// the tip allows.
pub fn verify_bns_recipient_proof_from_header<S: HeaderSource + ?Sized>(
    requested_name: &str,
    claimed_target: &[u8; 32],
    proof: &WalletBnsProof,
    headers: &S,
) -> Result<[u8; 32], String> {
    let tip = headers.latest_height();
    if proof.header_height.saturating_add(MAX_PROOF_LAG_BLOCKS) < tip {
        return Err(StaleProofHeader {
            anchored_at: proof.header_height,
            tip,
        }
        .to_string());
    }
    let (root, epoch) = headers
        .bns_root_at(proof.header_height)
        .ok_or_else(|| HeaderUnknown(proof.header_height).to_string())?;
    verify_recipient_against_root(requested_name, claimed_target, proof, &root, epoch)
}

/// No header at the named height in the source the wallet trusts.
///
/// A distinct type so a caller can tell "the node lied" from "I am behind".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderUnknown(pub u64);

impl std::fmt::Display for HeaderUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no verified header at height {}; the proof cannot be anchored",
            self.0
        )
    }
}

impl std::error::Error for HeaderUnknown {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header source holding one header. This is what a wallet hands the
    /// verifying entry point: a header it synced and believes, never a root
    /// it read out of the same node answer that carried the proof.
    struct OneHeader {
        height: u64,
        root: [u8; 32],
        epoch: u64,
    }

    impl HeaderSource for OneHeader {
        fn bns_root_at(&self, height: u64) -> Option<([u8; 32], u64)> {
            (height == self.height).then_some((self.root, self.epoch))
        }

        fn latest_height(&self) -> u64 {
            self.height
        }
    }

    /// The proof a node would send for `ayaz.bud` at header height 7.
    fn header_anchored_fixture() -> (WalletBnsProof, [u8; 32], [u8; 32]) {
        let owner = [0x11u8; 32];
        let vault = [0x22u8; 32];
        let meta = [0x33u8; 32];
        let sib = [0x44u8; 32];
        let (preimage, extras_digest) = sample_extras_preimage(Some(vault));
        let leaf = compute_bns_leaf_digest("ayaz.bud", &owner, 50, None, None, &extras_digest);
        let names_root = fold_bns_merkle_branch(leaf, &[sib], &[true]).unwrap();
        let root = compute_bns_registry_root(&meta, &names_root);
        let proof = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner,
            expires_at: 50,
            content_id: None,
            storage_root: None,
            extras_digest,
            extras_preimage: Some(preimage),
            meta_digest: meta,
            siblings: vec![sib],
            directions: vec![true],
            header_height: 7,
        };
        (proof, root, vault)
    }

    /// A wallet that synced history: it still holds the old header a node can
    /// replay, and its own tip is further on.
    struct SyncedHeaders {
        old_height: u64,
        root: [u8; 32],
        epoch: u64,
        tip: u64,
    }

    impl HeaderSource for SyncedHeaders {
        fn bns_root_at(&self, height: u64) -> Option<([u8; 32], u64)> {
            (height == self.old_height).then_some((self.root, self.epoch))
        }

        fn latest_height(&self) -> u64 {
            self.tip
        }
    }

    /// The replay. A name changed hands after header 7, and a lying node answers
    /// with the proof anchored at header 7, a header the wallet still holds, at
    /// which the name still pointed at the previous owner. The header is real
    /// and the proof folds to its root, so only the age of the anchor can refuse
    /// it.
    #[test]
    fn a_proof_anchored_below_the_wallet_tip_is_a_replay_and_is_refused() {
        let (proof, root, vault) = header_anchored_fixture();
        let tip = 7 + MAX_PROOF_LAG_BLOCKS + 1;
        let synced = SyncedHeaders {
            old_height: 7,
            root,
            epoch: 10,
            tip,
        };
        let refused = verify_bns_recipient_proof_from_header("ayaz.bud", &vault, &proof, &synced)
            .unwrap_err();
        assert_eq!(
            refused,
            StaleProofHeader {
                anchored_at: 7,
                tip,
            }
            .to_string()
        );
    }

    /// A node and a wallet rarely hold the same newest header, so a proof one
    /// checkpoint behind the tip is a race and still verifies.
    #[test]
    fn a_proof_one_checkpoint_behind_the_wallet_tip_still_verifies() {
        let (proof, root, vault) = header_anchored_fixture();
        let synced = SyncedHeaders {
            old_height: 7,
            root,
            epoch: 10,
            tip: 7 + MAX_PROOF_LAG_BLOCKS,
        };
        assert_eq!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &vault, &proof, &synced).unwrap(),
            vault
        );
    }

    #[test]
    fn a_proof_verifies_against_the_root_of_the_header_the_wallet_holds() {
        let (proof, root, vault) = header_anchored_fixture();
        let headers = OneHeader {
            height: 7,
            root,
            epoch: 10,
        };
        assert_eq!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &vault, &proof, &headers).unwrap(),
            vault
        );
    }

    /// The attack this trait exists for. The node answers with a proof and, in
    /// the same breath, tells the wallet which root to check it against. A
    /// wallet that took the node's root would accept a forged record. A wallet
    /// that reads the root from its own header does not, even when the node
    /// presents a proof that folds to the root it chose.
    #[test]
    fn a_root_chosen_by_the_node_cannot_substitute_a_recipient() {
        let (genuine, real_root, real_vault) = header_anchored_fixture();

        // The node builds a record for the attacker address and gets its own
        // root for it. The proof is internally consistent: it folds to a root.
        let attacker = [0x99u8; 32];
        let meta = [0x33u8; 32];
        let sib = [0x44u8; 32];
        let (forged_preimage, forged_extras) = sample_extras_preimage(Some(attacker));
        let forged_leaf =
            compute_bns_leaf_digest("ayaz.bud", &genuine.owner, 50, None, None, &forged_extras);
        let forged_names = fold_bns_merkle_branch(forged_leaf, &[sib], &[true]).unwrap();
        let forged_root = compute_bns_registry_root(&meta, &forged_names);
        let forged = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner: genuine.owner,
            expires_at: 50,
            content_id: None,
            storage_root: None,
            extras_digest: forged_extras,
            extras_preimage: Some(forged_preimage),
            meta_digest: meta,
            siblings: vec![sib],
            directions: vec![true],
            header_height: 7,
        };
        assert_ne!(forged_root, real_root, "the forgery needs its own root");

        // Refused: the wallet's header carries the real root, not the forged one.
        let headers = OneHeader {
            height: 7,
            root: real_root,
            epoch: 10,
        };
        let refused =
            verify_bns_recipient_proof_from_header("ayaz.bud", &attacker, &forged, &headers);
        assert!(
            refused.is_err(),
            "a proof folding to the nodes own root must not verify against the headers root"
        );

        // The forgery's branch is internally consistent: this is precisely
        // the root a malicious node would offer with its answer. The crate has
        // no entry point that takes a root as an argument, so the only way to
        // check a proof is against a trusted header.
        let forged_leaf = compute_bns_leaf_digest(
            &forged.name,
            &forged.owner,
            forged.expires_at,
            forged.content_id.as_ref(),
            forged.storage_root.as_ref(),
            &forged.extras_digest,
        );
        assert_eq!(
            compute_bns_registry_root(
                &forged.meta_digest,
                &fold_bns_merkle_branch(forged_leaf, &forged.siblings, &forged.directions).unwrap(),
            ),
            forged_root,
            "the attacker can produce a self-consistent but untrusted root"
        );

        // And the genuine proof still passes against the real root.
        assert_eq!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &real_vault, &genuine, &headers)
                .unwrap(),
            real_vault
        );
    }

    #[test]
    fn a_proof_for_a_height_the_wallet_has_no_header_for_is_refused() {
        let (proof, root, vault) = header_anchored_fixture();
        let behind = OneHeader {
            height: 6,
            root,
            epoch: 10,
        };
        let err = verify_bns_recipient_proof_from_header("ayaz.bud", &vault, &proof, &behind)
            .unwrap_err();
        assert!(
            err.contains("no verified header at height 7"),
            "the refusal names the missing height, got: {err}"
        );
    }

    fn sample_extras_preimage(address: Option<[u8; 32]>) -> (Vec<u8>, [u8; 32]) {
        let mut buf = Vec::new();
        buf.push(0u8); // resolver = None
        match address {
            Some(addr) => {
                buf.push(1u8);
                buf.extend_from_slice(&addr);
            }
            None => buf.push(0u8),
        }
        buf.push(0u8); // consensus_domain_id = None
        buf.push(0u8); // storage_domain_id = None
        buf.push(0u8); // storage_root_height = None
        buf.push(0u8); // bud3_content = None
        buf.extend_from_slice(&0u64.to_le_bytes()); // subdomains = 0
        buf.extend_from_slice(&0u64.to_le_bytes()); // records = 0

        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_EXTRAS_V1");
        hasher.update(&buf);
        (buf, hasher.finalize().into())
    }

    #[test]
    fn recipient_parser_classifies_direct_hex_and_bud_names_and_rejects_bad_inputs() {
        let addr_hex = format!("0x{}", "22".repeat(32));
        assert_eq!(
            parse_recipient_input(&addr_hex).unwrap(),
            RecipientTarget::Direct([0x22; 32])
        );
        assert_eq!(
            parse_recipient_input("ayaz.bud").unwrap(),
            RecipientTarget::BudName("ayaz.bud".to_string())
        );
        assert_eq!(
            parse_recipient_input("pay.ayaz.bud").unwrap(),
            RecipientTarget::BudName("pay.ayaz.bud".to_string())
        );

        for bad in [
            "",
            &format!("0x{}", "00".repeat(32)),
            "ab.bud",
            "Ayaz.bud",
            "-ayaz.bud",
            "a.b.ayaz.bud",
            "ayaz.eth",
        ] {
            assert!(
                parse_recipient_input(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn merkle_recipient_proof_authenticates_custom_forwarding_target_and_refuses_forgery_or_expiry()
    {
        let owner = [0x11; 32];
        let vault = [0x99; 32];
        let attacker = [0xEE; 32];
        let meta = [0x33; 32];
        let sib = [0x44; 32];

        let (preimage, extras_digest) = sample_extras_preimage(Some(vault));
        let leaf = compute_bns_leaf_digest("ayaz.bud", &owner, 50, None, None, &extras_digest);
        let names_root = fold_bns_merkle_branch(leaf, &[sib], &[true]).unwrap();
        let expected_root = compute_bns_registry_root(&meta, &names_root);

        let proof = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner,
            expires_at: 50,
            content_id: None,
            storage_root: None,
            extras_digest,
            extras_preimage: Some(preimage),
            meta_digest: meta,
            siblings: vec![sib],
            directions: vec![true],
            header_height: 7,
        };

        let headers = OneHeader {
            height: 7,
            root: expected_root,
            epoch: 10,
        };
        // The authenticated forwarding target verifies against the header.
        assert_eq!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &vault, &proof, &headers).unwrap(),
            vault
        );
        // Neither an attacker address nor the owner can replace a proven target.
        assert!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &attacker, &proof, &headers)
                .is_err()
        );
        assert!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &owner, &proof, &headers).is_err()
        );
        // A proven record whose expiration has passed is also refused.
        let expired_headers = OneHeader {
            epoch: 50,
            ..headers
        };
        assert!(verify_bns_recipient_proof_from_header(
            "ayaz.bud",
            &vault,
            &proof,
            &expired_headers
        )
        .is_err());
    }
}
