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

/// Maximum `extras_preimage` byte size accepted when opening `BDLM_BNS_EXTRAS_V3`.
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
    /// The 32 bytes the leaf commits to for the content of the name: the
    /// binding digest over the name, the owner and the content reference.
    /// The node sends it as `content_binding`.
    pub content_binding: Option<[u8; 32]>,
    pub storage_root: Option<[u8; 32]>,
    pub extras_digest: [u8; 32],
    /// Optional raw body committed after `b"BDLM_BNS_EXTRAS_V3"`. When supplied,
    /// `verify_bns_recipient_proof_from_header` verifies the digest against a
    /// trusted header root and extracts the authenticated `record.address`;
    /// when absent, the proof can authenticate `owner` directly.
    pub extras_preimage: Option<Vec<u8>>,
    pub meta_digest: [u8; 32],
    /// Sibling digests from the name's leaf node up to the names root.
    pub siblings: Vec<[u8; 32]>,
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
    content_binding: Option<&[u8; 32]>,
    storage_root: Option<&[u8; 32]>,
    extras_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_LEAF_V1");
    hasher.update((name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update(owner);
    hasher.update(expires_at.to_le_bytes());
    match content_binding {
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

/// The deepest a path in the name tree can go: one level per key bit.
const BNS_TREE_DEPTH: usize = 256;

/// The path of `name` in the sparse name tree: `SHA-256("BDLM_BNS_KEY_V1" || name)`.
#[must_use]
pub fn bns_tree_key(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_KEY_V1");
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// The leaf node that binds a record digest to a key (`BDLM_BNS_SMT_LEAF_V1`).
fn bns_tree_leaf(slot: &[u8; 32], record_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_SMT_LEAF_V1");
    hasher.update(slot);
    hasher.update(record_digest);
    hasher.finalize().into()
}

/// Bit `depth` of `key`, most significant first. Set means the right child.
fn bns_key_bit(key: &[u8; 32], depth: usize) -> bool {
    key.get(depth / 8)
        .is_some_and(|byte| (byte >> (7 - (depth % 8))) & 1 == 1)
}

fn bns_keys_share_prefix(a: &[u8; 32], b: &[u8; 32], depth: usize) -> bool {
    (0..depth.min(BNS_TREE_DEPTH)).all(|d| bns_key_bit(a, d) == bns_key_bit(b, d))
}

/// Fold a path of `key` from its terminal node up to the names root
/// (`BDLM_BNS_SMT_NODE_V1`). The side at each level is the key bit of that
/// level, so a path cannot be replayed for another name.
fn fold_bns_tree_path(
    key: &[u8; 32],
    terminal: [u8; 32],
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if siblings.len() > BNS_TREE_DEPTH {
        return None;
    }
    let mut acc = terminal;
    let mut depth = siblings.len();
    for sib in siblings {
        depth = depth.checked_sub(1)?;
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_SMT_NODE_V1");
        if bns_key_bit(key, depth) {
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

/// Fold the inclusion path of `name` from its record digest `leaf` up to
/// `names_merkle_root`.
#[must_use]
pub fn fold_bns_merkle_branch(
    name: &str,
    leaf: [u8; 32],
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let key = bns_tree_key(name);
    fold_bns_tree_path(&key, bns_tree_leaf(&key, &leaf), siblings)
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
) -> Result<Option<[u8; 32]>, String> {
    if preimage.len() > MAX_EXTRAS_PREIMAGE_BYTES {
        return Err("extras_preimage exceeds maximum size".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_EXTRAS_V3");
    hasher.update(preimage);
    let actual: [u8; 32] = hasher.finalize().into();
    if &actual != expected_extras_digest {
        return Err("extras_preimage does not match leaf extras_digest".into());
    }
    // Layout prefix of BDLM_BNS_EXTRAS_V3:
    //   address:  0u8 | (1u8 || [u8; 32])
    match preimage.first().copied() {
        None => Err("truncated extras_preimage before address tag".into()),
        // An empty address record: the name points at its owner.
        Some(0) => Ok(None),
        Some(1) => {
            let start = 1usize;
            let end = start + 32;
            let slice = preimage
                .get(start..end)
                .ok_or_else(|| "truncated target address in extras_preimage".to_string())?;
            let mut target = [0u8; 32];
            target.copy_from_slice(slice);
            if target == [0u8; 32] {
                return Err("proven BNS target address is the zero address".into());
            }
            Ok(Some(target))
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
/// * If `proof.extras_preimage` is `Some(bytes)`, verifies `BDLM_BNS_EXTRAS_V3`
///   and extracts the authenticated `record.address` forwarding target. A
///   cleared address record points at the owner; a zero address is refused.
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
        proof.content_binding.as_ref(),
        proof.storage_root.as_ref(),
        &proof.extras_digest,
    );
    let names_root = fold_bns_merkle_branch(&proof.name, leaf, &proof.siblings)
        .ok_or_else(|| "malformed BNS Merkle branch".to_string())?;
    let computed_root = compute_bns_registry_root(&proof.meta_digest, &names_root);
    if &computed_root != expected_bns_root {
        return Err("BNS Merkle proof did not reproduce expected header bns_root".into());
    }

    match &proof.extras_preimage {
        Some(preimage) => {
            let proven_target = parse_address_from_extras_preimage(preimage, &proof.extras_digest)?
                .unwrap_or(proof.owner);
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

/// A header the wallet has verified, reduced to what a `.bud` proof needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedBnsHeader {
    pub height: u64,
    /// The `.bud` registry root that header commits to.
    pub bns_root: [u8; 32],
    /// The epoch that header belongs to.
    pub epoch: u64,
}

/// The headers a host application has verified and hands to the wallet.
///
/// The host fills it from its own light client. The wallet reads the root
/// and the epoch of a proof from here and from nowhere else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BnsHeaderBook {
    headers: std::collections::BTreeMap<u64, ([u8; 32], u64)>,
}

impl BnsHeaderBook {
    /// An empty book. Every proof is refused until a header is added.
    /// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a header the host has verified.
    /// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
    pub fn trust(&mut self, header: TrustedBnsHeader) {
        self.headers
            .insert(header.height, (header.bns_root, header.epoch));
    }
}

impl HeaderSource for BnsHeaderBook {
    fn bns_root_at(&self, height: u64) -> Option<([u8; 32], u64)> {
        self.headers.get(&height).copied()
    }

    fn latest_height(&self) -> u64 {
        self.headers.keys().next_back().copied().unwrap_or(0)
    }
}

/// What a verified proof says about a held name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBnsRecord {
    pub owner: [u8; 32],
    /// Where the name points: its address record, or the owner when the
    /// record is empty.
    pub address: [u8; 32],
    pub expires_at: u64,
    /// Each subdomain label and where it points, with the same fallback to
    /// the subdomain's owner.
    pub subdomains: std::collections::BTreeMap<String, [u8; 32]>,
    pub records: std::collections::BTreeMap<String, String>,
}

/// The outcome of [`verify_bns_proof`]: the name is held, with its record,
/// or the name is proved absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBnsName {
    pub name: String,
    /// The header height the proof was checked against.
    pub height: u64,
    /// `None` when the registry holds no such name at that header.
    pub record: Option<VerifiedBnsRecord>,
}

impl VerifiedBnsName {
    /// The JSON form the bindings return.
    /// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
    #[must_use]
    pub fn to_json(&self) -> String {
        let hex32 = |bytes: &[u8; 32]| format!("0x{}", hex::encode(bytes));
        let value = match &self.record {
            None => serde_json::json!({ "held": false, "height": self.height }),
            Some(record) => serde_json::json!({
                "held": true,
                "owner": hex32(&record.owner),
                "address": hex32(&record.address),
                "expires_at": record.expires_at,
                "subdomains": record
                    .subdomains
                    .iter()
                    .map(|(label, address)| (label.clone(), hex32(address)))
                    .collect::<std::collections::BTreeMap<_, _>>(),
                "records": record.records,
                "height": self.height,
            }),
        };
        value.to_string()
    }
}

fn json_hex32(value: Option<&serde_json::Value>, field: &str) -> Result<[u8; 32], String> {
    let text = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof field {field} is missing"))?;
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|_| format!("proof field {field} is not hex"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("proof field {field} is not 32 bytes"))
}

fn json_optional_hex32(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Option<[u8; 32]>, String> {
    match value {
        Some(v) if !v.is_null() => json_hex32(Some(v), field).map(Some),
        _ => Ok(None),
    }
}

fn json_optional_u64(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    match value {
        Some(v) if !v.is_null() => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("proof field {field} is not a number")),
        _ => Ok(None),
    }
}

fn json_siblings(value: Option<&serde_json::Value>, field: &str) -> Result<Vec<[u8; 32]>, String> {
    let list = value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("proof field {field} is missing"))?;
    if list.len() > BNS_TREE_DEPTH {
        return Err(format!("proof field {field} is deeper than the tree"));
    }
    list.iter().map(|s| json_hex32(Some(s), field)).collect()
}

fn push_optional(buf: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            buf.push(1);
            buf.extend_from_slice(bytes);
        }
        None => buf.push(0),
    }
}

/// Re-encode the disclosed extras exactly as the registry hashes them under
/// `BDLM_BNS_EXTRAS_V3`, and read the fields a wallet shows on the way.
fn extras_from_json(
    extras: &serde_json::Value,
    owner: [u8; 32],
) -> Result<(Vec<u8>, VerifiedBnsRecord), String> {
    let mut buf = Vec::new();
    let address = json_optional_hex32(extras.get("address"), "extras.address")?;
    push_optional(&mut buf, address.as_ref().map(<[u8; 32]>::as_slice));
    for field in ["consensus_domain_id", "storage_domain_id"] {
        let id = json_optional_u64(extras.get(field), field)?
            .map(|id| u32::try_from(id).map_err(|_| format!("proof field {field} exceeds u32")))
            .transpose()?;
        push_optional(
            &mut buf,
            id.map(u32::to_le_bytes).as_ref().map(<[u8; 4]>::as_slice),
        );
    }
    let height = json_optional_u64(extras.get("storage_root_height"), "storage_root_height")?;
    push_optional(
        &mut buf,
        height
            .map(u64::to_le_bytes)
            .as_ref()
            .map(<[u8; 8]>::as_slice),
    );

    let subdomain_rows: std::collections::BTreeMap<String, &serde_json::Value> = extras
        .get("subdomains")
        .and_then(serde_json::Value::as_object)
        .ok_or("proof field extras.subdomains is missing")?
        .iter()
        .map(|(label, row)| (label.clone(), row))
        .collect();
    let mut subdomains = std::collections::BTreeMap::new();
    buf.extend_from_slice(&(subdomain_rows.len() as u64).to_le_bytes());
    for (label, row) in subdomain_rows {
        let sub_owner = json_hex32(row.get("owner"), "subdomain.owner")?;
        let sub_address = json_optional_hex32(row.get("address"), "subdomain.address")?;
        buf.extend_from_slice(&(label.len() as u64).to_le_bytes());
        buf.extend_from_slice(label.as_bytes());
        buf.extend_from_slice(&sub_owner);
        push_optional(&mut buf, sub_address.as_ref().map(<[u8; 32]>::as_slice));
        match row.get("content") {
            Some(content) if !content.is_null() => {
                buf.push(1);
                let kind = match content.get("kind").and_then(serde_json::Value::as_str) {
                    Some("public") => 0u8,
                    Some("sealed") => 1u8,
                    _ => return Err("proof field subdomain.content.kind is unknown".into()),
                };
                buf.push(kind);
                buf.extend_from_slice(&json_hex32(content.get("digest"), "content.digest")?);
                let len = content
                    .get("len")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("proof field subdomain.content.len is missing")?;
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(&json_hex32(
                    content.get("object_commitment"),
                    "content.object_commitment",
                )?);
                let nft = json_optional_hex32(content.get("nft_id"), "content.nft_id")?;
                push_optional(&mut buf, nft.as_ref().map(<[u8; 32]>::as_slice));
            }
            _ => buf.push(0),
        }
        subdomains.insert(label, sub_address.unwrap_or(sub_owner));
    }

    let mut records = std::collections::BTreeMap::new();
    for (key, value) in extras
        .get("records")
        .and_then(serde_json::Value::as_object)
        .ok_or("proof field extras.records is missing")?
    {
        let value = value
            .as_str()
            .ok_or("proof field extras.records holds a non-string")?;
        records.insert(key.clone(), value.to_string());
    }
    buf.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for (key, value) in &records {
        buf.extend_from_slice(&(key.len() as u64).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    if buf.len() > MAX_EXTRAS_PREIMAGE_BYTES {
        return Err("proof extras exceed the maximum size".into());
    }
    Ok((
        buf,
        VerifiedBnsRecord {
            owner,
            address: address.unwrap_or(owner),
            expires_at: 0,
            subdomains,
            records,
        },
    ))
}

/// Verify a `bud_bnsProof` answer for `name` against a header the wallet
/// trusts, and return what it proves: the record of a held name, or that the
/// name is not in the registry.
///
/// The root and the epoch are read from `headers` at the height the answer
/// names. Every field of the returned record is recomputed into the leaf
/// that folds to that root, so a node cannot change one byte of it. An
/// absence is a path of the queried name that ends in an empty slot or in
/// another name's leaf; a held name has no such path.
///
/// # Errors
///
/// A malformed answer, a name other than the one asked for, a header the
/// wallet does not hold or one too far below its tip, an expired record, and
/// any proof that does not fold to the header's root.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
pub fn verify_bns_proof<S: HeaderSource + ?Sized>(
    name: &str,
    proof_json: &str,
    headers: &S,
) -> Result<VerifiedBnsName, String> {
    if !is_valid_bud_name(name) {
        return Err(format!("invalid .bud name '{name}'"));
    }
    let answer: serde_json::Value =
        serde_json::from_str(proof_json).map_err(|e| format!("proof is not JSON: {e}"))?;
    let proof = match answer.get("result") {
        Some(result) if result.is_object() => result,
        _ => &answer,
    };
    if proof.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return Err("proof is for a different name".into());
    }
    let height = proof
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .ok_or("proof names no header height")?;
    let tip = headers.latest_height();
    if height.saturating_add(MAX_PROOF_LAG_BLOCKS) < tip {
        return Err(StaleProofHeader {
            anchored_at: height,
            tip,
        }
        .to_string());
    }
    let (root, epoch) = headers
        .bns_root_at(height)
        .ok_or_else(|| HeaderUnknown(height).to_string())?;
    let meta_digest = json_hex32(proof.get("meta_digest"), "meta_digest")?;
    let included = proof
        .get("included")
        .and_then(serde_json::Value::as_bool)
        .ok_or("proof field included is missing")?;
    let key = bns_tree_key(name);
    let entry = proof.get("entry").filter(|v| !v.is_null());
    let absence = proof.get("absence").filter(|v| !v.is_null());

    if !included {
        if entry.is_some() {
            return Err("an absence proof must not carry a record".into());
        }
        let absence = absence.ok_or("an absence proof must carry its path")?;
        let siblings = json_siblings(absence.get("siblings"), "absence.siblings")?;
        let terminal = match absence.get("occupant") {
            Some(slot) if !slot.is_null() => {
                let other = json_hex32(slot.get("key"), "absence.occupant.key")?;
                let value = json_hex32(slot.get("value"), "absence.occupant.value")?;
                if other == key {
                    return Err("the occupied slot holds the queried name itself".into());
                }
                if !bns_keys_share_prefix(&key, &other, siblings.len()) {
                    return Err("the occupied slot does not lie on the queried path".into());
                }
                bns_tree_leaf(&other, &value)
            }
            _ => [0u8; 32],
        };
        let names_root =
            fold_bns_tree_path(&key, terminal, &siblings).ok_or("malformed absence path")?;
        if compute_bns_registry_root(&meta_digest, &names_root) != root {
            return Err("absence path did not reproduce the header bns_root".into());
        }
        return Ok(VerifiedBnsName {
            name: name.to_string(),
            height,
            record: None,
        });
    }

    if absence.is_some() {
        return Err("an inclusion proof must not carry an absence path".into());
    }
    let entry = entry.ok_or("an inclusion proof must carry its record")?;
    if entry.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return Err("proof record is for a different name".into());
    }
    let owner = json_hex32(entry.get("owner"), "entry.owner")?;
    if owner == [0u8; 32] {
        return Err("BNS owner cannot be the zero address".into());
    }
    let expires_at = entry
        .get("expires_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or("proof field entry.expires_at is missing")?;
    let content_binding =
        json_optional_hex32(entry.get("content_binding"), "entry.content_binding")?;
    let storage_root = json_optional_hex32(entry.get("storage_root"), "entry.storage_root")?;
    let extras_digest = json_hex32(entry.get("extras_digest"), "entry.extras_digest")?;
    let extras = entry
        .get("extras")
        .filter(|v| !v.is_null())
        .ok_or("the proof does not disclose the record extras")?;
    let (preimage, mut record) = extras_from_json(extras, owner)?;
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_EXTRAS_V3");
    hasher.update(&preimage);
    let recomputed: [u8; 32] = hasher.finalize().into();
    if recomputed != extras_digest {
        return Err("disclosed extras do not match the extras digest".into());
    }
    let leaf = compute_bns_leaf_digest(
        name,
        &owner,
        expires_at,
        content_binding.as_ref(),
        storage_root.as_ref(),
        &extras_digest,
    );
    let siblings = json_siblings(entry.get("siblings"), "entry.siblings")?;
    let names_root =
        fold_bns_merkle_branch(name, leaf, &siblings).ok_or("malformed BNS tree path")?;
    if compute_bns_registry_root(&meta_digest, &names_root) != root {
        return Err("BNS proof did not reproduce the header bns_root".into());
    }
    if expires_at <= epoch {
        return Err("proven .bud name has expired at the verified header epoch".into());
    }
    if record.address == [0u8; 32] {
        return Err("proven BNS target address is the zero address".into());
    }
    record.expires_at = expires_at;
    Ok(VerifiedBnsName {
        name: name.to_string(),
        height,
        record: Some(record),
    })
}

/// Resolve `name` from the answers of the nodes the wallet is configured
/// with.
///
/// The host sends the `bud_bnsGetProof` body to each of its nodes and hands
/// every answer in. Each answer is checked with [`verify_bns_proof`] against
/// the headers the wallet trusts, so a node that lies is refused and cannot
/// change the result. Among the answers that verify, the one anchored at the
/// highest header is returned.
///
/// # Errors
///
/// No answers, or no answer that verifies. The error names the refusal of
/// each node.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
pub fn resolve_bns<S: HeaderSource + ?Sized>(
    name: &str,
    answers: &[String],
    headers: &S,
) -> Result<VerifiedBnsName, String> {
    if answers.is_empty() {
        return Err("no node answered".into());
    }
    let mut best: Option<VerifiedBnsName> = None;
    let mut refusals = Vec::new();
    for (node, answer) in answers.iter().enumerate() {
        match verify_bns_proof(name, answer, headers) {
            Ok(verified) => {
                if best
                    .as_ref()
                    .is_none_or(|held| verified.height > held.height)
                {
                    best = Some(verified);
                }
            }
            Err(reason) => refusals.push(format!("node {node}: {reason}")),
        }
    }
    best.ok_or_else(|| {
        format!(
            "no node gave a proof that verifies: {}",
            refusals.join("; ")
        )
    })
}

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
        let names_root = fold_bns_merkle_branch("ayaz.bud", leaf, &[sib]).unwrap();
        let root = compute_bns_registry_root(&meta, &names_root);
        let proof = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner,
            expires_at: 50,
            content_binding: None,
            storage_root: None,
            extras_digest,
            extras_preimage: Some(preimage),
            meta_digest: meta,
            siblings: vec![sib],
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
        let forged_names = fold_bns_merkle_branch("ayaz.bud", forged_leaf, &[sib]).unwrap();
        let forged_root = compute_bns_registry_root(&meta, &forged_names);
        let forged = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner: genuine.owner,
            expires_at: 50,
            content_binding: None,
            storage_root: None,
            extras_digest: forged_extras,
            extras_preimage: Some(forged_preimage),
            meta_digest: meta,
            siblings: vec![sib],
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
            forged.content_binding.as_ref(),
            forged.storage_root.as_ref(),
            &forged.extras_digest,
        );
        assert_eq!(
            compute_bns_registry_root(
                &forged.meta_digest,
                &fold_bns_merkle_branch(&forged.name, forged_leaf, &forged.siblings).unwrap(),
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
        buf.extend_from_slice(&0u64.to_le_bytes()); // subdomains = 0
        buf.extend_from_slice(&0u64.to_le_bytes()); // records = 0

        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_EXTRAS_V3");
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
        let names_root = fold_bns_merkle_branch("ayaz.bud", leaf, &[sib]).unwrap();
        let expected_root = compute_bns_registry_root(&meta, &names_root);

        let proof = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner,
            expires_at: 50,
            content_binding: None,
            storage_root: None,
            extras_digest,
            extras_preimage: Some(preimage),
            meta_digest: meta,
            siblings: vec![sib],
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

    /// A cleared address record points at the owner, and only at the owner.
    #[test]
    fn an_empty_address_record_resolves_to_the_owner() {
        let owner = [0x11; 32];
        let meta = [0x33; 32];
        let sib = [0x44; 32];
        let (preimage, extras_digest) = sample_extras_preimage(None);
        let leaf = compute_bns_leaf_digest("ayaz.bud", &owner, 50, None, None, &extras_digest);
        let names_root = fold_bns_merkle_branch("ayaz.bud", leaf, &[sib]).unwrap();
        let headers = OneHeader {
            height: 7,
            root: compute_bns_registry_root(&meta, &names_root),
            epoch: 10,
        };
        let proof = WalletBnsProof {
            name: "ayaz.bud".to_string(),
            owner,
            expires_at: 50,
            content_binding: None,
            storage_root: None,
            extras_digest,
            extras_preimage: Some(preimage),
            meta_digest: meta,
            siblings: vec![sib],
            header_height: 7,
        };
        assert_eq!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &owner, &proof, &headers).unwrap(),
            owner
        );
        assert!(
            verify_bns_recipient_proof_from_header("ayaz.bud", &[0xEE; 32], &proof, &headers)
                .is_err()
        );
    }

    /// The numbers the node pins in `bns_proof_vectors_are_the_ones_light_clients_pin`.
    #[test]
    fn the_tree_rules_match_the_node_vectors() {
        let key = bns_tree_key("ayaz.bud");
        assert_eq!(
            hex::encode(key),
            "9ca1f7a6ebb5956dea6ba6489119df3a518898a9dd46efc6c62e6b1102fec1e7"
        );
        let folded =
            fold_bns_merkle_branch("ayaz.bud", [0x55; 32], &[[0x44; 32], [0x66; 32]]).unwrap();
        assert_eq!(
            hex::encode(folded),
            "d706cddd816bc581463bdb4d6fc3b1fd3e43e9847636f3b7bc88cad8e95d6ed9"
        );
        assert!(fold_bns_merkle_branch("ayaz.bud", [0x55; 32], &vec![[0; 32]; 257]).is_none());
    }

    fn hx(bytes: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    /// A `bud_bnsProof` answer for a held `ayaz.bud` with one subdomain and
    /// one record, and the header root it folds to.
    fn held_answer(address: Option<[u8; 32]>) -> (serde_json::Value, [u8; 32]) {
        let owner = [0x11u8; 32];
        let meta = [0x33u8; 32];
        let siblings = [[0x44u8; 32], [0x66u8; 32]];
        let extras = serde_json::json!({
            "address": address.as_ref().map(hx),
            "consensus_domain_id": 7,
            "storage_domain_id": null,
            "storage_root_height": 9,
            "subdomains": {
                "pay": {"owner": hx(&owner), "address": hx(&[0x77; 32]), "content": null},
                "site": {"owner": hx(&[0x78; 32]), "address": null, "content": {
                    "kind": "public",
                    "digest": hx(&[0x01; 32]),
                    "len": 1024,
                    "object_commitment": hx(&[0x02; 32]),
                    "nft_id": null,
                }},
            },
            "records": {"url": "https://budlum.xyz"},
        });
        let (preimage, _) = extras_from_json(&extras, owner).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_EXTRAS_V3");
        hasher.update(&preimage);
        let extras_digest: [u8; 32] = hasher.finalize().into();
        let leaf = compute_bns_leaf_digest("ayaz.bud", &owner, 50, None, None, &extras_digest);
        let names_root = fold_bns_merkle_branch("ayaz.bud", leaf, &siblings).unwrap();
        let root = compute_bns_registry_root(&meta, &names_root);
        let answer = serde_json::json!({
            "name": "ayaz.bud",
            "included": true,
            "meta_digest": hx(&meta),
            "height": 7,
            "entry": {
                "name": "ayaz.bud",
                "owner": hx(&owner),
                "expires_at": 50,
                "content_binding": null,
                "storage_root": null,
                "extras_digest": hx(&extras_digest),
                "siblings": siblings.iter().map(hx).collect::<Vec<_>>(),
                "extras": extras,
            },
            "absence": null,
        });
        (answer, root)
    }

    fn book(root: [u8; 32]) -> BnsHeaderBook {
        let mut book = BnsHeaderBook::new();
        book.trust(TrustedBnsHeader {
            height: 7,
            bns_root: root,
            epoch: 10,
        });
        book
    }

    #[test]
    fn a_valid_proof_verifies_and_reads_the_record() {
        let (answer, root) = held_answer(Some([0x22; 32]));
        let verified = verify_bns_proof("ayaz.bud", &answer.to_string(), &book(root)).unwrap();
        let record = verified.record.clone().unwrap();
        assert_eq!(verified.height, 7);
        assert_eq!(record.owner, [0x11; 32]);
        assert_eq!(record.address, [0x22; 32]);
        assert_eq!(record.expires_at, 50);
        assert_eq!(record.subdomains["pay"], [0x77; 32]);
        assert_eq!(record.subdomains["site"], [0x78; 32]);
        assert_eq!(record.records["url"], "https://budlum.xyz");
        let json: serde_json::Value = serde_json::from_str(&verified.to_json()).unwrap();
        assert_eq!(json["held"], true);
        assert_eq!(json["address"], hx(&[0x22; 32]));

        // The same answer inside a JSON-RPC envelope.
        let wrapped = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": answer});
        assert_eq!(
            verify_bns_proof("ayaz.bud", &wrapped.to_string(), &book(root)).unwrap(),
            verified
        );

        // An empty address record points at the owner.
        let (answer, root) = held_answer(None);
        let verified = verify_bns_proof("ayaz.bud", &answer.to_string(), &book(root)).unwrap();
        assert_eq!(verified.record.unwrap().address, [0x11; 32]);
    }

    /// Flip one hex digit of every 32-byte value in the answer, one at a
    /// time, and change every number and string that feeds the leaf. Each
    /// changed answer is refused.
    #[test]
    fn a_proof_with_one_byte_changed_is_refused() {
        fn flip(text: &str) -> String {
            let mut out = text.to_string();
            let last = out.pop().unwrap();
            out.push(if last == '0' { '1' } else { '0' });
            out
        }
        fn mutate(value: &serde_json::Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        path.push(key.clone());
                        mutate(child, path, out);
                        path.pop();
                    }
                }
                serde_json::Value::Array(list) => {
                    for (i, child) in list.iter().enumerate() {
                        path.push(i.to_string());
                        mutate(child, path, out);
                        path.pop();
                    }
                }
                serde_json::Value::String(_) | serde_json::Value::Number(_) => {
                    out.push(path.clone());
                }
                _ => {}
            }
        }
        fn at<'a>(value: &'a mut serde_json::Value, path: &[String]) -> &'a mut serde_json::Value {
            path.iter().fold(value, |node, key| match node {
                serde_json::Value::Array(list) => &mut list[key.parse::<usize>().unwrap()],
                other => &mut other[key.as_str()],
            })
        }

        let (answer, root) = held_answer(Some([0x22; 32]));
        let headers = book(root);
        assert!(verify_bns_proof("ayaz.bud", &answer.to_string(), &headers).is_ok());
        let mut paths = Vec::new();
        mutate(&answer, &mut Vec::new(), &mut paths);
        assert!(paths.len() > 15);
        for path in paths {
            let mut bent = answer.clone();
            let node = at(&mut bent, &path);
            *node = match &*node {
                serde_json::Value::String(text) => serde_json::Value::String(flip(text)),
                serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 1),
                _ => unreachable!(),
            };
            assert!(
                verify_bns_proof("ayaz.bud", &bent.to_string(), &headers).is_err(),
                "a change at {path:?} was accepted"
            );
        }
        // And a header root with one bit changed refuses the honest answer.
        let mut other_root = root;
        other_root[31] ^= 1;
        assert!(verify_bns_proof("ayaz.bud", &answer.to_string(), &book(other_root)).is_err());
    }

    #[test]
    fn an_absence_proof_verifies_and_a_held_name_cannot_be_shown_absent() {
        let meta = [0x33u8; 32];
        let key = bns_tree_key("free.bud");
        let siblings = [[0x44u8; 32], [0x66u8; 32]];

        // The path of `free.bud` ends in an empty slot.
        let empty_root = compute_bns_registry_root(
            &meta,
            &fold_bns_tree_path(&key, [0; 32], &siblings).unwrap(),
        );
        let empty = serde_json::json!({
            "name": "free.bud", "included": false, "meta_digest": hx(&meta), "height": 7,
            "entry": null,
            "absence": {"siblings": siblings.iter().map(hx).collect::<Vec<_>>(), "occupant": null},
        });
        let verified = verify_bns_proof("free.bud", &empty.to_string(), &book(empty_root)).unwrap();
        assert!(verified.record.is_none());
        assert_eq!(verified.to_json(), r#"{"height":7,"held":false}"#);

        // The path ends in the leaf of another name that shares the prefix.
        let mut other = key;
        other[31] ^= 1;
        let value = [0x55u8; 32];
        let occupied_root = compute_bns_registry_root(
            &meta,
            &fold_bns_tree_path(&key, bns_tree_leaf(&other, &value), &siblings).unwrap(),
        );
        let occupied = serde_json::json!({
            "name": "free.bud", "included": false, "meta_digest": hx(&meta), "height": 7,
            "entry": null,
            "absence": {
                "siblings": siblings.iter().map(hx).collect::<Vec<_>>(),
                "occupant": {"key": hx(&other), "value": hx(&value)},
            },
        });
        assert!(
            verify_bns_proof("free.bud", &occupied.to_string(), &book(occupied_root))
                .unwrap()
                .record
                .is_none()
        );

        // One byte changed in either absence proof is refused.
        let mut bent = empty.clone();
        bent["absence"]["siblings"][0] = serde_json::json!(hx(&[0x45; 32]));
        assert!(verify_bns_proof("free.bud", &bent.to_string(), &book(empty_root)).is_err());
        let mut bent = occupied.clone();
        bent["absence"]["occupant"]["value"] = serde_json::json!(hx(&[0x56; 32]));
        assert!(verify_bns_proof("free.bud", &bent.to_string(), &book(occupied_root)).is_err());
        // A slot off the queried path proves nothing about the queried name.
        let mut far = key;
        far[0] ^= 0x80;
        let mut bent = occupied.clone();
        bent["absence"]["occupant"]["key"] = serde_json::json!(hx(&far));
        assert!(verify_bns_proof("free.bud", &bent.to_string(), &book(occupied_root)).is_err());

        // A held name: its own leaf cannot be relabelled as an absence.
        let (held, root) = held_answer(Some([0x22; 32]));
        let entry = &held["entry"];
        let owner = [0x11u8; 32];
        let extras_digest = json_hex32(entry.get("extras_digest"), "d").unwrap();
        let leaf = compute_bns_leaf_digest("ayaz.bud", &owner, 50, None, None, &extras_digest);
        for occupant in [
            serde_json::Value::Null,
            serde_json::json!({"key": hx(&bns_tree_key("ayaz.bud")), "value": hx(&leaf)}),
        ] {
            let forged = serde_json::json!({
                "name": "ayaz.bud", "included": false, "meta_digest": hx(&meta), "height": 7,
                "entry": null,
                "absence": {"siblings": entry["siblings"], "occupant": occupant},
            });
            assert!(verify_bns_proof("ayaz.bud", &forged.to_string(), &book(root)).is_err());
        }
    }

    #[test]
    fn a_proof_is_checked_against_a_header_the_wallet_holds() {
        let (answer, root) = held_answer(Some([0x22; 32]));
        let text = answer.to_string();
        // No header at all.
        let refused = verify_bns_proof("ayaz.bud", &text, &BnsHeaderBook::new()).unwrap_err();
        assert!(
            refused.contains("no verified header at height 7"),
            "{refused}"
        );
        // A header too far below the tip.
        let mut stale = book(root);
        stale.trust(TrustedBnsHeader {
            height: 7 + MAX_PROOF_LAG_BLOCKS + 1,
            bns_root: [0; 32],
            epoch: 10,
        });
        assert!(verify_bns_proof("ayaz.bud", &text, &stale).is_err());
        // The record expired at the header epoch.
        let mut late = BnsHeaderBook::new();
        late.trust(TrustedBnsHeader {
            height: 7,
            bns_root: root,
            epoch: 50,
        });
        assert!(verify_bns_proof("ayaz.bud", &text, &late).is_err());
        // Asked for one name, answered with another.
        assert!(verify_bns_proof("kaya.bud", &text, &book(root)).is_err());
        // An answer without a height cannot be anchored.
        let mut unanchored = answer;
        unanchored.as_object_mut().unwrap().remove("height");
        assert!(verify_bns_proof("ayaz.bud", &unanchored.to_string(), &book(root)).is_err());
    }

    #[test]
    fn resolve_bns_takes_the_freshest_answer_that_verifies_and_ignores_liars() {
        let meta = [0x33u8; 32];
        let root = compute_bns_registry_root(&meta, &[0u8; 32]);
        let proof_at = |height: u64| {
            format!(
                r#"{{"name":"free.bud","included":false,"meta_digest":"0x{}","height":{height},"entry":null,"absence":{{"siblings":[],"occupant":null}}}}"#,
                hex::encode(meta)
            )
        };
        let mut book = BnsHeaderBook::new();
        for height in [7, 9] {
            book.trust(TrustedBnsHeader {
                height,
                bns_root: root,
                epoch: 10,
            });
        }
        let liar = proof_at(9).replace("0x33", "0x34");

        assert!(resolve_bns("free.bud", &[], &book).is_err());
        let refused = resolve_bns("free.bud", &[liar.clone(), "not json".into()], &book)
            .expect_err("no honest node answered");
        assert!(
            refused.contains("node 0") && refused.contains("node 1"),
            "{refused}"
        );

        let resolved = resolve_bns("free.bud", &[liar, proof_at(7), proof_at(9)], &book)
            .expect("two honest nodes answered");
        assert_eq!(resolved.height, 9);
        assert!(resolved.record.is_none());
        // The answer of a node is never taken for another name.
        assert!(resolve_bns("other.bud", &[proof_at(9)], &book).is_err());
    }
}
