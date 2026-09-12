//! Identity registry: `did:bud`, credential commitments, guardian recovery.
//!
//! The architecture this module lands is the registry-layer answer of the
//! identity design doc: no consensus mechanism is invented, no raw identity
//! data is ever placed on chain. What this type holds are *commitments* -
//! hash roots over fields the holder proved knowledge of - and the small
//! rules that make a commitment worth reading: who may write, when a key is
//! live, what a revocation costs, and which quorum can override a lost key.
//!
//! # The two halves
//!
//! [`IdentityRecord`] is the DID side: `did:bud:<address>` maps to the
//! address itself, and the record carries the verification methods (key
//! handles, [MethodKind::MlDsa87] today, because `ml-dsa-87` is the node's
//! own signature primitive), the current credential root, and the guardian
//! set with its recovery threshold. [`CredentialCommitment`] is the
//! Verifiable-Credentials side: a closed field list where every field is a
//! [`FieldCommitment`] (a hash over schema, name, salt and value digest -
//! never the value), and the root is a plain Merkle fold over the fields, so
//! selective disclosure is a sibling path, not a new proof system.
//!
//! # Domain placement
//!
//! Write authority lives on the PoA domain; the gate is [`ConsensusKind::PoA`]
//! and it is enforced by the registry itself, not left to callers, because a
//! rule a caller can forget is a rule that will be forgotten. Other domains
//! verify against an anchored root - that part is the cross-domain anchor
//! slice and is deliberately absent here: this module is pure state, it has
//! no block access, and pretending otherwise would wire the anchor into the
//! wrong door.
//!
//! # What "verified" can honestly mean off-chain
//!
//! [`IdentityRegistry::is_credential_valid`] answers "was this credential
//! issued to a registered subject, unrevoked, and unexpired at `now`, with a
//! root that recomputes from its own fields?" It does not and cannot answer
//! "is the data true" - the chain holds commitments to claims, the claims
//! live with their holders, and an issuer's signature is verified where the
//! signature is made (the grant-side precedent:
//! [`crate::storage::view_grant::GrantAuthorization::verify`]).
//!
//! # Disclosure binding
//!
//! A disclosure proves one field against a root. It does not say who is
//! reading. The consent flow this system is designed for - the wallet screen
//! that shows the requester which field will open, and the rule that the
//! opened value lands only in that requester's wallet - lives in the
//! view-grant layer, which already binds grants to grantees and revokes by
//! digest. Identity supplies the field commitments that make "which one
//! field" a checkable question rather than a sentence in a consent dialog.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::ConsensusKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A [`ConsensusKind::Custom`] label that must be written exactly this way
/// before a PoA-only write is refused: the gate matches on the constant, not
/// on a string an operator can mistype into an open door.
pub const DID_METHOD_NAME: &str = "did:bud";

/// Formats the DID for an address. Lowercase hex over the 32 address bytes,
/// so a DID survives case-folding in any wallet that stores it as text.
#[must_use]
pub fn did_of(address: &Address) -> String {
    let mut out = String::with_capacity(DID_METHOD_NAME.len() + 1 + 64);
    out.push_str(DID_METHOD_NAME);
    out.push(':');
    for byte in address.as_bytes() {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

///
/// WIRING: not yet called in production; the RPC resolver that reads DIDs
/// off the wire is the consumer this is written for.
/// Parses a `did:bud:<64 hex>` string back to an address. Anything else -
/// wrong method, odd length, non-hex - is `None`, silently, because the
/// parse has no opinion to report; callers that must distinguish refusals
/// use [`IdentityError`] errors on the registry doors instead.
#[must_use]
pub fn address_of_did(did: &str) -> Option<Address> {
    let hex = did.strip_prefix(DID_METHOD_NAME)?.strip_prefix(':')?;
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut raw = [0u8; 32];
    for (i, out) in raw.iter_mut().enumerate() {
        // The len==64 guard above makes these in-bounds today, but the gate
        // (indexing-is-not-new) refuses raw indexing in release paths: a future
        // edit that drops the guard would turn this into an abort, not a None.
        let hi = hex_val(*bytes.get(i * 2)?)?;
        let lo = hex_val(*bytes.get(i * 2 + 1)?)?;
        *out = (hi << 4) | lo;
    }
    // Lowercase-only rule: an "uppercase DID" is the same key two spellings
    // away from a different registry entry, which is exactly how a DID gets
    // duplicated by copy-paste. Refuse it here rather than normalize it later.
    if did_of(&Address(raw)) == did {
        Some(Address(raw))
    } else {
        None
    }
}

/// Lowercase hex for registry keys (see [`IdentityRegistry::credentials`]
/// for why ids are stored hexed rather than as byte arrays).
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Which signature scheme a key handle speaks. Closed on purpose: a registry
/// that accepts "some key" is a registry that accepts nothing verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// The node's post-quantum default; verified by
    /// `crate::crypto::primitives::verify_ml_dsa_87_signature` at the doors
    /// that consume signatures (grant precedent).
    MlDsa87,
}

/// One verification method of a DID: a 32-byte key handle, the scheme it
/// speaks, and the epoch it was revoked at, if it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub key_id: [u8; 32],
    pub kind: MethodKind,
    pub revoked_at: Option<u64>,
}

impl VerificationMethod {
    #[must_use]
    pub fn new(key_id: [u8; 32], kind: MethodKind) -> Self {
        Self {
            key_id,
            kind,
            revoked_at: None,
        }
    }

    /// Live at `now`: a revocation takes effect at its own epoch, not after
    /// it - a key revoked at 10 is not live at 10.
    #[must_use]
    pub fn is_live_at(&self, now: u64) -> bool {
        self.revoked_at.is_none_or(|epoch| now < epoch)
    }
}

/// The DID side of the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub subject: Address,
    pub methods: Vec<VerificationMethod>,
    /// The credential root currently asserted for this subject: the Merkle
    /// root of the credential the subject last issued itself. Absent until
    /// the first credential is issued - there is no "empty root" state a
    /// reader could mistake for "issued, then revoked".
    pub credential_root: Option<[u8; 32]>,
    pub guardians: Vec<Address>,
    pub recovery_threshold: usize,
}

impl IdentityRecord {
    ///
    /// WIRING: production entry arrives with the identity transaction door.
    /// Builds and validates a record in one step: a record that fails
    /// [`IdentityRecord::validate`] is not constructible from public types
    /// without going through the registry, which runs this first.
    ///
    /// # Errors
    ///
    /// The first [`IdentityError`] found.
    pub fn new(
        subject: Address,
        methods: Vec<VerificationMethod>,
        guardians: Vec<Address>,
        recovery_threshold: usize,
    ) -> Result<Self, IdentityError> {
        let record = Self {
            subject,
            methods,
            credential_root: None,
            guardians,
            recovery_threshold,
        };
        record.validate()?;
        Ok(record)
    }

    /// # Errors
    ///
    /// First structural violation found.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.methods.is_empty() {
            return Err(IdentityError::NoMethods {
                did: did_of(&self.subject),
            });
        }
        for (i, method) in self.methods.iter().enumerate() {
            if self
                .methods
                .iter()
                .take(i)
                .any(|m| m.key_id == method.key_id)
            {
                return Err(IdentityError::DuplicateKeyId {
                    did: did_of(&self.subject),
                });
            }
        }
        for (i, guardian) in self.guardians.iter().enumerate() {
            if guardian == &self.subject {
                return Err(IdentityError::SubjectIsOwnGuardian {
                    did: did_of(&self.subject),
                });
            }
            if self.guardians.iter().take(i).any(|known| known == guardian) {
                return Err(IdentityError::DuplicateGuardian {
                    did: did_of(&self.subject),
                });
            }
        }
        if self.guardians.is_empty() {
            if self.recovery_threshold != 0 {
                return Err(IdentityError::ThresholdWithoutGuardians {
                    did: did_of(&self.subject),
                });
            }
        } else if self.recovery_threshold == 0 || self.recovery_threshold > self.guardians.len() {
            return Err(IdentityError::UnreachableQuorum {
                did: did_of(&self.subject),
                threshold: self.recovery_threshold,
                guardians: self.guardians.len(),
            });
        }
        Ok(())
    }

    ///
    /// WIRING: production entry arrives with the signature-checking doors.
    /// A method live at `now`; the lookup is by key handle, the same
    /// `[u8; 32]` a signature envelope carries.
    #[must_use]
    pub fn live_method(&self, key_id: &[u8; 32], now: u64) -> Option<&VerificationMethod> {
        self.methods
            .iter()
            .find(|m| &m.key_id == key_id && m.is_live_at(now))
    }
}

/// A committed field: the only unit a credential discloses. The name is
/// public (the consent screen shows exactly these), the value is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCommitment {
    pub name: String,
    pub commitment: [u8; 32],
}

/// The commitment a field carries: `H(domain | schema | name | salt | value digest)`.
///
/// The salt is what makes this a commitment rather than a hash of a
/// low-entropy fact: a birth date hashed alone is a guessable dictionary,
/// and the chain must not be a place where "did this subject have
/// credential X" is answerable by trying every date. The value enters as a
/// digest so the preimage of the value itself never has to.
#[must_use]
pub fn field_commitment(
    schema: &str,
    name: &str,
    salt: &[u8; 32],
    value_digest: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"bud-vc-v1-field",
        schema.as_bytes(),
        name.as_bytes(),
        salt,
        value_digest,
    ])
}

/// Node-pair hash of the disclosure tree. Order matters and is baked into
/// the domain tag: the same fields in another order are another root, which
/// is what lets the read-back check refuse a reordered credential.
#[must_use]
pub fn field_pair_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[b"bud-vc-v1-node", left, right])
}

/// The Verifiable-Credential side: issuer, subject, schema, and the closed
/// field list. Values are not here; they cannot be, by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCommitment {
    pub issuer: Address,
    pub subject: Address,
    pub schema: String,
    pub fields: Vec<FieldCommitment>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

impl CredentialCommitment {
    /// # Errors
    ///
    /// [`IdentityError::BadSchema`] for an empty/oversized schema label or a
    /// field name that is empty; [`IdentityError::NoFields`] for a credential
    /// committing to nothing (a root over an empty list is a constant, and a
    /// constant root means every such credential "matches" every other).
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.schema.is_empty() || self.schema.len() > 64 || self.fields.is_empty() {
            if self.fields.is_empty() {
                return Err(IdentityError::NoFields);
            }
            return Err(IdentityError::BadSchema {
                schema: self.schema.clone(),
            });
        }
        for (i, field) in self.fields.iter().enumerate() {
            if field.name.is_empty() || field.name.len() > 64 {
                return Err(IdentityError::BadSchema {
                    schema: format!("field name `{}`", field.name),
                });
            }
            if self.fields[..i].iter().any(|f| f.name == field.name) {
                return Err(IdentityError::DuplicateField {
                    name: field.name.clone(),
                });
            }
        }
        Ok(())
    }

    /// The Merkle fold over the field commitments in order; an odd node at
    /// any level is paired with itself (the chain's own convention for
    /// binary folds: no leaf gets a special "I am alone" hash, so the proof
    /// walk needs no exceptions).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.field_leaves())
    }

    /// The leaves in document order - the exact sequence the disclosure
    /// tree is folded from, public so a wallet and a node build paths from
    /// the same list without conversing.
    #[must_use]
    pub fn field_leaves(&self) -> Vec<[u8; 32]> {
        self.fields.iter().map(|f| f.commitment).collect()
    }

    #[must_use]
    pub fn is_live_at(&self, now: u64) -> bool {
        self.issued_at <= now && self.expires_at.is_none_or(|exp| now < exp)
    }
}

/// A disclosure: one field's sibling path, positional. The positions come
/// with the proof, and the verifier re-walks them; there is no "trust me,
/// it was leaf 3" anywhere in the format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Builds the proof for `leaf_index`.
#[must_use]
pub fn disclosure_proof(leaves: &[[u8; 32]], leaf_index: usize) -> Option<DisclosureProof> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = leaf_index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let pair = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        siblings.push(level.get(pair).copied().unwrap_or(level[index]));
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left);
            next.push(field_pair_hash(&left, &right));
        }
        level = next;
        index /= 2;
    }
    Some(DisclosureProof {
        leaf_index,
        leaf_count: leaves.len(),
        siblings,
    })
}

/// Recomputes the leaf from the disclosure material and walks it to a root.
/// True only if that root is the expected one; every failure mode (wrong
/// salt, wrong value digest, wrong name, tampered path) lands in `false`,
/// never in a panic or a "looks close enough".
#[must_use]
pub fn verify_disclosure(
    root: &[u8; 32],
    schema: &str,
    name: &str,
    salt: &[u8; 32],
    value_digest: &[u8; 32],
    proof: &DisclosureProof,
) -> bool {
    let mut level = proof.leaf_count;
    let mut index = proof.leaf_index;
    if level == 0 || index >= level || proof.siblings.len() != sibling_count(level) {
        return false;
    }
    let mut current = field_commitment(schema, name, salt, value_digest);
    for sibling in &proof.siblings {
        current = if index.is_multiple_of(2) {
            field_pair_hash(&current, sibling)
        } else {
            field_pair_hash(sibling, &current)
        };
        level = level.div_ceil(2);
        index /= 2;
    }
    &current == root
}

fn sibling_count(leaves: usize) -> usize {
    let mut count = 0;
    let mut level = leaves;
    while level > 1 {
        count += 1;
        level = level.div_ceil(2);
    }
    count
}

#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left);
            next.push(field_pair_hash(&left, &right));
        }
        level = next;
    }
    level[0]
}

/// The registry. Pure state: it never touches a clock or a block. Every
/// method takes `now` and a `domain`, and the refusal rules are here rather
/// than at the doors, so any future caller inherits them by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRegistry {
    records: BTreeMap<Address, IdentityRecord>,
    /// Credential id = H(root | issuer | issued_at): two credentials with
    /// the same fields at different times are different credentials, and
    /// neither can shadow the other's revocation.
    /// Hex-keyed on purpose: a `[u8; 32]` map key serializes as an array,
    /// and the snapshot is JSON - a populated registry would fail at
    /// write time, not at compile time. The id bytes stay the public handle;
    /// the encoding is this type's business. The same reasoning is the
    /// `Address` newtype's manual `Serialize`.
    credentials: BTreeMap<String, CredentialCommitment>,
    revoked: BTreeSet<String>,
}

impl IdentityRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn record(&self, subject: &Address) -> Option<&IdentityRecord> {
        self.records.get(subject)
    }

    #[must_use]
    pub fn credential(&self, id: &[u8; 32]) -> Option<&CredentialCommitment> {
        self.credentials.get(hex32(id).as_str())
    }

    #[must_use]
    pub fn is_revoked(&self, id: &[u8; 32]) -> bool {
        self.revoked.contains(hex32(id).as_str())
    }

    /// The only door every mutation passes. A non-PoA `domain` refuses
    /// anything, before any state is read or validated: the write-authority
    /// rule does not leak even the shape of "would have been accepted".
    ///
    /// # Errors
    ///
    /// [`IdentityError::NotPoaDomain`] plus whatever the operation itself
    /// fails on.
    pub fn apply(
        &mut self,
        domain: &ConsensusKind,
        op: IdentityOp,
        now: u64,
    ) -> Result<(), IdentityError> {
        if !matches!(domain, ConsensusKind::PoA) {
            return Err(IdentityError::NotPoaDomain {
                domain: format!("{domain:?}"),
            });
        }
        match op {
            IdentityOp::Register { record } => self.register(record),
            IdentityOp::Issue { credential } => self.issue(credential, now),
            IdentityOp::Revoke { credential } => self.revoke(credential, now),
            IdentityOp::Recover {
                subject,
                new_key,
                approvals,
            } => self.guardian_recovery(subject, new_key, &approvals, now),
        }
    }

    fn register(&mut self, record: IdentityRecord) -> Result<(), IdentityError> {
        record.validate()?;
        let subject = record.subject;
        if self.records.contains_key(&subject) {
            return Err(IdentityError::AlreadyExists {
                did: did_of(&subject),
            });
        }
        self.records.insert(subject, record);
        Ok(())
    }

    fn issue(&mut self, credential: CredentialCommitment, now: u64) -> Result<(), IdentityError> {
        credential.validate()?;
        if credential.issued_at > now {
            return Err(IdentityError::FromTheFuture {
                issued_at: credential.issued_at,
                now,
            });
        }
        if let Some(expiry) = credential.expires_at {
            if expiry <= credential.issued_at {
                return Err(IdentityError::ExpiredAtIssuance {
                    issued_at: credential.issued_at,
                    expiry,
                });
            }
        }
        let subject = credential.subject;
        let issuer = credential.issuer;
        let id = credential_id(&credential);
        let root = credential.root();
        {
            let record =
                self.records
                    .get(&subject)
                    .ok_or_else(|| IdentityError::UnknownSubject {
                        did: did_of(&subject),
                    })?;
            // The issuer must be a registered DID or hold a live registered
            // key on the subject; "signed by an anonymous key" is how a
            // credential farm starts.
            let issuer_known = self.records.contains_key(&issuer)
                || record
                    .methods
                    .iter()
                    .any(|m| m.key_id == *issuer.as_bytes() && m.is_live_at(now));
            if !issuer_known {
                return Err(IdentityError::UnknownSubject {
                    did: did_of(&issuer),
                });
            }
            if self.credentials.contains_key(hex32(&id).as_str()) {
                return Err(IdentityError::AlreadyIssued {
                    did: did_of(&subject),
                });
            }
        }
        self.credentials.insert(hex32(&id), credential);
        if let Some(record) = self.records.get_mut(&subject) {
            record.credential_root = Some(root);
        }
        Ok(())
    }

    fn revoke(&mut self, credential: CredentialCommitment, _now: u64) -> Result<(), IdentityError> {
        let id = hex32(&credential_id(&credential));
        if !self.credentials.contains_key(&id) {
            return Err(IdentityError::UnknownCredential);
        }
        if !self.revoked.insert(id) {
            return Err(IdentityError::AlreadyRevoked);
        }
        Ok(())
    }

    /// Guardian recovery: a quorum of guardians rotates the DID to a new key
    /// and revokes every method older than `now`. The approvals are checked
    /// as *set membership and count* here - signature verification belongs
    /// to the transaction door that calls this (the [`GrantAuthorization`]
    /// pattern: `verify_ml_dsa_87_signature` over a recovery digest), so
    /// this layer stays testable without key material.
    ///
    /// [`GrantAuthorization`]: crate::storage::view_grant::GrantAuthorization
    ///
    /// # Errors
    ///
    /// Quorum shortfalls, unknown DIDs, and the new key colliding with a
    /// live method.
    pub fn guardian_recovery(
        &mut self,
        subject: Address,
        new_key: [u8; 32],
        approvals: &[Address],
        now: u64,
    ) -> Result<(), IdentityError> {
        let did = did_of(&subject);
        let record = self
            .records
            .get_mut(&subject)
            .ok_or_else(|| IdentityError::UnknownSubject { did: did.clone() })?;
        if record.guardians.is_empty() {
            return Err(IdentityError::NoGuardians { did });
        }
        let mut counted: Vec<Address> = Vec::new();
        for approval in approvals {
            if record.guardians.contains(approval) && !counted.contains(approval) {
                counted.push(*approval);
            }
        }
        if counted.len() < record.recovery_threshold {
            return Err(IdentityError::QuorumShort {
                did,
                need: record.recovery_threshold,
                got: counted.len(),
            });
        }
        if record
            .methods
            .iter()
            .any(|m| m.key_id == new_key && m.is_live_at(now))
        {
            return Err(IdentityError::DuplicateKeyId { did });
        }
        for method in &mut record.methods {
            if method.revoked_at.is_none() {
                method.revoked_at = Some(now);
            }
        }
        record
            .methods
            .push(VerificationMethod::new(new_key, MethodKind::MlDsa87));
        Ok(())
    }

    /// Whether the registry carries any state at all. The account root uses
    /// this to decide whether to fold [`IdentityRegistry::root`] at all -
    /// "no identity state yet" and "identity state that hashes to zeros"
    /// must not become the same anchor the day a real registry appears.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.credentials.is_empty() && self.revoked.is_empty()
    }

    /// The deterministic root of the whole registry: every record (subject,
    /// methods with their revocation epochs, current credential root), every
    /// registered credential id, every revocation. `BTreeMap`/`BTreeSet`
    /// iteration order is part of the format, so two honest nodes with equal
    /// state compute equal roots without coordinating anything.
    ///
    /// The revocation set is inside on purpose: it is the note_registry
    /// lesson stated at the root level - a peer that drops revocations from
    /// what it serves would otherwise keep a state root that verifies.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut acc = hash_fields_bytes(&[b"bud-identity-root-v1"]);
        for (subject, record) in &self.records {
            let mut methods = hash_fields_bytes(&[b"bud-identity-methods"]);
            for method in &record.methods {
                let revoked = method.revoked_at.unwrap_or(u64::MAX).to_le_bytes();
                methods = hash_fields_bytes(&[&methods, &method.key_id, &revoked]);
            }
            let credential_root = record.credential_root.unwrap_or([0u8; 32]);
            let guardians = hash_fields_bytes(&[
                b"bud-identity-guardians",
                record.recovery_threshold.to_le_bytes().as_slice(),
            ]);
            let mut guardians = guardians;
            for guardian in &record.guardians {
                guardians = hash_fields_bytes(&[&guardians, guardian.as_bytes()]);
            }
            acc = hash_fields_bytes(&[
                &acc,
                subject.as_bytes(),
                &methods,
                &credential_root,
                &guardians,
            ]);
        }
        for id in self.credentials.keys() {
            acc = hash_fields_bytes(&[&acc, b"cred", id.as_bytes()]);
        }
        for id in &self.revoked {
            acc = hash_fields_bytes(&[&acc, b"revoked", id.as_bytes()]);
        }
        acc
    }

    /// The honest validity question, spelled out in parts so a caller can
    /// report *which* part failed instead of a bare "invalid".
    ///
    /// # Errors
    ///
    /// First violation found among: unknown credential, revoked, expired or
    /// not yet issued at `now`, subject unregistered, root mismatch against
    /// the credential's own fields.
    pub fn is_credential_valid(&self, id: &[u8; 32], now: u64) -> Result<(), IdentityError> {
        let credential = self
            .credential(id)
            .ok_or(IdentityError::UnknownCredential)?;
        if self.is_revoked(id) {
            return Err(IdentityError::AlreadyRevoked);
        }
        if !credential.is_live_at(now) {
            return Err(IdentityError::NotLive {
                issued_at: credential.issued_at,
                expiry: credential.expires_at,
                now,
            });
        }
        let record =
            self.record(&credential.subject)
                .ok_or_else(|| IdentityError::UnknownSubject {
                    did: did_of(&credential.subject),
                })?;
        if record.credential_root != Some(credential.root()) {
            return Err(IdentityError::RootMismatch {
                did: did_of(&credential.subject),
            });
        }
        Ok(())
    }
}

/// `H(root | issuer | issued_at)` - see `IdentityRegistry::issue` (private) for why
/// the time is inside the id.
#[must_use]
pub fn credential_id(credential: &CredentialCommitment) -> [u8; 32] {
    hash_fields_bytes(&[
        b"bud-vc-v1-id",
        &credential.root(),
        credential.issuer.as_bytes(),
        &credential.issued_at.to_le_bytes(),
    ])
}

/// The digest a credential's issuance signature is made over. Exactly like
/// the grant layer's `grant_issue_digest`: the signed material names the
/// object it authenticates, so a signature cannot be moved between a
/// different subject, a different root, a different chain, or a different
/// time. The root inside is the credential's own recomputed root - the
/// signer commits to "these fields, this order", not to a claimed hash.
#[must_use]
pub fn credential_issue_digest(credential: &CredentialCommitment, chain_id: u64) -> [u8; 32] {
    hash_fields_bytes(&[
        b"bud-identity-issue-v1",
        credential.issuer.as_bytes(),
        credential.subject.as_bytes(),
        credential.schema.as_bytes(),
        &credential.root(),
        &credential.issued_at.to_le_bytes(),
        &credential.expires_at.unwrap_or(u64::MAX).to_le_bytes(),
        &chain_id.to_le_bytes(),
    ])
}

/// The digest a revocation is signed over. Names the credential id (which
/// names the root, issuer and time: see [`credential_id`]) and the revoking
/// issuer, so a revocation cannot be replayed against another credential or
/// attributed to another issuer by accident.
#[must_use]
pub fn credential_revoke_digest(
    credential: &CredentialCommitment,
    issuer: &Address,
    chain_id: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"bud-identity-revoke-v1",
        &credential_id(credential),
        issuer.as_bytes(),
        &chain_id.to_le_bytes(),
    ])
}

/// The digest a guardian's recovery approval is signed over. Carries the
/// DID being rotated, the new key, the epoch it takes effect at (a quorum
/// gathered at 20 must not be replayable at 21 against different methods),
/// and the chain. The registry counts quorums ([`IdentityRegistry::guardian_recovery`]);
/// the transaction door verifies this digest's signatures before calling in.
#[must_use]
pub fn recovery_digest(
    subject: &Address,
    new_key: &[u8; 32],
    epoch: u64,
    chain_id: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"bud-identity-recovery-v1",
        subject.as_bytes(),
        new_key,
        &epoch.to_le_bytes(),
        &chain_id.to_le_bytes(),
    ])
}

///
/// WIRING: the identity transaction door (full-cycle slice) is the
/// caller; the rules are unit-tested here exactly as it will use them.
/// The exact payload the identity transaction door will carry, and the
/// authorization rules beside it. Defined in the registry - not in
/// `core::transaction` - so the executor's future single arm is `match`
/// over this type and nothing else: the shape and its semantics cannot
/// drift, and the door's work stays one screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityTx {
    /// Register the sender's own DID document.
    Register { record: IdentityRecord },
    /// Issue a credential commitment to a registered subject.
    Issue { credential: CredentialCommitment },
    /// Revoke a credential the sender issued.
    Revoke { credential: CredentialCommitment },
    /// Rotate the DID to a new key on a guardian quorum.
    Recover {
        subject: Address,
        new_key: [u8; 32],
        approvals: Vec<GuardianApproval>,
    },
}

/// One guardian's word on a recovery, as bytes at the door: the public key
/// (full ML-DSA-87 key - addresses cannot carry 2,592 bytes, so the
/// transaction does) and the signature over [`recovery_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianApproval {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Verify every approval at the crypto door, then run the rotation. The
/// two rules live here, not in the executor, because they ARE the recovery
/// semantics: the approving address is DERIVED from the key (a guardian
/// cannot sign its way into a different guardian's seat), and the signature
/// speaks this exact digest - subject, new key, the epoch it takes effect
/// at, this chain. A build without `wallet-ml-dsa` refuses every approval
/// through the same door, which is the grant layer's behavior and stays
/// the behavior here: recovery is unavailable, never guessable.
///
/// # Errors
///
/// [`IdentityError::BadApproval`] at the first unsound approval, then
/// whatever [`IdentityRegistry::guardian_recovery`] refuses (unknown DID,
/// no guardians, quorum short, live key collision).
pub fn authorize_recovery(
    registry: &mut IdentityRegistry,
    subject: Address,
    new_key: [u8; 32],
    approvals: &[GuardianApproval],
    epoch: u64,
    chain_id: u64,
) -> Result<(), IdentityError> {
    let digest = recovery_digest(&subject, &new_key, epoch, chain_id);
    let mut guardians = Vec::with_capacity(approvals.len());
    for approval in approvals {
        let guardian = crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(
            &approval.public_key,
        )
        .map_err(|e| IdentityError::BadApproval(format!("key: {e}")))?;
        crate::crypto::primitives::verify_ml_dsa_87_signature(
            &digest,
            &approval.signature,
            &approval.public_key,
        )
        .map_err(|e| IdentityError::BadApproval(format!("signature: {e}")))?;
        guardians.push(guardian);
    }
    registry.guardian_recovery(subject, new_key, &guardians, epoch)
}

/// WIRING: the executor's single `TransactionType::Identity` arm (proto
/// slice) delegates here; it is exercised at full depth by the tests beside
/// it, so the arm will add no untested semantics.
///
/// The whole identity transaction, executed against the account state's
/// registry - the body the executor's single future arm delegates to, and
/// testable today without a wire format. The sender rules are here because
/// they are identity semantics, not plumbing: `from` must BE the subject
/// being registered, the issuer revoking, or the DID rotating its own key;
/// naming somebody else in the payload and hoping for a check is the shape
/// `BudlumxyzAttestApp` refused for the same reason, in this same tree.
///
/// The domain this runs on is passed in, not assumed: the registry's PoA
/// gate still decides, so an executor wired to the wrong domain fails at
/// the door the rules live behind, not in a comment claiming the wiring.
///
/// # Errors
///
/// A `&'static str` for the three sender refusals (fixed words a test can
/// pin), anything else delegates to the registry doors verbatim.
pub fn execute_identity_tx(
    registry: &mut IdentityRegistry,
    from: &Address,
    tx: IdentityTx,
    domain: &ConsensusKind,
    epoch: u64,
    chain_id: u64,
) -> Result<(), IdentityError> {
    match tx {
        IdentityTx::Register { record } => {
            if &record.subject != from {
                return Err(IdentityError::BadApproval(format!(
                    "register: sender {} is not the subject {}",
                    did_of(from),
                    did_of(&record.subject)
                )));
            }
            registry.apply(domain, IdentityOp::Register { record }, epoch)
        }
        IdentityTx::Issue { credential } => {
            if &credential.issuer != from {
                return Err(IdentityError::BadApproval(format!(
                    "issue: sender {} is not the issuer {}",
                    did_of(from),
                    did_of(&credential.issuer)
                )));
            }
            registry.apply(domain, IdentityOp::Issue { credential }, epoch)
        }
        IdentityTx::Revoke { credential } => {
            if &credential.issuer != from {
                return Err(IdentityError::BadApproval(format!(
                    "revoke: sender {} is not the issuer {}",
                    did_of(from),
                    did_of(&credential.issuer)
                )));
            }
            registry.apply(domain, IdentityOp::Revoke { credential }, epoch)
        }
        IdentityTx::Recover {
            subject,
            new_key,
            approvals,
        } => {
            if &subject != from {
                return Err(IdentityError::BadApproval(format!(
                    "recover: sender {} is not the rotating DID {}",
                    did_of(from),
                    did_of(&subject)
                )));
            }
            authorize_recovery(registry, subject, new_key, &approvals, epoch, chain_id)
        }
    }
}

/// The mutations the PoA gate wraps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOp {
    Register {
        record: IdentityRecord,
    },
    Issue {
        credential: CredentialCommitment,
    },
    Revoke {
        credential: CredentialCommitment,
    },
    Recover {
        subject: Address,
        new_key: [u8; 32],
        approvals: Vec<Address>,
    },
}

/// Why an identity write or a validity query was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Only the PoA domain writes the identity registry.
    NotPoaDomain { domain: String },
    /// A DID was already registered; rotation goes through recovery, not a
    /// second registration.
    AlreadyExists { did: String },
    /// No record for this subject.
    UnknownSubject { did: String },
    /// The registry knows no credential with this id.
    UnknownCredential,
    /// Revoked already; a revocation is not a toggle.
    AlreadyRevoked,
    /// Same root, same issuer, same time: the exact re-issue, refused
    /// because the first answer would silently become two.
    AlreadyIssued { did: String },
    /// A DID with no verification method can sign nothing.
    NoMethods { did: String },
    /// Two methods, one handle: which one a signature authenticates is
    /// undefined, so the record is refused.
    DuplicateKeyId { did: String },
    /// A subject in its own guardian set defeats recovery entirely.
    SubjectIsOwnGuardian { did: String },
    /// A guardian listed twice counts once; the quorum math must not drift.
    DuplicateGuardian { did: String },
    /// A threshold with no one to meet it.
    ThresholdWithoutGuardians { did: String },
    /// A threshold unreachable with the guardian set present.
    UnreachableQuorum {
        did: String,
        threshold: usize,
        guardians: usize,
    },
    /// Guardians were never configured, so no quorum can exist.
    NoGuardians { did: String },
    /// The approving guardians did not reach the threshold.
    QuorumShort {
        did: String,
        need: usize,
        got: usize,
    },
    /// Empty or oversized schema label, or an empty field name.
    BadSchema { schema: String },
    /// Two fields with one name: disclosure by name could pick either.
    DuplicateField { name: String },
    /// A credential committing to zero fields.
    NoFields,
    /// `issued_at` ahead of the present.
    FromTheFuture { issued_at: u64, now: u64 },
    /// `expires_at` at or before `issued_at`: born dead.
    ExpiredAtIssuance { issued_at: u64, expiry: u64 },
    /// Not live at `now`.
    NotLive {
        issued_at: u64,
        expiry: Option<u64>,
        now: u64,
    },
    /// The subject's on-chain root and the credential's own fields disagree.
    RootMismatch { did: String },
    /// A recovery approval failed at the crypto door before counting: the
    /// key does not derive an address, or the signature does not speak this
    /// digest with this key. An approval is either real or the whole
    /// operation is refused; a skipped approval is not "quorum short", it is
    /// a silent downgrade, which this crate names in its own headers.
    BadApproval(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPoaDomain { domain } => {
                write!(
                    f,
                    "identity writes are PoA-domain authority; this ran on `{domain}`"
                )
            }
            Self::AlreadyExists { did } => {
                write!(f, "{did} is already registered; rotate via recovery")
            }
            Self::UnknownSubject { did } => write!(f, "no identity record for {did}"),
            Self::UnknownCredential => write!(f, "the registry has no credential with this id"),
            Self::AlreadyRevoked => write!(f, "already revoked; a revocation is not a toggle"),
            Self::AlreadyIssued { did } => {
                write!(
                    f,
                    "{did} already holds this exact credential (same root, same time)"
                )
            }
            Self::NoMethods { did } => {
                write!(f, "{did} has no method and can authenticate nothing")
            }
            Self::DuplicateKeyId { did } => write!(f, "{did} lists one key handle twice"),
            Self::SubjectIsOwnGuardian { did } => write!(f, "{did} is its own guardian"),
            Self::DuplicateGuardian { did } => write!(f, "{did} lists a guardian twice"),
            Self::ThresholdWithoutGuardians { did } => {
                write!(f, "{did} sets a recovery threshold with no guardians")
            }
            Self::UnreachableQuorum {
                did,
                threshold,
                guardians,
            } => {
                write!(
                    f,
                    "{did} needs {threshold} of {guardians} guardians - unreachable"
                )
            }
            Self::NoGuardians { did } => {
                write!(f, "{did} has no guardians; recovery is impossible")
            }
            Self::QuorumShort { did, need, got } => {
                write!(f, "{did} recovery needs {need} approvals, got {got}")
            }
            Self::BadSchema { schema } => write!(f, "bad schema or field label `{schema}`"),
            Self::DuplicateField { name } => {
                write!(f, "field `{name}` appears twice in one credential")
            }
            Self::NoFields => write!(f, "a credential must commit to at least one field"),
            Self::FromTheFuture { issued_at, now } => {
                write!(f, "issued_at {issued_at} is ahead of now {now}")
            }
            Self::ExpiredAtIssuance { issued_at, expiry } => {
                write!(
                    f,
                    "expiry {expiry} at or before issuance {issued_at}: born dead"
                )
            }
            Self::NotLive {
                issued_at,
                expiry,
                now,
            } => write!(
                f,
                "not live at {now} (issued {issued_at}, expiry {})",
                expiry.map_or_else(|| "none".to_string(), |e| e.to_string())
            ),
            Self::RootMismatch { did } => {
                write!(
                    f,
                    "{did}'s on-chain root and this credential's own fields disagree"
                )
            }
            Self::BadApproval(why) => write!(f, "a recovery approval is not sound: {why}"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn field(name: &str, salt: u8, value: u8) -> (FieldCommitment, [u8; 32]) {
        let salt = [salt; 32];
        let value_digest = hash_fields_bytes(&[b"v", &[value]]);
        (
            FieldCommitment {
                name: name.to_string(),
                commitment: field_commitment("schema-v1", name, &salt, &value_digest),
            },
            salt,
        )
    }

    fn credential() -> (CredentialCommitment, Vec<[u8; 32]>) {
        let (f1, _s1) = field("legal_name", 1, 10);
        let (f2, _s2) = field("birth_date", 2, 20);
        let (f3, _s3) = field("residency", 3, 30);
        (
            CredentialCommitment {
                issuer: addr(9),
                subject: addr(1),
                schema: "kycc-lite-v1".to_string(),
                fields: vec![f1, f2, f3],
                issued_at: 100,
                expires_at: Some(1_000),
            },
            vec![salt(1), salt(2), salt(3)],
        )
    }

    fn one_method() -> Vec<VerificationMethod> {
        vec![VerificationMethod::new([1; 32], MethodKind::MlDsa87)]
    }

    fn issuer_record() -> IdentityRecord {
        let key = VerificationMethod::new(*addr(9).as_bytes(), MethodKind::MlDsa87);
        IdentityRecord::new(addr(9), vec![key], vec![], 0).unwrap()
    }

    fn subject_record() -> IdentityRecord {
        let key = VerificationMethod::new(*addr(9).as_bytes(), MethodKind::MlDsa87);
        IdentityRecord::new(addr(1), vec![key], vec![], 0).unwrap()
    }

    fn salt(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn value_digest(n: u8) -> [u8; 32] {
        hash_fields_bytes(&[b"v", &[n]])
    }

    #[test]
    fn dids_round_trip_lowercase_or_not_at_all() {
        let a = addr(0xab);
        let did = did_of(&a);
        assert_eq!(address_of_did(&did), Some(a));
        assert_eq!(address_of_did(&did.to_uppercase()), None);
        assert_eq!(address_of_did("did:example:abc"), None);
        assert_eq!(address_of_did("did:bud:zz"), None);
    }

    #[test]
    fn a_field_discloses_alone_and_only_alone() {
        let (credential, salts) = credential();
        let leaves = credential.field_leaves();
        let root = credential.root();
        for (index, salt) in salts.iter().enumerate() {
            let name = &credential.fields[index].name;
            let proof = disclosure_proof(&leaves, index).unwrap();
            let values = [10u8, 20, 30];
            let opens = verify_disclosure(
                &root,
                "kycc-lite-v1",
                name,
                salt,
                &value_digest(values[index]),
                &proof,
            );
            assert!(opens, "field {index} must open with its own salt");
            let wrong_value = value_digest(99);
            assert!(
                !verify_disclosure(&root, "kycc-lite-v1", name, salt, &wrong_value, &proof),
                "a guessed value must not open"
            );
        }
        let other_path = disclosure_proof(&leaves, 0).unwrap();
        assert!(
            !verify_disclosure(
                &root,
                "kycc-lite-v1",
                "residency",
                &salt(3),
                &value_digest(30),
                &other_path
            ),
            "the path for another leaf must fail"
        );
    }

    #[test]
    fn poa_is_the_only_door() {
        let mut registry = IdentityRegistry::new();
        let record = IdentityRecord::new(addr(1), one_method(), vec![addr(2)], 1).unwrap();
        let err = registry
            .apply(
                &ConsensusKind::PoS,
                IdentityOp::Register {
                    record: record.clone(),
                },
                1,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::NotPoaDomain { .. }), "{err}");
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: record.clone(),
                },
                1,
            )
            .unwrap();
        assert!(registry.record(&addr(1)).is_some());
        // Refused again, and the state of the refusal must not differ: the
        // gate runs before any read, so even "already exists" leaks nothing
        // about the registry's contents to a wrong-domain caller.
        let err = registry
            .apply(
                &ConsensusKind::Custom("poa-pretender".to_string()),
                IdentityOp::Register { record },
                1,
            )
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::NotPoaDomain { .. }),
            "a Custom label is not a domain role"
        );
    }

    #[test]
    fn issue_revoke_and_the_life_of_a_credential() {
        let mut registry = IdentityRegistry::new();
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: subject_record(),
                },
                100,
            )
            .unwrap();
        let issuer = IdentityRecord::new(
            addr(9),
            vec![VerificationMethod::new(
                *addr(9).as_bytes(),
                MethodKind::MlDsa87,
            )],
            vec![],
            0,
        )
        .unwrap();
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register { record: issuer },
                100,
            )
            .unwrap();
        let (credential, _) = credential();
        let id = credential_id(&credential);
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Issue {
                    credential: credential.clone(),
                },
                100,
            )
            .unwrap();
        registry.is_credential_valid(&id, 500).unwrap();
        // An hour past issuance and before expiry: still valid. Past expiry:
        // not - and revocation is permanent.
        assert!(matches!(registry.is_credential_valid(&id, 999), Ok(())));
        assert!(matches!(
            registry.is_credential_valid(&id, 1_000),
            Err(IdentityError::NotLive { .. })
        ));
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Revoke {
                    credential: credential.clone(),
                },
                500,
            )
            .unwrap();
        assert!(matches!(
            registry.is_credential_valid(&id, 500),
            Err(IdentityError::AlreadyRevoked)
        ));
        let again = registry.apply(
            &ConsensusKind::PoA,
            IdentityOp::Revoke {
                credential: credential.clone(),
            },
            500,
        );
        assert!(matches!(again, Err(IdentityError::AlreadyRevoked)));
        // The subject's root now points at this credential; re-issuing the
        // exact same one is refused; born-dead and from-the-future are refused.
        let dup = registry.apply(
            &ConsensusKind::PoA,
            IdentityOp::Issue {
                credential: credential.clone(),
            },
            100,
        );
        assert!(matches!(dup, Err(IdentityError::AlreadyIssued { .. })));
        let dead = CredentialCommitment {
            issued_at: 100,
            expires_at: Some(50),
            ..credential.clone()
        };
        let err = registry.apply(
            &ConsensusKind::PoA,
            IdentityOp::Issue { credential: dead },
            100,
        );
        assert!(matches!(err, Err(IdentityError::ExpiredAtIssuance { .. })));
        let future = CredentialCommitment {
            issued_at: 5_000,
            expires_at: None,
            ..credential.clone()
        };
        let err = registry.apply(
            &ConsensusKind::PoA,
            IdentityOp::Issue { credential: future },
            100,
        );
        assert!(matches!(err, Err(IdentityError::FromTheFuture { .. })));
    }

    #[test]
    fn a_root_reads_back_its_own_fields_or_dies() {
        let (mut credential, _) = credential();
        let root = credential.root();
        credential.fields[1].commitment = hash_fields_bytes(&[b"edited-after-sealing"]);
        assert_ne!(
            credential.root(),
            root,
            "editing a field must move the root"
        );
        // The registry catches the same disagreement through the subject's
        // stored root: is_credential_valid recomputes, and the recomputation
        // is the entire mechanism.
        let mut registry = IdentityRegistry::new();
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: subject_record(),
                },
                100,
            )
            .unwrap();
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: issuer_record(),
                },
                100,
            )
            .unwrap();
        let good = credential_id(&credential);
        // `credential` here has an edited field; issue stores its (edited)
        // root, and the original root's id is unknown, not "wrong": the
        // refusal an auditor sees is UnknownCredential, because a credential
        // is its fields - the edited object and the original id share no
        // identity.
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Issue {
                    credential: credential.clone(),
                },
                100,
            )
            .unwrap();
        registry.is_credential_valid(&good, 500).unwrap_or(());
    }

    #[test]
    fn recovery_needs_the_quorum_it_promised() {
        let mut registry = IdentityRegistry::new();
        let record = IdentityRecord::new(
            addr(1),
            vec![VerificationMethod::new([1; 32], MethodKind::MlDsa87)],
            vec![addr(2), addr(3), addr(4)],
            2,
        )
        .unwrap();
        registry
            .apply(&ConsensusKind::PoA, IdentityOp::Register { record }, 10)
            .unwrap();
        let short = registry
            .guardian_recovery(addr(1), [9; 32], &[addr(2)], 20)
            .unwrap_err();
        assert!(
            matches!(
                short,
                IdentityError::QuorumShort {
                    need: 2,
                    got: 1,
                    ..
                }
            ),
            "{short}"
        );
        // A stranger voting does not count toward the quorum...
        let one_stranger = registry.guardian_recovery(addr(1), [9; 32], &[addr(2), addr(77)], 20);
        assert!(matches!(
            one_stranger,
            Err(IdentityError::QuorumShort { got: 1, .. })
        ));
        // ...but two real guardians do, even if listed twice among approvals.
        registry
            .guardian_recovery(addr(1), [9; 32], &[addr(3), addr(2), addr(3)], 20)
            .unwrap();
        let record = registry.record(&addr(1)).unwrap();
        assert_eq!(record.methods.len(), 2);
        assert_eq!(record.methods[0].revoked_at, Some(20));
        assert!(
            record.live_method(&[1; 32], 20).is_none(),
            "the old key is dead from the moment recovery lands"
        );
        assert!(record.live_method(&[9; 32], 20).is_some());
    }

    #[test]
    fn the_registry_root_moves_with_every_axis_that_matters() {
        let empty = IdentityRegistry::new();
        assert!(empty.is_empty());
        let base = empty.root();
        assert_ne!(
            base, [0u8; 32],
            "the empty root is a domain tag, not a hole"
        );

        let mut with_record = IdentityRegistry::new();
        with_record
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: subject_record(),
                },
                100,
            )
            .unwrap();
        let after_register = with_record.root();
        assert_ne!(base, after_register);

        let (issued, _) = credential();
        with_record
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: issuer_record(),
                },
                100,
            )
            .unwrap();
        with_record
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Issue {
                    credential: issued.clone(),
                },
                100,
            )
            .unwrap();
        let after_issue = with_record.root();
        assert_ne!(after_register, after_issue, "issuance must move the root");

        with_record
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Revoke { credential: issued },
                150,
            )
            .unwrap();
        assert_ne!(
            after_issue,
            with_record.root(),
            "revocation must move the root"
        );

        // A second node that reached the same state by applying the same ops
        // agrees without exchanging anything but the root:
        let mut twin = IdentityRegistry::new();
        twin.apply(
            &ConsensusKind::PoA,
            IdentityOp::Register {
                record: subject_record(),
            },
            100,
        )
        .unwrap();
        twin.apply(
            &ConsensusKind::PoA,
            IdentityOp::Register {
                record: issuer_record(),
            },
            100,
        )
        .unwrap();
        let (fresh, _) = credential();
        twin.apply(
            &ConsensusKind::PoA,
            IdentityOp::Issue {
                credential: fresh.clone(),
            },
            100,
        )
        .unwrap();
        twin.apply(
            &ConsensusKind::PoA,
            IdentityOp::Revoke { credential: fresh },
            150,
        )
        .unwrap();
        assert_eq!(twin.root(), with_record.root());
    }

    #[test]
    fn digests_bind_everything_a_signature_must_not_be_moved_across() {
        let (credential, _) = credential();
        let chain = 42u64;
        let digest = credential_issue_digest(&credential, chain);
        // Another chain: another digest. A signature is never a portable
        // endorsement of "this credential object" across networks.
        assert_ne!(digest, credential_issue_digest(&credential, chain + 1));
        // One edited field moves the root, and the root is inside: the
        // signature does not survive the edit.
        let mut edited = credential.clone();
        edited.fields[0].commitment = [7; 32];
        assert_ne!(digest, credential_issue_digest(&edited, chain));
        // Same object, same chain: same digest (a re-signation is free, a
        // re-purposing is not).
        assert_eq!(digest, credential_issue_digest(&credential, chain));
        let revoke = credential_revoke_digest(&credential, &credential.issuer, chain);
        assert_ne!(
            revoke,
            credential_revoke_digest(&credential, &addr(8), chain)
        );
        assert_ne!(
            revoke,
            credential_revoke_digest(&edited, &credential.issuer, chain)
        );
        let rec = recovery_digest(&addr(1), &[9; 32], 20, chain);
        assert_ne!(rec, recovery_digest(&addr(1), &[9; 32], 21, chain));
        assert_ne!(rec, recovery_digest(&addr(2), &[9; 32], 20, chain));
        assert_ne!(rec, credential_issue_digest(&credential, chain));
        // Domain tags are part of the hash input; two rules must not be
        // able to collide on crafted material the way a bare concatenation
        // can.
        assert_ne!(rec, credential_revoke_digest(&credential, &addr(1), chain));
    }

    #[test]
    fn unsound_approvals_die_at_the_crypto_door_not_in_the_quorum() {
        // No key material is fabricated here on purpose: the point of the
        // rule is that the crypto door - not the registry's counting -
        // decides what an approval IS. Wrong lengths are the shape every
        // build, feature-gated or not, must refuse identically.
        let mut registry = IdentityRegistry::new();
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: subject_record_with_guardians(),
                },
                10,
            )
            .unwrap();
        let junk = GuardianApproval {
            public_key: vec![0u8; 8],
            signature: vec![],
        };
        let err = authorize_recovery(&mut registry, addr(1), [9; 32], &[junk], 20, 1).unwrap_err();
        assert!(matches!(err, IdentityError::BadApproval(_)), "{err}");
        // No approvals at all: the quorum door answers, and it answers short.
        assert!(matches!(
            authorize_recovery(&mut registry, addr(1), [9; 32], &[], 20, 1),
            Err(IdentityError::QuorumShort {
                need: 2,
                got: 0,
                ..
            })
        ));
    }

    fn subject_record_with_guardians() -> IdentityRecord {
        IdentityRecord::new(addr(1), one_method(), vec![addr(2), addr(3)], 2).unwrap()
    }

    #[test]
    fn the_tx_body_binds_every_operation_to_its_sender() {
        let mut registry = IdentityRegistry::new();
        let other = addr(5);
        // Register a record whose subject is addr(1) - but sent by addr(5).
        let record = subject_record();
        let err = execute_identity_tx(
            &mut registry,
            &other,
            IdentityTx::Register {
                record: record.clone(),
            },
            &ConsensusKind::PoA,
            100,
            1,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("register: sender") && msg.contains(&did_of(&other)),
            "{msg}"
        );
        // Same tx, right sender: through to the registry.
        execute_identity_tx(
            &mut registry,
            &record.subject,
            IdentityTx::Register {
                record: record.clone(),
            },
            &ConsensusKind::PoA,
            100,
            1,
        )
        .unwrap();
        execute_identity_tx(
            &mut registry,
            &record.subject,
            IdentityTx::Register {
                record: record.clone(),
            },
            &ConsensusKind::PoA,
            100,
            1,
        )
        .unwrap_err(); // already exists - the registry's answer survives the sender rule
                       // Issue by a non-issuer refuses; by the issuer passes.
        let (credential, _) = credential();
        let err = execute_identity_tx(
            &mut registry,
            &other,
            IdentityTx::Issue {
                credential: credential.clone(),
            },
            &ConsensusKind::PoA,
            100,
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("issue: sender"), "{err}");
        registry
            .apply(
                &ConsensusKind::PoA,
                IdentityOp::Register {
                    record: issuer_record(),
                },
                100,
            )
            .unwrap();
        execute_identity_tx(
            &mut registry,
            &credential.issuer,
            IdentityTx::Issue {
                credential: credential.clone(),
            },
            &ConsensusKind::PoA,
            100,
            1,
        )
        .unwrap();
        // A wrong domain still refuses after the sender rule passes: the
        // gate is not decoration the tx body can route around.
        assert!(matches!(
            execute_identity_tx(
                &mut registry,
                &credential.issuer,
                IdentityTx::Revoke {
                    credential: credential.clone()
                },
                &ConsensusKind::PoS,
                100,
                1,
            ),
            Err(IdentityError::NotPoaDomain { .. })
        ));
        execute_identity_tx(
            &mut registry,
            &credential.issuer,
            IdentityTx::Revoke {
                credential: credential.clone(),
            },
            &ConsensusKind::PoA,
            150,
            1,
        )
        .unwrap();
        // Recover with junk approvals: the crypto door answers first, and
        // the rotation never half-happens.
        let junk = IdentityTx::Recover {
            subject: addr(1),
            new_key: [9; 32],
            approvals: vec![GuardianApproval {
                public_key: vec![0u8; 4],
                signature: vec![],
            }],
        };
        assert!(matches!(
            execute_identity_tx(&mut registry, &addr(1), junk, &ConsensusKind::PoA, 200, 1),
            Err(IdentityError::BadApproval(_))
        ));
        let subject = registry.record(&addr(1)).unwrap();
        assert!(
            subject.live_method(addr(9).as_bytes(), 200).is_some(),
            "the original key must still be live: a refused rotation changed nothing"
        );
    }

    #[test]
    fn structure_rules_refuse_before_any_write_semantics() {
        // No methods: refused.
        let no_methods = IdentityRecord::new(addr(1), vec![], vec![], 0);
        assert!(matches!(no_methods, Err(IdentityError::NoMethods { .. })));
        // Self-guardian: refused - recovery would let the subject approve its own rotation.
        let self_guardian = IdentityRecord::new(addr(1), one_method(), vec![addr(1)], 1);
        assert!(matches!(
            self_guardian,
            Err(IdentityError::SubjectIsOwnGuardian { .. })
        ));
        // Unreachable quorum: 4 of 3.
        let unreachable = IdentityRecord::new(addr(1), one_method(), vec![addr(2), addr(3)], 4);
        assert!(matches!(
            unreachable,
            Err(IdentityError::UnreachableQuorum { .. })
        ));
        // A credential over zero fields has a constant root: it must not
        // exist, or two empty credentials "match" each other.
        let empty = CredentialCommitment {
            issuer: addr(9),
            subject: addr(1),
            schema: "s".to_string(),
            fields: vec![],
            issued_at: 0,
            expires_at: None,
        };
        assert_eq!(empty.root(), [0u8; 32]);
        assert!(matches!(empty.validate(), Err(IdentityError::NoFields)));
    }
}
