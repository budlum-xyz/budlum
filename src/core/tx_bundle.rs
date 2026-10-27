//! Bundle transaction: one composite signature for several
//! operations of one sender.
//!
//! A bundle carries up to [`MAX_BUNDLE_TXS`] V7 transaction bodies and one
//! witness. The witness signs the bundle root, which commits to the signing
//! hash of every member in order, so the signature covers the set, the order
//! and every field of every member. The members are bare bodies: they carry no
//! signature of their own, and a member alone verifies nothing.
//!
//! The rules a verifier enforces, each with a test:
//!
//! * every member is a V7 body of the same sender and chain,
//! * nonces rise by exactly one from the first member, so the order cannot be
//!   permuted and no member can be dropped from the middle,
//! * the witness key derives the sender address (Address V3),
//! * both halves of the composite signature verify over the root.
//!
//! A bundle is executed as its members, in order. A node that accepts a bundle
//! admits all members or none.

use crate::core::address::Address;
use crate::core::transaction::{
    decode_v7_signer_key, encode_v7_signer_key, Transaction, TxWitness, SIGNATURE_VERSION_V7,
};
use crate::crypto::address_v3::{
    account_auth_v3, account_auth_v3_from_digests, address_from_auth, key_digest,
};
use crate::crypto::composite::{self, CompositeKeypair, CompositeSignature};
use crate::crypto::scheme::SchemeStatusRegistry;
use sha3::{Digest, Sha3_256};

/// The domain tag of the bundle root.
pub const BUNDLE_TAG: &[u8] = b"BDLM_TX_BUNDLE_V1";

/// The most members one bundle carries.
pub const MAX_BUNDLE_TXS: usize = 16;

/// Why a bundle is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// No members, or more than [`MAX_BUNDLE_TXS`].
    Size(usize),
    /// A member is not a bare V7 body (or its hash is stale).
    Member(usize),
    /// Members differ in sender or chain.
    Mixed(usize),
    /// The nonces do not rise by one from the first member.
    Nonce(usize),
    /// The witness key is malformed or does not derive the sender.
    Sender,
    /// The composite signature is malformed or does not verify.
    Signature(String),
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Size(n) => write!(f, "bundle size {n} is out of range"),
            Self::Member(i) => write!(f, "member {i} is not a bare V7 body"),
            Self::Mixed(i) => write!(f, "member {i} differs in sender or chain"),
            Self::Nonce(i) => write!(f, "member {i} breaks the nonce sequence"),
            Self::Sender => write!(f, "the witness key does not derive the sender"),
            Self::Signature(e) => write!(f, "composite signature refused: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Several V7 bodies and the one witness that authorizes them.
#[derive(Debug, Clone, PartialEq)]
pub struct TxBundle {
    /// The member bodies, in execution order.
    pub members: Vec<Transaction>,
    /// The witness: the V7 key blob and the composite signature over the root.
    pub witness: TxWitness,
}

/// The root a bundle witness signs: the tag, the member count and the signing
/// hash of every member, in order.
#[must_use]
pub fn bundle_root(members: &[Transaction]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(BUNDLE_TAG);
    hasher.update((members.len() as u32).to_be_bytes());
    for member in members {
        hasher.update(member.signing_hash());
    }
    hasher.finalize().into()
}

impl TxBundle {
    /// Build and sign a bundle. The members' `from`, version and hash are set
    /// here: `from` is the Address V3 of the keys, so a caller cannot point the
    /// bundle at another account.
    ///
    /// # Errors
    ///
    /// [`BundleError`] for an empty or oversized list, or a signing failure.
    pub fn sign(
        registry: &SchemeStatusRegistry,
        keypair: &CompositeKeypair,
        recovery_public_key: &[u8],
        mut members: Vec<Transaction>,
        rnd: &[u8; 32],
    ) -> Result<Self, BundleError> {
        if members.is_empty() || members.len() > MAX_BUNDLE_TXS {
            return Err(BundleError::Size(members.len()));
        }
        let public = keypair
            .public_key()
            .map_err(|e| BundleError::Signature(e.to_string()))?;
        let auth = account_auth_v3(public.suite, &public.pq, &public.ed, recovery_public_key)
            .map_err(|_| BundleError::Sender)?;
        let from = Address::from(address_from_auth(&auth));
        for member in &mut members {
            member.from = from;
            member.signature_version = SIGNATURE_VERSION_V7;
            member.signature = None;
            member.signer_public_key = Vec::new();
            member.authorization = None;
            member.hash = member.calculate_hash();
        }
        let root = bundle_root(&members);
        let signature = keypair
            .sign_in(registry, crate::crypto::ctx::TX_V7, &root, rnd)
            .map_err(|e| BundleError::Signature(e.to_string()))?;
        Ok(Self {
            members,
            witness: TxWitness {
                signer_public_key: encode_v7_signer_key(&public, &key_digest(recovery_public_key)),
                signature: signature.encode(),
                authorization_signatures: Vec::new(),
            },
        })
    }

    /// Verify the bundle under the scheme statuses of a chain.
    ///
    /// # Errors
    ///
    /// The first [`BundleError`] found.
    pub fn verify_in(&self, registry: &SchemeStatusRegistry) -> Result<(), BundleError> {
        if self.members.is_empty() || self.members.len() > MAX_BUNDLE_TXS {
            return Err(BundleError::Size(self.members.len()));
        }
        let first = &self.members[0];
        for (i, member) in self.members.iter().enumerate() {
            if member.signature_version != SIGNATURE_VERSION_V7
                || member.signature.is_some()
                || !member.signer_public_key.is_empty()
                || member.authorization.is_some()
                || member.hash != member.calculate_hash()
            {
                return Err(BundleError::Member(i));
            }
            if member.from != first.from || member.chain_id != first.chain_id {
                return Err(BundleError::Mixed(i));
            }
            if member.nonce != first.nonce.saturating_add(i as u64)
                || first.nonce.checked_add(i as u64).is_none()
            {
                return Err(BundleError::Nonce(i));
            }
        }
        let (public, recovery_digest) = decode_v7_signer_key(&self.witness.signer_public_key)
            .map_err(|_| BundleError::Sender)?;
        let auth = account_auth_v3_from_digests(
            public.suite,
            &key_digest(&public.pq),
            &key_digest(&public.ed),
            &recovery_digest,
        )
        .map_err(|_| BundleError::Sender)?;
        if address_from_auth(&auth) != *first.from.as_bytes() {
            return Err(BundleError::Sender);
        }
        let signature = CompositeSignature::decode(&self.witness.signature)
            .map_err(|e| BundleError::Signature(e.to_string()))?;
        composite::verify_in(
            registry,
            &public,
            crate::crypto::ctx::TX_V7,
            &bundle_root(&self.members),
            &signature,
        )
        .map_err(|e| BundleError::Signature(e.to_string()))
    }

    /// The members, for execution in order. Call after [`Self::verify_in`].
    #[must_use]
    pub fn into_members(self) -> Vec<Transaction> {
        self.members
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::TransactionType;
    use crate::crypto::key_derivation::{RootSecret, UserAccount};

    fn account() -> UserAccount {
        RootSecret::derive(&[6u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap()
    }

    fn member(nonce: u64, amount: u64) -> Transaction {
        let mut to = [0u8; 32];
        to[0] = 9;
        Transaction::new_with_chain_id(
            Address::zero(),
            Address::from(to),
            amount,
            1,
            nonce,
            vec![],
            45262,
            TransactionType::Transfer,
        )
    }

    fn bundle(acct: &UserAccount, n: u64) -> TxBundle {
        TxBundle::sign(
            &SchemeStatusRegistry::genesis(),
            &acct.signing,
            &acct.recovery_public_key,
            (0..n).map(|i| member(i, 1 + i)).collect(),
            &[2u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn a_bundle_verifies_and_its_members_alone_do_not() {
        let acct = account();
        let b = bundle(&acct, 3);
        assert_eq!(b.verify_in(&SchemeStatusRegistry::genesis()), Ok(()));
        for m in &b.members {
            assert!(!m.verify(), "a bare member carries no authority");
            assert_eq!(m.from, Address::from(acct.address));
        }
    }

    #[test]
    fn dropping_reordering_or_editing_a_member_breaks_the_signature() {
        let acct = account();
        let reg = SchemeStatusRegistry::genesis();
        let b = bundle(&acct, 3);

        let mut dropped = b.clone();
        dropped.members.remove(1);
        assert!(dropped.verify_in(&reg).is_err());

        let mut swapped = b.clone();
        swapped.members.swap(0, 1);
        assert!(swapped.verify_in(&reg).is_err());

        let mut edited = b.clone();
        edited.members[2].amount += 1;
        edited.members[2].hash = edited.members[2].calculate_hash();
        assert!(matches!(
            edited.verify_in(&reg),
            Err(BundleError::Signature(_))
        ));

        let mut tail = b;
        tail.members.pop();
        assert!(matches!(
            tail.verify_in(&reg),
            Err(BundleError::Signature(_))
        ));
    }

    #[test]
    fn the_nonce_sequence_chain_and_sender_are_enforced() {
        let acct = account();
        let reg = SchemeStatusRegistry::genesis();
        let mut gap = bundle(&acct, 2);
        gap.members[1].nonce = 5;
        gap.members[1].hash = gap.members[1].calculate_hash();
        assert_eq!(gap.verify_in(&reg), Err(BundleError::Nonce(1)));

        let mut chain = bundle(&acct, 2);
        chain.members[1].chain_id = 1;
        chain.members[1].hash = chain.members[1].calculate_hash();
        assert_eq!(chain.verify_in(&reg), Err(BundleError::Mixed(1)));

        let mut sender = bundle(&acct, 2);
        for m in &mut sender.members {
            m.from = Address::from([1u8; 32]);
            m.hash = m.calculate_hash();
        }
        assert_eq!(sender.verify_in(&reg), Err(BundleError::Sender));
    }

    #[test]
    fn size_limits_and_a_signed_member_are_refused() {
        let acct = account();
        let reg = SchemeStatusRegistry::genesis();
        assert_eq!(
            TxBundle::sign(
                &reg,
                &acct.signing,
                &acct.recovery_public_key,
                vec![],
                &[0; 32]
            ),
            Err(BundleError::Size(0))
        );
        let mut b = bundle(&acct, 2);
        b.members[0].signature = Some(vec![1]);
        assert_eq!(b.verify_in(&reg), Err(BundleError::Member(0)));
    }
}
