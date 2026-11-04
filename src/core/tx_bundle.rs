//! Bundle transaction: one composite signature for several
//! operations of one sender.
//!
//! A bundle carries up to [`MAX_BUNDLE_TXS`] V7 transactions of one sender and
//! one witness. Every member carries its own V7 signature - that is what makes
//! it admissible to the pool and to a block, since every admission gate
//! verifies a body's own authority - and the witness signs the bundle root,
//! which commits to the signing hash of every member in order. The witness is
//! what makes the set indivisible: it says "these members, in this order", so
//! a relay that drops or re-orders one produces a set the sender never
//! authorized, and the door admits all of them or none.
//!
//! The rules a verifier enforces, each with a test:
//!
//! * every member is a V7 transaction of the same sender and chain, signed by
//!   the witness's own key and verifiable on its own,
//! * nonces rise by exactly one from the first member, so the order cannot be
//!   permuted and no member can be dropped from the middle,
//! * the witness key derives the sender address (Address V3),
//! * both halves of the composite signature verify over the root.
//!
//! A bundle is executed as its members, in order. A node that accepts a bundle
//! admits all members or none: `bud_sendTxBundle` verifies the witness and every
//! member first, then hands them to the chain one at a time and takes the ones
//! already admitted back out if the pool refuses a later member. `bud tx bundle
//! --file <path>` is the client end of the same door.

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
/// exposed for: the bundle door - `bud_sendTxBundle` and `bud tx bundle` both
/// speak a root under this tag, so it stays a named constant instead of a
/// literal copied into three files.
pub const BUNDLE_TAG: &[u8] = b"BDLM_TX_BUNDLE_V1";

/// The most members one bundle carries.
/// exposed for: the bundle door - the verifier enforces the cap and the RPC
/// reports it, so a client learns the bound from the same number the check
/// uses.
pub const MAX_BUNDLE_TXS: usize = 16;

/// Why a bundle is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the bundle door - `bud_sendTxBundle` hands this to the client
/// as the JSON-RPC error, so the variants are the client's error list.
pub enum BundleError {
    /// No members, or more than [`MAX_BUNDLE_TXS`].
    Size(usize),
    /// A member is not a V7 transaction this bundle's key signed (or its hash
    /// is stale).
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
            Self::Member(i) => write!(f, "member {i} is not a V7 body signed by this bundle"),
            Self::Mixed(i) => write!(f, "member {i} differs in sender or chain"),
            Self::Nonce(i) => write!(f, "member {i} breaks the nonce sequence"),
            Self::Sender => write!(f, "the witness key does not derive the sender"),
            Self::Signature(e) => write!(f, "composite signature refused: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Several V7 bodies and the one witness that authorizes them.
///
/// `Serialize`/`Deserialize` are the wire shape `bud_sendTxBundle` takes: a
/// client signs a bundle and the node verifies it before it admits a member.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
/// exposed for: the bundle door - `bud_sendTxBundle` takes a bundle in this
/// shape and `bud tx bundle --file` posts one, so the wire form is fixed here
/// for both ends.
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
        let signer_key = encode_v7_signer_key(&public, &key_digest(recovery_public_key));
        for (index, member) in members.iter_mut().enumerate() {
            member.from = from;
            member.signature_version = SIGNATURE_VERSION_V7;
            member.signer_public_key = signer_key.clone();
            member.authorization = None;
            // Each member is signed on its own, because every admission gate
            // verifies a transaction's own authority: a bare body is refused
            // by the pool and by block validation alike, so a bundle of bare
            // bodies would be a door that admits nothing. The per-member
            // randomness is derived from the caller's, one value per member,
            // so two members are never signed under the same salt.
            let mut member_randomness = *rnd;
            member_randomness[0] ^= index as u8;
            member_randomness[1] ^= (index >> 8) as u8;
            let signature = keypair
                .sign_in(
                    registry,
                    crate::crypto::ctx::TX_V7,
                    &member.signing_hash(),
                    &member_randomness,
                )
                .map_err(|e| BundleError::Signature(e.to_string()))?;
            member.signature = Some(signature.encode());
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
    /// The checks run in three passes, cheapest and most specific first:
    ///
    /// 1. the shape of the set - one sender, one chain, a nonce ladder rising
    ///    by one from the first member, so a relay cannot drop, reorder or
    ///    splice a member out of the middle ([`BundleError::Mixed`],
    ///    [`BundleError::Nonce`]);
    /// 2. the witness - the key blob decodes, it derives the sender
    ///    ([`BundleError::Sender`]), and its composite signature verifies over
    ///    the root of exactly these members in this order
    ///    ([`BundleError::Signature`]). That root commits to every member's
    ///    signing hash, so an edited, dropped or reordered member lands here
    ///    as a signature refusal - the set that was signed is not the set on
    ///    the wire;
    /// 3. each member's own authority, so a bundle that could never be
    ///    admitted is refused before the pool is touched
    ///    ([`BundleError::Member`]).
    ///
    /// The order is also the cheap one under load: the structural scan is a
    /// few comparisons per member and the witness check is one signature
    /// verification, both of which run before the per-member post-quantum
    /// verifications (up to [`MAX_BUNDLE_TXS`] of them). A bundle with a bad
    /// witness is therefore refused without paying for 16 member checks, and a
    /// bundle whose members disagree about the sender or the nonce ladder is
    /// refused before the composite signature is even decoded.
    ///
    /// Every pass is required: the witness signature does not replace a
    /// member's own authority (the pool and block validation re-verify it),
    /// and a member's own authority does not replace the witness (a member
    /// carries no knowledge of the set it is in).
    ///
    /// # Errors
    ///
    /// The first [`BundleError`] in that order.
    pub fn verify_in(&self, registry: &SchemeStatusRegistry) -> Result<(), BundleError> {
        if self.members.is_empty() || self.members.len() > MAX_BUNDLE_TXS {
            return Err(BundleError::Size(self.members.len()));
        }
        let first = &self.members[0];
        // Pass 1: the shape of the set. These are properties of the members
        // the witness commits to, and they are what a relay can break without
        // touching a signature.
        for (i, member) in self.members.iter().enumerate() {
            if member.from != first.from || member.chain_id != first.chain_id {
                return Err(BundleError::Mixed(i));
            }
            if member.nonce != first.nonce.saturating_add(i as u64)
                || first.nonce.checked_add(i as u64).is_none()
            {
                return Err(BundleError::Nonce(i));
            }
        }
        // Pass 2: the witness is this sender's key, and this exact set is what
        // it signed.
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
        .map_err(|e| BundleError::Signature(e.to_string()))?;
        // Pass 3: the members' own authority, which is what admission gates
        // downstream verify. Deferred to last because it is the expensive pass
        // and because a set the witness disowns is refused before it.
        for (i, member) in self.members.iter().enumerate() {
            if member.signature_version != SIGNATURE_VERSION_V7
                || member.signer_public_key != self.witness.signer_public_key
                || member.authorization.is_some()
                || member.hash != member.calculate_hash()
                || !member.verify_in(registry)
            {
                return Err(BundleError::Member(i));
            }
        }
        Ok(())
    }

    /// The members, for execution in order. Call after [`Self::verify_in`],
    /// which is what `bud_sendTxBundle` does before it touches the pool.
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

    /// Every member is admitted on its own authority, and the witness is what
    /// makes the set indivisible.
    ///
    /// A bare body would be refused by the pool and by block validation, so a
    /// bundle of bare bodies would be a door that admits nothing - the shape
    /// this test used to pin. Each member is signed by the bundle's own key,
    /// and the witness covers the set and its order.
    #[test]
    fn every_member_verifies_on_its_own_and_the_witness_binds_the_set() {
        let acct = account();
        let reg = SchemeStatusRegistry::genesis();
        let b = bundle(&acct, 3);
        assert_eq!(b.verify_in(&reg), Ok(()));
        for m in &b.members {
            assert!(m.verify_in(&reg), "a member must carry its own authority");
            assert_eq!(m.from, Address::from(acct.address));
            assert_eq!(m.signer_public_key, b.witness.signer_public_key);
        }
        // The same member outside the bundle says nothing about the bundle:
        // dropping one leaves the others valid and the set unauthorized.
        let mut without = b.clone();
        without.members.remove(1);
        assert!(
            without.verify_in(&reg).is_err(),
            "a set the sender never signed must not verify"
        );
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
    fn size_limits_and_a_forged_member_are_refused() {
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
        // A member whose signature does not verify is refused, and the
        // refusal names the member rather than the set.
        let mut b = bundle(&acct, 2);
        b.members[0].signature = Some(vec![1]);
        assert_eq!(b.verify_in(&reg), Err(BundleError::Member(0)));

        // A member signed by another key is the same refusal: the witness key
        // is the bundle's signer, and every member has to carry that key.
        let foreign = RootSecret::derive(&[7u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap();
        let theirs = bundle(&foreign, 2);
        let mut spliced = bundle(&acct, 2);
        spliced.members[0].signature = theirs.members[0].signature.clone();
        spliced.members[0].signer_public_key = theirs.members[0].signer_public_key.clone();
        assert_eq!(spliced.verify_in(&reg), Err(BundleError::Member(0)));
    }
}
