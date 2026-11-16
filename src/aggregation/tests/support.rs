//! A signer for the flow tests: a real ML-DSA-87 wallet key.

use crate::aggregation::envelope::{Envelope, ObjectKind};
use crate::core::address::Address;
use crate::crypto::primitives::WalletKeyPair;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};

/// An account with a key.
pub struct Signer {
    keypair: WalletKeyPair,
}

impl Signer {
    pub fn new(seed: u8) -> Self {
        Self {
            keypair: WalletKeyPair::from_seed(&[seed; 32]),
        }
    }

    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// The envelope of this account's signature over a transaction: the
    /// public key, then the signature a V5 transaction carries.
    pub fn envelope(&self, domain: DomainId, tx_hash: Hash32) -> Envelope {
        let mut payload = self.keypair.public_key_bytes().to_vec();
        payload.extend_from_slice(&self.keypair.sign(crate::crypto::ctx::TX_V5, &tx_hash));
        Envelope {
            kind: ObjectKind::Signature,
            scheme: SchemeId::ML_DSA_87,
            payload,
            tx_hash,
            domain,
        }
    }

    /// A second valid signature of the same transaction, with other bytes:
    /// wallet signing is randomized.
    pub fn envelope_again(&self, domain: DomainId, tx_hash: Hash32) -> Envelope {
        self.envelope(domain, tx_hash)
    }
}
