//! One signature object of the aggregation layer, checked by `BudISA`
//! code.
//!
//! The code reads four byte strings from fixed cells: the signer (32
//! bytes), the message hash (32 bytes), the public key and the signature.
//! It runs to its end when, and only when,
//!
//! * the signer is the address of the public key, and
//! * the signature is a valid ML-DSA-87 signature of the message hash
//!   under the context string of the chain.
//!
//! Anything else stops the run with a failed assertion. These are the two
//! checks the native verifier of a signature object makes; the claim the
//! object stands for is `(scheme, signer, message hash)`.

use super::asm::{Asm, AsmError};
use super::bytes::{emit_assert_equal, emit_constant, emit_copy};
use super::keccak::{Domain, Keccak, Rate};
use super::mldsa::{MlDsa, DIGEST_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, W1_BYTES};

/// Bytes of an address and of a message hash.
pub const HASH_BYTES: u64 = 32;
/// Cells of one object record: signer, message hash, public key, signature.
pub const OBJECT_CELLS: u64 = 2 * HASH_BYTES + PUBLIC_KEY_BYTES + SIGNATURE_BYTES;

/// What the verifier of an object is built for.
#[derive(Debug, Clone, Copy)]
pub struct ObjectRules<'a> {
    /// The domain tag an address is derived under:
    /// `SHA3-256(tag || public key)`.
    pub address_tag: &'a [u8],
    /// The FIPS 204 context string of the signature, at most 255 bytes.
    pub context: &'a [u8],
}

/// The memory of the object verifier in one program.
#[derive(Debug, Clone, Copy)]
pub struct ObjectVerifier {
    /// First cell of the 32 bytes of the signer.
    pub signer: u64,
    /// First cell of the 32 bytes of the message hash.
    pub message: u64,
    /// First cell of the public key.
    pub public_key: u64,
    /// First cell of the signature.
    pub signature: u64,
    address_in: u64,
    address_len: u64,
    mu_in: u64,
    mu_len: u64,
    w1_in: u64,
    digest: u64,
}

impl ObjectVerifier {
    /// Reserve the memory.
    ///
    /// # Errors
    ///
    /// When the context is longer than 255 bytes.
    pub fn new(asm: &mut Asm, rules: &ObjectRules<'_>) -> Result<Self, AsmError> {
        let tag_len =
            u64::try_from(rules.address_tag.len()).map_err(|_| AsmError::AddressOutOfRange(0))?;
        let context_len = u64::from(
            u8::try_from(rules.context.len()).map_err(|_| AsmError::AddressOutOfRange(0))?,
        );
        let rate = Rate::R136.bytes();
        let signer = asm.alloc(HASH_BYTES);
        let message = asm.alloc(HASH_BYTES);
        // The tag, the key and room for the padding of the two hashes that
        // read the key in place.
        let address_len = tag_len + PUBLIC_KEY_BYTES;
        let address_in = asm.alloc(address_len + rate);
        let signature = asm.alloc(SIGNATURE_BYTES);
        // tr || 0 || len(context) || context || message, and its padding.
        let mu_len = DIGEST_BYTES + 2 + context_len + HASH_BYTES;
        let mu_in = asm.alloc(mu_len + rate);
        // mu || w1, and its padding.
        let w1_in = asm.alloc(DIGEST_BYTES + W1_BYTES + rate);
        let digest = asm.alloc(DIGEST_BYTES);
        Ok(Self {
            signer,
            message,
            public_key: address_in.saturating_add(tag_len),
            signature,
            address_in,
            address_len,
            mu_in,
            mu_len,
            w1_in,
            digest,
        })
    }

    /// Write the constant bytes of the hash inputs. Once per program.
    pub fn emit_init(&self, asm: &mut Asm, rules: &ObjectRules<'_>) {
        emit_constant(asm, self.address_in, rules.address_tag);
        let context_len = u8::try_from(rules.context.len()).unwrap_or(u8::MAX);
        emit_constant(asm, self.mu_in + DIGEST_BYTES, &[0, context_len]);
        emit_constant(asm, self.mu_in + DIGEST_BYTES + 2, rules.context);
    }

    /// Check the object in the four input places. Every cell of them must
    /// already be known to hold a byte.
    pub fn emit_verify(&self, asm: &mut Asm, keccak: &Keccak, mldsa: &MlDsa) {
        // The signer is the address of the key.
        asm.region("address");
        keccak.emit_hash(
            asm,
            self.address_in,
            self.address_len,
            Rate::R136,
            Domain::Sha3,
        );
        keccak.emit_squeeze(asm, None, self.digest, HASH_BYTES / 4);
        emit_assert_equal(asm, self.digest, self.signer, HASH_BYTES);

        // tr = SHAKE256(public key), 64 bytes, straight into the input of
        // mu = SHAKE256(tr || 0 || len(context) || context || message).
        asm.region("message_representative");
        keccak.emit_hash(
            asm,
            self.public_key,
            PUBLIC_KEY_BYTES,
            Rate::R136,
            Domain::Shake,
        );
        keccak.emit_squeeze(asm, None, self.mu_in, DIGEST_BYTES / 4);
        emit_copy(
            asm,
            self.mu_in + self.mu_len - HASH_BYTES,
            self.message,
            HASH_BYTES,
        );
        keccak.emit_hash(asm, self.mu_in, self.mu_len, Rate::R136, Domain::Shake);
        keccak.emit_squeeze(asm, None, self.w1_in, DIGEST_BYTES / 4);

        mldsa.emit_verify_core(
            asm,
            keccak,
            self.public_key,
            self.signature,
            self.w1_in + DIGEST_BYTES,
        );

        // The challenge seed is SHAKE256(mu || w1).
        asm.region("challenge");
        keccak.emit_hash(
            asm,
            self.w1_in,
            DIGEST_BYTES + W1_BYTES,
            Rate::R136,
            Domain::Shake,
        );
        keccak.emit_squeeze(asm, None, self.digest, DIGEST_BYTES / 4);
        emit_assert_equal(asm, self.digest, self.signature, DIGEST_BYTES);
    }
}
