//! `verify_sig`: the program that checks one signature object and halts.
//!
//! This is [`super::object::ObjectVerifier`] alone in a program: the input
//! is checked to be bytes, the object is verified, the run ends. A run
//! that halts says the object is valid; a failed assertion says it is not.
//! It is the reference the signature chips of phase 2 are compared with,
//! and what the cost of one verification is measured on.
//!
//! WIRING: unwired - a tick is proven over `agg_tick`, which embeds the same verifier; this program is run by the tests and by `benches/agg_tick_steps`, and by the chip work of phase 2 as its oracle.

use super::asm::{Asm, AsmError, Program};
use super::bytes::Bytes;
use super::keccak::Keccak;
use super::mldsa::{MlDsa, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use super::object::{ObjectRules, ObjectVerifier, HASH_BYTES};

/// The program that checks one object and halts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySig {
    /// The bytecode.
    pub program: Program,
    /// First cell of the 32 bytes of the signer.
    pub signer: u64,
    /// First cell of the 32 bytes of the message hash.
    pub message: u64,
    /// First cell of the public key.
    pub public_key: u64,
    /// First cell of the signature.
    pub signature: u64,
}

/// Build the program that checks one object.
///
/// # Errors
///
/// [`AsmError`] when the program does not assemble; with a context of at
/// most 255 bytes it does.
pub fn verify_sig(rules: &ObjectRules<'_>) -> Result<VerifySig, AsmError> {
    let mut asm = Asm::new();
    let keccak = Keccak::new(&mut asm);
    let mldsa = MlDsa::new(&mut asm);
    let bytes = Bytes::new(&mut asm);
    let object = ObjectVerifier::new(&mut asm, rules)?;

    asm.region("init");
    keccak.emit_init(&mut asm);
    object.emit_init(&mut asm, rules);
    bytes.check(&mut asm, object.signer, HASH_BYTES);
    bytes.check(&mut asm, object.message, HASH_BYTES);
    bytes.check(&mut asm, object.public_key, PUBLIC_KEY_BYTES);
    bytes.check(&mut asm, object.signature, SIGNATURE_BYTES);
    object.emit_verify(&mut asm, &keccak, &mldsa);
    asm.halt();

    bytes.emit_subroutines(&mut asm);
    mldsa.emit_subroutines(&mut asm, &keccak);
    keccak.emit_subroutines(&mut asm);
    Ok(VerifySig {
        program: asm.finish()?,
        signer: object.signer,
        message: object.message,
        public_key: object.public_key,
        signature: object.signature,
    })
}
