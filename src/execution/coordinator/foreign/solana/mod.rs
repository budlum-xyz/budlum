//! The `Foreign::Solana` transaction envelope (directive 8.6.2, the `Solana`
//! row of the foreign envelope table: a versioned transaction, `bincode`,
//! Ed25519, the last 150 Budlum block digests, and the signature replay
//! cache).
//!
//! A Solana foreign transaction is the RAW versioned transaction a Solana wallet
//! already builds: a compact-`u16` signature count, the 64-byte signatures, then
//! the message. No wrapper, no Budlum field, no extra prefix. The wallet that
//! signs it does not know Budlum exists, which is the point of the row: the
//! shape is the one `solana-web3.js`, Anchor and the SPL tooling already emit.
//!
//! Two replay protections hold, and both are needed:
//!
//! * **The recent blockhash.** The message names a recent blockhash. The
//!   caller passes the digests of the last [`SOLANA_BLOCKHASH_WINDOW`] Budlum
//!   blocks, and a message whose blockhash is not among them is stale. The
//!   message also has to name a *Budlum* block: a transaction built against
//!   Solana mainnet names a Solana blockhash and no Budlum block carries it.
//! * **The signature cache.** A signature that already ran cannot run again even
//!   inside the window, so the caller passes the signatures it has seen and this
//!   module refuses a repeat. The mempool lane keeps the same cache
//!   (`LaneReplayRule::SolanaWindow`); the check here is what keeps a duplicate
//!   out of the lane in the first place.
//!
//! The envelope verifies every signature. Ed25519 verification is strict
//! (`verify_strict`), because a non-strict verifier accepts small-order public
//! keys that forge a signature for almost any message; the signer list is a
//! prefix of the account list, and an account that appears twice can never be
//! checked unambiguously, so duplicates are refused before any signature is
//! verified.
//!
//! Instruction semantics are NOT evaluated here: an instruction belongs to the
//! SVM worker (`0x03`). This module answers who signed, which accounts the
//! transaction locks, and who pays.
//!
//! WIRING: the foreign-lane door (`crate::mempool::lanes`, the `Solana` lane
//! row) admits the envelope once the SVM worker lands; the lane already holds
//! the 150-block window and the signature cache this module reads. Until then
//! the module is exercised by its tests, mirroring the scheduler's and the
//! Ethereum envelope's landing.

pub mod message;
pub mod reader;

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::execution::coordinator::foreign::solana::message::{
    Message, MessageError, MessageVersion,
};
use crate::execution::coordinator::foreign::solana::reader::{base58_decode_exact, ReadError};
use crate::mempool::lanes::SOLANA_BLOCKHASH_WINDOW;

/// The most signatures one versioned transaction may carry. The runtime's own
/// `short_vec` bound; a transaction over it cannot be loaded by any SVM.
pub const MAX_SIGNATURES: usize = 64;
/// The most accounts a resolved message may name. The runtime's per-transaction
/// account lock bound.
pub const MAX_RESOLVED_ACCOUNTS: usize = 256;
/// The most bytes one transaction may be, which is the runtime's packet size.
pub const MAX_TRANSACTION_BYTES: usize = 1232;

/// Why a foreign Solana envelope is refused.
#[derive(Debug, Error)]
pub enum ForeignSolanaError {
    /// The transaction is larger than the runtime's packet.
    #[error("transaction is {size} bytes, over the {MAX_TRANSACTION_BYTES}-byte packet")]
    OverPacketSize {
        /// The size the caller handed in.
        size: usize,
    },
    /// The signature list or the message grammar refused the bytes.
    #[error("unsigned message: {0}")]
    Message(#[from] MessageError),
    /// The envelope's own wire reads refused the bytes.
    #[error("envelope: {0}")]
    Wire(#[from] ReadError),
    /// The signature count is over the bound, or does not equal the number of
    /// signatures the header requires.
    #[error("the header requires {required} signatures and the envelope carries {carried}")]
    SignatureCount {
        /// How many the header's signer count requires.
        required: usize,
        /// How many the envelope carried.
        carried: usize,
    },
    /// One signer account appears more than once, so its signature cannot be
    /// attributed.
    #[error("signer account {index} appears twice")]
    DuplicateSigner {
        /// The second position of the repeated signer.
        index: usize,
    },
    /// A signer public key is not a valid Ed25519 verifying key.
    #[error("signer {index} is not a valid Ed25519 key")]
    InvalidSignerKey {
        /// Which signer slot held the key.
        index: usize,
    },
    /// A signature does not verify over the message bytes.
    #[error("signature {index} does not verify over the message")]
    BadSignature {
        /// Which signature slot failed.
        index: usize,
    },
    /// The message names a blockhash outside the window the caller supplied.
    #[error("the recent blockhash is outside the {SOLANA_BLOCKHASH_WINDOW}-block window")]
    StaleBlockhash,
    /// One signature already ran.
    #[error("signature {index} has already been applied")]
    ReplayedSignature {
        /// Which signature slot was seen before.
        index: usize,
    },
    /// A resolved account list is larger than any transaction may lock.
    #[error("{count} accounts, over the {MAX_RESOLVED_ACCOUNTS}-account lock bound")]
    TooManyAccounts {
        /// How many the message resolved to.
        count: usize,
    },
}

/// The account bands a resolved message locks, in the runtime's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaAccountLocks {
    /// Signers that may write.
    pub writable_signers: Vec<[u8; 32]>,
    /// Signers that may only read.
    pub readonly_signers: Vec<[u8; 32]>,
    /// Non-signers that may write.
    pub writable_unsigned: Vec<[u8; 32]>,
    /// Non-signers that may only read.
    pub readonly_unsigned: Vec<[u8; 32]>,
}

impl SolanaAccountLocks {
    /// The four bands in the order the runtime locks them, deduplicated.
    #[must_use]
    pub fn all(&self) -> Vec<[u8; 32]> {
        let mut all = Vec::with_capacity(
            self.writable_signers.len()
                + self.readonly_signers.len()
                + self.writable_unsigned.len()
                + self.readonly_unsigned.len(),
        );
        all.extend_from_slice(&self.writable_signers);
        all.extend_from_slice(&self.readonly_signers);
        all.extend_from_slice(&self.writable_unsigned);
        all.extend_from_slice(&self.readonly_unsigned);
        all
    }
}

/// A parsed, signature-verified foreign Solana transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignSolanaTransaction {
    /// The message form the transaction carried.
    pub version: MessageVersion,
    /// The 64-byte signatures, in signer order.
    pub signatures: Vec<[u8; 64]>,
    /// The signer accounts: the first `num_required_signatures` resolved keys.
    pub signers: Vec<[u8; 32]>,
    /// How many of the trailing signers may only read.
    pub readonly_signers: usize,
    /// The resolved account list: static keys, then the writable lookups, then
    /// the readonly lookups.
    pub accounts: Vec<[u8; 32]>,
    /// How many of the trailing non-signers may only read.
    pub readonly_unsigned: usize,
    /// The recent blockhash the transaction is bounded by.
    pub recent_blockhash: [u8; 32],
    /// The instructions, whose program ids are already checked to name accounts.
    pub instructions: Vec<CompiledInstruction>,
}

impl ForeignSolanaTransaction {
    /// The account bands the transaction locks.
    ///
    /// The first `num_required_signatures` resolved accounts are the signers, of
    /// which the trailing `readonly_signers` may only read. The remaining
    /// accounts are the non-signers, of which the trailing `readonly_unsigned`
    /// may only read.
    ///
    /// # Panics
    ///
    /// Never: the header counts were checked against the key list when the
    /// message was parsed, the resolved list begins with the static keys, and the
    /// signer count is exactly the header's, so every index here is in range.
    #[must_use]
    pub fn locks(&self) -> SolanaAccountLocks {
        let signer_count = self.signers.len();
        let readonly_from = signer_count - self.readonly_signers;
        let rest = &self.accounts[signer_count..];
        let writable_unsigned_count = rest.len() - self.readonly_unsigned;
        SolanaAccountLocks {
            writable_signers: self.signers[..readonly_from].to_vec(),
            readonly_signers: self.signers[readonly_from..].to_vec(),
            writable_unsigned: rest[..writable_unsigned_count].to_vec(),
            readonly_unsigned: rest[writable_unsigned_count..].to_vec(),
        }
    }

    /// The fee payer: the first signer the runtime charges (`accounts[0]`).
    #[must_use]
    pub fn fee_payer(&self) -> Option<[u8; 32]> {
        self.signers.first().copied()
    }

    /// Whether every signature that already ran is new.
    ///
    /// # Errors
    ///
    /// [`ForeignSolanaError::ReplayedSignature`] naming the first signature the
    /// caller's cache already holds.
    pub fn check_replay(&self, seen: &[[u8; 64]]) -> Result<(), ForeignSolanaError> {
        for (index, signature) in self.signatures.iter().enumerate() {
            if seen.contains(signature) {
                return Err(ForeignSolanaError::ReplayedSignature { index });
            }
        }
        Ok(())
    }

    /// Whether the message's blockhash is one of the last
    /// [`SOLANA_BLOCKHASH_WINDOW`] Budlum blocks.
    ///
    /// # Errors
    ///
    /// [`ForeignSolanaError::StaleBlockhash`] when the window does not hold it.
    pub fn check_blockhash(&self, window: &[[u8; 32]]) -> Result<(), ForeignSolanaError> {
        if window.contains(&self.recent_blockhash) {
            Ok(())
        } else {
            Err(ForeignSolanaError::StaleBlockhash)
        }
    }
}

/// Parses a raw versioned transaction and verifies every signature.
///
/// `resolved` holds one entry per address-table lookup, in message order, as
/// [`Message::resolve_accounts`] takes them. `blockhash_window` is the digests of
/// the last [`SOLANA_BLOCKHASH_WINDOW`] Budlum blocks, newest last, and
/// `seen_signatures` is the replay cache.
///
/// The checks, in order, and only these:
///
/// 1. the transaction is at most [`MAX_TRANSACTION_BYTES`];
/// 2. the signature count is at most [`MAX_SIGNATURES`] and equals the header's
///    `num_required_signatures`, so no signature is unaccounted for;
/// 3. the message parses, including its grammar, version, header and account
///    index checks;
/// 4. the first `num_required_signatures` resolved accounts are distinct, so
///    each signature has exactly one key;
/// 5. the recent blockhash is in the window;
/// 6. no signature is in the replay cache;
/// 7. every signature verifies strictly over the message bytes;
/// 8. the resolved account list is at most [`MAX_RESOLVED_ACCOUNTS`].
///
/// # Errors
///
/// [`ForeignSolanaError`], naming the check that refused the transaction.
pub fn parse_foreign_solana(
    bytes: &[u8],
    resolved: &[Vec<[u8; 32]>],
    blockhash_window: &[[u8; 32]],
    seen_signatures: &[[u8; 64]],
) -> Result<ForeignSolanaTransaction, ForeignSolanaError> {
    // 1. The packet bound comes first: a transaction no runtime will load is
    //    not worth parsing, and the read below would be unbounded work.
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ForeignSolanaError::OverPacketSize { size: bytes.len() });
    }

    // 2. The signature list, then the message. Where the message starts is a
    //    function of the signature count, so it is one read.
    let mut reader = reader::Reader::new(bytes);
    let declared = usize::from(reader.compact_u16()?);
    if declared > MAX_SIGNATURES {
        return Err(ForeignSolanaError::Wire(ReadError::BadCompactLength));
    }
    let mut signatures = Vec::with_capacity(declared);
    for _ in 0..declared {
        signatures.push(reader.signature()?);
    }
    let message_bytes = &bytes[bytes.len() - reader.remaining()..];

    // 3. The message.
    let message = Message::parse(message_bytes)?;

    // The header's signer count is what the runtime checks each signature
    // against, so a mismatch means a signature nobody asked for, or a signer
    // nobody signed for. Both are refused.
    let required = usize::from(message.header.num_required_signatures);
    if required != declared {
        return Err(ForeignSolanaError::SignatureCount {
            required,
            carried: declared,
        });
    }

    // 4. The signer keys, distinct.
    let accounts = message.resolve_accounts(resolved)?;
    let signers = accounts[..required].to_vec();
    for (index, key) in signers.iter().enumerate() {
        if signers[..index].contains(key) {
            return Err(ForeignSolanaError::DuplicateSigner { index });
        }
    }

    // 5. Replay: the blockhash window, then the signature cache.
    if !blockhash_window.contains(&message.recent_blockhash) {
        return Err(ForeignSolanaError::StaleBlockhash);
    }
    for (index, signature) in signatures.iter().enumerate() {
        if seen_signatures.contains(signature) {
            return Err(ForeignSolanaError::ReplayedSignature { index });
        }
    }

    // 6. Every signature, strictly.
    for (index, (key, signature)) in signers.iter().zip(&signatures).enumerate() {
        let verifying_key =
            VerifyingKey::from_bytes(key).map_err(|_| ForeignSolanaError::InvalidSignerKey { index })?;
        let signature = Signature::from_bytes(signature);
        verifying_key
            .verify_strict(message_bytes, &signature)
            .map_err(|_| ForeignSolanaError::BadSignature { index })?;
    }

    // 7. The account bound.
    if accounts.len() > MAX_RESOLVED_ACCOUNTS {
        return Err(ForeignSolanaError::TooManyAccounts {
            count: accounts.len(),
        });
    }

    Ok(ForeignSolanaTransaction {
        version: message.version,
        signatures,
        signers,
        readonly_signers: usize::from(message.header.num_readonly_signed_accounts),
        accounts,
        readonly_unsigned: usize::from(message.header.num_readonly_unsigned_accounts),
        recent_blockhash: message.recent_blockhash,
        instructions: message.instructions,
    })
}

/// Parses a versioned transaction from the base64 string `sendTransaction`
/// takes.
///
/// Solana RPC carries the transaction as standard padded base64. The decode is
/// canonical (a non-zero spare bit is refused), so a string has exactly one byte
/// string here.
///
/// # Errors
///
/// [`ForeignSolanaError::Wire`] carrying [`ReadError::BadBase64`] when the string
/// is not canonical base64, and every error [`parse_foreign_solana`] raises.
pub fn parse_foreign_solana_base64(
    encoded: &str,
    resolved: &[Vec<[u8; 32]>],
    blockhash_window: &[[u8; 32]],
    seen_signatures: &[[u8; 64]],
) -> Result<ForeignSolanaTransaction, ForeignSolanaError> {
    let bytes = reader::base64_decode(encoded)?;
    parse_foreign_solana(&bytes, resolved, blockhash_window, seen_signatures)
}

/// Encodes a byte string as standard padded base64, the inverse of the decode.
///
/// Kept here so a test can build the string `sendTransaction` sends without a
/// second base64 implementation drifting from the reader's.
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[(triple >> 18) as usize & 0x3F]));
        out.push(char::from(ALPHABET[(triple >> 12) as usize & 0x3F]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(triple >> 6) as usize & 0x3F])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[triple as usize & 0x3F])
        } else {
            '='
        });
    }
    out
}

/// Decodes a base58 account key, the format wallets and RPC pass around.
///
/// # Errors
///
/// [`ReadError::BadBase58`] outside the alphabet or for a value wider than 32
/// bytes.
pub fn account_key_from_base58(text: &str) -> Result<[u8; 32], ReadError> {
    base58_decode_exact::<32>(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// The window length matches the mempool lane's, because the lane is what
    /// admits these envelopes.
    #[test]
    fn the_blockhash_window_is_the_lane_window() {
        assert_eq!(SOLANA_BLOCKHASH_WINDOW, 150);
    }

    /// One instruction naming the system program, so the message is loadable.
    fn instruction(system_program_index: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(system_program_index);
        bytes.push(1);
        bytes.push(0); // one account, index 0
        bytes.push(4);
        bytes.extend_from_slice(&[2, 0, 0, 0]); // a transfer: 2, lamports
        bytes
    }

    /// Builds a signed legacy transaction: `signers` keys, one instruction.
    fn signed_transaction(
        signers: &[SigningKey],
        blockhash: [u8; 32],
        readonly_signed: u8,
        readonly_unsigned: u8,
    ) -> Vec<u8> {
        // The key list: the signers, then the readonly extras, then the program.
        // The program sits last so that the header's `readonly_unsigned` band
        // covers it, which is the layout every wallet produces: a program account
        // is never written by the instructions that call it.
        let mut keys: Vec<[u8; 32]> = signers
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        for extra in 0..readonly_unsigned {
            keys.push([0x10 + extra; 32]);
        }
        keys.push([0xEE; 32]); // the program's own account, last
        let program_index = u8::try_from(keys.len() - 1).unwrap();

        // The message.
        let mut message = Vec::new();
        message.push(u8::try_from(signers.len()).unwrap());
        message.push(readonly_signed);
        message.push(readonly_unsigned);
        message.push(u8::try_from(keys.len()).unwrap());
        for key in &keys {
            message.extend_from_slice(key);
        }
        message.extend_from_slice(&blockhash);
        message.push(1); // one instruction
        message.extend_from_slice(&instruction(program_index));

        // The signatures over the message.
        let mut transaction = Vec::new();
        transaction.push(u8::try_from(signers.len()).unwrap());
        for key in signers {
            let signature = key.sign(&message);
            transaction.extend_from_slice(&signature.to_bytes());
        }
        transaction.extend_from_slice(&message);
        transaction
    }

    #[test]
    fn a_signed_transfer_parses_and_locks_the_signer() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let blockhash = [0x42u8; 32];
        // The program is a readonly non-signer, so the header says `0, 1`.
        let bytes = signed_transaction(&[key.clone()], blockhash, 0, 1);
        let transaction =
            parse_foreign_solana(&bytes, &[], &[blockhash], &[]).expect("a valid transfer");

        assert_eq!(transaction.version, MessageVersion::Legacy);
        assert_eq!(transaction.signatures.len(), 1);
        assert_eq!(
            transaction.signers,
            vec![key.verifying_key().to_bytes()],
            "the signer is the first account"
        );
        assert_eq!(transaction.recent_blockhash, blockhash);
        assert_eq!(transaction.instructions.len(), 1);

        let locks = transaction.locks();
        assert_eq!(locks.writable_signers.len(), 1, "the payer may write");
        assert!(locks.readonly_signers.is_empty());
        assert_eq!(locks.readonly_unsigned.len(), 1, "the program is readonly");
        assert_eq!(transaction.fee_payer(), Some(key.verifying_key().to_bytes()));
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let blockhash = [0x01u8; 32];
        let mut bytes = signed_transaction(&[key], blockhash, 0, 0);
        // The first signature byte sits right after the count.
        bytes[1] ^= 0xFF;
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[blockhash], &[]),
            Err(ForeignSolanaError::BadSignature { index: 0 })
        ));
    }

    #[test]
    fn a_tampered_message_is_refused() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let blockhash = [0x02u8; 32];
        let mut bytes = signed_transaction(&[key], blockhash, 0, 0);
        // Flip a byte of the instruction data, inside the signed region.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[blockhash], &[]),
            Err(ForeignSolanaError::BadSignature { index: 0 })
        ));
    }

    #[test]
    fn a_stale_blockhash_is_refused() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let blockhash = [0x03u8; 32];
        let bytes = signed_transaction(&[key], blockhash, 0, 0);
        // A window that does not hold the message's blockhash.
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[[0xFFu8; 32]], &[]),
            Err(ForeignSolanaError::StaleBlockhash)
        ));
        // The same transaction clears the window that does hold it, so the
        // refusal above is the blockhash and not something else.
        assert!(parse_foreign_solana(&bytes, &[], &[blockhash], &[]).is_ok());
    }

    #[test]
    fn a_replayed_signature_is_refused() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let blockhash = [0x04u8; 32];
        let bytes = signed_transaction(&[key], blockhash, 0, 0);
        let first = parse_foreign_solana(&bytes, &[], &[blockhash], &[]).unwrap();
        let seen = vec![first.signatures[0]];
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[blockhash], &seen),
            Err(ForeignSolanaError::ReplayedSignature { index: 0 })
        ));
    }

    #[test]
    fn two_signers_both_verify_and_split_their_bands() {
        let payer = SigningKey::from_bytes(&[8u8; 32]);
        let second = SigningKey::from_bytes(&[9u8; 32]);
        let blockhash = [0x05u8; 32];
        // The second signer may only read.
        let bytes = signed_transaction(&[payer.clone(), second.clone()], blockhash, 1, 1);
        let transaction = parse_foreign_solana(&bytes, &[], &[blockhash], &[]).unwrap();
        assert_eq!(transaction.signers.len(), 2);
        let locks = transaction.locks();
        assert_eq!(locks.writable_signers, vec![payer.verifying_key().to_bytes()]);
        assert_eq!(locks.readonly_signers, vec![second.verifying_key().to_bytes()]);
        assert_eq!(transaction.fee_payer(), Some(payer.verifying_key().to_bytes()));
    }

    #[test]
    fn a_signature_count_that_disagrees_with_the_header_is_refused() {
        let key = SigningKey::from_bytes(&[10u8; 32]);
        let blockhash = [0x06u8; 32];
        let mut bytes = signed_transaction(&[key], blockhash, 0, 0);
        // Drop the signature but keep the header's one-signer demand by
        // rewriting the count to 0 and removing 64 bytes.
        bytes[0] = 0;
        bytes.drain(1..65);
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[blockhash], &[]),
            Err(ForeignSolanaError::SignatureCount {
                required: 1,
                carried: 0
            })
        ));
    }

    #[test]
    fn a_transaction_over_the_packet_is_refused_before_parsing() {
        let bytes = vec![0u8; MAX_TRANSACTION_BYTES + 1];
        assert!(matches!(
            parse_foreign_solana(&bytes, &[], &[], &[]),
            Err(ForeignSolanaError::OverPacketSize { .. })
        ));
    }

    #[test]
    fn a_duplicate_signer_is_refused_before_verification() {
        // A one-key message whose only key the caller's static list names twice
        // cannot happen through `resolve_accounts` (it refuses duplicates), so
        // the guard is reached through a lookup that resolves to a signer.
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let blockhash = [0x07u8; 32];
        let bytes = signed_transaction(&[key], blockhash, 0, 0);
        // The resolved list for a message with no lookups must be empty; a
        // non-empty one is a count mismatch and is refused as a lookup error.
        assert!(matches!(
            parse_foreign_solana(&bytes, &[vec![[0u8; 32]]], &[blockhash], &[]),
            Err(ForeignSolanaError::Message(MessageError::LookupIndexOutOfRange))
        ));
    }

    #[test]
    fn the_base64_door_accepts_what_send_transaction_sends() {
        let key = SigningKey::from_bytes(&[12u8; 32]);
        let blockhash = [0x08u8; 32];
        let bytes = signed_transaction(&[key], blockhash, 0, 0);
        let encoded = base64_encode(&bytes);

        let from_base64 = parse_foreign_solana_base64(&encoded, &[], &[blockhash], &[]).unwrap();
        let from_raw = parse_foreign_solana(&bytes, &[], &[blockhash], &[]).unwrap();
        assert_eq!(from_base64, from_raw, "both doors agree on the transaction");

        // The encoder is the reader's inverse on every tail width.
        for length in 0..64usize {
            let bytes: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(
                reader::base64_decode(&base64_encode(&bytes)).unwrap(),
                bytes
            );
        }

        // A non-canonical string is refused at the decode, before any parse.
        assert!(matches!(
            parse_foreign_solana_base64("AB==", &[], &[], &[]),
            Err(ForeignSolanaError::Wire(ReadError::BadBase64))
        ));
    }

    #[test]
    fn an_account_key_decodes_from_the_alphabet() {
        let system = account_key_from_base58("11111111111111111111111111111111").unwrap();
        assert_eq!(system, [0u8; 32]);
        assert_eq!(
            account_key_from_base58("0OIl"),
            Err(ReadError::BadBase58)
        );
    }
}
