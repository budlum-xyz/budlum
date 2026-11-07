//! `Foreign::Aptos`: the Move/Aptos foreign envelope (WP-32, 2/N).
//!
//! Directive 8.4.2 fixes the alias of a local account in the Move environment:
//! `SHA3-256(address32 || 0xBD)`. Rule 2 reserves `0xBD` and requires WP-32 to
//! verify that the pinned aptos-core version does not use that byte in its
//! authentication-key scheme table. That verification is real, not asserted in
//! prose: [`APTOS_AUTH_SCHEME_IDS`] is the `Scheme` enum of the pinned commit
//! [`APTOS_FRAMEWORK_COMMIT`], fetched from `types/src/transaction/
//! authenticator.rs` on 2026-11-06 and recorded in
//! `docs/audit/WP32_MOVE_2N_2026-11-06.md` with the exact source lines.
//!
//! Directive 8.6.2 fixes the envelope: chain id 205, a sequence number and an
//! expiration timestamp. BCS (Binary Canonical Serialization) is the wire
//! format of `POST /v1/transactions`. This module implements the bounded,
//! canonical subset the envelope needs: little-endian `u64`, a `u8`, a fixed
//! 32-byte address and a ULEB128-length byte vector. It refuses trailing
//! bytes, non-canonical ULEB128, oversized payloads and any second use of a
//! replay id. No float, no wall clock: the caller passes `now_secs`.
//!
//! WIRING: unwired - `src/rpc/compat/aptos/move_worker.rs` calls [`check_envelope`]
//! before it refuses a BCS transaction by name. The Move VM worker itself
//! (aptos-vm, sequential execution, Block-STM off) is owed to the next
//! delivery; until then every admitted envelope ends in
//! [`AptosRefusal::WorkerUnavailable`], never in a fabricated execution.

use std::collections::BTreeSet;

use sha3::{Digest, Sha3_256};

/// The pinned aptos-core commit whose framework and `Scheme` enum are used.
/// Fetched from `api.github.com/repos/aptos-labs/aptos-core/commits/main` on
/// 2026-11-06. A change of this constant is a framework change, not a config
/// tweak: the scheme-byte verification has to be repeated for the new commit.
pub const APTOS_FRAMEWORK_COMMIT: &str = "81d89f428fe8e4b69d53b4916993e9a930afc37c";

/// The scheme byte reserved for Budlum's Move alias (directive 8.4.2 rule 2).
pub const MOVE_ALIAS_SCHEME_BYTE: u8 = 0xBD;

/// The Aptos chain id of the foreign envelope (directive 8.6.2 / WP-32).
pub const APTOS_CHAIN_ID: u8 = 205;

/// The native door that refuses a Move transaction before the worker runs.
pub const MOVE_WORKER_DOOR: &str = "bud_sendRawTransaction";

/// `Scheme` of the pinned aptos-core `types/src/transaction/authenticator.rs`.
/// `0xBD` (189) is absent: the byte is free for the Budlum Move alias.
pub const APTOS_AUTH_SCHEME_IDS: &[u8] = &[
    0, 1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255,
];

/// The largest BCS payload one envelope may carry. TESTNET-DEFAULT.
pub const MAX_BCS_BYTES: usize = 1024 * 1024;

/// Why a BCS body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcsError {
    /// The body ended before a field was complete.
    UnexpectedEnd,
    /// A ULEB128 length was not written in its shortest form.
    NonCanonicalUleb128,
    /// A declared length exceeds [`MAX_BCS_BYTES`].
    LengthTooLarge,
    /// Bytes remain after the envelope.
    TrailingBytes,
}

/// Why a foreign Aptos envelope was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AptosRefusal {
    /// The chain id is not 205.
    WrongChainId {
        /// The expected id.
        expected: u8,
        /// The id the envelope carried.
        got: u8,
    },
    /// The envelope expired before it was admitted.
    Expired {
        /// The caller's clock.
        now: u64,
        /// The envelope's expiry.
        expires: u64,
    },
    /// This replay id was admitted before.
    Replay,
    /// The pinned framework uses the reserved alias scheme byte.
    SchemeByteReused,
    /// The framework commit is not pinned to a full 40-character hash.
    FrameworkNotPinned,
    /// The BCS body is not canonical.
    BadBcs(BcsError),
    /// The envelope is well-formed but no Move VM worker runs yet.
    WorkerUnavailable {
        /// The native door that answers the same question today.
        door: &'static str,
    },
}

fn sha3_of(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for field in fields {
        hasher.update(*field);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The Move alias of a local 32-byte address (directive 8.4.2).
#[must_use]
pub fn move_alias(local: &[u8; 32]) -> [u8; 32] {
    sha3_of(&[local, &[MOVE_ALIAS_SCHEME_BYTE]])
}

/// Whether the pinned framework leaves the alias scheme byte free.
#[must_use]
pub fn framework_scheme_byte_is_free() -> bool {
    let pinned = APTOS_FRAMEWORK_COMMIT.len() == 40
        && APTOS_FRAMEWORK_COMMIT
            .bytes()
            .all(|b| b.is_ascii_hexdigit());
    pinned && !APTOS_AUTH_SCHEME_IDS.contains(&MOVE_ALIAS_SCHEME_BYTE)
}

fn put_uleb128(out: &mut Vec<u8>, value: usize) {
    let mut rest = value;
    loop {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rest == 0 {
            break;
        }
    }
}

fn take_uleb128(input: &[u8], pos: &mut usize) -> Result<usize, BcsError> {
    let mut value: usize = 0;
    let mut shift = 0u32;
    loop {
        let byte = *input.get(*pos).ok_or(BcsError::UnexpectedEnd)?;
        *pos += 1;
        if shift >= usize::BITS {
            return Err(BcsError::LengthTooLarge);
        }
        value |= usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(BcsError::LengthTooLarge)?;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    // The shortest encoding never ends with a zero payload byte after a
    // continuation: `0x80 0x00` encodes zero in two bytes instead of one.
    if shift > 7 && pos.checked_sub(1).and_then(|i| input.get(i)) == Some(&0) {
        return Err(BcsError::NonCanonicalUleb128);
    }
    if value > MAX_BCS_BYTES {
        return Err(BcsError::LengthTooLarge);
    }
    Ok(value)
}

fn take_u64(input: &[u8], pos: &mut usize) -> Result<u64, BcsError> {
    let end = (*pos).checked_add(8).ok_or(BcsError::UnexpectedEnd)?;
    let bytes: [u8; 8] = input
        .get(*pos..end)
        .ok_or(BcsError::UnexpectedEnd)?
        .try_into()
        .map_err(|_| BcsError::UnexpectedEnd)?;
    *pos = end;
    Ok(u64::from_le_bytes(bytes))
}

fn take_exact(input: &[u8], pos: &mut usize, count: usize) -> Result<Vec<u8>, BcsError> {
    let end = (*pos).checked_add(count).ok_or(BcsError::UnexpectedEnd)?;
    let slice = input
        .get(*pos..end)
        .ok_or(BcsError::UnexpectedEnd)?
        .to_vec();
    *pos = end;
    Ok(slice)
}

/// The BCS body of a `Foreign::Aptos` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosEnvelope {
    /// Aptos chain id, always [`APTOS_CHAIN_ID`].
    pub chain_id: u8,
    /// The sender's sequence number.
    pub sequence_number: u64,
    /// Expiry as a Unix timestamp in seconds.
    pub expiration_timestamp_secs: u64,
    /// The sender's Move alias, 32 bytes.
    pub sender_alias: [u8; 32],
    /// The opaque Move transaction payload.
    pub payload: Vec<u8>,
}

impl AptosEnvelope {
    /// Serialize canonically. The only fallible case is an oversized payload.
    ///
    /// # Errors
    ///
    /// [`BcsError::LengthTooLarge`] above [`MAX_BCS_BYTES`].
    pub fn bcs_encode(&self) -> Result<Vec<u8>, BcsError> {
        if self.payload.len() > MAX_BCS_BYTES {
            return Err(BcsError::LengthTooLarge);
        }
        let mut out = Vec::with_capacity(1 + 8 + 8 + 32 + 5 + self.payload.len());
        out.push(self.chain_id);
        out.extend_from_slice(&self.sequence_number.to_le_bytes());
        out.extend_from_slice(&self.expiration_timestamp_secs.to_le_bytes());
        out.extend_from_slice(&self.sender_alias);
        put_uleb128(&mut out, self.payload.len());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse a canonical BCS body. Trailing bytes are refused.
    ///
    /// # Errors
    ///
    /// [`BcsError`] for a truncated, oversized, non-canonical or trailing body.
    pub fn bcs_decode(input: &[u8]) -> Result<Self, BcsError> {
        if input.len() > MAX_BCS_BYTES.saturating_add(64) {
            return Err(BcsError::LengthTooLarge);
        }
        let mut pos = 0usize;
        let chain_id = *input.get(pos).ok_or(BcsError::UnexpectedEnd)?;
        pos += 1;
        let sequence_number = take_u64(input, &mut pos)?;
        let expiration_timestamp_secs = take_u64(input, &mut pos)?;
        let alias = take_exact(input, &mut pos, 32)?;
        let mut sender_alias = [0u8; 32];
        sender_alias.copy_from_slice(&alias);
        let len = take_uleb128(input, &mut pos)?;
        let payload = take_exact(input, &mut pos, len)?;
        if pos != input.len() {
            return Err(BcsError::TrailingBytes);
        }
        Ok(Self {
            chain_id,
            sequence_number,
            expiration_timestamp_secs,
            sender_alias,
            payload,
        })
    }

    /// The replay id: SHA3-256 of the canonical BCS bytes.
    #[must_use]
    pub fn replay_id(&self) -> [u8; 32] {
        let bytes = self.bcs_encode().unwrap_or_default();
        sha3_of(&[&bytes])
    }
}

/// The node-local set of admitted foreign replay ids.
#[derive(Debug, Clone, Default)]
pub struct ForeignReplayCache {
    seen: BTreeSet<[u8; 32]>,
}

impl ForeignReplayCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a replay id once.
    ///
    /// # Errors
    ///
    /// [`AptosRefusal::Replay`] when the id was admitted before.
    pub fn admit(&mut self, id: [u8; 32]) -> Result<(), AptosRefusal> {
        if !self.seen.insert(id) {
            return Err(AptosRefusal::Replay);
        }
        Ok(())
    }

    /// How many ids the cache holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Check one envelope against the chain id, the clock, the pinned framework
/// and the replay cache. Returns its replay id on success.
///
/// # Errors
///
/// [`AptosRefusal`] naming the first rule the envelope broke.
pub fn check_envelope(
    envelope: &AptosEnvelope,
    now_secs: u64,
    cache: &mut ForeignReplayCache,
) -> Result<[u8; 32], AptosRefusal> {
    if envelope.chain_id != APTOS_CHAIN_ID {
        return Err(AptosRefusal::WrongChainId {
            expected: APTOS_CHAIN_ID,
            got: envelope.chain_id,
        });
    }
    if envelope.expiration_timestamp_secs < now_secs {
        return Err(AptosRefusal::Expired {
            now: now_secs,
            expires: envelope.expiration_timestamp_secs,
        });
    }
    if !framework_scheme_byte_is_free() {
        return Err(AptosRefusal::SchemeByteReused);
    }
    let id = envelope.replay_id();
    cache.admit(id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(expiry: u64) -> AptosEnvelope {
        AptosEnvelope {
            chain_id: APTOS_CHAIN_ID,
            sequence_number: 7,
            expiration_timestamp_secs: expiry,
            sender_alias: move_alias(&[3u8; 32]),
            payload: vec![0xa1, 0xa2, 0xa3],
        }
    }

    #[test]
    fn move_alias_scheme_byte_is_unused() {
        assert_eq!(MOVE_ALIAS_SCHEME_BYTE, 0xBD);
        assert!(framework_scheme_byte_is_free());
        assert!(!APTOS_AUTH_SCHEME_IDS.contains(&MOVE_ALIAS_SCHEME_BYTE));
        // The alias is a hash of the address and the reserved byte, not the
        // address itself, and two addresses do not share an alias.
        assert_ne!(move_alias(&[1u8; 32]), [1u8; 32]);
        assert_ne!(move_alias(&[1u8; 32]), move_alias(&[2u8; 32]));
    }

    #[test]
    fn aptos_framework_commit_is_pinned() {
        assert_eq!(APTOS_FRAMEWORK_COMMIT.len(), 40);
        assert!(APTOS_FRAMEWORK_COMMIT.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn aptos_bcs_round_trip_is_canonical() {
        let env = envelope(500);
        let bytes = env.bcs_encode().unwrap();
        assert_eq!(AptosEnvelope::bcs_decode(&bytes).unwrap(), env);
        // re-encoding a decoded body is byte-identical
        assert_eq!(AptosEnvelope::bcs_decode(&bytes).unwrap().bcs_encode().unwrap(), bytes);
    }

    #[test]
    fn aptos_bcs_refuses_trailing_and_noncanonical_bodies() {
        let mut bytes = envelope(500).bcs_encode().unwrap();
        bytes.push(0);
        assert_eq!(
            AptosEnvelope::bcs_decode(&bytes),
            Err(BcsError::TrailingBytes)
        );
        let mut short = envelope(500).bcs_encode().unwrap();
        short.truncate(10);
        assert_eq!(
            AptosEnvelope::bcs_decode(&short),
            Err(BcsError::UnexpectedEnd)
        );
    }

    #[test]
    fn uel_foreign_tx_replay_refused_aptos() {
        let env = envelope(500);
        let mut cache = ForeignReplayCache::new();
        assert_eq!(check_envelope(&env, 100, &mut cache), Ok(env.replay_id()));
        assert_eq!(
            check_envelope(&env, 100, &mut cache),
            Err(AptosRefusal::Replay)
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn aptos_envelope_refuses_wrong_chain_and_expiry() {
        let mut cache = ForeignReplayCache::new();
        let mut env = envelope(500);
        env.chain_id = 1;
        assert_eq!(
            check_envelope(&env, 100, &mut cache),
            Err(AptosRefusal::WrongChainId {
                expected: APTOS_CHAIN_ID,
                got: 1,
            })
        );
        let env = envelope(50);
        assert_eq!(
            check_envelope(&env, 100, &mut cache),
            Err(AptosRefusal::Expired {
                now: 100,
                expires: 50,
            })
        );
        assert!(cache.is_empty(), "a refused envelope leaves no replay id");
    }
}
