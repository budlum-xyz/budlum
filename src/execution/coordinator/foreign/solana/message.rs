//! The unsigned Solana message: legacy, and version 0 with address-table
//! lookups (directive 8.6.1 `SVM` row, 8.6.2 `Solana` row).
//!
//! A `Solana` foreign envelope carries a *versioned transaction*: a compact-`u16`
//! signature count, the signatures, then the message. The message names the
//! accounts it touches by index, so the same transaction runs against a
//! different set of account keys once an address lookup table is resolved. This
//! module parses both message forms and resolves the indexes against the keys
//! the caller supplies, which is the step that turns a message into an ordered
//! account list the runtime can load.
//!
//! The grammar (the runtime's `sanitize` rules, in the same order):
//!
//! * legacy: `header(3)`, `short_vec<account_key>`, `recent_blockhash(32)`,
//!   `short_vec<instruction>`;
//! * versioned: `0x80` (the version byte with the high bit set), `header(3)`,
//!   `short_vec<account_key>`, `recent_blockhash(32)`,
//!   `short_vec<instruction>`, `short_vec<address_table_lookup>`, where a lookup
//!   is `account_key(32)`, `short_vec<writable_index>`,
//!   `short_vec<readonly_index>`;
//! * an instruction is `program_id_index(1)`, `short_vec<account_index>`,
//!   `short_vec<data>`.
//!
//! The checks that make a message loadable are all here and none of them are
//! deferred to the runtime: the header's account counts must add up to the key
//! count, an instruction's program id must name a key, every account index must
//! be in range, a writable lookup must land after the static writable keys, a
//! readonly lookup must land after the static readonly keys, and every lookup
//! index must be less than the number of entries the caller resolved the table
//! to. A message that passes carries the property that no two resolved accounts
//! collide, which the loader checks once the keys are known.

use crate::execution::coordinator::foreign::solana::reader::{ReadError, Reader};

/// The account-key count a legacy message may not exceed (the runtime's
/// `short_vec` bound for account keys).
pub const MAX_ACCOUNT_KEYS: usize = 256;
/// The instruction count one message may carry.
pub const MAX_INSTRUCTIONS: usize = 256;
/// The address-table lookup count one message may carry.
pub const MAX_LOOKUPS: usize = 256;
/// The account indexes one lookup may name.
pub const MAX_LOOKUP_INDEXES: usize = 256;

/// The first three bytes of a message: how to split the keys into signers, and
/// the writable and readonly bands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// How many of the leading keys must sign.
    pub num_required_signatures: u8,
    /// How many of the signer keys are readonly.
    pub num_readonly_signed_accounts: u8,
    /// How many of the non-signer keys are readonly.
    pub num_readonly_unsigned_accounts: u8,
}

/// One instruction: a program and the accounts it reads, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInstruction {
    /// The index of the program's account in the message's key list.
    pub program_id_index: u8,
    /// The accounts the instruction reads, in the order it reads them.
    pub accounts: Vec<u8>,
    /// The instruction data.
    pub data: Vec<u8>,
}

/// One address-table lookup: a table account, then the indexes to load from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageAddressTableLookup {
    /// The lookup table account key.
    pub account_key: [u8; 32],
    /// Indexes into the table's writable band, loaded first.
    pub writable_indexes: Vec<u8>,
    /// Indexes into the table's readonly band, loaded after.
    pub readonly_indexes: Vec<u8>,
}

/// Which message form the bytes carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageVersion {
    /// No version prefix: the original form.
    Legacy,
    /// The `0x80` prefix.
    V0,
}

/// An unsigned, parsed Solana message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Which form the bytes carried.
    pub version: MessageVersion,
    /// The header.
    pub header: MessageHeader,
    /// The account keys the message names itself.
    pub account_keys: Vec<[u8; 32]>,
    /// The recent blockhash the transaction is bounded by.
    pub recent_blockhash: [u8; 32],
    /// The instructions, in order.
    pub instructions: Vec<CompiledInstruction>,
    /// The address-table lookups; empty for a legacy message.
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// The unsigned message grammar refused the bytes.
    Wire(ReadError),
    /// The version byte names a form this node does not run. Sui-style wide
    /// version prefixes and any version above `0` are outside the T-Opening
    /// surface.
    UnknownVersion,
    /// An instruction's program id index does not name an account.
    ProgramIdOutOfRange,
    /// The header's signer and readonly counts do not add up to the key count.
    HeaderInconsistent,
    /// A lookup index is beyond the entries the caller resolved the table to.
    LookupIndexOutOfRange,
    /// The header demands more signers than the message carried signatures for,
    /// or than there are keys.
    NotEnoughSigners,
    /// Two account keys resolve to the same address, so the runtime cannot tell
    /// which one an index means.
    DuplicateAccount,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Wire(inner) => return write!(f, "unsigned message: {inner}"),
            Self::UnknownVersion => "message version is not one this node runs",
            Self::ProgramIdOutOfRange => "instruction program id is not an account",
            Self::HeaderInconsistent => "header account counts do not match the key list",
            Self::LookupIndexOutOfRange => "address table lookup index out of range",
            Self::NotEnoughSigners => "fewer signers than the header requires",
            Self::DuplicateAccount => "the same account is named twice",
        };
        f.write_str(text)
    }
}

impl From<ReadError> for MessageError {
    fn from(inner: ReadError) -> Self {
        Self::Wire(inner)
    }
}

/// The version byte that marks the form after legacy.
const VERSION_PREFIX: u8 = 0x80;
/// The only version value this node runs: `0`.
const VERSION_V0: u8 = 0x00;

impl Message {
    /// Parses the message bytes that follow the signature list.
    ///
    /// # Errors
    ///
    /// [`MessageError`] for the grammar, the version byte and the structural
    /// checks that need no account list. Account resolution is
    /// [`Message::resolve_accounts`].
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut reader = Reader::new(bytes);
        let (version, header) = Self::read_version_and_header(&mut reader)?;
        let account_keys = Self::read_keys(&mut reader)?;
        let recent_blockhash = reader.hash32()?;
        let instructions = Self::read_instructions(&mut reader)?;
        let address_table_lookups = if version == MessageVersion::V0 {
            Self::read_lookups(&mut reader)?
        } else {
            Vec::new()
        };
        reader.finish()?;

        Self::check_header(&header, account_keys.len())?;
        for instruction in &instructions {
            if usize::from(instruction.program_id_index) >= account_keys.len() {
                return Err(MessageError::ProgramIdOutOfRange);
            }
        }
        Ok(Self {
            version,
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups,
        })
    }

    /// Reads the version prefix and the header.
    fn read_version_and_header(
        reader: &mut Reader<'_>,
    ) -> Result<(MessageVersion, MessageHeader), MessageError> {
        let first = *reader.take(1)?.first().ok_or(ReadError::Truncated)?;
        let version = if first & VERSION_PREFIX == VERSION_PREFIX {
            if first & !VERSION_PREFIX != VERSION_V0 {
                return Err(MessageError::UnknownVersion);
            }
            MessageVersion::V0
        } else {
            MessageVersion::Legacy
        };
        // On the legacy form the byte just read is the first header byte; on the
        // versioned form the header starts after it.
        let (required, readonly_signed, readonly_unsigned) = if version == MessageVersion::Legacy {
            (first, reader.u8()?, reader.u8()?)
        } else {
            (reader.u8()?, reader.u8()?, reader.u8()?)
        };
        Ok((
            version,
            MessageHeader {
                num_required_signatures: required,
                num_readonly_signed_accounts: readonly_signed,
                num_readonly_unsigned_accounts: readonly_unsigned,
            },
        ))
    }

    /// Reads the key list, bounded by [`MAX_ACCOUNT_KEYS`].
    fn read_keys(reader: &mut Reader<'_>) -> Result<Vec<[u8; 32]>, MessageError> {
        let count = usize::from(reader.compact_u16()?);
        if count > MAX_ACCOUNT_KEYS {
            return Err(MessageError::Wire(ReadError::BadCompactLength));
        }
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(reader.pubkey()?);
        }
        Ok(keys)
    }

    /// Reads the instruction list, bounded by [`MAX_INSTRUCTIONS`].
    fn read_instructions(reader: &mut Reader<'_>) -> Result<Vec<CompiledInstruction>, MessageError> {
        let count = usize::from(reader.compact_u16()?);
        if count > MAX_INSTRUCTIONS {
            return Err(MessageError::Wire(ReadError::BadCompactLength));
        }
        let mut instructions = Vec::with_capacity(count);
        for _ in 0..count {
            let program_id_index = reader.u8()?;
            let accounts = reader.short_vec()?.to_vec();
            let data = reader.short_vec()?.to_vec();
            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data,
            });
        }
        Ok(instructions)
    }

    /// Reads the address-table lookup list, bounded by [`MAX_LOOKUPS`].
    fn read_lookups(reader: &mut Reader<'_>) -> Result<Vec<MessageAddressTableLookup>, MessageError> {
        let count = usize::from(reader.compact_u16()?);
        if count > MAX_LOOKUPS {
            return Err(MessageError::Wire(ReadError::BadCompactLength));
        }
        let mut lookups = Vec::with_capacity(count);
        for _ in 0..count {
            let account_key = reader.pubkey()?;
            let writable = reader.short_vec()?;
            let readonly = reader.short_vec()?;
            if writable.len() > MAX_LOOKUP_INDEXES || readonly.len() > MAX_LOOKUP_INDEXES {
                return Err(MessageError::Wire(ReadError::BadCompactLength));
            }
            lookups.push(MessageAddressTableLookup {
                account_key,
                writable_indexes: writable.to_vec(),
                readonly_indexes: readonly.to_vec(),
            });
        }
        Ok(lookups)
    }

    /// The header counts must fit inside the key list.
    fn check_header(header: &MessageHeader, key_count: usize) -> Result<(), MessageError> {
        let signers = usize::from(header.num_required_signatures);
        let readonly_signed = usize::from(header.num_readonly_signed_accounts);
        let readonly_unsigned = usize::from(header.num_readonly_unsigned_accounts);
        // Signers are a prefix of the keys, and the readonly unsigned keys are a
        // suffix, so neither may exceed the list and the readonly signers must
        // fit inside the signer prefix.
        if signers > key_count || readonly_signed > signers {
            return Err(MessageError::HeaderInconsistent);
        }
        let unsigned = key_count - signers;
        if readonly_unsigned > unsigned {
            return Err(MessageError::HeaderInconsistent);
        }
        Ok(())
    }

    /// How many writable static keys the message has.
    #[must_use]
    pub fn writable_static_count(&self) -> usize {
        let signers = usize::from(self.header.num_required_signatures);
        let writable_signers = signers.saturating_sub(usize::from(
            self.header.num_readonly_signed_accounts,
        ));
        let unsigned = self.account_keys.len().saturating_sub(signers);
        let writable_unsigned =
            unsigned.saturating_sub(usize::from(self.header.num_readonly_unsigned_accounts));
        writable_signers + writable_unsigned
    }

    /// The ordered account list, with the address-table lookups resolved.
    ///
    /// `resolved` holds one entry per lookup, in message order: the account keys
    /// the caller loaded from that table, indexed the same way the lookup
    /// indexes them. A writable lookup index is an index into the table's keys,
    /// and the runtime re-reads the table at load time, so the caller is the only
    /// party that can say what index `7` means.
    ///
    /// # Errors
    ///
    /// [`MessageError::LookupIndexOutOfRange`] when a lookup index is beyond the
    /// entries supplied for that table, and [`MessageError::DuplicateAccount`]
    /// when the resolved list names one account twice.
    ///
    /// # Panics
    ///
    /// Never: every index is range-checked first.
    pub fn resolve_accounts(
        &self,
        resolved: &[Vec<[u8; 32]>],
    ) -> Result<Vec<[u8; 32]>, MessageError> {
        if resolved.len() != self.address_table_lookups.len() {
            return Err(MessageError::LookupIndexOutOfRange);
        }
        let mut accounts = self.account_keys.clone();
        // Writable lookups come first, then readonly, across every table in
        // message order. The runtime's `LoadedAddresses` keeps the two bands so
        // the writable band can be locked before the readonly one.
        for (lookup, entries) in self.address_table_lookups.iter().zip(resolved) {
            for &index in &lookup.writable_indexes {
                let entry = entries
                    .get(usize::from(index))
                    .ok_or(MessageError::LookupIndexOutOfRange)?;
                accounts.push(*entry);
            }
        }
        for (lookup, entries) in self.address_table_lookups.iter().zip(resolved) {
            for &index in &lookup.readonly_indexes {
                let entry = entries
                    .get(usize::from(index))
                    .ok_or(MessageError::LookupIndexOutOfRange)?;
                accounts.push(*entry);
            }
        }
        // A key named twice makes every index ambiguous: `accounts[3]` and
        // `accounts[9]` would be one lock, so the runtime refuses the message.
        for (position, account) in accounts.iter().enumerate() {
            if accounts[..position].contains(account) {
                return Err(MessageError::DuplicateAccount);
            }
        }
        Ok(accounts)
    }

    /// The indexes that must sign: the first `num_required_signatures` keys.
    #[must_use]
    pub fn signer_indexes(&self) -> core::ops::RangeInclusive<usize> {
        0..=usize::from(self.header.num_required_signatures).saturating_sub(1)
    }

    /// Which of the message's signer slots are readonly.
    #[must_use]
    pub fn readonly_signer_count(&self) -> usize {
        usize::from(self.header.num_readonly_signed_accounts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a legacy message: one signer, one instruction.
    fn legacy_message() -> Vec<u8> {
        let mut bytes = Vec::new();
        // header: 1 signer, 0 readonly signers, 0 readonly unsigned.
        bytes.extend_from_slice(&[1, 0, 0]);
        // one account key.
        bytes.push(1);
        bytes.extend_from_slice(&[7u8; 32]);
        // the recent blockhash.
        bytes.extend_from_slice(&[9u8; 32]);
        // one instruction: program 0, two accounts, three data bytes.
        bytes.push(1);
        bytes.push(0);
        bytes.push(2);
        bytes.extend_from_slice(&[0, 1]);
        bytes.push(3);
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        bytes
    }

    #[test]
    fn legacy_message_parses_and_names_one_signer() {
        let message = Message::parse(&legacy_message()).unwrap();
        assert_eq!(message.version, MessageVersion::Legacy);
        assert_eq!(message.account_keys.len(), 1);
        assert_eq!(message.recent_blockhash, [9u8; 32]);
        assert_eq!(message.instructions.len(), 1);
        assert_eq!(message.instructions[0].program_id_index, 0);
        assert_eq!(message.instructions[0].accounts, vec![0, 1]);
        assert_eq!(message.instructions[0].data, vec![0xAA, 0xBB, 0xCC]);
        assert!(message.address_table_lookups.is_empty());
        assert_eq!(message.resolve_accounts(&[]).unwrap(), vec![[7u8; 32]]);
    }

    #[test]
    fn a_versioned_message_reads_the_v0_prefix() {
        let legacy = legacy_message();
        let mut versioned = Vec::with_capacity(legacy.len() + 3);
        versioned.push(VERSION_PREFIX | VERSION_V0);
        versioned.extend_from_slice(&legacy);
        // No lookups.
        versioned.push(0);
        let message = Message::parse(&versioned).unwrap();
        assert_eq!(message.version, MessageVersion::V0);
        assert_eq!(message.account_keys.len(), 1);
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut bytes = legacy_message();
        bytes[0] = 1;
        let mut versioned = Vec::new();
        versioned.push(VERSION_PREFIX | 0x01);
        versioned.extend_from_slice(&bytes);
        assert_eq!(
            Message::parse(&versioned).unwrap_err(),
            MessageError::UnknownVersion
        );
        // A legacy byte with the high bit set is a version, not a 129-signer
        // header: 0x81 is version 1.
        let mut raw = legacy_message();
        raw[0] = 0x81;
        assert_eq!(Message::parse(&raw).unwrap_err(), MessageError::UnknownVersion);
    }

    #[test]
    fn a_program_id_beyond_the_key_list_is_refused() {
        let mut bytes = legacy_message();
        // The instruction's program id index sits five bytes before the data
        // length and the three data bytes: rewrite it to name key 1.
        let program_at = bytes.len() - 6;
        bytes[program_at] = 1;
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::ProgramIdOutOfRange
        );
    }

    #[test]
    fn an_inconsistent_header_is_refused() {
        // 2 signers over a one-key list.
        let mut bytes = legacy_message();
        bytes[0] = 2;
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::HeaderInconsistent
        );
        // More readonly signers than signers.
        let mut bytes = legacy_message();
        bytes[1] = 2;
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::HeaderInconsistent
        );
        // More readonly unsigned keys than unsigned keys.
        let mut bytes = legacy_message();
        bytes[2] = 1;
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::HeaderInconsistent
        );
    }

    #[test]
    fn trailing_bytes_after_the_message_are_refused() {
        let mut bytes = legacy_message();
        bytes.push(0x00);
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::Wire(ReadError::TrailingBytes)
        );
    }

    #[test]
    fn a_v0_message_resolves_writable_before_readonly() {
        let mut bytes = Vec::new();
        bytes.push(VERSION_PREFIX | VERSION_V0);
        // one signer, no readonly statics.
        bytes.extend_from_slice(&[1, 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        // no instructions.
        bytes.push(0);
        // one lookup: table [5;32], writable [0], readonly [1].
        bytes.push(1);
        bytes.extend_from_slice(&[5u8; 32]);
        bytes.push(1);
        bytes.push(0);
        bytes.push(1);
        bytes.push(1);

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.address_table_lookups.len(), 1);
        assert_eq!(message.address_table_lookups[0].writable_indexes, vec![0]);
        assert_eq!(message.address_table_lookups[0].readonly_indexes, vec![1]);

        let table = vec![[0x11u8; 32], [0x22u8; 32]];
        let accounts = message.resolve_accounts(&[table]).unwrap();
        // The static key first, then the writable band, then the readonly band.
        assert_eq!(accounts, vec![[1u8; 32], [0x11u8; 32], [0x22u8; 32]]);
    }

    #[test]
    fn a_lookup_index_beyond_the_table_is_refused() {
        let mut bytes = Vec::new();
        bytes.push(VERSION_PREFIX | VERSION_V0);
        bytes.extend_from_slice(&[1, 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.push(0);
        bytes.push(1);
        bytes.extend_from_slice(&[5u8; 32]);
        bytes.push(1);
        bytes.push(9); // writable index 9
        bytes.push(0);

        let message = Message::parse(&bytes).unwrap();
        let table = vec![[0x11u8; 32]];
        assert_eq!(
            message.resolve_accounts(&[table]).unwrap_err(),
            MessageError::LookupIndexOutOfRange
        );
        // A count mismatch between lookups and resolved tables is refused too.
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(
            message.resolve_accounts(&[]).unwrap_err(),
            MessageError::LookupIndexOutOfRange
        );
    }

    #[test]
    fn a_duplicate_resolved_account_is_refused() {
        let mut bytes = Vec::new();
        bytes.push(VERSION_PREFIX | VERSION_V0);
        bytes.extend_from_slice(&[1, 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&[1u8; 32]);
        bytes.extend_from_slice(&[2u8; 32]);
        bytes.push(0);
        bytes.push(1);
        bytes.extend_from_slice(&[5u8; 32]);
        bytes.push(1);
        bytes.push(0);
        bytes.push(0);

        let message = Message::parse(&bytes).unwrap();
        // The lookup resolves to the static key: one account named twice.
        let table = vec![[1u8; 32]];
        assert_eq!(
            message.resolve_accounts(&[table]).unwrap_err(),
            MessageError::DuplicateAccount
        );
    }

    #[test]
    fn the_writable_static_count_follows_the_header() {
        let message = Message::parse(&legacy_message()).unwrap();
        // One signer which is writable, no unsigned keys.
        assert_eq!(message.writable_static_count(), 1);
        assert_eq!(message.readonly_signer_count(), 0);
        assert_eq!(message.signer_indexes(), 0..=0);
    }

    #[test]
    fn a_key_list_over_the_bound_is_refused_before_it_is_read() {
        // The count says 257 keys; the body is absent. The bound is checked
        // first, so the failure is the bound and not a short read.
        let bytes = [1u8, 0, 0, 0x81, 0x02];
        assert_eq!(
            Message::parse(&bytes).unwrap_err(),
            MessageError::Wire(ReadError::BadCompactLength)
        );
    }

    #[test]
    fn an_empty_message_is_a_short_read() {
        assert_eq!(
            Message::parse(&[]).unwrap_err(),
            MessageError::Wire(ReadError::Truncated)
        );
    }
}
