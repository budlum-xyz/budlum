//! Solana JSON-RPC compatibility gateway (`127.0.0.1:18548`, directive 8.11.1 and
//! 8.11.3, `WP-31`).
//!
//! The gateway is the Solana-facing door of the same node: it answers the method
//! set in [`SOL_METHOD_CLASSES`] over HTTP and WebSocket, hands `sendTransaction`
//! to the SVM foreign door
//! ([`crate::execution::coordinator::foreign::solana::parse_foreign_solana`]) and
//! then to the mempool's `Solana` lane, and routes `requestAirdrop` to the faucet
//! rather than minting anything itself.
//!
//! What it deliberately does NOT do:
//!
//! * It holds no balance. `requestAirdrop` is a request to the faucet (WP-41),
//!   which grants testnet BUD behind its own proof-of-work and its own limits.
//! * It changes no consensus state. Every row is a read, a signed transaction
//!   handed to the mempool, or node-local session state (directive 8.11.1).
//! * It does not evaluate an instruction. An instruction belongs to the SVM worker
//!   (`0x03`); the gateway answers questions about accounts and history and passes
//!   the transaction along.
//!
//! The listener port, the public name (`https://solana.<TESTNET_DOMAIN>`) and the
//! code path are directive 8.11.1's table row for Solana: `127.0.0.1:18548`,
//! `src/rpc/compat/solana`.
//!
//! WIRING: [`SolCompatConfig`] is built from the node's CLI compatibility section
//! and [`SolCompatServer::start`] binds the listener once the SVM worker lands, in
//! the same step the Ethereum gateway binds `18547`. Until then the module is
//! exercised by its tests: the table, the listener split, the airdrop door and the
//! send door, each against the envelope parser it will call.

pub mod method_class;

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::execution::coordinator::foreign::solana::{
    parse_foreign_solana, parse_foreign_solana_base64, ForeignSolanaError, ForeignSolanaTransaction,
};

use self::method_class::{
    check_served_sol_methods, lookup_sol_method, SolMethodClass, SOL_METHOD_CLASSES,
};

/// The loopback listener the Solana gateway serves on (directive 8.11.1).
pub const SOL_DEFAULT_LISTEN: &str = "127.0.0.1:18548";

/// The public host the gateway is published at (directive 8.11.1).
pub const SOL_PUBLIC_HOST: &str = "solana";

/// The JSON-RPC error code for a method this gateway does not serve. The
/// compatibility gateways answer an unlisted method with the standard "method not
/// found" rather than a panic, because a wallet probing an unsupported method is
/// normal, not an attack.
pub const SOL_METHOD_NOT_FOUND: i32 = -32601;

/// The JSON-RPC error code for an argument the parser refused.
pub const SOL_INVALID_PARAMS: i32 = -32602;

/// The JSON-RPC error code for a request this node refuses for its own reasons
/// (a stale blockhash, a replayed signature, the faucet being closed).
pub const SOL_REFUSED: i32 = -32003;

/// Why the gateway refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolStartupError {
    /// The configured listen address is not the loopback one directive 8.11.1
    /// names. A compatibility gateway on a public interface would bypass the
    /// reverse proxy that terminates TLS and applies the rate limits.
    NotLoopback(String),
    /// The served methods and the classification table disagree.
    MethodTable(String),
}

impl core::fmt::Display for SolStartupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLoopback(addr) => write!(
                f,
                "the Solana gateway binds {addr}; directive 8.11.1 puts it on {SOL_DEFAULT_LISTEN}"
            ),
            Self::MethodTable(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for SolStartupError {}

/// The gateway's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolCompatConfig {
    /// The loopback listener.
    pub listen: SocketAddr,
    /// Whether `requestAirdrop` is forwarded to the faucet. Mainnet sets this to
    /// `false` and the method answers [`SOL_METHOD_NOT_FOUND`].
    pub airdrop_enabled: bool,
}

impl Default for SolCompatConfig {
    fn default() -> Self {
        // The default address is directive 8.11.1's loopback pair.
        Self {
            listen: SOL_DEFAULT_LISTEN
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 18548))),
            airdrop_enabled: true,
        }
    }
}

impl SolCompatConfig {
    /// Checks the configuration against the directive before the socket is bound.
    ///
    /// # Errors
    ///
    /// [`SolStartupError::NotLoopback`] when the address is not loopback.
    pub fn validate(&self) -> Result<(), SolStartupError> {
        if self.listen.ip().is_loopback() {
            Ok(())
        } else {
            Err(SolStartupError::NotLoopback(self.listen.to_string()))
        }
    }
}

/// The classification of one incoming call, as the gateway dispatches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolDispatch {
    /// A read this gateway serves.
    Read(SolMethodClass),
    /// `sendTransaction`: the body is a base64 versioned transaction.
    SendTransaction,
    /// `requestAirdrop`: forwarded to the faucet when it is open.
    Airdrop,
    /// A subscription or unsubscribe: node-local session state.
    Subscription(SolMethodClass),
    /// A method outside the table.
    NotFound,
}

/// Classifies one incoming method name.
///
/// `airdrop_enabled` is the faucet's flag: when the faucet is closed the row still
/// exists (so the table stays complete) but the call is answered as not found,
/// which is what a caller sees when a method is not offered.
#[must_use]
pub fn dispatch(method: &str, airdrop_enabled: bool) -> SolDispatch {
    let Some(class) = lookup_sol_method(method) else {
        return SolDispatch::NotFound;
    };
    match method {
        "sendTransaction" => SolDispatch::SendTransaction,
        "requestAirdrop" if airdrop_enabled => SolDispatch::Airdrop,
        "requestAirdrop" => SolDispatch::NotFound,
        _ if method.ends_with("Subscribe") || method.ends_with("Unsubscribe") => {
            SolDispatch::Subscription(class)
        }
        _ => SolDispatch::Read(class),
    }
}

/// The result of the send door: the foreign transaction, or the refusal.
pub type SolSendResult = Result<ForeignSolanaTransaction, ForeignSolanaError>;

/// Parses the body of a `sendTransaction` call.
///
/// `encoded` is the base64 string the method takes. `resolved` and the two windows
/// are the caller's: the address-table entries for this message, the last
/// [`crate::mempool::lanes::SOLANA_BLOCKHASH_WINDOW`] Budlum block digests, and the
/// signature cache the node has already run.
///
/// # Errors
///
/// [`ForeignSolanaError`], from the envelope door.
pub fn parse_send_transaction(
    encoded: &str,
    resolved: &[Vec<[u8; 32]>],
    blockhash_window: &[[u8; 32]],
    seen_signatures: &[[u8; 64]],
) -> SolSendResult {
    parse_foreign_solana_base64(encoded, resolved, blockhash_window, seen_signatures)
}

/// The same door for a caller that already holds the raw bytes.
///
/// # Errors
///
/// [`ForeignSolanaError`], from the envelope door.
pub fn parse_send_transaction_bytes(
    bytes: &[u8],
    resolved: &[Vec<[u8; 32]>],
    blockhash_window: &[[u8; 32]],
    seen_signatures: &[[u8; 64]],
) -> SolSendResult {
    parse_foreign_solana(bytes, resolved, blockhash_window, seen_signatures)
}

/// The JSON-RPC error code and message for a refusal, so the gateway answers with
/// the same code for the same cause every time.
#[must_use]
pub fn error_for(refusal: &ForeignSolanaError) -> (i32, String) {
    let code = match refusal {
        // A malformed transaction is the caller's mistake.
        ForeignSolanaError::Message(_)
        | ForeignSolanaError::Wire(_)
        | ForeignSolanaError::OverPacketSize { .. }
        | ForeignSolanaError::SignatureCount { .. }
        | ForeignSolanaError::InvalidSignerKey { .. } => SOL_INVALID_PARAMS,
        // A well-formed transaction this node will not run is a refusal.
        ForeignSolanaError::StaleBlockhash
        | ForeignSolanaError::ReplayedSignature { .. }
        | ForeignSolanaError::DuplicateSigner { .. }
        | ForeignSolanaError::BadSignature { .. }
        | ForeignSolanaError::TooManyAccounts { .. }
        | ForeignSolanaError::NoPayer
        | ForeignSolanaError::Account(_) => SOL_REFUSED,
    };
    (code, refusal.to_string())
}

/// The served method names, for the startup check.
#[must_use]
pub fn served_methods(airdrop_enabled: bool) -> BTreeSet<&'static str> {
    SOL_METHOD_CLASSES
        .iter()
        .map(|row| row.name)
        .filter(|name| *name != "requestAirdrop" || airdrop_enabled)
        .collect()
}

/// Checks the gateway's method surface against its table and its airdrop flag.
///
/// # Errors
///
/// [`SolStartupError::MethodTable`] when the table is duplicated or the served
/// set has drifted from it.
pub fn check_startup(airdrop_enabled: bool) -> Result<(), SolStartupError> {
    let mut with_airdrop: Vec<&str> = SOL_METHOD_CLASSES.iter().map(|row| row.name).collect();
    if !airdrop_enabled {
        with_airdrop.retain(|name| *name != "requestAirdrop");
    }
    // The table check itself runs over the whole table, so a duplicate row is
    // caught even when the airdrop is closed.
    check_served_sol_methods(SOL_METHOD_CLASSES.iter().map(|row| row.name))
        .map_err(SolStartupError::MethodTable)?;
    if with_airdrop.len() != served_methods(airdrop_enabled).len() {
        return Err(SolStartupError::MethodTable(
            "the served Solana method set drifted from SOL_METHOD_CLASSES".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A one-signer legacy transaction over `blockhash`, with a readonly program.
    fn signed_transfer(key: &SigningKey, blockhash: [u8; 32]) -> Vec<u8> {
        let mut message = vec![1u8, 0, 1, 2];
        message.extend_from_slice(&key.verifying_key().to_bytes());
        message.extend_from_slice(&[0xEEu8; 32]);
        message.extend_from_slice(&blockhash);
        message.push(1);
        message.extend_from_slice(&[1, 1, 0, 1, 0]);
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&key.sign(&message).to_bytes());
        bytes.extend_from_slice(&message);
        bytes
    }

    #[test]
    fn the_default_config_is_the_directive_listener() {
        let config = SolCompatConfig::default();
        assert_eq!(config.listen.to_string(), "127.0.0.1:18548");
        assert!(config.airdrop_enabled);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn a_public_listener_is_refused_before_binding() {
        let config = SolCompatConfig {
            listen: "0.0.0.0:18548".parse().unwrap(),
            airdrop_enabled: true,
        };
        assert!(matches!(
            config.validate(),
            Err(SolStartupError::NotLoopback(_))
        ));
    }

    #[test]
    fn the_startup_check_passes_for_both_airdrop_flags() {
        assert_eq!(check_startup(true), Ok(()));
        assert_eq!(check_startup(false), Ok(()));
    }

    #[test]
    fn dispatch_sends_the_two_doors_where_the_directive_sends_them() {
        assert_eq!(
            dispatch("sendTransaction", true),
            SolDispatch::SendTransaction
        );
        assert_eq!(dispatch("requestAirdrop", true), SolDispatch::Airdrop);
        // A closed faucet answers as a missing method, not as a refusal: the
        // caller should see the same thing as on a node that never had it.
        assert_eq!(dispatch("requestAirdrop", false), SolDispatch::NotFound);
        assert!(matches!(
            dispatch("accountSubscribe", true),
            SolDispatch::Subscription(_)
        ));
        assert!(matches!(
            dispatch("accountUnsubscribe", true),
            SolDispatch::Subscription(_)
        ));
        assert!(matches!(
            dispatch("getBalance", true),
            SolDispatch::Read(row) if row.effect == crate::rpc::compat::ethereum::method_class::CompatEffect::Read
        ));
        assert_eq!(dispatch("getRecentBlockhash", true), SolDispatch::NotFound);
    }

    #[test]
    fn the_send_door_takes_base64_and_refuses_a_stale_blockhash() {
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let blockhash = [0x5Au8; 32];
        let bytes = signed_transfer(&key, blockhash);
        let encoded =
            crate::execution::coordinator::foreign::solana::base64_encode(&bytes);

        let transaction = parse_send_transaction(&encoded, &[], &[blockhash], &[])
            .expect("a valid transfer through the base64 door");
        assert_eq!(transaction.recent_blockhash, blockhash);
        assert_eq!(transaction.signatures.len(), 1);

        // The same bytes through the raw door agree.
        let from_bytes = parse_send_transaction_bytes(&bytes, &[], &[blockhash], &[]).unwrap();
        assert_eq!(transaction, from_bytes);

        // A window without the blockhash is the node's refusal, not a parse error.
        let refusal = parse_send_transaction(&encoded, &[], &[[0u8; 32]], &[]).unwrap_err();
        assert_eq!(error_for(&refusal).0, SOL_REFUSED);
        // A malformed string is the caller's mistake.
        let malformed = parse_send_transaction("not base64!", &[], &[], &[]).unwrap_err();
        assert_eq!(error_for(&malformed).0, SOL_INVALID_PARAMS);
    }

    #[test]
    fn the_error_code_is_stable_per_cause() {
        // Every cause maps to one of two answers, and the message is the refusal's
        // own text so a caller can act on it.
        let stale = ForeignSolanaError::StaleBlockhash;
        let (code, message) = error_for(&stale);
        assert_eq!(code, SOL_REFUSED);
        assert!(message.contains("150-block window"), "{message}");

        let replay = ForeignSolanaError::ReplayedSignature { index: 2 };
        let (code, message) = error_for(&replay);
        assert_eq!(code, SOL_REFUSED);
        assert!(message.contains("2"), "{message}");
    }

    #[test]
    fn the_served_set_follows_the_airdrop_flag() {
        let open = served_methods(true);
        let closed = served_methods(false);
        assert!(open.contains("requestAirdrop"));
        assert!(!closed.contains("requestAirdrop"));
        assert_eq!(open.len(), closed.len() + 1);
    }
}
