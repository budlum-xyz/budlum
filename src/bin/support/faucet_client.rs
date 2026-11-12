//! Shared in-process faucet HTTP client for `bud faucet request` and
//! `budlum-faucet request`.
//!
//! Keeps one proof-of-work and receipt-verification implementation across both
//! binaries without spawning a child executable or consulting `current_exe()`.

use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// TESTNET-DEFAULT: 100 BUD per request.
pub const DEFAULT_AMOUNT_BUD: u64 = 100;

/// Domain tag for the faucet proof-of-work challenge.
const POW_DOMAIN: &[u8] = b"budlum-faucet-v1";

pub fn parse_address(raw: &str) -> Result<Address, String> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err("address must be 32 bytes of hex".into());
    }
    let address = Address::from_hex(hex).map_err(|e| format!("invalid address: {e}"))?;
    if address == Address::zero() {
        return Err("the zero address cannot receive".into());
    }
    Ok(address)
}

pub fn pow_hash(chain_id: u64, token: &[u8; 16], address: &Address, nonce: u64) -> [u8; 32] {
    use sha2_010::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(POW_DOMAIN);
    hasher.update(chain_id.to_le_bytes());
    hasher.update(token);
    hasher.update(address.as_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

pub fn meets_difficulty(hash: &[u8; 32], difficulty_bits: u8) -> bool {
    let mut remaining = difficulty_bits;
    for byte in hash {
        let need = remaining.min(8);
        if byte.leading_zeros() < u32::from(need) {
            return false;
        }
        remaining -= need;
        if remaining == 0 {
            return true;
        }
    }
    true
}

pub async fn request_funds(url: &str, address: &str) -> Result<(), String> {
    let to = parse_address(address)?;
    let base = reqwest::Url::parse(url).map_err(|e| format!("faucet URL: {e}"))?;
    let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (base.scheme() != "https" && !(base.scheme() == "http" && local))
        || base.path() != "/"
        || base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err("faucet URL must be an HTTPS origin (HTTP only on loopback)".into());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let mut challenge_url = base.join("challenge").map_err(|e| e.to_string())?;
    challenge_url
        .query_pairs_mut()
        .append_pair("address", &format!("0x{}", to.to_hex()));
    let response = client
        .get(challenge_url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "faucet challenge refused: HTTP {}",
            response.status()
        ));
    }
    let challenge: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    let token_hex = challenge
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("invalid challenge token")?;
    let raw = hex::decode(token_hex).map_err(|_| "invalid challenge hex")?;
    let token: [u8; 16] = raw.try_into().map_err(|_| "invalid challenge length")?;
    let bits = challenge
        .get("difficulty_bits")
        .and_then(|v| v.as_u64())
        .ok_or("invalid challenge difficulty")?;
    let chain_id = challenge
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or("invalid challenge chain")?;
    let expiry = challenge
        .get("expires_at")
        .and_then(|v| v.as_u64())
        .ok_or("invalid challenge expiry")?;
    if bits == 0 || bits > 20 || chain_id != Network::Testnet.chain_id().value() {
        return Err("unsupported faucet challenge or chain".into());
    }
    let nonce = (0..8_000_000u64)
        .find(|n| {
            meets_difficulty(&pow_hash(chain_id, &token, &to, *n), bits as u8)
                && SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .is_ok_and(|d| d.as_secs() < expiry)
        })
        .ok_or("challenge could not be solved before expiry")?;
    let response = client
        .post(base.join("request").map_err(|e| e.to_string())?)
        .json(&serde_json::json!({
            "address": format!("0x{}", to.to_hex()), "challenge": token_hex, "nonce": nonce
        }))
        .send()
        .await
        .map_err(|e| format!("request failed (submission may have succeeded): {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "faucet request refused: HTTP {}",
            response.status()
        ));
    }
    let receipt: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("invalid receipt: {e}"))?;
    let returned_to = receipt
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or("receipt has no recipient")?;
    let tx_hash = receipt
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .ok_or("receipt has no transaction hash")?;
    if parse_address(returned_to)? != to
        || receipt.get("amount_atoms").and_then(|v| v.as_u64())
            != Some(budlum_core::tokenomics::bud(DEFAULT_AMOUNT_BUD))
        || tx_hash
            .strip_prefix("0x")
            .is_none_or(|h| h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("faucet receipt mismatches recipient, amount or transaction hash".into());
    }
    println!("{}", receipt);
    Ok(())
}
