// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe`
// block enters, the build FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! # ai-integrations - the external data adapter skeleton
//!
//! Reusable patterns for connecting to external services under the
//! closed-circuit principle: WebSocket connection management, REST
//! request/response models, batched message parsing and the kill signal.
//!
//! This crate does not open the connection itself; the caller picks the
//! transport (tokio-tungstenite, reqwest and so on). That keeps it
//! dependency-free for tests and for different runtimes.

pub mod rest;
pub mod ws;

/// The most items one batched message may carry.
///
/// Convenience: pub so a sender can size a batch against the same
/// limit the parser in this crate refuses past.
pub const MAX_BATCH_ITEMS: usize = 10_000;

/// The batched message parsing helper: it turns an incoming JSON value into a
/// vector whether it is a single object or an array of objects.
///
/// # Errors
///
/// When the value is neither an array nor an object.
pub fn as_items(value: serde_json::Value) -> Result<Vec<serde_json::Value>, String> {
    match value {
        serde_json::Value::Array(items) if items.len() > MAX_BATCH_ITEMS => Err(format!(
            "batch of {} items exceeds the limit of {MAX_BATCH_ITEMS}",
            items.len()
        )),
        serde_json::Value::Array(items) => Ok(items),
        serde_json::Value::Object(_) => Ok(vec![value]),
        serde_json::Value::Null => Err("expected an object or an array, got null".into()),
        serde_json::Value::Bool(_) => Err("expected an object or an array, got a boolean".into()),
        serde_json::Value::Number(_) => Err("expected an object or an array, got a number".into()),
        serde_json::Value::String(_) => Err("expected an object or an array, got a string".into()),
    }
}

/// Inspects a status message: it recognises the connection and session
/// notifications shaped as `{"T":"success","msg":"connected"}` or
/// `{"T":"success","msg":"authenticated"}`.
#[must_use]
pub fn is_success_connected_or_authed(item: &serde_json::Value) -> bool {
    let is_success = item.get("T").and_then(serde_json::Value::as_str) == Some("success");
    let msg = item
        .get("msg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    is_success && matches!(msg, "connected" | "authenticated")
}

/// Canonical symbol mapping: it looks the given symbol up in the configured
/// list in uppercase; when there is no exact match it tries the form with the
/// last character dropped (some providers send `BTCUSD`/`BTCUSDT` instead of
/// `BTC`).
#[must_use]
pub fn canonical_symbol(symbol: &str, known: &std::collections::BTreeSet<String>) -> String {
    let s = symbol.trim().to_uppercase();
    if known.contains(&s) {
        return s;
    }
    // Try every prefix, longest first. The previous form dropped exactly one
    // character, so `BTCUSD` -> `BTCUS` never matched `BTC` and the documented
    // `BTCUSDT` case could not work either; the suffix is not one character.
    // Longest-first keeps the match greedy: with both `BTC` and `BTCU` known,
    // `BTCUSD` resolves to `BTCU`.
    // `char_indices` keeps the cut on a UTF-8 boundary; `s[..n]` on a byte
    // index would panic mid-character.
    for (i, _) in s.char_indices().rev() {
        if i == 0 {
            break;
        }
        if known.contains(&s[..i]) {
            return s[..i].to_string();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_items_normalizes_scalar_and_array() {
        let single = serde_json::json!({"a": 1});
        assert_eq!(as_items(single).unwrap().len(), 1);
        let many = serde_json::json!([{"a": 1}, {"b": 2}]);
        assert_eq!(as_items(many).unwrap().len(), 2);
        assert!(as_items(serde_json::json!(42)).is_err());
        let oversized =
            serde_json::Value::Array(vec![serde_json::Value::Null; MAX_BATCH_ITEMS + 1]);
        assert!(as_items(oversized).is_err());
        let echoed = as_items(serde_json::json!("secret-token-value")).unwrap_err();
        assert!(!echoed.contains("secret-token-value"));
    }

    #[test]
    fn connection_messages_detected() {
        assert!(is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "connected"})
        ));
        assert!(is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "authenticated"})
        ));
        assert!(!is_success_connected_or_authed(
            &serde_json::json!({"T": "error", "msg": "connected"})
        ));
        assert!(!is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "x"})
        ));
    }

    #[test]
    fn canonical_symbol_matches_trimmed_suffix() {
        let known = std::collections::BTreeSet::from(["BTC".to_string(), "ETH".to_string()]);
        assert_eq!(canonical_symbol(" btc ", &known), "BTC");
        assert_eq!(canonical_symbol("BTCUSD", &known), "BTC");
        assert_eq!(canonical_symbol("ETHUSDT", &known), "ETH");
        assert_eq!(canonical_symbol("SOL", &known), "SOL"); // unknown -> as it is
    }

    #[test]
    fn canonical_symbol_handles_multibyte_input() {
        let known = std::collections::BTreeSet::from(["BTC".to_string()]);
        assert_eq!(canonical_symbol("btc\u{e9}\u{df}", &known), "BTC");
        assert_eq!(canonical_symbol("\u{e9}", &known), "\u{c9}");
    }

    #[test]
    fn should_retry_policy_counts_attempts() {
        let policy = crate::rest::RetryPolicy::default();
        assert!(policy.should_retry(503, 0));
        assert!(!policy.should_retry(503, 2));
        assert!(!policy.should_retry(404, 0));
    }
}
