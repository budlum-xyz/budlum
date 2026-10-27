//! JSON-RPC bodies and answers for the node's public listener (testnet
//! item 5).
//!
//! Transport-free: the host sends a body this module builds over HTTP (the
//! browser's `fetch`, the platform client on mobile, any HTTP client in Rust)
//! and hands the answer back to the matching reader. The crate gains no
//! network dependency, and the same code runs in wasm and native builds.

/// A JSON-RPC 2.0 request body. `params` is a JSON array, written as text.
#[must_use]
pub fn request(method: &str, params: &str, id: u64) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

/// `bud_chainId`.
#[must_use]
pub fn chain_id() -> String {
    request("bud_chainId", "[]", 1)
}

/// `bud_getNonce` of a hex address.
#[must_use]
pub fn get_nonce(address_hex: &str) -> String {
    let address = address_hex.trim_start_matches("0x");
    request("bud_getNonce", &format!("[\"{address}\"]"), 1)
}

/// `bud_getBalance` of a hex address.
#[must_use]
pub fn get_balance(address_hex: &str) -> String {
    let address = address_hex.trim_start_matches("0x");
    request("bud_getBalance", &format!("[\"{address}\"]"), 1)
}

/// `bud_sendRawTransaction` of a signed transaction's JSON
/// (`transfer::signed_transfer_json`).
#[must_use]
pub fn send_raw_transaction(signed_json: &str) -> String {
    request("bud_sendRawTransaction", &format!("[{signed_json}]"), 1)
}

/// The text of the value after `"key":` in `answer`, up to the end of a
/// string or a bare token.
fn field<'a>(answer: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = answer.find(&needle)? + needle.len();
    let rest = answer.get(start..)?.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return quoted.get(..end);
    }
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest.get(..end)
}

/// The `result` of an answer as text, or the node's error.
///
/// # Errors
///
/// The answer carries an `error`, or no `result`.
pub fn string_result(answer: &str) -> Result<String, String> {
    if answer.contains("\"error\":") && !answer.contains("\"error\":null") {
        return Err(format!("the node refused: {answer}"));
    }
    field(answer, "result")
        .map(str::to_string)
        .ok_or_else(|| format!("the answer has no result: {answer}"))
}

/// The `result` of an answer as a number (`0x` quantity or decimal).
///
/// # Errors
///
/// As [`string_result`], or a result that is not a number.
pub fn quantity_result(answer: &str) -> Result<u64, String> {
    let text = string_result(answer)?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|e| format!("the result '{text}' is not a number: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_name_their_method_and_params() {
        assert_eq!(
            get_nonce("0xab"),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"bud_getNonce\",\"params\":[\"ab\"]}"
        );
        assert!(send_raw_transaction("{\"a\":1}").contains("\"params\":[{\"a\":1}]"));
    }

    #[test]
    fn answers_are_read_or_refused() {
        assert_eq!(
            quantity_result("{\"jsonrpc\":\"2.0\",\"result\":\"0x1f\",\"id\":1}"),
            Ok(31)
        );
        assert_eq!(quantity_result("{\"result\":7,\"id\":1}"), Ok(7));
        assert_eq!(
            string_result("{\"result\":\"0xabc\",\"id\":1}"),
            Ok("0xabc".to_string())
        );
        assert!(string_result("{\"error\":{\"code\":-32602},\"id\":1}").is_err());
        assert!(quantity_result("{\"result\":\"x\"}").is_err());
    }
}
