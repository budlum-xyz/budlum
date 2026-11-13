//! JSON-RPC bodies and answers for the node's public listener (testnet
//! item 5).
//!
//! Transport-free: the host sends a body this module builds over HTTP (the
//! browser's `fetch`, the platform client on mobile, any HTTP client in Rust)
//! and hands the answer back to the matching reader. The crate gains no
//! network dependency, and the same code runs in wasm and native builds.

fn json_escape_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn strip_hex_prefix(address_hex: &str) -> &str {
    address_hex
        .strip_prefix("0x")
        .or_else(|| address_hex.strip_prefix("0X"))
        .unwrap_or(address_hex)
}

/// A JSON-RPC 2.0 request body. `params` is a JSON array, written as text.
#[must_use]
pub fn request(method: &str, params: &str, id: u64) -> String {
    let safe_method = json_escape_str(method);
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{safe_method}\",\"params\":{params}}}")
}

/// `bud_chainId`.
#[must_use]
pub fn chain_id() -> String {
    request("bud_chainId", "[]", 1)
}

/// `bud_getNonce` of a hex address.
#[must_use]
pub fn get_nonce(address_hex: &str) -> String {
    let address = json_escape_str(strip_hex_prefix(address_hex));
    request("bud_getNonce", &format!("[\"{address}\"]"), 1)
}

/// `bud_getBalance` of a hex address.
#[must_use]
pub fn get_balance(address_hex: &str) -> String {
    let address = json_escape_str(strip_hex_prefix(address_hex));
    request("bud_getBalance", &format!("[\"{address}\"]"), 1)
}

/// `bud_sendRawTransaction` of a signed transaction's JSON
/// (`transfer::signed_transfer_json`).
#[must_use]
pub fn send_raw_transaction(signed_json: &str) -> String {
    request("bud_sendRawTransaction", &format!("[{signed_json}]"), 1)
}

/// `bud_bnsResolve` of a validated `<label>.bud` or `<sub_label>.<label>.bud` name.
///
/// # Errors
///
/// Refuses malformed or non-`.bud` names before constructing the RPC body.
pub fn bns_resolve(name: &str) -> Result<String, String> {
    if !crate::bns::is_valid_resolvable_bud_name(name) {
        return Err(format!("invalid .bud name '{name}'"));
    }
    let escaped = json_escape_str(name);
    Ok(request("bud_bnsResolve", &format!("[\"{escaped}\"]"), 1))
}

/// `bud_bnsResolveFull` of a validated `<label>.bud` name.
///
/// # Errors
///
/// Refuses malformed or non-`.bud` names before constructing the RPC body.
pub fn bns_resolve_full(name: &str) -> Result<String, String> {
    if !crate::bns::is_valid_bud_name(name) {
        return Err(format!("invalid .bud name '{name}'"));
    }
    let escaped = json_escape_str(name);
    Ok(request(
        "bud_bnsResolveFull",
        &format!("[\"{escaped}\"]"),
        1,
    ))
}

/// `bud_bnsGetProof` of a validated `<label>.bud` name.
///
/// # Errors
///
/// Refuses malformed or non-`.bud` names before constructing the RPC body.
pub fn bns_get_proof(name: &str) -> Result<String, String> {
    if !crate::bns::is_valid_bud_name(name) {
        return Err(format!("invalid .bud name '{name}'"));
    }
    let escaped = json_escape_str(name);
    Ok(request("bud_bnsGetProof", &format!("[\"{escaped}\"]"), 1))
}

/// `bud_bnsReverseResolve` of a hex address.
#[must_use]
pub fn bns_reverse_resolve(address_hex: &str) -> String {
    let address = json_escape_str(strip_hex_prefix(address_hex));
    request("bud_bnsReverseResolve", &format!("[\"{address}\"]"), 1)
}

/// Locate a top-level JSON object key outside nested objects, arrays, and
/// string literals, returning the trimmed slice starting at its value.
fn top_level_value<'a>(answer: &'a str, key: &str) -> Option<&'a str> {
    let bytes = answer.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let str_start = i + 1;
                i += 1;
                let mut has_escape = false;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        has_escape = true;
                        i = (i + 2).min(bytes.len());
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                if i >= bytes.len() {
                    return None;
                }
                let str_end = i;
                i += 1;
                if depth == 1 && !has_escape && &answer[str_start..str_end] == key {
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == b':' {
                        i += 1;
                        return answer.get(i..).map(str::trim_start);
                    }
                }
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Read a string or scalar token from the start of a JSON value slice.
fn read_scalar_or_string(rest: &str) -> Option<&str> {
    if let Some(quoted) = rest.strip_prefix('"') {
        let bytes = quoted.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if bytes[i] == b'"' {
                return quoted.get(..i);
            }
            i += 1;
        }
        return None;
    }
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        rest.get(..end)
    }
}

fn has_non_null_error(answer: &str) -> bool {
    let Some(val) = top_level_value(answer, "error") else {
        return false;
    };
    let Some(tok) = val
        .strip_prefix("null")
        .filter(|tail| tail.is_empty() || tail.starts_with([',', '}', ' ', '\t', '\r', '\n']))
    else {
        return true;
    };
    let _ = tok;
    false
}

/// The `result` of an answer as text, or the node's error.
///
/// # Errors
///
/// The answer carries an `error`, or no `result`.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub fn string_result(answer: &str) -> Result<String, String> {
    if has_non_null_error(answer) {
        return Err(format!("the node refused: {answer}"));
    }
    top_level_value(answer, "result")
        .and_then(read_scalar_or_string)
        .map(str::to_string)
        .ok_or_else(|| format!("the answer has no result: {answer}"))
}

/// The `result` of an answer as a number (`0x` quantity or decimal).
///
/// # Errors
///
/// As [`string_result`], or a result that is not a number.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub fn quantity_result(answer: &str) -> Result<u64, String> {
    let text = string_result(answer)?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|e| format!("the result '{text}' is not a number: {e}"))
}

/// Parse a `bud_bnsResolve` JSON-RPC answer into `Ok(None)` (`"result": null`)
/// or a non-zero 32-byte recipient address (`"result": "0x<64hex>"`).
///
/// # Errors
///
/// Refuses RPC error responses, malformed hex, or the zero address.
pub fn optional_address_result(answer: &str) -> Result<Option<[u8; 32]>, String> {
    let text = string_result(answer)?;
    if text == "null" {
        return Ok(None);
    }
    let clean = strip_hex_prefix(&text);
    if clean.len() != 64 {
        return Err(format!("resolved address '{text}' is not 32 bytes"));
    }
    let bytes = hex::decode(clean).map_err(|e| format!("invalid resolved address hex: {e}"))?;
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    if addr == [0u8; 32] {
        return Err("resolved BNS target cannot be the zero address".into());
    }
    Ok(Some(addr))
}

/// Parse a `bud_bnsReverseResolve` JSON-RPC answer into `Ok(None)` (`"result": null`)
/// or a syntax-validated `<label>.bud` primary name.
///
/// # Errors
///
/// Refuses RPC error responses or any returned string that violates `.bud` label rules.
pub fn optional_bud_name_result(answer: &str) -> Result<Option<String>, String> {
    let text = string_result(answer)?;
    if text == "null" {
        return Ok(None);
    }
    if !crate::bns::is_valid_bud_name(&text) {
        return Err(format!("RPC returned invalid reverse .bud name '{text}'"));
    }
    Ok(Some(text))
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

    #[test]
    fn error_is_not_masked_by_error_null_inside_string_or_spaces() {
        // Pretty-printed `"error": null` must succeed rather than false-rejecting.
        let ok_ans = "{\"jsonrpc\": \"2.0\", \"error\": null, \"result\": \"0x10\", \"id\": 1}";
        assert_eq!(quantity_result(ok_ans), Ok(16));
        // Whitespace before `:` on a real error must still be refused.
        let err_ans = "{\"jsonrpc\": \"2.0\", \"error\" : {\"code\": -32000}, \"result\": \"0x1\"}";
        assert!(string_result(err_ans).is_err());
        // A nested `"error":null` substring inside `data` must NOT mask a top-level error.
        let masked =
            "{\"error\":{\"code\":-32000,\"data\":\"\\\"error\\\":null\"},\"result\":\"0x5\"}";
        assert!(string_result(masked).is_err());
    }

    #[test]
    fn address_param_escapes_json_injection_payloads() {
        let injected = "0x11\"],\"method\":\"bud_admin\",\"params\":[\"";
        let body = get_balance(injected);
        assert!(
            !body.contains("\"method\":\"bud_admin\""),
            "escaped address parameter must never break out of the params string literal"
        );
    }

    #[test]
    fn bns_rpc_builders_and_readers_validate_bud_rules_and_reject_zero_or_spoofed_answers() {
        assert_eq!(
            bns_resolve("ayaz.bud").unwrap(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"bud_bnsResolve\",\"params\":[\"ayaz.bud\"]}"
        );
        assert!(bns_resolve("pay.ayaz.bud").is_ok());
        assert!(bns_resolve("ab.bud").is_err());
        assert!(bns_get_proof("ayaz.bud").is_ok());
        assert!(bns_get_proof("pay.ayaz.bud").is_err());

        let addr_ans = format!(
            "{{\"jsonrpc\":\"2.0\",\"result\":\"0x{}\",\"id\":1}}",
            "55".repeat(32)
        );
        assert_eq!(
            optional_address_result(&addr_ans).unwrap(),
            Some([0x55; 32])
        );
        assert_eq!(
            optional_address_result("{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":1}").unwrap(),
            None
        );
        let zero_ans = format!(
            "{{\"jsonrpc\":\"2.0\",\"result\":\"0x{}\",\"id\":1}}",
            "00".repeat(32)
        );
        assert!(optional_address_result(&zero_ans).is_err());

        assert_eq!(
            optional_bud_name_result("{\"jsonrpc\":\"2.0\",\"result\":\"ayaz.bud\",\"id\":1}")
                .unwrap(),
            Some("ayaz.bud".to_string())
        );
        assert!(optional_bud_name_result(
            "{\"jsonrpc\":\"2.0\",\"result\":\"Spoof.bud\",\"id\":1}"
        )
        .is_err());
    }
}
