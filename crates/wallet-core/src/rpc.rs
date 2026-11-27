//! JSON-RPC bodies and answers for the node's public listener (testnet
//! item 5).
//!
//! Transport-free: the host sends a body this module builds over HTTP (the
//! browser's `fetch`, the platform client on mobile, any HTTP client in Rust)
//! and hands the answer back to the matching reader. The crate gains no
//! network dependency, and the same code runs in wasm and native builds.

use std::collections::HashSet;

const MAX_RPC_ANSWER_BYTES: usize = 4 * 1024 * 1024;

fn json_escape_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let code = c as u32;
                if code <= 0xFFFF {
                    use std::fmt::Write as _;
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
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

/// A JSON-RPC 2.0 request body. `params` must be a valid JSON array; malformed
/// or non-array text is normalized to `[]` so injected properties can never
/// escape into the outer JSON-RPC envelope.
#[must_use]
pub fn request(method: &str, params: &str, id: u64) -> String {
    let safe_method = json_escape_str(method);
    let safe_params = match serde_json::from_str::<serde_json::Value>(params) {
        Ok(val) if val.is_array() => {
            serde_json::to_string(&val).unwrap_or_else(|_| String::from("[]"))
        }
        _ => String::from("[]"),
    };
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{safe_method}\",\"params\":{safe_params}}}"
    )
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
///
/// Re-serializes a validated single JSON object so malformed or injected input
/// can never break out of the outer JSON-RPC `params` envelope.
#[must_use]
pub fn send_raw_transaction(signed_json: &str) -> String {
    let safe_param = match serde_json::from_str::<serde_json::Value>(signed_json) {
        Ok(val) if val.is_object() => {
            serde_json::to_string(&val).unwrap_or_else(|_| "null".to_string())
        }
        _ => "null".to_string(),
    };
    request("bud_sendRawTransaction", &format!("[{safe_param}]"), 1)
}

/// `bud_bnsResolve` of a validated `<label>.bud` or `<sub_label>.<label>.bud` name.
///
/// # Errors
///
/// Refuses malformed or non-`.bud` names before constructing the RPC body.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
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
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
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
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
pub fn bns_get_proof(name: &str) -> Result<String, String> {
    if !crate::bns::is_valid_bud_name(name) {
        return Err(format!("invalid .bud name '{name}'"));
    }
    let escaped = json_escape_str(name);
    Ok(request("bud_bnsGetProof", &format!("[\"{escaped}\"]"), 1))
}

/// `bud_bnsReverseResolve` of a hex address.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
#[must_use]
pub fn bns_reverse_resolve(address_hex: &str) -> String {
    let address = json_escape_str(strip_hex_prefix(address_hex));
    request("bud_bnsReverseResolve", &format!("[\"{address}\"]"), 1)
}

/// Reject any JSON object that repeats a top-level key (e.g. a non-null
/// `"error"` shadowed by a later `"error": null`, or duplicate `"result"`
/// keys, including Unicode-escaped spellings like `"\u0065rror"`).
///
/// Called only after `serde_json::from_str::<serde_json::Value>` has already
/// confirmed `answer` is syntactically valid RFC 8259 JSON whose root is an
/// object.
fn reject_duplicate_top_level_keys(answer: &str) -> Result<(), String> {
    let bytes = answer.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut expect_key = false;
    let mut seen = HashSet::new();

    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => {
                let start = i;
                i += 1;
                while let Some(&cur) = bytes.get(i) {
                    if cur == b'\\' {
                        i = i.saturating_add(2);
                        continue;
                    }
                    if cur == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if depth == 1 && expect_key {
                    let raw = answer
                        .get(start..i)
                        .ok_or_else(|| "invalid JSON-RPC key slice".to_string())?;
                    let decoded: String = serde_json::from_str(raw)
                        .map_err(|e| format!("invalid JSON-RPC key escape: {e}"))?;
                    if !seen.insert(decoded) {
                        return Err("RPC answer contains duplicate top-level JSON keys".into());
                    }
                    expect_key = false;
                }
            }
            b'{' => {
                depth += 1;
                if depth == 1 {
                    expect_key = true;
                }
                i += 1;
            }
            b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' => {
                if depth == 1 {
                    expect_key = true;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(())
}

/// Strictly parse a JSON-RPC 2.0 answer object, enforcing size limits, valid
/// JSON syntax, unique top-level keys, and fail-closed `error` detection.
fn parse_rpc_result(answer: &str) -> Result<serde_json::Value, String> {
    if answer.len() > MAX_RPC_ANSWER_BYTES {
        return Err(format!(
            "RPC answer exceeds maximum allowed size ({} > {MAX_RPC_ANSWER_BYTES} bytes)",
            answer.len()
        ));
    }
    let parsed: serde_json::Value =
        serde_json::from_str(answer).map_err(|e| format!("RPC answer is not valid JSON: {e}"))?;
    let serde_json::Value::Object(mut map) = parsed else {
        return Err("RPC answer root must be a JSON object".into());
    };
    reject_duplicate_top_level_keys(answer)?;
    if let Some(err_val) = map.get("error") {
        if !err_val.is_null() {
            return Err(format!("the node refused: {answer}"));
        }
    }
    map.remove("result")
        .ok_or_else(|| format!("the answer has no result: {answer}"))
}

/// The `result` of an answer as text, or the node's error.
///
/// # Errors
///
/// The answer carries an `error`, is malformed JSON, or carries no scalar string/number `result`.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub fn string_result(answer: &str) -> Result<String, String> {
    match parse_rpc_result(answer)? {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => Err(format!(
            "the answer result is not a string or number: {answer}"
        )),
    }
}

/// The `result` of an answer as a number (`0x`/`0X` quantity or decimal).
///
/// # Errors
///
/// As [`string_result`], or a result that is not a non-negative integer.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub fn quantity_result(answer: &str) -> Result<u64, String> {
    match parse_rpc_result(answer)? {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| format!("the result '{n}' is not a non-negative integer")),
        serde_json::Value::String(text) => {
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!("the result '{text}' is not a valid hex quantity"));
                }
                u64::from_str_radix(hex, 16)
                    .map_err(|e| format!("the result '{text}' is not a number: {e}"))
            } else {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("the result '{text}' is not a decimal quantity"));
                }
                text.parse::<u64>()
                    .map_err(|e| format!("the result '{text}' is not a number: {e}"))
            }
        }
        other => Err(format!("the result '{other}' is not a number")),
    }
}

/// Parse a `bud_bnsResolve` JSON-RPC answer into `Ok(None)` (`"result": null`)
/// or a non-zero 32-byte recipient address (`"result": "0x<64hex>"`).
///
/// # Errors
///
/// Refuses RPC error responses, malformed hex, string `"null"`, or the zero address.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
pub fn optional_address_result(answer: &str) -> Result<Option<[u8; 32]>, String> {
    match parse_rpc_result(answer)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(text) => {
            let clean = strip_hex_prefix(&text);
            if clean.len() != 64 {
                return Err(format!("resolved address '{text}' is not 32 bytes"));
            }
            let bytes =
                hex::decode(clean).map_err(|e| format!("invalid resolved address hex: {e}"))?;
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&bytes);
            if addr == [0u8; 32] {
                return Err("resolved BNS target cannot be the zero address".into());
            }
            Ok(Some(addr))
        }
        other => Err(format!(
            "resolved address must be a hex string or null, got {other}"
        )),
    }
}

/// Parse a `bud_bnsReverseResolve` JSON-RPC answer into `Ok(None)` (`"result": null`)
/// or a syntax-validated `<label>.bud` primary name.
///
/// # Errors
///
/// Refuses RPC error responses, string `"null"`, or any returned string that violates `.bud` label rules.
/// exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
pub fn optional_bud_name_result(answer: &str) -> Result<Option<String>, String> {
    match parse_rpc_result(answer)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(text) => {
            if !crate::bns::is_valid_bud_name(&text) {
                return Err(format!("RPC returned invalid reverse .bud name '{text}'"));
            }
            Ok(Some(text))
        }
        other => Err(format!(
            "reverse .bud name must be a string or null, got {other}"
        )),
    }
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

    #[test]
    fn walcore02_rpc_blocks_unicode_error_bypass_dup_keys_string_null_and_injection() {
        // 1. Unicode-escaped `"error"` key must NOT bypass error detection.
        let unicode_err =
            r#"{"jsonrpc":"2.0","\u0065rror":{"code":-32000},"result":"0x10","id":1}"#;
        assert!(
            string_result(unicode_err).is_err(),
            "unicode-escaped error key must be refused"
        );
        assert!(
            quantity_result(unicode_err).is_err(),
            "quantity_result must refuse unicode-escaped error key"
        );

        // 2. Duplicate `"error"` keys (non-null shadowed by later null, or vice versa) must be refused.
        let dup_err =
            r#"{"jsonrpc":"2.0","error":{"code":-32000},"error":null,"result":"0x10","id":1}"#;
        assert!(
            string_result(dup_err).is_err(),
            "duplicate top-level error keys must be refused"
        );
        let dup_res = r#"{"jsonrpc":"2.0","result":"0x1","result":"0x2","id":1}"#;
        assert!(
            string_result(dup_res).is_err(),
            "duplicate top-level result keys must be refused"
        );

        // 3. Truncated JSON, trailing garbage, object/array/bool results must be refused.
        for malformed in [
            r#"{"result":"0x10""#,
            r#"{"result":"0x10"} trailing"#,
            r#"{"result":{"nested":1}}"#,
            r#"{"result":[1,2]}"#,
            r#"{"result":true}"#,
            r#"[{"result":"0x10"}]"#,
        ] {
            assert!(
                string_result(malformed).is_err(),
                "malformed/non-scalar RPC answer must be refused: {malformed}"
            );
        }

        // 4. JSON string `"null"` must NOT be confused with JSON `null` in optional readers.
        assert!(
            optional_address_result(r#"{"jsonrpc":"2.0","result":"null","id":1}"#).is_err(),
            "quoted string \"null\" must not decode as Ok(None) address"
        );
        assert!(
            optional_bud_name_result(r#"{"jsonrpc":"2.0","result":"null","id":1}"#).is_err(),
            "quoted string \"null\" must not decode as Ok(None) bud name"
        );

        // 5. Quantity parser rejects `+7`, `0x+7`, negative/float, and accepts `0X1f`.
        for bad_qty in [
            r#"{"result":"+7"}"#,
            r#"{"result":"0x+7"}"#,
            r#"{"result":"0x"}"#,
            r#"{"result":-1}"#,
            r#"{"result":1.5}"#,
        ] {
            assert!(
                quantity_result(bad_qty).is_err(),
                "invalid quantity must be refused: {bad_qty}"
            );
        }
        assert_eq!(quantity_result(r#"{"result":"0X1f"}"#), Ok(31));

        // 6. `send_raw_transaction` must never allow JSON-RPC envelope breakout.
        let evil_tx = r#"{"a":1}],"method":"bud_admin","params":[{"x":1}"#;
        let body = send_raw_transaction(evil_tx);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("send_raw_transaction must always emit valid JSON");
        assert_eq!(parsed["method"], "bud_sendRawTransaction");
        assert!(
            !body.contains("\"method\":\"bud_admin\""),
            "injected method must not break out of params"
        );

        // 7. Oversized RPC answer (> 4 MiB) must be refused before parsing.
        let huge = format!("{{\"result\":\"{}\"}}", "a".repeat(4 * 1024 * 1024 + 1));
        assert!(
            string_result(&huge).is_err(),
            "oversized RPC response must be refused"
        );

        // 8. Unicode-escaped duplicate error key shadowed by later null must be refused.
        let uni_dup =
            r#"{"jsonrpc":"2.0","\u0065rror":{"code":-1},"error":null,"result":"0x1","id":1}"#;
        assert!(
            string_result(uni_dup).is_err(),
            "unicode-escaped duplicate error key must be refused"
        );

        // 9. Control characters in address parameters are escaped as \u00XX, producing valid JSON.
        let ctrl_body = get_balance("0xab\u{0000}cd");
        assert!(ctrl_body.contains("\\u0000"));
        assert!(serde_json::from_str::<serde_json::Value>(&ctrl_body).is_ok());

        // 10. rpc::request must never allow raw `params` text to inject sibling JSON-RPC fields.
        let injected_req = request("bud_getBalance", "[],\"method\":\"bud_evil\"", 7);
        let parsed_req: serde_json::Value =
            serde_json::from_str(&injected_req).expect("request must always emit valid JSON");
        assert_eq!(parsed_req["method"], "bud_getBalance");
        assert!(!injected_req.contains("\"method\":\"bud_evil\""));
    }
}
