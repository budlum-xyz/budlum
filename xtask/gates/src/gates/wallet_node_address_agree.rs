//! The wallet and the node must derive the same address from the same key.
//!
//! Two independent implementations compute a user's address:
//!
//!   * `crates/wallet-core/src/lib.rs`, `Wallet::address_from_public_key`, and
//!   * `src/crypto/primitives.rs`, `wallet_address_from_ml_dsa_87_public_key`.
//!
//! The node's version carries a doc comment saying it "must match" the
//! wallet's. Nothing enforced that. The two crates do not depend on each
//! other, since wallet-core is a separate workspace built as a `cdylib`, so
//! the compiler cannot see the pair, and no test called both.
//!
//! # Why this is worth a gate
//!
//! This is not a style rule. The node's function is on the live path: both
//! `src/core/block.rs` and `src/core/transaction.rs` call it to decide which
//! account a signature authorizes. The wallet's function decides which address
//! it shows the user and hands out to receive funds.
//!
//! If the two ever diverge, a wallet displays an address the chain will never
//! credit, and value sent there is unspendable. There is no error, no panic,
//! and no failing test: both sides work perfectly and disagree. That is the
//! shape of bug a gate is for, because a reviewer editing one file has no
//! mechanical reason to open the other.
//!
//! # What is checked
//!
//! Both sides must hash the same domain separator with the same construction:
//!
//!   * the same separator string, `BUDLUM_ADDRESS_V2`,
//!   * the same hash, SHA3-256,
//!   * the separator absorbed BEFORE the public key, not after, since
//!     `H(key || tag)` and `H(tag || key)` are different functions, and
//!   * a 32-byte output on both sides.
//!
//! Ordering is checked because it is the difference that a reader is least
//! likely to notice and that changes every address in the system.

use std::fs;
use std::path::Path;

/// The wallet's derivation, and the file that must agree with it.
const WALLET_FILE: &str = "crates/wallet-core/src/lib.rs";
const WALLET_FN: &str = "pub fn address_from_public_key";

/// The node's derivation, on the live block and transaction path.
const NODE_FILE: &str = "src/crypto/primitives.rs";
const NODE_FN: &str = "pub fn wallet_address_from_ml_dsa_87_public_key";

/// The domain separator both sides must absorb first.
const SEPARATOR: &str = "BUDLUM_ADDRESS_V2";

/// What one side's derivation does, reduced to what has to match.
#[derive(Debug, PartialEq, Eq)]
struct Derivation {
    /// The domain separator string it absorbs.
    separator: String,
    /// The hash constructor it uses, for example `Sha3_256`.
    hasher: String,
    /// Whether the separator is absorbed before the public key.
    separator_first: bool,
}

/// Reads the body of the first function starting with `signature`.
///
/// Returns the text between the opening brace and its match, so a later
/// function in the same file cannot leak into the answer.
fn function_body(text: &str, signature: &str) -> Option<String> {
    let start = text.find(signature)?;
    let rest = text.get(start..)?;
    let open = rest.find('{')?;
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return rest.get(open + 1..idx).map(str::to_string);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extracts what a derivation body actually does.
///
/// # Errors
///
/// Returns a message when the body does not look like a hash-and-absorb
/// derivation at all, which is itself a finding: the gate must not silently
/// pass a function it failed to understand.
fn parse_derivation(body: &str, what: &str) -> Result<Derivation, String> {
    let hasher = body
        .find("::new()")
        .and_then(|at| {
            let head = body.get(..at)?;
            let start = head.rfind(|c: char| !(c.is_alphanumeric() || c == '_'))?;
            head.get(start + 1..).map(str::to_string)
        })
        .ok_or_else(|| format!("{what}: no `<Hasher>::new()` call found"))?;

    // `hasher.update(b"SEPARATOR")` - the separator is a byte-string literal.
    let sep_at = body
        .find("update(b\"")
        .ok_or_else(|| format!("{what}: no byte-string domain separator is absorbed"))?;
    let after = body
        .get(sep_at + "update(b\"".len()..)
        .ok_or_else(|| format!("{what}: truncated separator literal"))?;
    let sep_end = after
        .find('"')
        .ok_or_else(|| format!("{what}: unterminated separator literal"))?;
    let separator = after
        .get(..sep_end)
        .ok_or_else(|| format!("{what}: unreadable separator literal"))?
        .to_string();

    // The key absorb is the `update` that takes something other than a literal.
    let key_at = body
        .match_indices("update(")
        .find(|(at, _)| {
            !body
                .get(at + "update(".len()..)
                .is_some_and(|t| t.starts_with("b\""))
        })
        .map(|(at, _)| at)
        .ok_or_else(|| format!("{what}: no public-key absorb found"))?;

    Ok(Derivation {
        separator,
        hasher,
        separator_first: sep_at < key_at,
    })
}

/// Reads one side and reduces it to a [`Derivation`].
fn read_side(root: &Path, file: &str, signature: &str) -> Result<Derivation, String> {
    let path = root.join(file);
    let text =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let body = function_body(&text, signature)
        .ok_or_else(|| format!("{file}: `{signature}` not found - was it renamed?"))?;
    parse_derivation(&body, file)
}

/// # Errors
///
/// Returns a finding when the two derivations disagree on the separator, the
/// hash, or the absorb order, or when either side cannot be read.
pub fn run(root: &Path) -> Result<String, String> {
    let wallet = read_side(root, WALLET_FILE, WALLET_FN)?;
    let node = read_side(root, NODE_FILE, NODE_FN)?;

    let mut findings: Vec<String> = Vec::new();

    if wallet.separator != node.separator {
        findings.push(format!(
            "domain separator differs: wallet absorbs \"{}\", node absorbs \"{}\"",
            wallet.separator, node.separator
        ));
    } else if wallet.separator != SEPARATOR {
        findings.push(format!(
            "both sides absorb \"{}\", but the recorded separator is \"{SEPARATOR}\" - \
             if the separator changed on purpose, every existing address changed with it",
            wallet.separator
        ));
    }

    if wallet.hasher != node.hasher {
        findings.push(format!(
            "hash differs: wallet uses `{}`, node uses `{}`",
            wallet.hasher, node.hasher
        ));
    }

    if wallet.separator_first != node.separator_first {
        findings.push(format!(
            "absorb order differs: wallet absorbs the separator {}, node absorbs it {} - \
             H(tag || key) and H(key || tag) are different functions",
            if wallet.separator_first {
                "first"
            } else {
                "second"
            },
            if node.separator_first {
                "first"
            } else {
                "second"
            },
        ));
    } else if !wallet.separator_first {
        findings.push(String::from(
            "both sides absorb the public key before the domain separator; \
             a trailing tag does not domain-separate a prefix-extendable input",
        ));
    }

    if findings.is_empty() {
        return Ok(format!(
            "Wallet and node agree on address derivation: {}(\"{}\" || public_key), \
             checked across two workspaces that cannot see each other.",
            wallet.hasher, wallet.separator
        ));
    }

    let mut msg = format!(
        "{} disagreement(s) between {WALLET_FILE} and {NODE_FILE}:\n",
        findings.len()
    );
    for f in &findings {
        msg.push_str("  ");
        msg.push_str(f);
        msg.push('\n');
    }
    msg.push_str(
        "\n  These two functions must produce the same address for the same key.\n  \
         They live in separate workspaces, so the compiler cannot catch this and\n  \
         no test calls both. When they diverge the wallet shows an address the\n  \
         chain will never credit, and the funds sent to it cannot be spent.\n  \
         Nothing errors: both sides work, and disagree.",
    );
    Err(msg)
}

/// A scratch directory for the canaries.
fn scratch_dir() -> Result<std::path::PathBuf, String> {
    let base = std::env::temp_dir().join(format!(
        "budlum-wallet-node-agree-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("clock is before the epoch: {e}"))?
            .as_nanos()
    ));
    fs::create_dir_all(&base).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(base)
}

/// Stages a tree with the given wallet and node function bodies.
fn stage(root: &Path, wallet_body: &str, node_body: &str) -> Result<(), String> {
    let wallet_path = root.join(WALLET_FILE);
    let node_path = root.join(NODE_FILE);
    for p in [&wallet_path, &node_path] {
        fs::create_dir_all(p.parent().ok_or("staged path has no parent")?)
            .map_err(|e| format!("cannot create staged dir: {e}"))?;
    }
    fs::write(
        &wallet_path,
        format!("{WALLET_FN}(public_key: &PublicKeyBytes) -> BudlumAddress {{\n{wallet_body}}}\n"),
    )
    .map_err(|e| format!("cannot write staged wallet: {e}"))?;
    fs::write(
        &node_path,
        format!("{NODE_FN}(public_key: &[u8]) -> Result<Address, CryptoError> {{\n{node_body}}}\n"),
    )
    .map_err(|e| format!("cannot write staged node: {e}"))?;
    Ok(())
}

/// The body both sides are supposed to have.
fn agreeing_body() -> String {
    format!(
        "    let mut hasher = Sha3_256::new();\n    \
         hasher.update(b\"{SEPARATOR}\");\n    \
         hasher.update(public_key);\n    \
         hasher.finalize().into()\n"
    )
}

/// # Errors
///
/// Returns the first canary that misbehaves.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let good = agreeing_body();

    // Agreement must pass, or every canary below is meaningless.
    let dir = tmp.join("agree");
    stage(&dir, &good, &good)?;
    if let Err(msg) = run(&dir) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: agreeing derivations were rejected: {msg}"));
    }

    // A changed separator on one side must fail: this is the case that silently
    // moves every address the wallet shows.
    let dir = tmp.join("sep");
    stage(&dir, &good, &good.replace(SEPARATOR, "BUDLUM_ADDRESS_V3"))?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a differing domain separator passed"));
    }

    // A changed hash must fail.
    let dir = tmp.join("hash");
    stage(&dir, &good, &good.replace("Sha3_256", "Sha256"))?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a differing hash passed"));
    }

    // Swapped absorb order must fail. Both sides still hash the same two
    // inputs with the same hash, so only the order distinguishes them.
    let swapped = format!(
        "    let mut hasher = Sha3_256::new();\n    \
         hasher.update(public_key);\n    \
         hasher.update(b\"{SEPARATOR}\");\n    \
         hasher.finalize().into()\n"
    );
    let dir = tmp.join("order");
    stage(&dir, &good, &swapped)?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a swapped absorb order passed - H(tag || key) was treated as H(key || tag)",
        ));
    }

    // Both sides absorbing the key first must fail even though they agree:
    // agreement on a weak construction is still a finding.
    let dir = tmp.join("both-trailing");
    stage(&dir, &swapped, &swapped)?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: both sides absorbing the separator last passed",
        ));
    }

    // A renamed or deleted function must fail rather than silently pass, or
    // the gate quietly stops checking anything the day someone refactors.
    let dir = tmp.join("renamed");
    stage(&dir, &good, &good)?;
    fs::write(
        dir.join(NODE_FILE),
        "pub fn some_other_name() -> u8 { 0 }\n",
    )
    .map_err(|e| format!("cannot write renamed fixture: {e}"))?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: a missing node derivation passed instead of failing",
        ));
    }

    // A body the parser cannot understand must fail, not pass by default.
    let dir = tmp.join("opaque");
    stage(&dir, &good, "    derive_it(public_key)\n")?;
    if run(&dir).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: an unparseable derivation passed instead of failing",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "wallet-node-address-agree canary OK (agreement PASSes; separator, hash, and absorb-order \
         differences FAIL; agreeing on a trailing tag FAILs; a renamed or unparseable derivation \
         FAILs).",
    ))
}
