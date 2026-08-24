//! The wallet binding descriptor must match what the bindings actually do.
//!
//! Ported from `scripts/check-binding-claims-match-reality.sh`.
//! `WalletBindingCapabilities::bindings_are_wired` claims mobile/wasm
//! bindings are wired; the gate verifies the claim against the feature
//! exports in the code.

use std::fmt::Write as _;
use std::path::Path;

fn strip_block_comments(text: &str) -> String {
    let mut out = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    let mut depth = 0i32;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            continue;
        }
        if depth > 0 {
            i += 1;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn strip_non_code(text: &str) -> String {
    let mut out = String::new();
    for l in text.lines() {
        let idx = l.find("//").unwrap_or(l.len());
        out.push_str(&l[..idx]);
        out.push('\n');
    }
    let out = strip_block_comments(&out);
    // string/char literals -> "" / ''
    let mut out2 = String::new();
    let b = out.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i];
            out2.push(if q == b'"' { '"' } else { '\'' });
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            out2.push(b[i] as char);
            i += 1;
        }
    }
    out2
}

/// The message when `bindings_are_wired` is true but the tree cannot back it.
fn unwired_message(has_mobile: bool, has_browser: bool) -> String {
    let mut missing: Vec<String> = Vec::new();
    if !has_mobile {
        missing.push(format!(
            "no `.udl` file and no `uniffi::{}` or \
             `uniffi::setup_{}`, so nothing reaches Kotlin or Swift",
            "export", "scaffolding"
        ));
    }
    if !has_browser {
        missing.push(format!(
            "no `#[wasm_bind{}gen]` attribute anywhere, so no symbol \
             reaches a browser",
            "gen"
        ));
    }
    format!(
        "`bindings_are_wired` is true and the tree does not support it: {} \
         . This is a capability descriptor, so a caller reads it to \
         decide what it can invoke.",
        missing.join("; ")
    )
}

/// Walk the tree: `.udl` or uniffi exports = mobile, `#[wasm_bindgen]` =
/// browser.
fn scan_bindings(root: &Path) -> (bool, bool) {
    let mut has_mobile = false;
    let mut has_browser = false;
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let n = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if !matches!(n.as_str(), ".git" | "target" | "node_modules") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "udl") {
                has_mobile = true;
            } else if path.extension().is_some_and(|x| x == "rs") {
                if let Ok(body) = std::fs::read_to_string(&path) {
                    let body = strip_non_code(&body);
                    if body.contains(&format!("#[wasm_bind{}gen", "gen")) {
                        has_browser = true;
                    }
                    if body.contains(&format!("uniffi::{}{}", "exp", "ort"))
                        || body.contains(&format!("uniffi::setup_{}", "scaffolding"))
                    {
                        has_mobile = true;
                    }
                }
            }
        }
    }
    (has_mobile, has_browser)
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let f = root.join("crates/wallet-core/src/lib.rs");
    if !f.is_file() {
        return Err(format!("no wallet core at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let code = strip_non_code(&src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    checked += 1;
    if !src.contains("WalletBindingCapabilities") {
        problems.push(
            "wallet-core no longer defines `WalletBindingCapabilities`. If the \
             descriptor was removed the entry here should go with it, in the same \
             commit, with the reason."
                .to_string(),
        );
    } else if !src.contains("bindings_are_wired") {
        problems.push(
            "`WalletBindingCapabilities` has no `bindings_are_wired` field, so \
             this gate cannot tell what the descriptor is claiming. The field was \
             added because the previous flags, `uniffi_mobile` and `wasm_browser`, \
             were hard-coded true with nothing behind them."
                .to_string(),
        );
    } else {
        let claimed = code
            .lines()
            .find(|l| {
                l.contains("bindings_are_wired") && (l.contains(": true") || l.contains(": false"))
            })
            .and_then(|l| {
                let rest = l.rsplit(':').next()?;
                let v = rest.trim();
                let token: String = v
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if token == "true" {
                    Some(true)
                } else if token == "false" {
                    Some(false)
                } else {
                    None
                }
            });
        match claimed {
            None => problems.push(
                "`bindings_are_wired` is never given a literal value this gate can \
                 read. If it became a computed expression, update the gate in the \
                 same commit."
                    .to_string(),
            ),
            Some(false) => {
                // The descriptor is honest: nothing wired. OK.
            }
            Some(true) => {
                checked += 1;
                let (has_mobile, has_browser) = scan_bindings(root);
                let really_wired = has_mobile && has_browser;
                checked += 2;
                if !really_wired {
                    problems.push(unwired_message(has_mobile, has_browser));
                }
            }
        }
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(String::from(
        "binding claims gate OK: descriptor matches the code",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-bc-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("crates/wallet-core/src"));

    // Honest: no binding surface, descriptor says false (value in lib.rs).
    let honest = "pub struct WalletBindingCapabilities {\n    pub bindings_are_wired: bool,\n}\npub const CLAIM: WalletBindingCapabilities = WalletBindingCapabilities { bindings_are_wired: false };\n";
    std::fs::write(dir.join("crates/wallet-core/src/lib.rs"), honest).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: durust descriptor reddedildi"));
    }

    // Claims wired but nothing backs it: must fail.
    let wired = honest.replace("bindings_are_wired: false", "bindings_are_wired: true");
    std::fs::write(dir.join("crates/wallet-core/src/lib.rs"), wired).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: kablosuz 'wired' iddiasi gecti"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "binding-claims canary OK (honest PASSes, an unfounded claim FAILs).",
    ))
}
