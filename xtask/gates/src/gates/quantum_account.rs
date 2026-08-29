//! A post-quantum account is only as real as the checks that let it exist.

//!
//! `QuantumAccount` is an ML-DSA-87 key with a guardian set. The address is
//! derived from the public key, so an account whose claimed address does not
//! match its key would be spendable by whoever guessed the pairing; and the
//! guardian rules (threshold within the set, non-empty, a timelock) are what
//! keep recovery from becoming a second owner. `validate_all` is the single
//! place those rules are stated.
//!
//! The gate therefore requires: the address derivation to go through the
//! domain-separated hash rather than a bare key hash, the key field to be
//! typed at the ML-DSA-87 length, the registry to call `validate_all` on
//! both the insert and the replace path, and the seed derivation to refuse a
//! short entropy input instead of stretching it.

use std::fmt::Write as _;
use std::path::Path;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("no {rel} at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

fn body_of(src: &str, name: &str) -> Option<String> {
    let at = src.find(&format!("fn {name}("))?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    let mut out = String::new();
    for ch in src[open..].chars() {
        out.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
            }
            _ => {}
        }
    }
    None
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let acct = read(root, "src/account_abstraction/quantum_account.rs")?;
    let reg = read(root, "src/account_abstraction/registry.rs")?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let addr = body_of(&acct, "address_from_public_key").unwrap_or_default();
    if addr.contains("ADDRESS_DOMAIN") && (addr.contains("Sha3_256") || addr.contains("Sha256")) {
        checked += 1;
    } else {
        problems.push(
            "`address_from_public_key` no longer hashes a domain constant with the key. A bare \
             hash of a public key collides with every other use of the same key, so an address \
             could be reused across purposes the account was never issued for."
                .to_string(),
        );
    }
    if acct.contains("pub pq_public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN]") {
        checked += 1;
    } else {
        problems.push(
            "`pq_public_key` is not typed at `ML_DSA_87_PUBLIC_KEY_LEN`. A length-carrying byte \
             vector lets a smaller, weaker key be presented as a post-quantum one."
                .to_string(),
        );
    }
    let seed = body_of(&acct, "seed_from_entropy").unwrap_or_default();
    if seed.contains("SeedError") && seed.contains("entropy.len()") {
        checked += 1;
    } else {
        problems.push(
            "`seed_from_entropy` no longer inspects the entropy length. SHA3-256 returns 32 \
             bytes whatever it is fed, so a two-byte seed looks strong in the output and is \
             nothing in the wallet."
                .to_string(),
        );
    }
    let guards = body_of(&acct, "guardian_root").unwrap_or_default();
    if guards.contains("guardians") && (guards.contains("Sha3_256") || guards.contains("Sha256")) {
        checked += 1;
    } else {
        problems.push(
            "`guardian_root` is missing or no longer hashes the guardian set. Recovery is only \
             bounded by a commitment the guardians cannot change after the fact."
                .to_string(),
        );
    }
    let calls = reg.matches(".validate_all()").count();
    if calls >= 2 {
        checked += 1;
    } else {
        problems.push(format!(
            "`registry.rs` calls `validate_all` {calls} times. Insert and replace each need it: \
             an account that skips the guard on update can be swapped into a policy that fails \
             the rules while still holding its address."
        ));
    }
    if reg.contains("address_from_public_key(&account.pq_public_key)") {
        checked += 1;
    } else {
        problems.push(
            "the registry no longer re-derives the address from the account's own public key. \
             That line is what makes the claimed owner and the spendable key the same thing."
                .to_string(),
        );
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "quantum account guardrails OK: {checked} checks, domain-separated address, typed \
         ML-DSA-87 key, entropy floor, hashed guardian set, and validate_all on both registry \
         paths"
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-qa-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/account_abstraction")).map_err(|e| e.to_string())?;
    let acct = "pub struct QuantumAccount {\n    pub pq_public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],\n}\n\nimpl QuantumAccount {\n    pub fn address_from_public_key(k: &[u8; ML_DSA_87_PUBLIC_KEY_LEN]) -> [u8; 32] {\n        let mut h = Sha3_256::new();\n        h.update(ADDRESS_DOMAIN_V2);\n        h.update(k);\n        h.finalize().into()\n    }\n    pub fn seed_from_entropy(entropy: &[u8]) -> Result<[u8; 32], SeedError> {\n        if entropy.len() < 16 { return Err(SeedError::TooShort); }\n        Ok(h(entropy))\n    }\n    pub fn guardian_root(guardians: &[[u8; 32]]) -> [u8; 32] {\n        let mut h = Sha3_256::new();\n        for g in guardians { h.update(g); }\n        h.finalize().into()\n    }\n}\n";
    let reg = "impl Registry {\n    pub fn register(&mut self, account: QuantumAccount) -> Result<(), E> {\n        let derived = QuantumAccount::address_from_public_key(&account.pq_public_key);\n        if let Err(reason) = account.validate_all() { return Err(E(reason)); }\n        self.insert(derived, account);\n        Ok(())\n    }\n    pub fn replace(&mut self, candidate: QuantumAccount) -> Result<(), E> {\n        if let Err(reason) = candidate.validate_all() { return Err(E(reason)); }\n        Ok(())\n    }\n}\n";
    std::fs::write(dir.join("src/account_abstraction/quantum_account.rs"), acct).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/account_abstraction/registry.rs"), reg).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a guarded account was refused"));
    }
    let no_update = reg.replace("if let Err(reason) = candidate.validate_all() { return Err(E(reason)); }\n        ", "");
    std::fs::write(dir.join("src/account_abstraction/registry.rs"), no_update).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unguarded replace path passed"));
    }
    std::fs::write(dir.join("src/account_abstraction/registry.rs"), reg).map_err(|e| e.to_string())?;
    let bare = acct.replace("        h.update(ADDRESS_DOMAIN_V2);\n", "");
    std::fs::write(dir.join("src/account_abstraction/quantum_account.rs"), bare).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an address derived from a bare key passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "quantum account canary OK (guarded tree PASSes; an unguarded replace and an \
         undivided address hash each FAIL).",
    ))
}
