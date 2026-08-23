//! Pollen sells permission. B.U.D. serves bytes. They were built separately
//! and nothing joined them, so the same object could be listed for sale here
//! and fetched from storage by anyone who knew its `manifest_id`, with the
//! second path asking no questions.
//!
//! Ported from `scripts/check-paid-content-cannot-be-read-for-free.sh`.
//!
//! # What is checked
//!
//! 1. The read path refuses when no grant is presented (`GrantRequired` in
//!    `authorize_read`).
//! 2. Protected content can never be declared public
//!    (`ProtectedCannotBePublic` in `check_may_be_public`).
//! 3. The binding is one-way: no `bindings.remove/clear/retain` and no
//!    `fn unbind/unprotect/release_content`.
//! 4. The registry offers `authorize_content_read` for the storage layer to
//!    call, and `protected_content` is hashed into the registry root.
//! 5. The declaration path actually calls `check_content_may_be_public`.
//! 6. Every RPC endpoint that publishes a shard id asks Pollen first.
//! 7. The AI runtime cannot reach storage bytes except through Pollen.

use std::fmt::Write as _;
use std::path::Path;

/// Blank line comments, mirroring `sed 's://.*::'` and `re.sub("//[^\n]*")`.
fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    out
}

/// The lines from the first line containing `start` through the line equal to
/// `end`, mirroring awk's `/start/,/^end$/` range.
fn awk_range(src: &str, start: &str, end: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut s = None;
    let mut e = None;
    for (i, line) in lines.iter().enumerate() {
        if s.is_none() && line.contains(start) {
            s = Some(i);
        }
        if s.is_some() && *line == end {
            e = Some(i);
            break;
        }
    }
    let Some(s) = s else {
        return String::new();
    };
    let e = e.unwrap_or(lines.len().saturating_sub(1));
    lines[s..=e].join("\n")
}

/// `grep -cE 'needle'` over an awk range: the number of matching lines.
fn count_in_range(src: &str, start: &str, end: &str, needle: &str) -> usize {
    awk_range(src, start, end)
        .lines()
        .filter(|l| l.contains(needle))
        .count()
}

/// Lines matching `bindings\.(remove|clear|retain)|fn (unbind|unprotect|release_content)`
/// after comments are stripped.
fn unbind_lines(src: &str) -> Vec<(usize, String)> {
    let stripped = strip_line_comments(src);
    let mut out = Vec::new();
    for (i, line) in stripped.lines().enumerate() {
        let l = line;
        let binding_hit = ["remove", "clear", "retain"]
            .iter()
            .any(|op| l.contains(&format!("bindings.{op}")));
        let fn_hit = ["unbind", "unprotect", "release_content"]
            .iter()
            .any(|n| l.contains(&format!("fn {n}")));
        if binding_hit || fn_hit {
            out.push((i + 1, line.to_string()));
        }
    }
    out
}

/// Endpoint names whose body emits a shard id without a Pollen check.
/// Names of `*_to_json` helpers in `src` whose own body emits a shard id.
///
/// An endpoint that calls a serialiser publishes whatever that serialiser
/// publishes, so the indirection has to be followed. Treating *every*
/// `_to_json(&` call as a shard-id emission was the blunt version of this
/// check: it flagged endpoints serialising something else entirely (an
/// account proof, a block header), which teaches a reader that the gate
/// cries wolf. Following the call keeps the check strict where it matters.
fn shard_emitting_helpers(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inbody = false;
    let mut emits = false;
    let mut name = String::new();
    for line in src.lines() {
        if inbody {
            if line.contains("\"shardId\":") {
                emits = true;
            }
            if line == "    }" {
                if emits {
                    out.push(name.clone());
                }
                inbody = false;
            }
        } else if let Some(rest) = line.trim_start().strip_prefix("fn ") {
            let candidate = rest.split('(').next().unwrap_or("").trim();
            if candidate.ends_with("_to_json") {
                name = candidate.to_string();
                inbody = true;
                emits = false;
            }
        }
    }
    out
}

/// The name of the `*_to_json` helper called on `line`, if any.
fn called_serialiser(line: &str) -> Option<String> {
    let head = line.split("_to_json(&").next()?;
    let ident: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if ident.is_empty() {
        None
    } else {
        Some(format!("{ident}_to_json"))
    }
}

fn unguarded_endpoints(src: &str) -> Vec<String> {
    let shard_helpers = shard_emitting_helpers(src);
    let mut out = Vec::new();
    let mut inbody = false;
    let mut emits = false;
    let mut guards = false;
    let mut name = String::new();
    for line in src.lines() {
        if inbody {
            if line.contains("\"shardId\":") {
                emits = true;
            }
            if line.contains("_to_json(&") {
                // An unresolvable serialiser is assumed to emit: the gate
                // must not go quiet because it could not find the callee.
                match called_serialiser(line) {
                    None => emits = true,
                    Some(called) => {
                        let defined = src.contains(&format!("fn {called}("));
                        if !defined || shard_helpers.iter().any(|h| *h == called) {
                            emits = true;
                        }
                    }
                }
            }
            if line.contains("pollen_asset_for_content") {
                guards = true;
            }
            if line == "    }" {
                if emits && !guards {
                    out.push(name.clone());
                }
                inbody = false;
            }
        } else if let Some(rest) = line.strip_prefix("    async fn ") {
            name = rest.split('(').next().unwrap_or("").trim().to_string();
            inbody = true;
            emits = false;
            guards = false;
        }
    }
    out
}

fn line_reaches_storage(line: &str) -> bool {
    [
        "get_storage_manifest",
        "storage_registry",
        "reconstruct_object",
        "deals_by_shard",
    ]
    .iter()
    .any(|n| line.contains(n))
}

fn walk_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(p_kind) = e.file_type() else {
            continue;
        };
        let p = e.path();
        if p_kind.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Files under `dir` that reach storage without mentioning Pollen, as
/// `path:line:text` lines.
fn ai_storage_reach(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    let mut files = Vec::new();
    walk_rs(dir, &mut files);
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        if !text.lines().any(line_reaches_storage) {
            continue;
        }
        let lower = text.to_lowercase();
        let mentions_pollen = lower.contains("pollen") || lower.contains("authorize_content_read");
        if mentions_pollen {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if line_reaches_storage(line) {
                out.push(format!("{}:{}:{line}", f.display(), i + 1));
            }
        }
    }
    out
}

/// `grep -c 'check_content_may_be_public'` over the file with comments
/// stripped; `0` when the file is absent.
fn declaration_call_count(actor: &Path) -> usize {
    let Ok(text) = std::fs::read_to_string(actor) else {
        return 0;
    };
    let stripped = strip_line_comments(&text);
    stripped
        .lines()
        .filter(|l| l.contains("check_content_may_be_public"))
        .count()
}

/// # Errors
///
/// A fail-open read path, protected content that can be declared public, a
/// removable binding, a registry that offers no authorisation or hides the
/// map from its root, an uncalled refusal, an unguarded shard-id endpoint,
/// or an AI path reaching storage directly.
pub fn run(root: &Path) -> Result<String, String> {
    let gate = root.join("src/pollen/content_gate.rs");
    let offers = root.join("src/pollen/offers.rs");
    if !gate.is_file() {
        return Err(format!("FAIL: missing {}", gate.display()));
    }
    if !offers.is_file() {
        return Err(format!("FAIL: missing {}", offers.display()));
    }
    let gate_src = std::fs::read_to_string(&gate).unwrap_or_default();
    let offers_src = std::fs::read_to_string(&offers).unwrap_or_default();

    // 1. The authorisation path refuses when no grant is presented.
    if count_in_range(&gate_src, "fn authorize_read", "    }", "GrantRequired") == 0 {
        return Err(String::from(
            "FAIL: authorize_read does not refuse a missing grant: paid content is \
             readable for free",
        ));
    }

    // 2. The public-class check refuses protected content.
    if count_in_range(
        &gate_src,
        "fn check_may_be_public",
        "    }",
        "ProtectedCannotBePublic",
    ) == 0
    {
        return Err(String::from(
            "FAIL: check_may_be_public does not refuse protected content: paid data \
             would be deduplicated",
        ));
    }

    // 3. No unbind.
    let unbind = unbind_lines(&gate_src);
    if !unbind.is_empty() {
        let mut msg = String::new();
        for (nr, line) in &unbind {
            let _ = writeln!(msg, "{nr}:{line}");
        }
        msg.push_str(
            "FAIL: a binding can be removed: an owner could take payment then free \
             the bytes",
        );
        return Err(msg);
    }

    // 4. The registry offers the read authorisation and hashes the binding
    //    map into its root.
    if offers_src
        .lines()
        .filter(|l| l.contains("pub fn authorize_content_read"))
        .count()
        == 0
    {
        return Err(String::from(
            "FAIL: MarketplaceRegistry exposes no authorize_content_read for the \
             storage layer to call",
        ));
    }
    if count_in_range(&offers_src, "pub fn root(", "    }", "protected_content") == 0 {
        return Err(String::from(
            "FAIL: protected_content is not hashed into the registry root",
        ));
    }

    // 5. The declaration path actually calls the refusal.
    let actor = root.join("src/chain/chain_actor.rs");
    if declaration_call_count(&actor) == 0 {
        return Err(String::from(
            "FAIL: nothing calls check_content_may_be_public on the declaration \
             path: paid content can register as plaintext and be deduplicated, \
             which is the leak the refusal exists to prevent",
        ));
    }

    // 6. Every RPC endpoint that publishes a shard id asks Pollen first.
    let rpc = root.join("src/rpc/server.rs");
    if rpc.is_file() {
        let unguarded = unguarded_endpoints(&std::fs::read_to_string(&rpc).unwrap_or_default());
        if !unguarded.is_empty() {
            let mut msg = String::new();
            for u in &unguarded {
                let _ = writeln!(msg, "{u}");
            }
            msg.push_str(
                "FAIL: RPC endpoint(s) publish shard ids without asking Pollen: the \
                 handles for fetching paid bytes are served to anyone",
            );
            return Err(msg);
        }
    }

    // 7. The AI runtime cannot reach storage bytes except through Pollen.
    let reach = ai_storage_reach(&root.join("src/ai"));
    if !reach.is_empty() {
        let mut msg = String::new();
        for r in &reach {
            let _ = writeln!(msg, "{r}");
        }
        msg.push_str(
            "FAIL: the AI runtime reaches storage without going through Pollen: a \
             request with no Pollen prefix would read protected bytes",
        );
        return Err(msg);
    }

    Ok(String::from(
        "OK: paid content needs a live grant, stays out of the public class, and is \
         bound permanently",
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the sixteen canaries of the shell version.
// ---------------------------------------------------------------------------

const C1: &str = "    pub fn authorize_read(&self, id: &ContentId, g: Option<AssetId>) -> Result<(), E> {\n        Ok(())\n    }\n";
const C2: &str = "    pub fn authorize_read(&self, id: &ContentId, g: Option<AssetId>) -> Result<(), E> {\n        let Some(required) = self.asset_for(id) else { return Ok(()); };\n        match g {\n            None => Err(ContentGateError::GrantRequired { manifest_id: *id, asset_id: required }),\n            Some(_) => Ok(()),\n        }\n    }\n";
const C3: &str = "    pub fn check_may_be_public(&self, id: &ContentId) -> Result<(), E> {\n        Ok(())\n    }\n";
const C4: &str =
    "    pub fn unbind(&mut self, id: &ContentId) {\n        self.bindings.remove(id);\n    }\n";
const C5: &str = "    pub fn prune(&mut self, keep: usize) {\n        self.bindings.retain(|_, _| keep > 0);\n    }\n";
const C6: &str = "    // There is no unbind: bindings.remove would let an owner take payment\n    // and then release the bytes into the free path.\n    pub fn asset_for(&self, id: &ContentId) -> Option<AssetId> { self.bindings.get(id).copied() }\n";
const C7: &str = "    pub fn root(&self) -> [u8; 32] {\n        hasher.update(b\"offers\");\n        hasher.finalize().into()\n    }\n";
const C8: &str = "    fn helper(x: u64) -> u64 { x + 1 }\n";
const C9: &str = "    async fn leaky(&self, id: String) -> Result<Value, E> {\n        Ok(json!({ \"shardId\": hex::encode(s.shard_id.0) }))\n    }\n";
const C10: &str = "    async fn guarded(&self, id: String) -> Result<Value, E> {\n        let protecting_asset = self.chain.pollen_asset_for_content(id).await;\n        let shards = if protecting_asset.is_some() { vec![] } else {\n            vec![json!({ \"shardId\": hex::encode(s.shard_id.0) })]\n        };\n        Ok(json!({ \"shards\": shards }))\n    }\n";
const C11: &str = "    async fn unrelated(&self) -> Result<Value, E> {\n        Ok(json!({ \"height\": 1 }))\n    }\n";
/// An endpoint calling a serialiser that itself emits a shard id: the
/// indirection must not hide the leak.
const C13: &str = "    fn deal_to_json(d: &Deal) -> Value {\n        json!({ \"shardId\": hex::encode(d.shard_id.0) })\n    }\n\n    async fn indirect_leak(&self, id: String) -> Result<Value, E> {\n        Ok(Self::deal_to_json(&d))\n    }\n";
/// An endpoint calling a serialiser that emits no shard id: nothing to guard.
const C14: &str = "    fn header_to_json(h: &Header) -> Value {\n        json!({ \"height\": h.height })\n    }\n\n    async fn innocent(&self, id: String) -> Result<Value, E> {\n        Ok(Self::header_to_json(&h))\n    }\n";
/// A serialiser the gate cannot find: it assumes the worst, it does not go quiet.
const C15: &str = "    async fn unknown_helper(&self, id: String) -> Result<Value, E> {\n        Ok(Self::mystery_to_json(&x))\n    }\n";
const AI_REACH: &str = "    let manifest = chain.get_storage_manifest(id).await;\n";
const AI_MEDIATED: &str = "    let ok = pollen.authorize_content_read(&id, &who, grant, block)?;\n    let manifest = chain.get_storage_manifest(id).await;\n";
const AI_CLEAN: &str = "    let out = model.infer(&request.input_ref);\n";
const UNCALLED: &str = "ChainCommand::RegisterStorageManifest { manifest, response } => {\n    if let Err(e) = manifest.validate_untrusted() { continue; }\n    self.blockchain.state.storage_registry.register_manifest(&manifest);\n}\n";
const CALLED: &str = "if matches!(manifest.encryption, ContentEncryption::Plaintext) {\n    if let Err(e) = self.blockchain.state.marketplace\n        .check_content_may_be_public(&manifest.manifest_id) { continue; }\n}\n";

/// Write `content` to a temp file under `sub` and return the directory.
fn temp_file(sub: &str, name: &str, content: &str) -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-paid-{}-{nanos}", std::process::id()));
    let path = dir.join(sub);
    let _ = std::fs::create_dir_all(&path);
    std::fs::write(path.join(name), content).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn expect_bool(cond: bool, label: &str, canaries: &mut usize) -> Result<(), String> {
    if cond {
        *canaries += 1;
        Ok(())
    } else {
        Err(format!("canary failed: {label}"))
    }
}

fn canaries_strings(canaries: &mut usize) -> Result<(), String> {
    // 1. A fail-open authorize_read is caught.
    expect_bool(
        count_in_range(C1, "fn authorize_read", "    }", "GrantRequired") == 0,
        "a fail-open authorize_read was not detected",
        canaries,
    )?;

    // 2. An honest one passes, so the check is not rejecting everything.
    expect_bool(
        count_in_range(C2, "fn authorize_read", "    }", "GrantRequired") != 0,
        "an honest authorize_read must pass",
        canaries,
    )?;

    // 3. A public check that never refuses is caught.
    expect_bool(
        count_in_range(
            C3,
            "fn check_may_be_public",
            "    }",
            "ProtectedCannotBePublic",
        ) == 0,
        "a check_may_be_public that never refuses was not detected",
        canaries,
    )?;

    // 4. An unbind method is caught.
    expect_bool(
        !unbind_lines(C4).is_empty(),
        "an unbind method was not detected",
        canaries,
    )?;

    // 5. A retain that quietly drops bindings is caught too.
    expect_bool(
        !unbind_lines(C5).is_empty(),
        "a retain that drops bindings was not detected",
        canaries,
    )?;

    // 6. Prose about unbinding must NOT be flagged.
    expect_bool(
        unbind_lines(C6).is_empty(),
        "prose explaining the absence of unbind was flagged",
        canaries,
    )?;

    // 7. A root that omits the binding map is caught.
    expect_bool(
        count_in_range(C7, "pub fn root(", "    }", "protected_content") == 0,
        "a root omitting protected_content was not detected",
        canaries,
    )?;

    // 8. A clean file trips nothing.
    expect_bool(
        unbind_lines(C8).is_empty(),
        "a clean file was flagged",
        canaries,
    )?;

    // 9. An endpoint printing shard ids with no Pollen check is caught.
    expect_bool(
        !unguarded_endpoints(C9).is_empty(),
        "an endpoint publishing shard ids with no Pollen check was not detected",
        canaries,
    )?;

    // 10. One that does ask must pass.
    expect_bool(
        unguarded_endpoints(C10).is_empty(),
        "a guarded endpoint must pass",
        canaries,
    )?;

    // 11. An endpoint touching no shard id is not asked to guard.
    expect_bool(
        unguarded_endpoints(C11).is_empty(),
        "an endpoint with no shard id was flagged",
        canaries,
    )?;

    // 13. A shard id reached through a serialiser is still a shard id.
    expect_bool(
        !unguarded_endpoints(C13).is_empty(),
        "a shard id published through a *_to_json helper was not detected",
        canaries,
    )?;

    // 14. A serialiser emitting no shard id does not make an endpoint guilty.
    expect_bool(
        unguarded_endpoints(C14).is_empty(),
        "an endpoint serialising something other than a shard id was flagged",
        canaries,
    )?;

    // 15. An unresolvable serialiser is assumed to emit: the gate stays loud.
    expect_bool(
        !unguarded_endpoints(C15).is_empty(),
        "an unresolvable serialiser silenced the gate",
        canaries,
    )?;
    Ok(())
}

fn canaries_files(canaries: &mut usize) -> Result<(), String> {
    // 12. An AI module reaching storage directly is caught.
    let dir = temp_file("ai12", "m.rs", AI_REACH)?;
    let reach = ai_storage_reach(&dir.join("ai12"));
    let _ = std::fs::remove_dir_all(&dir);
    expect_bool(
        !reach.is_empty(),
        "an AI module reaching storage was not detected",
        canaries,
    )?;

    // 13. Reaching it through Pollen is allowed.
    let dir = temp_file("ai13", "m.rs", AI_MEDIATED)?;
    let reach = ai_storage_reach(&dir.join("ai13"));
    let _ = std::fs::remove_dir_all(&dir);
    expect_bool(
        reach.is_empty(),
        "a Pollen-mediated storage read must be allowed",
        canaries,
    )?;

    // 14. An AI module touching no storage at all is clean.
    let dir = temp_file("ai14", "m.rs", AI_CLEAN)?;
    let reach = ai_storage_reach(&dir.join("ai14"));
    let _ = std::fs::remove_dir_all(&dir);
    expect_bool(
        reach.is_empty(),
        "an AI module with no storage reach was flagged",
        canaries,
    )?;

    // 15. The refusal exists but nothing on the declaration path calls it.
    let dir = temp_file("", "uncalled.rs", UNCALLED)?;
    let count = declaration_call_count(&dir.join("uncalled.rs"));
    let _ = std::fs::remove_dir_all(&dir);
    expect_bool(
        count == 0,
        "a declaration path that never calls the refusal was not detected",
        canaries,
    )?;

    // 16. The healthy shape must pass.
    let dir = temp_file("", "called.rs", CALLED)?;
    let count = declaration_call_count(&dir.join("called.rs"));
    let _ = std::fs::remove_dir_all(&dir);
    expect_bool(
        count != 0,
        "a declaration path that does call the refusal was rejected",
        canaries,
    )?;
    Ok(())
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut canaries = 0usize;
    canaries_strings(&mut canaries)?;
    canaries_files(&mut canaries)?;
    Ok(format!(
        "paid content gate self-test OK: {canaries} canaries"
    ))
}
