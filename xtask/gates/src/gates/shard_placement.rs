//! Shard placement must be derived, sticky, stake-weighted, and must never put
//! two shards of one object on one address.
//!
//! Ported from `scripts/check-shard-placement-is-sticky-and-staked.sh`.
//!
//! # The failure this closes
//!
//! Everything else in `src/storage/` describes content and none of it says who
//! holds the bytes. The four ways placement can be written so it looks right
//! and is not:
//!
//! 1. It reshuffles on every set change (rendezvous hashing over a shuffle).
//! 2. It ignores stake: the bond is what answers for a lost shard.
//! 3. It pads a short validator set with duplicates, so one departure costs
//!    two shards.
//! 4. It uses floating point, so two nodes can disagree about who owes a
//!    shard.
//!
//! # What is checked
//!
//! `rendezvous_score` exists, reads the stake, hashes its inputs with the
//! placement domain tag and excludes zero-stake validators; the production
//! half has no floating point; `assign_shard` sorts by score, breaks ties
//! deterministically and refuses a set smaller than the scheme needs;
//! `assign_object` does not swallow placement errors; `displaced_shards`
//! exists; and the named regressions exist as real `#[test]` functions.

use std::fmt::Write as _;
use std::path::Path;

/// Python `\s`.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

/// Brace-matched body of the item whose header is `pub fn NAME\s*\(` or
/// `fn NAME\s*\(`.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    for prefix in ["pub fn ", "fn "] {
        let header = format!("{prefix}{name}");
        let mut from = 0usize;
        while let Some(pos) = src[from..].find(&header) {
            let abs = from + pos;
            let rest = &src[abs + header.len()..];
            if !skip_py_ws(rest).starts_with('(') {
                from = abs + 1;
                continue;
            }
            let open_rel = src[abs + header.len()..].find('{')?;
            let i = abs + header.len() + open_rel;
            let mut depth = 0usize;
            for (off, c) in src[i..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&src[i..i + off + c.len_utf8()]);
                        }
                    }
                    _ => {}
                }
            }
            return None;
        }
    }
    None
}

/// `stake\s*==\s*0`.
fn has_stake_eq_zero(score: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = score[from..].find("stake") {
        let abs = from + pos;
        let rest = skip_py_ws(&score[abs + "stake".len()..]);
        let Some(rest) = rest.strip_prefix("==") else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(rest).starts_with('0') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `\bf32\b|\bf64\b|\.ln\(\)|\.log\(|\.powf\(`.
fn has_float_placement(prod: &str) -> bool {
    for needle in ["f32", "f64"] {
        let mut from = 0usize;
        while let Some(pos) = prod[from..].find(needle) {
            let abs = from + pos;
            let before = prod[..abs]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
            let after = prod[abs + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
            if before && after {
                return true;
            }
            from = abs + 1;
        }
    }
    prod.contains(".ln()") || prod.contains(".log(") || prod.contains(".powf(")
}

/// `#[test]\s*(?:#\[[^\]]*\]\s*)*fn\s+TEST\s*\(` in the raw source.
fn has_test_fn(src: &str, test: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = src[from..].find("#[test]") {
        let abs = from + pos;
        let mut rest = &src[abs + "#[test]".len()..];
        rest = skip_py_ws(rest);
        while rest.starts_with("#[") {
            let Some(close) = rest.find(']') else {
                break;
            };
            rest = skip_py_ws(&rest[close + 1..]);
        }
        let Some(after_fn) = rest.strip_prefix("fn") else {
            from = abs + 1;
            continue;
        };
        if after_fn.len() == skip_py_ws(after_fn).len() {
            from = abs + 1;
            continue; // `\s+` after `fn` is required
        }
        let after_fn = skip_py_ws(after_fn);
        let Some(tail) = after_fn.strip_prefix(test) else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(tail).starts_with('(') {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn check_score(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The scoring function must exist and must read the stake.
    *checked += 1;
    if let Some(score) = body_of(prod, "rendezvous_score") {
        *checked += 1;
        if !score.contains("stake") {
            problems.push(String::from(
                "`rendezvous_score` does not read the stake. The bond is what \
                 answers for a lost shard, so placement that ignores it puts \
                 shards behind collateral that cannot pay for their loss.",
            ));
        }
        *checked += 1;
        if !score.contains("hash_fields_bytes") {
            problems.push(String::from(
                "`rendezvous_score` no longer hashes its inputs, so placement is \
                 not derived from entropy the operator cannot choose.",
            ));
        }
        *checked += 1;
        if !has_stake_eq_zero(score) {
            problems.push(String::from(
                "`rendezvous_score` does not exclude zero-stake validators. An \
                 operator with nothing at risk has nothing to lose by dropping \
                 the bytes.",
            ));
        }
    } else {
        problems.push(String::from(
            "`rendezvous_score` is gone. Without a per-validator score there is \
             no placement, and the coder, the coding audit and the repair \
             arithmetic all stay unreachable.",
        ));
    }
}

fn check_float(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // No floating point anywhere in the production half.
    *checked += 1;
    if has_float_placement(prod) {
        problems.push(String::from(
            "placement uses floating point. Every node recomputes this, and a \
             float makes the answer depend on the machine's rounding mode, so \
             two nodes can disagree about who owes a shard.",
        ));
    }
}

fn check_selection(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The selection must take the top `n` by score, break ties
    // deterministically, and refuse duplicates rather than pad.
    *checked += 1;
    if let Some(assign) = body_of(prod, "assign_shard") {
        *checked += 1;
        if !assign.contains("sort") {
            problems.push(String::from(
                "`assign_shard` does not order candidates by score, so the top \
                 `n` are whatever order the input arrived in.",
            ));
        }
        *checked += 1;
        if !assign.contains("then_with") && !assign.contains("then(") {
            problems.push(String::from(
                "`assign_shard` has no tiebreak. Two validators whose scores \
                 collide would be ordered by input order, which differs between \
                 nodes.",
            ));
        }
        *checked += 1;
        if !assign.contains("NotEnoughValidators") {
            problems.push(String::from(
                "`assign_shard` does not refuse a set smaller than the scheme \
                 needs. Placing two shards of one object on one address means a \
                 single departure costs two shards, and the erasure scheme's \
                 tolerance assumed it costs one.",
            ));
        }
    } else {
        problems.push(String::from(
            "`assign_shard` is gone; nothing selects holders.",
        ));
    }
}

fn check_object_index(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The object-level index must not silently return a partial answer.
    *checked += 1;
    if let Some(obj) = body_of(prod, "assign_object") {
        *checked += 1;
        if !obj.contains('?') {
            problems.push(String::from(
                "`assign_object` swallows placement errors. A caller holding \
                 placements for some shards and not others reads the missing \
                 ones as lost.",
            ));
        }
    } else {
        problems.push(String::from(
            "`assign_object` is gone; there is no location index.",
        ));
    }
}

fn check_displacement(prod: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The displacement check is what turns a departure into a repair.
    *checked += 1;
    if body_of(prod, "displaced_shards").is_none() {
        problems.push(String::from(
            "`displaced_shards` is gone. Nothing compares the current placement \
             against the recorded one, so a departure produces no repair.",
        ));
    }

    // The domain tag must be specific to placement.
    *checked += 1;
    if !prod.contains("BDLM_SHARD_PLACEMENT_V1") {
        problems.push(String::from(
            "the placement domain tag is missing or renamed. Sharing a tag with \
             another hash lets a digest computed for one purpose be replayed as \
             the other.",
        ));
    }
}

fn check_tests(raw: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The regressions must exist as real tests.
    *checked += 1;
    for test in TEST_NAMES {
        if !has_test_fn(raw, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
            ));
        }
    }
}

/// # Errors
///
/// Missing sources, a placement that ignores stake or entropy, floating
/// point, an unsorted or duplicate-padded selection, a swallowed error, or a
/// missing regression test.
pub fn run(root: &Path) -> Result<String, String> {
    let src = root.join("src/storage/assignment.rs");
    if !src.is_file() {
        return Err(format!(
            "FAIL: expected source file missing: {}",
            src.display()
        ));
    }

    let raw = std::fs::read_to_string(&src).unwrap_or_default();
    let mut code = String::with_capacity(raw.len());
    for line in raw.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            code.push_str(line);
            continue;
        };
        code.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            code.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    let prod = code.split("#[cfg(test)]").next().unwrap_or(&code);

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    check_score(prod, &mut problems, &mut checked);
    check_float(prod, &mut problems, &mut checked);
    check_selection(prod, &mut problems, &mut checked);
    check_object_index(prod, &mut problems, &mut checked);
    check_displacement(prod, &mut problems, &mut checked);
    check_tests(&raw, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "shard placement gate OK: {checked} checks, placement is derived, sticky, \
         stake-weighted and refuses duplicates"
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the twelve canaries of the shell version.
// ---------------------------------------------------------------------------

const SCORE_OK: &str = "fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {\n\
    if c.stake == 0 { return 0; }\n\
    let d = hash_fields_bytes(&[b\"BDLM_SHARD_PLACEMENT_V1\", shard_id.as_bytes(), entropy, c.address.as_bytes()]);\n\
    let u = u128::from(u64::from_le_bytes(d[..8].try_into().unwrap())).max(1);\n\
    u128::from(c.stake).saturating_mul(u) / (SCORE_SCALE - u.min(SCORE_SCALE - 1))\n\
}\n";
const SCORE_NOSTAKE: &str =
    "fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {\n\
    let d = hash_fields_bytes(&[b\"BDLM_SHARD_PLACEMENT_V1\", shard_id.as_bytes(), entropy]);\n\
    u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))\n\
}\n";
const SCORE_FLOAT: &str =
    "fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {\n\
    if c.stake == 0 { return 0; }\n\
    let d = hash_fields_bytes(&[b\"BDLM_SHARD_PLACEMENT_V1\", shard_id.as_bytes(), entropy]);\n\
    let u = u64::from_le_bytes(d[..8].try_into().unwrap()) as f64 / u64::MAX as f64;\n\
    (-(c.stake as f64) / u.ln()) as u128\n\
}\n";
const SCORE_NOZERO: &str =
    "fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {\n\
    let d = hash_fields_bytes(&[b\"BDLM_SHARD_PLACEMENT_V1\", shard_id.as_bytes(), entropy]);\n\
    u128::from(c.stake) * u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))\n\
}\n";
const SCORE_NOTAG: &str =
    "fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {\n\
    if c.stake == 0 { return 0; }\n\
    let d = hash_fields_bytes(&[shard_id.as_bytes(), entropy]);\n\
    u128::from(c.stake) * u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))\n\
}\n";
const ASSIGN_OK: &str = "pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)\n\
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();\n\
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }\n\
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));\n\
    Ok(scored.into_iter().take(n).map(|(_, a)| a).collect())\n\
}\n";
const ASSIGN_NOSORT: &str = "pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let scored: Vec<Address> = c.iter().filter(|x| x.stake > 0).map(|x| x.address).collect();\n\
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }\n\
    Ok(scored.into_iter().take(n).collect())\n\
}\n";
const ASSIGN_NOTIE: &str = "pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)\n\
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();\n\
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }\n\
    scored.sort_by(|a, b| b.0.cmp(&a.0));\n\
    Ok(scored.into_iter().take(n).map(|(_, a)| a).collect())\n\
}\n";
const ASSIGN_PAD: &str =
    "pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)\n\
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();\n\
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));\n\
    Ok(scored.iter().cycle().take(n).map(|(_, a)| *a).collect())\n\
}\n";
const OBJ_OK: &str = "pub fn assign_object(ids: &[ContentId], e: &Hash32, c: &[ShardCandidate])\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let mut out = Vec::new();\n\
    for id in ids { out.push(assign_shard(id, e, c, 1)?[0]); }\n\
    Ok(out)\n\
}\n";
const OBJ_SWALLOW: &str =
    "pub fn assign_object(ids: &[ContentId], e: &Hash32, c: &[ShardCandidate])\n\
    -> Result<Vec<Address>, AssignmentError> {\n\
    let mut out = Vec::new();\n\
    for id in ids {\n\
        if let Ok(p) = assign_shard(id, e, c, 1) { out.push(p[0]); }\n\
    }\n\
    Ok(out)\n\
}\n";
const DISPLACED: &str =
    "pub fn displaced_shards(prev: &[Address], cur: &[Address]) -> Vec<usize> {\n\
    prev.iter().zip(cur.iter()).enumerate()\n\
        .filter_map(|(i, (a, b))| (a != b).then_some(i)).collect()\n\
}\n";
const TEST_NAMES: [&str; 7] = [
    "a_departure_moves_one_shard_and_leaves_the_rest",
    "placement_follows_stake",
    "a_validator_with_no_stake_holds_nothing",
    "too_few_validators_is_refused_not_padded",
    "one_address_never_holds_two_shards_of_an_object",
    "the_same_inputs_place_a_shard_the_same_way",
    "placement_spreads_across_the_set",
];

/// Write a fixture `assignment.rs` and check the gate's verdict.
fn check_fixture(
    score: &str,
    assign: &str,
    obj: &str,
    tests_present: bool,
    expect_ok: bool,
    label: &str,
) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-shard-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src/storage"));

    let names = if tests_present {
        &TEST_NAMES[..]
    } else {
        &TEST_NAMES[..TEST_NAMES.len() - 1]
    };
    let mut tests = String::from("#[cfg(test)]\nmod tests {\n");
    for n in names {
        let _ = writeln!(tests, "#[test]\nfn {n}() {{}}");
    }
    tests.push_str("}\n");

    let body = format!(
        "const SCORE_SCALE: u128 = 1 << 64;\n{}\n{assign}{obj}{DISPLACED}{tests}",
        score.trim_end()
    );
    std::fs::write(dir.join("src/storage/assignment.rs"), body).map_err(|e| e.to_string())?;

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    // 1. The corrected shape must pass, or every canary below proves nothing.
    check_fixture(
        SCORE_OK,
        ASSIGN_OK,
        OBJ_OK,
        true,
        true,
        "the corrected tree was rejected",
    )?;

    // 2. No scoring at all.
    check_fixture(
        "",
        ASSIGN_OK,
        OBJ_OK,
        true,
        false,
        "a tree with no placement score",
    )?;

    // 3. Scoring that ignores stake.
    check_fixture(
        SCORE_NOSTAKE,
        ASSIGN_OK,
        OBJ_OK,
        true,
        false,
        "placement that ignores the bond",
    )?;

    // 4. Floating point, so two nodes can compute different placements.
    check_fixture(
        SCORE_FLOAT,
        ASSIGN_OK,
        OBJ_OK,
        true,
        false,
        "placement that depends on rounding mode",
    )?;

    // 5. Zero-stake validators still eligible.
    check_fixture(
        SCORE_NOZERO,
        ASSIGN_OK,
        OBJ_OK,
        true,
        false,
        "a validator with nothing at risk holding shards",
    )?;

    // 6. The domain tag dropped.
    check_fixture(
        SCORE_NOTAG,
        ASSIGN_OK,
        OBJ_OK,
        true,
        false,
        "a placement hash with no domain tag",
    )?;

    // 7. Selection disappears.
    check_fixture(SCORE_OK, "", OBJ_OK, true, false, "a missing selection")?;

    // 8. Selection that never orders by score.
    check_fixture(
        SCORE_OK,
        ASSIGN_NOSORT,
        OBJ_OK,
        true,
        false,
        "a selection that ignores the score",
    )?;

    // 9. No tiebreak.
    check_fixture(
        SCORE_OK,
        ASSIGN_NOTIE,
        OBJ_OK,
        true,
        false,
        "a selection with no deterministic tiebreak",
    )?;

    // 10. A short set padded by cycling.
    check_fixture(
        SCORE_OK,
        ASSIGN_PAD,
        OBJ_OK,
        true,
        false,
        "a short validator set padded with duplicates",
    )?;

    // 11. The object index disappears.
    check_fixture(
        SCORE_OK,
        ASSIGN_OK,
        "",
        true,
        false,
        "a missing location index",
    )?;

    // 12. The object index swallows errors.
    check_fixture(
        SCORE_OK,
        ASSIGN_OK,
        OBJ_SWALLOW,
        true,
        false,
        "a partial index read as loss",
    )?;

    // 13. A regression test is dropped.
    check_fixture(
        SCORE_OK,
        ASSIGN_OK,
        OBJ_OK,
        false,
        false,
        "a missing regression test",
    )?;

    Ok(String::from(
        "shard placement gate self-test OK: 12 canaries",
    ))
}
