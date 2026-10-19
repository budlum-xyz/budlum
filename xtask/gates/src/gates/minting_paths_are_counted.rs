//! Every path that creates supply must be counted and bound to the ceiling.
//!
//! A fixed supply ceiling is a bound only if **every single supply-creating path** asks it.
//! If one path is left out the ceiling becomes only a document:
//! a reader believes 100 million is the upper bound while the code does something else.
//!
//! What is measured is this: every production line calling `try_add_balance` is
//! either a **transfer** (it takes existing money from one place to another: a
//! refund, a fee, an unlock) or a **mint** (it creates new money). The mints must
//! call `try_mint_balance`; that function is the only place checking the ceiling,
//! and the gate checks that it still calls `ensure_mint_headroom`.
//!
//! # Why a list is kept
//!
//! The gate **cannot infer** from the source which call is a transfer and which
//! is a mint - that is an accounting question, not a syntax question. So the
//! reason each `try_add_balance` call site is a transfer is written down once
//! below. When a new call is added the gate goes red and forces whoever adds it
//! to answer this question: is this new money, or money changing place?
//!
//! Every production file under `src/` is scanned. A file that is not on the
//! list must hold no `try_add_balance` call at all.
//!
//! The friction is deliberate. Silently adding a supply-creating path is the most expensive
//! mistake this chain can make; the cost of the gate is writing one line of
//! rationale.

use std::fmt::Write as _;
use std::path::Path;

/// Every production file under this root is scanned. A file that is not in
/// [`TRANSFER_JUSTIFICATIONS`] must contain no `try_add_balance` call at all,
/// so a new supply-creating call in another file is red, not invisible.
const SCAN_ROOT: &str = "src";

/// The file that defines the minting function.
const ACCOUNT_FILE: &str = "src/core/account.rs";

/// The call `try_mint_balance` must make before it adds.
const HEADROOM_FN: &str = "ensure_mint_headroom";

/// The only function that checks the ceiling.
const MINT_FN: &str = "try_mint_balance";

/// The function that adds balance without a ceiling check.
const MOVE_FN: &str = "try_add_balance";

/// The expected `try_add_balance` call count and why each of them is a
/// **transfer**.
///
/// The count is kept deliberately: if a call is added the total changes and the gate fires.
/// The rationales tell the reader why those lines do not ask the ceiling.
const TRANSFER_JUSTIFICATIONS: &[(&str, usize, &str)] = &[
    (
        "src/chain/blockchain.rs",
        10,
        "ten calls, each one puts back or splits money this ledger already \
         took from another place. \
         One in the verified-burn unlock (decision K4-A): the owner gets back \
         the burned amount, which the lock debited from the owner less the \
         relayer fee the mint paid out of the arriving asset. \
         Two in the relay unlock of a burned bridge transfer: the owner share \
         and the relayer cut, which together equal the amount that the lock \
         debited from the owner. \
         One in `apply_bridge_sweep_to_state`: the refund of an expired lock \
         to its owner, again the amount the lock debited. \
         One in the storage reward tick: the operator is paid out of the fee \
         that `open_deal` debited from the payer, as the difference of two \
         cumulative totals so the sum cannot pass the escrowed fee. \
         Two in `distribute_bud_boost_share_in_state`: the operator shares and \
         the rounding dust of the 4 percent share that the NFT boost carved \
         out of the booster's debit, and the shares plus dust equal exactly \
         that pending amount. \
         One in `refund_opener_bond`: the challenge bond that \
         `debit_opener_bond` took from the opener. \
         One in the storage deal expiry sweep: the operator bond that \
         `open_deal` debited. \
         One in the block-application storage prune: the operator bond that \
         `open_deal` debited, returned when the owner burns the content and \
         the prune ends the deal early. \
         None of these create new supply. The bridge mint paths use \
         `try_mint_balance` and are not on this list.",
    ),
    (
        "src/chain/chain_actor.rs",
        1,
        "the manual storage prune returns the operator bond that `open_deal` \
         debited from that operator when it opened the deal. The block \
         application path runs the same settlement; the bond is money \
         changing place, not new supply.",
    ),
    (
        "src/execution/executor.rs",
        3,
        "bridge unlock inside a RelayerResult (the owner's locked money is \
         returned and the relayer's cut is carved out of that same refund) and \
         the producer's share of a transaction fee that was already paid. The \
         bridge mint inside a RelayerResult is not on this list: it creates \
         supply and goes through `try_mint_balance`.",
    ),
    (
        "src/core/account.rs",
        2,
        "one is the release of the unbonding queue (money already committed as stake \
         and already counted against the ceiling is returned - not new supply \
         but supply changing category); the other is the body of `try_mint_balance` itself, \
         the line that performs the actual addition after checking the ceiling.",
    ),
];

/// Net brace depth change of a line, ignoring braces in line comments.
fn brace_delta(line: &str) -> i64 {
    let code = line.split("//").next().unwrap_or(line);
    let mut d = 0i64;
    for c in code.chars() {
        match c {
            '{' => d += 1,
            '}' => d -= 1,
            _ => {}
        }
    }
    d
}

/// Does this line define (not call) one of the two balance functions?
fn is_definition(line: &str) -> bool {
    line.contains(&format!("fn {MOVE_FN}")) || line.contains(&format!("fn {MINT_FN}"))
}

/// Does a line open a test item at column zero?
fn opens_test_item(line: &str) -> bool {
    line == "#[cfg(test)]" || line.starts_with("mod tests") || line.starts_with("pub mod tests")
}

/// Production lines of a file: test modules and comments removed.
///
/// A test item starts at a column-zero `#[cfg(test)]` or `mod tests` and ends
/// where its braces close (or at a `;` for a bodyless item), so production
/// code that follows a test module is scanned again; an earlier version set a
/// flag at the first `mod tests` and never cleared it. Indented
/// `#[cfg(test)]` attributes appear inside production code (test-only
/// branches), so only column-zero ones open a skip. Definitions of the two
/// functions are not calls; a one-line function that calls one of them is.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut skipping = false;
    let mut depth = 0i64;
    let mut opened = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if skipping || opens_test_item(line) {
            if !skipping {
                skipping = true;
                depth = 0;
                opened = false;
            }
            depth += brace_delta(line);
            if line.contains('{') {
                opened = true;
            }
            let bodyless = !opened && t.ends_with(';');
            if (opened && depth <= 0) || bodyless {
                skipping = false;
            }
            continue;
        }
        // Comments do not count: a function name appearing in a rationale text
        // is not a call.
        if t.starts_with("//") || is_definition(line) {
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

/// Every `.rs` file under `dir` that is not a test file, as
/// `(repo-relative path, text)`.
fn collect_sources(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("could not read directory {}: {e}", dir.display()))?;
    for e in entries.flatten() {
        let path = e.path();
        let kind = e
            .file_type()
            .map_err(|err| format!("could not stat {}: {err}", path.display()))?;
        if kind.is_dir() {
            collect_sources(root, &path, out)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|err| format!("could not read {rel}: {err}"))?;
            out.push((rel, text));
        }
    }
    Ok(())
}

/// Does `try_mint_balance` still ask the ceiling before it adds?
fn mint_fn_checks_headroom(account_src: &str) -> bool {
    let needle = format!("pub fn {MINT_FN}");
    let Some(start) = account_src.find(&needle) else {
        return false;
    };
    let rest = &account_src[start..];
    let Some(open) = rest.find('{') else {
        return false;
    };
    let mut depth = 0i64;
    let mut end = rest.len();
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body: String = rest[open..end]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    body.contains(&format!("{HEADROOM_FN}("))
}

/// # Errors
///
/// If the number of balance-adding calls differs from the justified count.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = String::new();
    let mut minting = 0usize;
    let mut moving = 0usize;

    let mut sources: Vec<(String, String)> = Vec::new();
    collect_sources(root, &root.join(SCAN_ROOT), &mut sources)?;
    sources.sort();
    if sources.is_empty() {
        return Err(format!(
            "minting-paths-are-counted: no sources found under {SCAN_ROOT}"
        ));
    }

    // Every justified file must be present, or its rationale is stale.
    for (name, _, _) in TRANSFER_JUSTIFICATIONS {
        if !sources.iter().any(|(rel, _)| rel == name) {
            let _ = write!(
                problems,
                "\n  {name}: listed in the justifications but not found."
            );
        }
    }

    for (source, text) in &sources {
        let lines = production_lines(text);

        let found_move = lines
            .iter()
            .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
            .count();
        let found_mint = lines.iter().filter(|(_, l)| l.contains(MINT_FN)).count();
        moving += found_move;
        minting += found_mint;

        let (expected, why) = TRANSFER_JUSTIFICATIONS
            .iter()
            .find(|(name, _, _)| name == source)
            .map_or(
                (0, "this file has no recorded transfer call"),
                |(_, n, w)| (*n, *w),
            );

        if found_move != expected {
            let _ = write!(
                problems,
                "\n  {source}: there are {found_move} `{MOVE_FN}` calls, \
                 the justified count is {expected}.\n    \
                 Recorded rationale: {why}\n    \
                 If a call was added this question has to be answered: is this new money \
                 (then `{MINT_FN}` must be used, it checks the ceiling) or money that \
                 merely changes place (then the rationale must be written into this gate)? \
                 If a call was deleted the count must be updated."
            );
        }
    }

    let account_ok = sources
        .iter()
        .find(|(rel, _)| rel == ACCOUNT_FILE)
        .is_some_and(|(_, t)| mint_fn_checks_headroom(t));
    if !account_ok {
        let _ = write!(
            problems,
            "\n  {ACCOUNT_FILE}: `{MINT_FN}` no longer calls `{HEADROOM_FN}`. It is the \
             only function that checks the ceiling; without that call every mint is uncapped."
        );
    }

    if !problems.is_empty() {
        return Err(format!("minting-paths-are-counted:{problems}"));
    }
    if minting == 0 {
        return Err(format!(
            "minting-paths-are-counted: no `{MINT_FN}` call was found at all. \
             If the ceiling check was removed the supply cap is only a document."
        ));
    }

    Ok(format!(
        "minting-paths-are-counted OK: {minting} mint calls are bound to the ceiling, \
         {moving} transfer calls are justified"
    ))
}

/// # Errors
///
/// If the gate cannot tell test code apart from production code.
pub fn self_test() -> Result<String, String> {
    let count_moves = |text: &str| {
        production_lines(text)
            .iter()
            .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
            .count()
    };
    let sample = r"
        fn production() {
            self.state.try_add_balance(&a, 1)?;
            self.state.try_mint_balance(&b, 2)?;
        }
#[cfg(test)]
mod tests {
    fn setup() {
        state.try_add_balance(&c, 3);
        state.try_add_balance(&d, 4);
    }
}
    ";
    let mints = production_lines(sample)
        .iter()
        .filter(|(_, l)| l.contains(MINT_FN))
        .count();
    let moves = count_moves(sample);
    if moves != 1 {
        return Err(format!(
            "self_test: 1 move was expected in production, {moves} were counted (the test module may have leaked in)"
        ));
    }
    if mints != 1 {
        return Err(format!(
            "self_test: 1 mint was expected in production, {mints} were counted"
        ));
    }
    // An example in a comment line must not be counted.
    let commented = "        // self.state.try_add_balance(&a, 1);";
    if !production_lines(commented).is_empty() {
        return Err("self_test: a call inside a comment was counted".into());
    }
    // A one-line function that calls the move function is a call.
    let one_liner = "pub fn pay(s: &mut S) { s.try_add_balance(&a, 1).ok(); }\n";
    if count_moves(one_liner) != 1 {
        return Err("self_test: a call on a one-line fn was not counted".into());
    }
    // The definition itself is not a call.
    let def =
        "    pub fn try_add_balance(&mut self, k: &Address, a: u64) -> Result<(), String> {\n";
    if count_moves(def) != 0 {
        return Err("self_test: the definition was counted as a call".into());
    }
    // Production code after a closed test module is scanned again.
    let after = "#[cfg(test)]\nmod tests {\n    fn t() { s.try_add_balance(&a, 1); }\n}\n\nfn later() {\n    s.try_add_balance(&a, 1)?;\n}\n";
    let n = count_moves(after);
    if n != 1 {
        return Err(format!(
            "self_test: code after a test module counted {n} calls instead of 1"
        ));
    }
    // A bodyless `#[cfg(test)]` item does not hide the next production fn.
    let bodyless = "#[cfg(test)]\nuse crate::x::Y;\nfn p() {\n    s.try_add_balance(&a, 1)?;\n}\n";
    if count_moves(bodyless) != 1 {
        return Err("self_test: a bodyless cfg(test) item hid production code".into());
    }
    // The mint function must keep calling the headroom check.
    let good = "pub fn try_mint_balance(&mut self) -> R {\n    self.ensure_mint_headroom(a)?;\n    self.try_add_balance(k, a)\n}\n";
    let bad = "pub fn try_mint_balance(&mut self) -> R {\n    // self.ensure_mint_headroom(a)?;\n    self.try_add_balance(k, a)\n}\n";
    if !mint_fn_checks_headroom(good) || mint_fn_checks_headroom(bad) {
        return Err("self_test: the headroom-call check misjudged a fixture".into());
    }
    Ok("minting-paths-are-counted self-test OK: test modules, comments, definitions, one-line fns and code after test modules are classified correctly".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("minting-paths self-test");
    }
}
