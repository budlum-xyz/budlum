//! Every path that creates supply must be counted and bound to the ceiling.
//!
//! A fixed supply ceiling is a bound only if **every single supply-creating path** asks it.
//! If one path is left out the ceiling becomes only a document:
//! a reader believes 100 million is the upper bound while the code does something else.
//!
//! What is measured is this: every production line calling `try_add_balance` is
//! either a **transfer** (it takes existing money from one place to another: a
//! refund, a fee, an unlock) or a **mint** (it creates new money). The mints must
//! call `try_mint_balance`; that function is the only place checking the ceiling.
//!
//! # Why a list is kept
//!
//! The gate **cannot infer** from the source which call is a transfer and which
//! is a mint - that is an accounting question, not a syntax question. So the
//! reason each `try_add_balance` call site is a transfer is written down once
//! below. When a new call is added the gate goes red and forces whoever adds it
//! to answer this question: is this new money, or money changing place?
//!
//! The friction is deliberate. Silently adding a supply-creating path is the most expensive
//! mistake this chain can make; the cost of the gate is writing one line of
//! rationale.

use std::fmt::Write as _;
use std::path::Path;

/// The source files that are checked.
const SOURCES: &[&str] = &["src/chain/blockchain.rs", "src/core/account.rs"];

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
        11,
        "bridge unlock and refund (existing locked money is returned), \
         storage deal refunds and operator bond refunds (money that was \
         already owed), and fee distribution (splitting a fee that was already paid). \
         None of these create new supply.",
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

/// Roughly tells whether a line is production code or test code.
///
/// Tests are exempt from the ceiling: funding an account there is part of the
/// setup.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut in_tests = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        // The boundary is only a column-zero `mod tests`: `#[cfg(test)]` also
        // appears inside production code (test-only branches, test-only
        // helpers), so treating it as the boundary would make half the file
        // invisible.
        if line.starts_with("mod tests") || line.starts_with("pub mod tests") {
            in_tests = true;
        }
        // Comments do not count: a function name appearing in a rationale text is not a
        // call. A line starting with `fn` does not count either - the definition of the
        // function is not a call to it.
        if in_tests || t.starts_with("//") || t.starts_with("pub fn") || t.starts_with("fn ") {
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

/// # Errors
///
/// If the number of balance-adding calls differs from the justified count.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = String::new();
    let mut minting = 0usize;
    let mut moving = 0usize;

    for source in SOURCES {
        let text = std::fs::read_to_string(root.join(source))
            .map_err(|e| format!("could not read {source}: {e}"))?;
        let lines = production_lines(&text);

        let found_move = lines
            .iter()
            .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
            .count();
        let found_mint = lines.iter().filter(|(_, l)| l.contains(MINT_FN)).count();
        moving += found_move;
        minting += found_mint;

        let Some((_, expected, why)) = TRANSFER_JUSTIFICATIONS
            .iter()
            .find(|(name, _, _)| name == source)
        else {
            continue;
        };

        if found_move != *expected {
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
    let lines = production_lines(sample);
    let moves = lines
        .iter()
        .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
        .count();
    let mints = lines.iter().filter(|(_, l)| l.contains(MINT_FN)).count();
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
    Ok("minting-paths-are-counted self-test OK: the test module and comments are outside the count".into())
}
