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

/// Saturating balance helper that bypasses `try_add_balance` / `try_mint_balance`.
const RAW_ADD_FN: &str = "add_balance";

/// Fractional attoBUD normalizer that writes `self.balance` directly.
const ATTOS_SET_FN: &str = "set_from_total_attos";

/// Direct `.balance` writes (`+=`, non-debit `=`, `&mut ...balance`),
/// saturating `.add_balance(` calls, and `.set_from_total_attos(` calls across
/// all production files under `src/`.
///
/// Without counting these sites alongside `try_add_balance`, a supply-creating
/// change could write `account.balance += minted`, `account.balance =
/// account.balance.saturating_add(minted)` or `state.add_balance(&who, minted)`
/// and leave `minting-paths-are-counted` completely silent.
const DIRECT_BALANCE_JUSTIFICATIONS: &[(&str, usize, &str)] = &[
    (
        "src/aggregation/fraud.rs",
        1,
        "one in `try_credit_escrow_redistribution`: credits an already-debited \
         challenger bond or confiscated aggregator stake redistribution after \
         rejecting zero, burn-reserve and `checked_add` overflow - escrow \
         moving back, never new supply.",
    ),
    (
        "src/chain/blockchain.rs",
        4,
        "one slashing-report fee refund (`saturating_add(fee)` returning the \
         exact `fee` debited at the top of the same block), one expired AI \
         request `max_fee` refund returning the requester's escrowed fee, and \
         two devnet-only consensus-refused test faucet helpers (`fund_devnet` \
         and `credit_devnet`, both hard-gated on `devnet_chain_id()` and \
         unreachable on mainnet or testnet).",
    ),
    (
        "src/chain/genesis.rs",
        3,
        "three initial genesis allocation credits inside genesis construction, \
         bounded by the genesis supply invariant before any block executes.",
    ),
    (
        "src/core/account.rs",
        11,
        "one inside `Account::set_from_total_attos`, two snapshot restores \
         (`from_snapshot` and `from_snapshot_v2`), three unbonding/withdrawal \
         settlements returning staked principal (`withdraw_delegation`, \
         `withdraw_role`, `withdraw_ai_operator`), one expired proof-market \
         escrow refund in epoch close, the single body line of `add_balance` \
         and the single body line of `try_add_balance`, plus the two sender/ \
         recipient `set_from_total_attos` calls in `transfer_attos_in_unit` \
         where `new_sender_total` and `new_recipient_total` conserve total \
         attoBUD.",
    ),
    (
        "src/execution/coordinator/conformance.rs",
        2,
        "two isolated `AccountState::new()` funding lines in `funded_pair` for \
         the self-contained Prague EVM conformance vector runner.",
    ),
    (
        "src/execution/coordinator/gas.rs",
        1,
        "one `acct.set_from_total_attos(after)` burn debit in gas settlement \
         where `after = current.checked_sub(exact_burn_attos)` strictly \
         decreases balance and increments `burned_total`.",
    ),
    (
        "src/execution/coordinator/overlay.rs",
        1,
        "one `acct.balance = *bal` rollback restore in `restore_accounts`, \
         putting back the pre-execution snapshot on revert.",
    ),
    (
        "src/execution/executor.rs",
        12,
        "twelve `checked_add` transfer/escrow settlements inside transaction \
         execution: P2P transfer receiver credit (debited from sender), BNS \
         resale seller credit (debited from buyer), NFT boost creator and \
         burn-reserve shares (carved out of booster debit), Pollen marketplace \
         seller credit (debited from buyer), two AI request `max_fee` escrow \
         refunds on timeout/cancel, immediate AI agent payment recipient \
         credit, escrowed AI agent payment release and expiry reclaim, and \
         storage custody endowment/gateway split credits (carved out of \
         `charged_storage_fee`). None creates new supply.",
    ),
    (
        "src/settlement/domains.rs",
        3,
        "three `ProofMarketTx` escrow payouts (`PayReceipt` prover reward, \
         `RefundExpired` creator refund, and `WithdrawEscrow` withdrawal), \
         each paid strictly out of funds previously escrowed into \
         `state.proof_market`.",
    ),
    (
        "src/sharding/mod.rs",
        1,
        "one shard transfer `receiver.balance = receiver.balance.checked_add(tx.amount)` \
         immediately following `sender.balance.checked_sub(total_cost)`.",
    ),
];

/// The expected `try_add_balance` call count and why each of them is a
/// **transfer**.
///
/// The count is kept deliberately: if a call is added the total changes and the gate fires.
/// The rationales tell the reader why those lines do not ask the ceiling.
const TRANSFER_JUSTIFICATIONS: &[(&str, usize, &str)] = &[
    (
        "src/chain/blockchain.rs",
        5,
        "five calls, each one puts back or splits money this ledger already \
         took from another place. \
         One in `apply_bridge_sweep_to_state`: the refund of an expired lock \
         to its owner, again the amount the lock debited. \
         Two in `distribute_bud_boost_share_in_state`: the operator shares and \
         the rounding dust of the 4 percent share that the NFT boost carved \
         out of the booster's debit, and the shares plus dust equal exactly \
         that pending amount. \
         Two in the block-application storage prune (`prune_storage_content_in_state`): \
         the operator bond that `open_deal` debited, returned when the owner \
         burns the content and the prune ends the deal early, and the storage \
         fee for the epochs the ended deal will no longer serve, which \
         `open_deal` debited from the payer up front, returned to that payer; \
         what the operator already earned for the served epochs came out of \
         the same escrowed fee, so the refund cannot exceed what was taken. \
         None of these create new supply. The bridge mint paths use \
         `try_mint_balance` and are not on this list.",
    ),
    (
        "src/execution/executor.rs",
        6,
        "two in `pay_claim_fees`: the aggregator share and the producer share \
         of the claim fees of a block. `ClaimSettlement` charges each claim \
         fee to the transaction that pays for the claim, and \
         `finalize_block_with_claims` takes exactly that amount out of the \
         fee the sender already paid before the burn and the fee split see \
         it, so the two credits equal what was withheld and create no \
         supply; a sender who cannot cover its claims is not executed and \
         is charged nothing. One in `pay_agreeing_verifiers` (the requester's escrowed AI request \
         fee `max_fee`, already debited when the request opened, split across \
         the agreeing verifiers without creating supply), one bridge unlock \
         inside a RelayerResult (the owner's burned share is returned; the \
         relayer's cut was already minted on target arrival), and the two \
         fee-split recipients of a transaction fee that was already paid - the \
         application share to the recipient and the protocol share to the \
         producer. The bridge mint inside a RelayerResult is not on this list: \
         it creates supply and goes through `try_mint_balance`.",
    ),
    (
        "src/settlement/domains.rs",
        5,
        "three in `execute_relayer_intent_tx`: the unused paid fee returned to \
         the sender, the owner's unspent escrow returned on the outcomes that \
         cancel or expire the intent, and the bond returned out of the same \
         recorded escrow; two in `execute_proof_market_tx`: the task creator's \
         reward paid out of the fees the requester already paid into the task. \
         Every line moves recorded value back to the party that paid it in.",
    ),
    (
        "src/settlement/app_binding.rs",
        1,
        "one in `credit`: the intent payment moves the user's own escrowed \
         funds to the solver on fulfilment - the amount the intent locked, \
         not new supply.",
    ),
    (
        "src/core/account.rs",
        6,
        "one is the release of the unbonding queue (money already committed as stake \
         and already counted against the ceiling is returned - not new supply \
         but supply changing category); one is the body of `try_mint_balance` itself, \
         the line that performs the actual addition after checking the ceiling. \
         Two are the external-domain bond escrow: \
         `release_external_bond` returns what `lock_external_bond` took out \
         of the same poster's balance, capped at what the escrow actually \
         holds, and `slash_external_bond` pays the challenger a reward no \
         larger than the amount the same call takes out of the prover's \
         escrow, with the remainder recorded in `burned_total`. The escrow \
         counts in `total_bud_committed` the whole time it is held, so \
         neither line opens minting headroom. The fifth is \
         `claim_delegator_rewards`: it pays out the delegation reward row that \
         the distribution already booked against fees taken in - recorded \
         value changing hands, not new supply. The sixth is \
         `release_pool_deposit`: it returns what `lock_pool_deposit` took out \
         of the same owner's balance, capped at what the pool-deposit escrow \
         actually holds, and that escrow counts in `total_bud_committed` the \
         whole time it is held - an occupancy deposit coming home, not new \
         supply.",
    ),
    (
        "src/chain/storage_maintenance.rs",
        4,
        "the storage reward tick pays the operator out of the fee that \
         `open_deal` debited from the payer, as the difference of two \
         cumulative totals so the sum cannot pass the escrowed fee; the \
         refund of a slashed deal returns the unserved part of that same \
         prepaid fee to the payer the ledger took it from; the missed-challenge \
         settlement returns the opener bond that `open_challenge` debited from \
         the triggering challenger and also refunds the opener bond of every \
         sibling open challenge resolved when the parent deal is slashed; and \
         the storage deal expiry sweep returns the operator bond that \
         `open_deal` debited when the deal's term ends unrenewed. Each line \
         puts back money this ledger already took, so none of them creates \
         supply.",
    ),
    (
        "src/cross_domain/bridge_tx.rs",
        2,
        "the verified-burn unlock returns the owner the burned amount the lock \
         debited from the owner less the relayer fee the mint paid out of the \
         arriving asset, and the relay unlock of a burned bridge transfer \
         returns the owner share recorded on burn (the relayer cut was \
         already paid at mint).",
    ),
    (
        "src/domain/storage_tx.rs",
        1,
        "the challenge settlement returns the opener's bond to the opener: the \
         amount `answer_challenge`'s debit side took out of the opener's \
         escrow when the challenge was opened, so the refund cannot exceed \
         what was taken; and `SlashDeal` refunds the opener bonds of any open \
         challenges on the slashed deal that are resolved alongside the slash, \
         returning only the exact escrowed bond each `open_challenge` debited.",
    ),
    (
        "src/tokenomics/reward_pool.rs",
        1,
        "one in `pay_epoch`: the epoch payout moves the pool account's own \
         pre-funded balance to the validators, capped by what the pool holds - \
         recorded value changing hands, and nothing is minted.",
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

/// Does this line define (not call) one of the balance functions?
fn is_definition(line: &str) -> bool {
    line.contains(&format!("fn {MOVE_FN}"))
        || line.contains(&format!("fn {MINT_FN}"))
        || line.contains(&format!("fn {RAW_ADD_FN}"))
        || line.contains(&format!("fn {ATTOS_SET_FN}"))
}

/// True when `code` calls `.method(` as a receiver method call.
fn has_dot_call(code: &str, method: &str) -> bool {
    let needle = format!(".{method}");
    let mut from = 0usize;
    while let Some(pos) = code[from..].find(&needle) {
        let after = &code[from + pos + needle.len()..];
        if after.trim_start().starts_with('(') {
            return true;
        }
        from += pos + needle.len();
    }
    false
}

/// True when `code` borrows `&mut <expr>.balance` so a helper could credit it
/// through a mutable reference without naming `try_mint_balance`.
fn has_mut_ref_balance(code: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = code[from..].find("&mut") {
        let after = &code[from + pos + 4..];
        if after
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_whitespace())
        {
            let expr = after.trim_start();
            let end = expr
                .find(|c: char| {
                    !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '(' | ')' | '[' | ']'))
                })
                .unwrap_or(expr.len());
            if expr[..end].ends_with(".balance") {
                return true;
            }
        }
        from += pos + 4;
    }
    false
}

/// True when `rhs` is strictly a pure debit (`checked_sub`, `saturating_sub`
/// or `balance - <ident>;` with no `add` anywhere in the statement).
fn is_pure_debit_rhs(rhs: &str) -> bool {
    let trimmed = rhs.trim_start();
    if trimmed.contains("add") {
        return false;
    }
    if trimmed.contains("checked_sub(") || trimmed.contains("saturating_sub(") {
        return true;
    }
    if let Some(after_bal) = trimmed.strip_prefix("balance") {
        let after_bal = after_bal.trim_start();
        if let Some(after_minus) = after_bal.strip_prefix('-') {
            let operand = after_minus.trim_start();
            let id_len = operand
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(operand.len());
            if id_len > 0 && operand[id_len..].trim_start().starts_with(';') {
                return true;
            }
        }
    }
    false
}

/// True when `lines[idx]` mutates an account balance outside `try_add_balance`
/// / `try_mint_balance` via `.add_balance(`, `.set_from_total_attos(`,
/// `&mut ...balance`, `.balance +=`, or a non-debit `.balance =` write.
fn is_direct_balance_credit(lines: &[(usize, &str)], idx: usize) -> bool {
    let line = lines[idx].1;
    let code = line.split("//").next().unwrap_or(line);
    if has_dot_call(code, RAW_ADD_FN) || has_dot_call(code, ATTOS_SET_FN) {
        return true;
    }
    if has_mut_ref_balance(code) {
        return true;
    }
    let needle = ".balance";
    let mut from = 0usize;
    while let Some(pos) = code[from..].find(needle) {
        let abs = from + pos;
        let after_idx = abs + needle.len();
        let next_byte = code.as_bytes().get(after_idx).copied();
        if next_byte.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') {
            from = after_idx;
            continue;
        }
        let rest = code[after_idx..].trim_start();
        if rest.starts_with("+=") {
            return true;
        }
        if rest.starts_with('=') && !rest.starts_with("==") {
            let mut window = code[abs..].to_string();
            for (_, next_line) in lines.iter().skip(idx + 1).take(4) {
                if window.contains(';') {
                    break;
                }
                window.push(' ');
                window.push_str(next_line.split("//").next().unwrap_or(next_line).trim());
            }
            if let Some((_, rhs)) = window.split_once('=') {
                if !is_pure_debit_rhs(rhs) {
                    return true;
                }
            }
        }
        from = after_idx;
    }
    false
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
    let mut direct_sites = 0usize;

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
    for (name, _, _) in DIRECT_BALANCE_JUSTIFICATIONS {
        if !sources.iter().any(|(rel, _)| rel == name) {
            let _ = write!(
                problems,
                "\n  {name}: listed in the direct-balance justifications but not found."
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
        let found_direct = (0..lines.len())
            .filter(|&i| is_direct_balance_credit(&lines, i))
            .count();
        moving += found_move;
        minting += found_mint;
        direct_sites += found_direct;

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

        let (expected_direct, why_direct) = DIRECT_BALANCE_JUSTIFICATIONS
            .iter()
            .find(|(name, _, _)| name == source)
            .map_or(
                (0, "this file has no recorded direct balance write"),
                |(_, n, w)| (*n, *w),
            );

        if found_direct != expected_direct {
            let _ = write!(
                problems,
                "\n  {source}: there are {found_direct} direct `.balance` / `{RAW_ADD_FN}` / \
                 `{ATTOS_SET_FN}` write sites, the justified count is {expected_direct}.\n    \
                 Recorded rationale: {why_direct}\n    \
                 Direct field writes bypass `{MINT_FN}` and `{HEADROOM_FN}`: new supply must \
                 go through `{MINT_FN}`, and any transfer/escrow write must be justified."
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
         {moving} transfer calls and {direct_sites} direct balance writes are justified"
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
    // Direct field writes, saturating `.add_balance`, and `&mut ...balance`
    // bypass `try_mint_balance` and must be counted, while pure debits and
    // equality comparisons must not.
    let count_direct = |text: &str| {
        let pl = production_lines(text);
        (0..pl.len())
            .filter(|&i| is_direct_balance_credit(&pl, i))
            .count()
    };
    let bypass_plus_eq = "fn mint(a: &mut Account, v: u64) {\n    a.balance += v;\n}\n";
    if count_direct(bypass_plus_eq) != 1 {
        return Err("self_test: direct `.balance +=` bypass was not counted".into());
    }
    let bypass_sat =
        "fn mint(a: &mut Account, v: u64) {\n    a.balance = a.balance.saturating_add(v);\n}\n";
    if count_direct(bypass_sat) != 1 {
        return Err(
            "self_test: direct `.balance = ...saturating_add` bypass was not counted".into(),
        );
    }
    let bypass_raw_add =
        "fn mint(s: &mut AccountState, k: &Address, v: u64) {\n    s.add_balance(k, v);\n}\n";
    if count_direct(bypass_raw_add) != 1 {
        return Err("self_test: saturating `.add_balance(` call was not counted".into());
    }
    let bypass_mut_ref =
        "fn mint(a: &mut Account) {\n    let b = &mut a.balance;\n    *b += 1;\n}\n";
    if count_direct(bypass_mut_ref) != 1 {
        return Err("self_test: `&mut account.balance` borrow was not counted".into());
    }
    let pure_debit_and_cmp = "fn debit(a: &mut Account, fee: u64) -> Result<bool, &'static str> {\n    a.balance = a\n        .balance\n        .checked_sub(fee)\n        .ok_or(\"underflow\")?;\n    Ok(a.balance == 0)\n}\n";
    if count_direct(pure_debit_and_cmp) != 0 {
        return Err(
            "self_test: pure `checked_sub` debit or `==` comparison was miscounted as a credit"
                .into(),
        );
    }
    Ok("minting-paths-are-counted self-test OK: test modules, comments, definitions, one-line fns, code after test modules and direct `.balance` / `add_balance` bypasses are classified correctly".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("minting-paths self-test");
    }
}
