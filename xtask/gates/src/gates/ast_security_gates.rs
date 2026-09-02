//! `syn`-based AST security gates.
//!
//! Substring+brace-walk gate'ler (`zero_address_sender_is_verified`,
//! `tee_trust_boundary_is_structural`, `gov_slash_evidence_is_validator_only`)
//! could not model parser-level reasoning: each round found a new
//! varyant (closure, nested helper, nested conditional, move closure,
//! collection item). This module verifies the same three guards on a REAL Rust AST;
//! function bodies are walked with `syn::visit`, and closures
//! and nested blocks are distinguished as AST nodes.
//!
//! Korumalar:
//!   1. zero-address: inside `validate_transaction_with_context`, success in the zero-address
//!      branch (`Ok(())` / `return Ok(())`) must be DIRECTLY inside the `if tx.verify()`
//!      block (not in a closure, nested fn item, nested if, match
//!      arm or loop), and the path after the verify block must be fail-closed
//!      (`return Err` / an `Err` tail).
//!   2. TEE: inside `sign_with_privacy` the result of the `verifier.verify_quote` call
//!      (the attestation) must be used with a DIRECT `return Err` in the
//!      `if !verify_measurement/backend/report_data` conditions (a closure/nested-block decoy
//!      does not count), and these guards must come BEFORE the success.
//!   3. gov-slash: in the `SlashValidator` branch of `execute_proposal` the digest
//!      comparison must drive the success: either a DIRECT `return true;` in the
//!      `if digest == evidence_hash` block, or as the TAIL expression of the
//!      `.any(|..| { ..; digest == hash })` closure.
//!
//! Hardening note: the later review findings
//! (nested conditional `return true`, nested-item `Ok(())`, nested conditional
//! (`return Err`, closure decoy) were closed at AST level too; each visitor
//! carries a nesting counter and counts only the checks that are DIRECT members of the
//! target block.

use quote::ToTokens;
use std::path::Path;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprReturn, Stmt};

/// Whitespace-compact token text: drops the spaces in the token stream so
/// comparisons become formatting independent.
fn compact<T: ToTokens>(t: &T) -> String {
    t.to_token_stream()
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Is it an `Ok(())` call? The last path segment is `Ok` and the single argument is the empty tuple.
fn is_ok_unit_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Ok"))
        && node.args.len() == 1
        && matches!(&node.args[0], Expr::Tuple(t) if t.elems.is_empty())
}

/// Is it any `Ok(...)` call? (For the ordering check; the payload type
/// does not matter.)
fn is_ok_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Ok"))
}

/// Is it an `Err(...)` call? (For the tail fail-closed form.)
fn is_err_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Err"))
}

/// Walk the inside of the `if tx.verify() { .. }` block; success counts only as a direct
/// (nesting == 0) `Ok(())` / `return Ok(())`. An `Ok(())` inside a closure, nested
/// fn item, nested if, match arm or loop is a decoy (
/// CWE-697: nested helper and nested-item decoys).
#[derive(Default)]
struct VerifySuccess {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for VerifySuccess {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.nesting == 0 && is_ok_unit_call(node) {
            self.found = true;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if matches!(expr.as_ref(), Expr::Call(c) if is_ok_unit_call(c)) {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

/// Walk the zero-address branch in order: find `if tx.verify()`, check its inside
/// with `VerifySuccess`, and verify that the following expressions are
/// fail-closed.
#[derive(Default)]
struct ZeroBlockCheck {
    guarded_success: bool,
    after_verify_has_success: bool,
}

/// Is the expression after the verify block fail-closed? Only `return Err`,
/// an `Err(...)` tail or a bare `return;` counts; a helper call, a macro
/// or a value expression could leak success outwards (CWE-697:
/// helper and tail success).
fn stmt_fails_closed(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::Return(ret), _) => match &ret.expr {
            None => true,
            Some(e) => compact(e).contains("Err"),
        },
        Stmt::Expr(Expr::Call(call), None) => is_err_call(call),
        _ => false,
    }
}

/// Does the expression contain any `Ok(())`? (Catches unguarded success before
/// the verify.)
fn stmt_contains_unit_ok(stmt: &Stmt) -> bool {
    struct UnitOkFinder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for UnitOkFinder {
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if is_ok_unit_call(node) {
                self.found = true;
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut f = UnitOkFinder { found: false };
    f.visit_stmt(stmt);
    f.found
}

impl<'ast> Visit<'ast> for ZeroBlockCheck {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let mut after_verify = false;
        for stmt in &node.stmts {
            if let Stmt::Expr(Expr::If(ifn), _) = stmt {
                let cond = compact(&ifn.cond);
                if !after_verify && !cond.starts_with('!') && cond.contains("tx.verify()") {
                    let mut vs = VerifySuccess::default();
                    vs.visit_block(&ifn.then_branch);
                    self.guarded_success = vs.found;
                    // Success in the else branch is not guarded by the verify.
                    if let Some((_, else_expr)) = &ifn.else_branch {
                        if let Expr::Block(else_block) = else_expr.as_ref() {
                            let mut evs = VerifySuccess::default();
                            evs.visit_block(&else_block.block);
                            if evs.found {
                                self.after_verify_has_success = true;
                            }
                        }
                    }
                    after_verify = true;
                    continue;
                }
            }
            if after_verify && !stmt_fails_closed(stmt) {
                self.after_verify_has_success = true;
            }
            if !after_verify && stmt_contains_unit_ok(stmt) {
                // Success before the verify is unguarded success (for example
                // `if !tx.verify() { return Ok(()); }`).
                self.after_verify_has_success = true;
            }
        }
    }
}

/// Anchors on the `validate_transaction_with_context` function; finds the zero-address
/// branch and verifies it with `ZeroBlockCheck`.
#[derive(Default)]
struct ZeroAddressFinder {
    result: Option<ZeroBlockCheck>,
    in_validate: bool,
}

impl<'ast> Visit<'ast> for ZeroAddressFinder {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "validate_transaction_with_context" {
            let prev = self.in_validate;
            self.in_validate = true;
            visit::visit_item_fn(self, node);
            self.in_validate = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "validate_transaction_with_context" {
            let prev = self.in_validate;
            self.in_validate = true;
            visit::visit_impl_item_fn(self, node);
            self.in_validate = prev;
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_validate && self.result.is_none() {
            let cond = compact(&node.cond);
            if cond.contains("Address::zero") {
                let mut check = ZeroBlockCheck::default();
                check.visit_block(&node.then_branch);
                self.result = Some(check);
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }
}

/// Walk the `then` block of the TEE guard; `return Err` counts only when direct
/// (nesting == 0). A `return Err` inside a closure/nested if/nested item/match arm/loop
/// is a decoy (CWE-697).
#[derive(Default)]
struct GuardErrCheck {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for GuardErrCheck {
    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if compact(expr).contains("Err") {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

#[allow(clippy::struct_excessive_bools)]
struct TeeVisitor {
    in_sign_with_privacy: bool,
    has_quote_call: bool,
    has_verify_quote: bool,
    measurement_guard: bool,
    backend_guard: bool,
    report_guard: bool,
    saw_success: bool,
    measurement_after_success: bool,
    backend_after_success: bool,
    report_after_success: bool,
}

impl TeeVisitor {
    fn new() -> Self {
        Self {
            in_sign_with_privacy: false,
            has_quote_call: false,
            has_verify_quote: false,
            measurement_guard: false,
            backend_guard: false,
            report_guard: false,
            saw_success: false,
            measurement_after_success: false,
            backend_after_success: false,
            report_after_success: false,
        }
    }
}

impl<'ast> Visit<'ast> for TeeVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "sign_with_privacy" {
            let prev = self.in_sign_with_privacy;
            self.in_sign_with_privacy = true;
            visit::visit_item_fn(self, node);
            self.in_sign_with_privacy = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "sign_with_privacy" {
            let prev = self.in_sign_with_privacy;
            self.in_sign_with_privacy = true;
            visit::visit_impl_item_fn(self, node);
            self.in_sign_with_privacy = prev;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let recv = node.receiver.to_token_stream().to_string();
        if self.in_sign_with_privacy && method == "quote" {
            self.has_quote_call = true;
        }
        if self.in_sign_with_privacy && method == "verify_quote" && recv.contains("verifier") {
            self.has_verify_quote = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.in_sign_with_privacy && is_ok_call(node) {
            // The source is ordered (pre-order): if the guards come after the success
            // islenirse asagida yakalanir.
            self.saw_success = true;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_sign_with_privacy {
            let cond = compact(&node.cond);
            let which = if cond.contains("verify_measurement") {
                Some(0)
            } else if cond.contains("backend") {
                Some(1)
            } else if cond.contains("verify_report_data") {
                Some(2)
            } else {
                None
            };
            if let Some(kind) = which {
                let mut g = GuardErrCheck::default();
                g.visit_block(&node.then_branch);
                let ok = g.found;
                let after_success = self.saw_success;
                match kind {
                    0 => {
                        self.measurement_guard = ok;
                        self.measurement_after_success = after_success;
                    }
                    1 => {
                        self.backend_guard = ok;
                        self.backend_after_success = after_success;
                    }
                    _ => {
                        self.report_guard = ok;
                        self.report_after_success = after_success;
                    }
                }
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }
}

/// Walk the inside of the `if digest == evidence_hash { .. }` block; `return true;`
/// counts only when direct (nesting == 0) (CWE-697:
/// nested conditional `return true` decoy).
#[derive(Default)]
struct TopLevelTrue {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for TopLevelTrue {
    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if compact(expr) == "true" {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

/// Is the tail expression of the `.any(|..| { .. })` closure the digest comparison?
/// A trailing expression with `;` or a value such as `true` does not drive the
/// comparison (CWE-697: overriding the tail form).
fn closure_tail_is_digest_cmp(body: &Expr) -> bool {
    let last: Option<&Expr> = match body {
        Expr::Block(b) => match b.block.stmts.last() {
            Some(Stmt::Expr(e, None)) => Some(e),
            _ => None,
        },
        other => Some(other),
    };
    last.is_some_and(|e| {
        let c = compact(e);
        c.contains("evidence_hash") && c.contains("==")
    })
}

/// Does the closure body contain any digest comparison? (Enough for
/// `has_digest_condition` even when not in tail position; `digest_guards_return`
/// only accepts the tail form.)
fn closure_has_digest_cmp(body: &Expr) -> bool {
    let c = compact(body);
    c.contains("evidence_hash") && c.contains("sha2")
}

#[allow(clippy::struct_excessive_bools)]
struct GovSlashVisitor {
    in_execute_proposal: bool,
    in_slash_validator: bool,
    has_digest_condition: bool,
    digest_guards_return: bool,
}

impl GovSlashVisitor {
    fn new() -> Self {
        Self {
            in_execute_proposal: false,
            in_slash_validator: false,
            has_digest_condition: false,
            digest_guards_return: false,
        }
    }
}

impl<'ast> Visit<'ast> for GovSlashVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "execute_proposal" {
            let prev = self.in_execute_proposal;
            self.in_execute_proposal = true;
            visit::visit_item_fn(self, node);
            self.in_execute_proposal = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "execute_proposal" {
            let prev = self.in_execute_proposal;
            self.in_execute_proposal = true;
            visit::visit_impl_item_fn(self, node);
            self.in_execute_proposal = prev;
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.in_execute_proposal {
            let scrut = node.expr.to_token_stream().to_string();
            if scrut.contains("p_type") {
                for arm in &node.arms {
                    let pat = arm.pat.to_token_stream().to_string();
                    if pat.contains("SlashValidator") {
                        let prev = self.in_slash_validator;
                        self.in_slash_validator = true;
                        visit::visit_expr(self, &arm.body);
                        self.in_slash_validator = prev;
                        return;
                    }
                }
            }
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_slash_validator {
            let cond = compact(&node.cond);
            if cond.contains("evidence_hash") {
                self.has_digest_condition = true;
                let mut v = TopLevelTrue::default();
                v.visit_block(&node.then_branch);
                if v.found {
                    self.digest_guards_return = true;
                }
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.in_slash_validator && node.method == "any" {
            for arg in &node.args {
                if let Expr::Closure(c) = arg {
                    if closure_has_digest_cmp(&c.body) {
                        self.has_digest_condition = true;
                        if closure_tail_is_digest_cmp(&c.body) {
                            self.digest_guards_return = true;
                        }
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Which guards to look for in this file.
#[derive(Clone, Copy)]
struct Checks {
    zero_address: bool,
    tee: bool,
    gov_slash: bool,
}

fn judge_file(src: &str, checks: Checks) -> Vec<String> {
    let mut problems = Vec::new();
    let ast: syn::File = match syn::parse_file(src) {
        Ok(f) => f,
        Err(e) => {
            problems.push(format!("parse error: {e}"));
            return problems;
        }
    };

    if checks.zero_address {
        let mut finder = ZeroAddressFinder::default();
        finder.visit_file(&ast);
        match &finder.result {
            Some(check) => {
                if !check.guarded_success || check.after_verify_has_success {
                    problems.push(String::from(
                        "AST: no real guarded success in the zero-address branch of validate_transaction_with_context: Ok(()) must be directly inside the tx.verify() block (not in a closure, nested fn, nested if, match arm or loop) and the path after verify must be fail-closed (return Err / Err). The CWE-306 guard could not be verified.",
                    ));
                }
            }
            None => {
                problems.push(String::from(
                    "AST: no Address::zero branch found in validate_transaction_with_context; the CWE-306 guard is missing.",
                ));
            }
        }
    }

    if checks.tee {
        let mut tee = TeeVisitor::new();
        tee.visit_file(&ast);
        if !tee.has_quote_call || !tee.has_verify_quote {
            problems.push(String::from(
                "AST: the sign_with_privacy quote to verify_quote chain is missing.",
            ));
        }
        if !tee.measurement_guard {
            problems.push(String::from(
                "AST: no verify_measurement fail-closed guard, or the return Err sits inside a closure/nested block.",
            ));
        }
        if !tee.backend_guard {
            problems.push(String::from(
                "AST: no backend fail-closed guard, or the return Err sits inside a closure/nested block.",
            ));
        }
        if !tee.report_guard {
            problems.push(String::from(
                "AST: no verify_report_data fail-closed guard, or the return Err sits inside a closure/nested block.",
            ));
        }
        let after_success = [
            (tee.measurement_after_success, "verify_measurement"),
            (tee.backend_after_success, "backend"),
            (tee.report_after_success, "verify_report_data"),
        ];
        for (after, name) in after_success {
            if after {
                problems.push(format!(
                    "AST: the {name} guard comes after the success in sign_with_privacy; success cannot be returned before the attestation check runs."
                ));
            }
        }
    }

    if checks.gov_slash {
        let mut gs = GovSlashVisitor::new();
        gs.visit_file(&ast);
        if !gs.has_digest_condition {
            problems.push(String::from(
                "AST: no digest condition in the SlashValidator branch (neither if digest == evidence_hash nor an .any closure tail).",
            ));
        } else if !gs.digest_guards_return {
            problems.push(String::from(
                "AST: the digest condition in the SlashValidator branch does not drive the success: there is no direct return true in the if block, or the .any closure tail is not the digest comparison.",
            ));
        }
    }

    problems
}

/// # Errors
///
/// AST-based findings.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    let plan: &[(&str, Checks)] = &[
        (
            "src/core/account.rs",
            Checks {
                zero_address: true,
                tee: false,
                gov_slash: true,
            },
        ),
        (
            "crates/wallet-core/src/lib.rs",
            Checks {
                zero_address: false,
                tee: true,
                gov_slash: false,
            },
        ),
        (
            "crates/wallet-core/src/tee.rs",
            Checks {
                zero_address: false,
                tee: false,
                gov_slash: false,
            },
        ),
    ];
    for (rel, checks) in plan {
        let p = root.join(rel);
        let src = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("cannot read {}: {e}", p.display()));
                continue;
            }
        };
        problems.extend(judge_file(&src, *checks));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "AST security gates OK: zero-address, TEE trust boundary and gov-slash evidence are enforced on the real Rust AST.",
        ));
    }
    Err(problems.join("\n"))
}

// Self-test canaries: each is a source tree the gate must refuse or accept.
// Keeping them as consts keeps self_test short.
const GOOD_TREE: &str = r#"
fn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {
    if tx.from == Address::zero() {
        if tx.verify() {
            return Ok(());
        }
        return Err("x".into());
    }
    Ok(())
}
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        Ok([0u8; 64])
    }
}
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                return true;
            }
        }
    }
}
"#;
const GOOD_ANY_TREE: &str = r#"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            let evidence_matches = records.iter().any(|record| {
                if record.report.role != crate::registry::role::roles::VALIDATOR {
                    return false;
                }
                let bytes = bincode::serialize(&record.report).expect("x");
                sha2::Sha256::digest(&bytes).as_slice() == evidence_hash
            });
        }
    }
}
"#;
const ZA_BAD: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
const ZA_NESTED_ITEM: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            fn decoy() -> Result<(), String> { Ok(()) }\n        }\n        return helper_accepting_zero_address(tx);\n    }\n    Ok(())\n}\n";
const ZA_CLOSURE_DECOY: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            let _d = || { return Ok(()); };\n        }\n        return Err(\"x\".into());\n    }\n    Ok(())\n}\n";
const ZA_FAILED_VERIFY: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if !tx.verify() {\n            return Ok(());\n        }\n        return Err(\"x\".into());\n    }\n    Ok(())\n}\n";
const TEE_NESTED_CONDITIONAL: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        if attestation.backend != TeeBackendKind::ClientSgx { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        if !attestation.verify_report_data(&[0u8; 32]) { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        Ok([0u8; 64])
    }
}
"#;
const TEE_CLOSURE_DECOY: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { let _d = || { return Err(WalletError::TeeUnavailable("x".into())); }; }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        Ok([0u8; 64])
    }
}
"#;
const TEE_AFTER_SUCCESS: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        Ok([0u8; 64]);
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
    }
}
"#;
const GOV_NESTED_CONDITIONAL: &str = r"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                if false { return true; }
            }
            true
        }
    }
}
";
const GOV_NON_TAIL: &str = r"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            let ok = records.iter().any(|record| {
                sha2::Sha256::digest(&bytes).as_slice() == evidence_hash;
                true
            });
        }
    }
}
";

/// # Errors
///
/// Canaries.
fn expect_problem(
    problems: &mut Vec<String>,
    src: &str,
    checks: Checks,
    needle: &str,
    vacuous: &str,
) {
    let finds = judge_file(src, checks);
    if !finds.iter().any(|p| p.contains(needle)) {
        problems.push(format!("VACUOUS: {vacuous} (got {finds:?})"));
    }
}

fn expect_clean(problems: &mut Vec<String>, src: &str, checks: Checks, broken: &str) {
    let finds = judge_file(src, checks);
    if !finds.is_empty() {
        problems.push(format!("BROKEN: {broken}: {finds:?}"));
    }
}

/// # Errors
///
/// Canaries.
pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();
    let all = Checks {
        zero_address: true,
        tee: true,
        gov_slash: true,
    };
    let za_only = Checks {
        zero_address: true,
        tee: false,
        gov_slash: false,
    };
    let tee_only = Checks {
        zero_address: false,
        tee: true,
        gov_slash: false,
    };
    let gov_only = Checks {
        zero_address: false,
        tee: false,
        gov_slash: true,
    };

    // Good trees: the correct shape of all three guards.
    expect_clean(&mut problems, GOOD_TREE, all, "good tree rejected");
    expect_clean(
        &mut problems,
        GOOD_ANY_TREE,
        gov_only,
        "good .any tail tree rejected",
    );

    // Zero-address: guard'siz, nested-item, closure-decoy, failed-verify.
    expect_problem(
        &mut problems,
        ZA_BAD,
        za_only,
        "zero-address",
        "unguarded zero-address success accepted",
    );
    expect_problem(
        &mut problems,
        ZA_NESTED_ITEM,
        za_only,
        "zero-address",
        "nested-item Ok(()) decoy with a tail helper success accepted",
    );
    expect_problem(
        &mut problems,
        ZA_CLOSURE_DECOY,
        za_only,
        "zero-address",
        "closure-decoy Ok(()) accepted as guarded success",
    );
    expect_problem(
        &mut problems,
        ZA_FAILED_VERIFY,
        za_only,
        "zero-address",
        "failed-verify branch success accepted",
    );

    // TEE: nested conditional, closure decoy, post-success guard.
    expect_problem(
        &mut problems,
        TEE_NESTED_CONDITIONAL,
        tee_only,
        "fail-closed guard",
        "TEE nested conditional return Err decoy accepted",
    );
    expect_problem(
        &mut problems,
        TEE_CLOSURE_DECOY,
        tee_only,
        "fail-closed guard",
        "TEE closure-decoy return Err accepted",
    );
    expect_problem(
        &mut problems,
        TEE_AFTER_SUCCESS,
        tee_only,
        "comes after the success",
        "TEE guards after the success were accepted",
    );

    // Gov-slash: nested conditional return true, non-tail closure.
    expect_problem(
        &mut problems,
        GOV_NESTED_CONDITIONAL,
        gov_only,
        "does not drive the success",
        "gov-slash nested conditional return true accepted",
    );
    expect_problem(
        &mut problems,
        GOV_NON_TAIL,
        gov_only,
        "does not drive the success",
        "gov-slash non-tail .any closure accepted",
    );

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "AST security gates self-test OK: good tree passes, decoy variants rejected.",
    ))
}
